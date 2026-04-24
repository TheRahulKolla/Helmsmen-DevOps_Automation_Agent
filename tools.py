"""
tools.py - The six things the DevOps agent can DO.

Pattern mirrors Agent/tools.py: each tool is a plain Python function,
TOOL_MAP maps tool names to functions, and get_tool_definitions()
returns the JSON schema list that Claude sees.

Tools:
  1. get_ci_status       - latest GitHub Actions run result + failed steps
  2. scan_dependencies   - OSV.dev CVE scan of requirements.txt / package.json
  3. list_stale_prs      - PRs open > N days with no activity
  4. create_github_issue - opens a GitHub issue (dedup via state.py)
  5. post_slack_digest   - sends a message to a Slack channel
  6. web_search          - Tavily search (for CVE fix lookup)
"""

import os
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta

import requests as http_requests
from github import Github, GithubException
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

import state

OSV_API = "https://api.osv.dev/v1/querybatch"


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _gh() -> Github:
    """Return an authenticated PyGitHub client."""
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN environment variable not set.")
    return Github(token)


def _fingerprint(owner: str, repo: str, title: str) -> str:
    """Stable short hash used to detect duplicate issues across runs."""
    raw = f"{owner}/{repo}:{title.lower().strip()}"
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _ensure_labels(repo_obj, labels: list) -> None:
    """Create any labels that don't exist yet (PyGitHub silently drops unknown labels otherwise)."""
    existing = {lbl.name for lbl in repo_obj.get_labels()}
    color_map = {"bug": "d73a4a", "security": "b60205", "stale": "cfd3d7"}
    for label in labels:
        if label not in existing:
            try:
                repo_obj.create_label(name=label, color=color_map.get(label, "ededed"))
            except GithubException:
                pass  # benign — label may have been created in a concurrent run


def _parse_requirements(content: str) -> list[dict]:
    """Parse requirements.txt, skipping VCS/editable/recursive lines."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(("-e ", "-r ", "git+")):
            continue
        line = re.sub(r"\[.*?\]", "", line)  # strip extras like [security]
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)?\s*([\w\.\*]+)?", line)
        if not match:
            continue
        name, op, version = match.groups()
        if op == "==" and version:
            packages.append({"name": name, "version": version})
        else:
            packages.append({"name": name, "version": ""})
    return packages


# ─────────────────────────────────────────────────────────────────────────────
# Tool 1: get_ci_status
# ─────────────────────────────────────────────────────────────────────────────

def get_ci_status(owner: str, repo: str) -> str:
    """Fetch the most recent completed GitHub Actions run + failed step names."""
    try:
        repo_obj = _gh().get_repo(f"{owner}/{repo}")
        runs = repo_obj.get_workflow_runs(status="completed")
        if runs.totalCount == 0:
            return "CI Status: No completed workflow runs found."

        run = runs[0]  # most recent
        state.set_last_ci_run_id(str(run.id))

        lines = [
            f"CI Status: {run.conclusion.upper() if run.conclusion else 'UNKNOWN'}",
            f"Workflow: {run.name} (run #{run.id})",
            f"Branch: {run.head_branch}",
            f"Commit: {run.head_sha[:7]}",
            f"URL: {run.html_url}",
        ]

        if run.conclusion == "failure":
            failed_jobs, failed_steps = [], []
            for job in run.jobs()[:10]:  # limit to first page
                if job.conclusion == "failure":
                    failed_jobs.append(job.name)
                    for step in (job.steps or []):
                        if step.conclusion == "failure":
                            failed_steps.append(f"{job.name} -> {step.name}")
            if failed_jobs:
                lines.append(f"Failed jobs: {', '.join(failed_jobs)}")
            if failed_steps:
                lines.append(f"Failed steps: {'; '.join(failed_steps)}")

        return "\n".join(lines)

    except GithubException as e:
        return f"get_ci_status error: GitHub API returned {e.status} - {e.data.get('message', '')}"
    except Exception as e:
        return f"get_ci_status error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 2: scan_dependencies
# ─────────────────────────────────────────────────────────────────────────────

def scan_dependencies(owner: str, repo: str) -> str:
    """Scan requirements.txt or package.json against OSV.dev for known CVEs."""
    try:
        repo_obj = _gh().get_repo(f"{owner}/{repo}")
        packages, ecosystem = [], None

        try:
            content = repo_obj.get_contents("requirements.txt")
            text = content.decoded_content.decode("utf-8")
            packages = _parse_requirements(text)
            ecosystem = "PyPI"
        except GithubException:
            pass

        if not packages:
            try:
                content = repo_obj.get_contents("package.json")
                data = json.loads(content.decoded_content.decode("utf-8"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                packages = [{"name": k, "version": v.lstrip("^~>=<* ")} for k, v in deps.items()]
                ecosystem = "npm"
            except GithubException:
                return "No requirements.txt or package.json found in repository root."

        if not packages:
            return "No packages found to scan."

        # Build OSV batch queries
        queries = []
        for pkg in packages:
            q = {"package": {"name": pkg["name"], "ecosystem": ecosystem}}
            if pkg.get("version"):
                q["version"] = pkg["version"]
            queries.append(q)

        all_vulns = []
        seen_ids = set()

        # Chunk into 500-query batches (OSV accepts up to 1000; 500 is conservative)
        for i in range(0, len(queries), 500):
            chunk = queries[i:i + 500]
            pkg_chunk = packages[i:i + 500]
            resp = http_requests.post(OSV_API, json={"queries": chunk}, timeout=30)
            if resp.status_code != 200:
                return f"OSV.dev API error: {resp.status_code} - {resp.text[:200]}"
            results = resp.json().get("results", [])

            for j, result in enumerate(results):
                for v in result.get("vulns", []):
                    vid = v.get("id", "")
                    if vid in seen_ids:
                        continue
                    seen_ids.add(vid)
                    all_vulns.append({
                        "package": pkg_chunk[j]["name"],
                        "version": pkg_chunk[j].get("version", "unknown") or "unknown",
                        "id": vid,
                        "aliases": v.get("aliases", []),
                        "summary": v.get("summary", ""),
                    })

        if not all_vulns:
            return f"No vulnerabilities found in {len(packages)} {ecosystem} packages. All clear."

        lines = [f"Found {len(all_vulns)} vulnerability(s) in {len(packages)} {ecosystem} packages:\n"]
        for v in all_vulns:
            cve = next((a for a in v["aliases"] if a.startswith("CVE-")), v["id"])
            lines.append(f"- {v['package']}=={v['version']}: {cve} - {v['summary']}")
        return "\n".join(lines)

    except Exception as e:
        return f"scan_dependencies error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 3: list_stale_prs
# ─────────────────────────────────────────────────────────────────────────────

def list_stale_prs(owner: str, repo: str, stale_days: int = 7) -> str:
    """List open PRs with no activity for > stale_days."""
    try:
        repo_obj = _gh().get_repo(f"{owner}/{repo}")
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        stale = []

        for pr in repo_obj.get_pulls(state="open", sort="updated", direction="asc"):
            updated = pr.updated_at
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            if updated >= cutoff:
                break  # sorted oldest-first; rest are fresher
            age = (datetime.now(timezone.utc) - updated).days
            stale.append({
                "number": pr.number,
                "title": pr.title,
                "age_days": age,
                "url": pr.html_url,
                "author": pr.user.login if pr.user else "unknown",
            })

        if not stale:
            return f"No PRs stale longer than {stale_days} days."

        lines = [f"Found {len(stale)} stale PR(s) (> {stale_days} days no activity):\n"]
        for pr in stale:
            lines.append(f"- #{pr['number']} '{pr['title']}' by @{pr['author']} "
                         f"({pr['age_days']}d idle) - {pr['url']}")
        return "\n".join(lines)

    except GithubException as e:
        return f"list_stale_prs error: GitHub API {e.status} - {e.data.get('message', '')}"
    except Exception as e:
        return f"list_stale_prs error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 4: create_github_issue
# ─────────────────────────────────────────────────────────────────────────────

def create_github_issue(owner: str, repo: str, title: str, body: str,
                        labels: list = None) -> str:
    """Open a GitHub issue, skipping if a duplicate fingerprint already exists."""
    labels = labels or []
    fp = _fingerprint(owner, repo, title)

    if state.has_open_issue(fp):
        existing = state.get_issue_url(fp)
        return f"SKIPPED: duplicate issue already open at {existing}"

    try:
        repo_obj = _gh().get_repo(f"{owner}/{repo}")
        if labels:
            _ensure_labels(repo_obj, labels)
        issue = repo_obj.create_issue(title=title, body=body, labels=labels)
        state.record_issue(fp, issue.html_url)
        return f"Issue created: {issue.html_url}"

    except GithubException as e:
        return f"create_github_issue error: GitHub API {e.status} - {e.data.get('message', '')}"
    except Exception as e:
        return f"create_github_issue error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 5: post_slack_digest
# ─────────────────────────────────────────────────────────────────────────────

def post_slack_digest(channel: str, blocks_or_text: str) -> str:
    """Post a digest to Slack. Accepts plain text or Block Kit JSON (string starting with '[')."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        return "post_slack_digest error: SLACK_BOT_TOKEN not set."

    try:
        client = WebClient(token=token)
        channel_clean = channel.lstrip("#")
        kwargs = {"channel": channel_clean}

        stripped = blocks_or_text.strip()
        if stripped.startswith("["):
            try:
                kwargs["blocks"] = json.loads(stripped)
                kwargs["text"] = "Helmsmen digest"  # fallback for notifications
            except json.JSONDecodeError:
                kwargs["text"] = blocks_or_text
        else:
            kwargs["text"] = blocks_or_text

        resp = client.chat_postMessage(**kwargs)
        return f"Slack message posted. ts={resp['ts']}"

    except SlackApiError as e:
        err = e.response.get("error", "unknown")
        if err == "not_in_channel":
            return (f"post_slack_digest error: bot is not a member of #{channel_clean}. "
                    f"Invite the bot or add 'chat:write.public' scope.")
        return f"post_slack_digest error: Slack API returned '{err}'"
    except Exception as e:
        return f"post_slack_digest error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Tool 6: web_search (Tavily - reused pattern from Agent/tools.py)
# ─────────────────────────────────────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """Search the web via Tavily. Used for CVE fix lookups."""
    try:
        from tavily import TavilyClient
        api_key = os.environ.get("TAVILY_API_KEY")
        if not api_key:
            return "web_search error: TAVILY_API_KEY not set."
        client = TavilyClient(api_key=api_key)
        resp = client.search(query, max_results=max_results)
        results = resp.get("results", [])
        if not results:
            return "No results found."
        out = []
        for i, r in enumerate(results, 1):
            snippet = (r.get("content", "") or "")[:200]
            out.append(f"[{i}] {r.get('title', '')}\n{snippet}\nSource: {r.get('url', '')}")
        return "\n\n".join(out)
    except Exception as e:
        return f"web_search error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Registry: TOOL_MAP, tool definitions, dispatcher
# ─────────────────────────────────────────────────────────────────────────────

TOOL_MAP = {
    "get_ci_status": get_ci_status,
    "scan_dependencies": scan_dependencies,
    "list_stale_prs": list_stale_prs,
    "create_github_issue": create_github_issue,
    "post_slack_digest": post_slack_digest,
    "web_search": web_search,
}


_TOOL_DEFINITIONS = [
    {
        "name": "get_ci_status",
        "description": "Fetch the most recent completed GitHub Actions run for a repo. Returns conclusion (success/failure), workflow name, failed jobs and steps, and URL.",
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "GitHub owner/organization"},
                "repo": {"type": "string", "description": "GitHub repository name"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "scan_dependencies",
        "description": "Scan the repo's requirements.txt or package.json against the OSV.dev vulnerability database. Returns a list of CVEs affecting pinned packages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "list_stale_prs",
        "description": "List open pull requests with no activity for more than stale_days days.",
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "stale_days": {"type": "integer", "description": "Threshold in days", "default": 7},
            },
            "required": ["owner", "repo"],
        },
    },
    {
        "name": "create_github_issue",
        "description": "Open a GitHub issue. Automatically deduplicates against previously opened issues using a title-based fingerprint. Returns SKIPPED if a duplicate is found.",
        "input_schema": {
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
                "title": {"type": "string", "description": "Issue title. Format: '[Helmsmen] <Problem>: <Detail>'"},
                "body": {"type": "string", "description": "Issue body in GitHub markdown"},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Labels to apply, e.g. ['bug'], ['security'], ['stale']",
                },
            },
            "required": ["owner", "repo", "title", "body"],
        },
    },
    {
        "name": "post_slack_digest",
        "description": "Post a digest summary to a Slack channel. Pass plain text, OR a JSON string of Block Kit blocks (must start with '[').",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Slack channel, e.g. '#devops-alerts'"},
                "blocks_or_text": {"type": "string", "description": "Plain text message or Block Kit JSON"},
            },
            "required": ["channel", "blocks_or_text"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the web for CVE fix recommendations, advisories, or remediation guidance.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "integer", "default": 5},
            },
            "required": ["query"],
        },
    },
]


def get_tool_definitions() -> list:
    """Return the list of tool schemas Claude sees. All tools always available."""
    return _TOOL_DEFINITIONS


def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Dispatch a tool call to the right function. All tools return a string."""
    if tool_name not in TOOL_MAP:
        return f"Unknown tool: {tool_name}"
    try:
        return TOOL_MAP[tool_name](**tool_input)
    except TypeError as e:
        return f"Tool '{tool_name}' called with bad arguments: {e}"
    except Exception as e:
        return f"Tool '{tool_name}' raised unexpected error: {e}"
