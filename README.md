# Helmsmen

An autonomous DevOps agent that watches a GitHub repository, detects real problems (failing CI, vulnerable dependencies, stale pull requests), and takes action — opens issues, drafts fix recommendations, and posts a Slack digest — all without being asked.

Built on a ReAct loop driven by Claude Sonnet 4.6, with pluggable tools for GitHub, Slack, and OSV.dev.

---

## Why it exists

Most "AI DevOps" demos are chatbots wrapped around an API. Helmsmen is the opposite: it's a persistent agent with a trigger, multiple tools, decision-making across tool results, and actions with real consequences (it writes to GitHub, posts to Slack, tracks state between runs).

It runs either on a schedule (every hour by default) or on a GitHub webhook. Each run does a full repo health check and is idempotent — it dedupes its own issues so you don't wake up to 24 copies of "CI is broken."

---

## How it works

```
┌─────────────────┐      ┌─────────────────────────────────────────┐
│  APScheduler    │      │              ReAct Loop                 │
│  OR             │─────▶│  Reason → Act → Observe → repeat        │
│  Flask webhook  │      │  (Claude Sonnet 4.6 drives the loop)    │
└─────────────────┘      └───────────────┬─────────────────────────┘
                                         │
                   ┌─────────────────────┼─────────────────────┐
                   ▼                     ▼                     ▼
          ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
          │ GitHub API     │  │ OSV.dev CVE DB │  │ Slack          │
          │ (PyGitHub)     │  │ (no auth)      │  │ (slack_sdk)    │
          └────────────────┘  └────────────────┘  └────────────────┘
                   │                     │                     │
                   └─────────────────────┴─────────────────────┘
                                         │
                                         ▼
                               ┌──────────────────┐
                               │ helmsmen_state   │
                               │ .json (dedup)    │
                               └──────────────────┘
```

Every run follows the same four-phase workflow, enforced by the system prompt:

1. **Gather** — pull CI status, scan dependencies, list stale PRs
2. **Reason** — classify each finding as CRITICAL / WARNING / INFO
3. **Act** — open GitHub issues for actionable findings (dedup applied automatically)
4. **Report** — post a Slack digest summarizing everything, even on clean runs

---

## Tools

| Tool | Purpose |
|------|---------|
| `get_ci_status` | Fetch the latest GitHub Actions workflow run; extract failed jobs and steps |
| `scan_dependencies` | Scan `requirements.txt` or `package.json` against OSV.dev's CVE database |
| `list_stale_prs` | List open PRs with no activity for > N days |
| `create_github_issue` | Open a GitHub issue with dedup via a fingerprint stored in `helmsmen_state.json` |
| `post_slack_digest` | Send the final digest to a Slack channel (plain text or Block Kit) |
| `web_search` | Tavily search used to look up CVE fix recommendations |

All six tools are registered in `tools.py` via the same `TOOL_MAP` / `execute_tool()` pattern. Adding a new tool is a matter of writing one function and one JSON schema entry.

---

## Project layout

```
Helmsmen/
├── agent.py        ReAct loop (Claude Sonnet 4.6)
├── tools.py        Six DevOps tools + TOOL_MAP + execute_tool()
├── prompts.py      System prompt (agent's "job description")
├── state.py        JSON-backed memory: dedup, last_run, CI run tracking
├── scheduler.py    APScheduler (blocking + background modes)
├── app.py          Flask server: /webhook, /run, /health, dashboard
├── run.py          CLI entry point: --once | --schedule | --webhook
├── requirements.txt
└── .env.example    Copy to .env and fill in your secrets
```

---

## Setup

**1. Clone and install**

```bash
git clone https://github.com/TheRahulKolla/Helmsmen.git
cd Helmsmen
python -m pip install -r requirements.txt
```

**2. Copy the env template**

```bash
cp .env.example .env
```

**3. Fill in `.env`** — you'll need:

- `ANTHROPIC_API_KEY` — [console.anthropic.com](https://console.anthropic.com/settings/keys)
- `GITHUB_TOKEN` — [github.com/settings/tokens](https://github.com/settings/tokens) (scopes: `repo`, `workflow`)
- `GITHUB_REPO` — in `owner/repo` format
- `SLACK_BOT_TOKEN` + `SLACK_CHANNEL` — create a Slack app at [api.slack.com/apps](https://api.slack.com/apps) with `chat:write` scope
- `TAVILY_API_KEY` — [tavily.com](https://tavily.com) (optional — enables CVE fix search)
- `GITHUB_WEBHOOK_SECRET` — any long random string (only used in webhook mode)

---

## Run

**Single run** (best for first-time testing):

```bash
python run.py --once
```

**Scheduled cron** (blocks forever, runs every hour):

```bash
python run.py --schedule --hours 1
```

**Webhook + cron** (Flask server on :5000 plus background scheduler):

```bash
python run.py --webhook
```

Then configure a webhook in your GitHub repo → Settings → Webhooks, pointing at `http://<your-host>:5000/webhook` with the same `GITHUB_WEBHOOK_SECRET`.

---

## Example output

```
============================================================
HELMSMEN RUN: TheRahulKolla/Test_Repo
============================================================

--- Iteration 1 ---
  Tool: get_ci_status(owner=..., repo=...)
  Result: CI Status: FAILURE
          Failed steps: test -> Fail on purpose
  Tool: scan_dependencies(owner=..., repo=...)
  Result: Found 5 vulnerability(s) in 2 PyPI packages:
          - requests==2.20.0: CVE-2018-18074
          - urllib3==1.24.1: CVE-2019-11324
  Tool: list_stale_prs(...)
  Result: No PRs stale longer than 7 days.

--- Iteration 2 ---
  Tool: web_search(query=CVE-2018-18074 fix)
  ...

--- Iteration 3 ---
  Tool: create_github_issue([Helmsmen] CI Failure: ...)
  Result: Issue created: https://github.com/.../issues/1
  Tool: create_github_issue([Helmsmen] Security: CVE in requests...)
  Result: Issue created: https://github.com/.../issues/2
  Tool: post_slack_digest(#devops-alerts, ...)
  Result: Slack message posted. ts=1745519...

HELMSMEN DONE.
```

---

## Design notes

- **Dedup via fingerprint, not issue ID** — the fingerprint `ci_failure:owner/repo:CI Pipeline` stays stable across runs, so the same broken workflow isn't reported twice. Fingerprints are stored in `helmsmen_state.json`, pruned after 30 days.
- **Single-instance scheduler** — APScheduler is configured with `max_instances=1` and `coalesce=True`. A long-running agent can never be overtaken by the next tick, and missed firings merge into one catch-up run.
- **Webhook-safe** — webhook handlers return 202 within milliseconds; the agent runs in a daemon thread. A 60-second debounce absorbs duplicate triggers (push + workflow_run for the same commit).
- **Adaptive token budget** — `agent.py` retries any turn that hits `max_tokens`, doubling the budget up to 16K. Complex runs drafting multiple issue bodies + a Slack digest won't get truncated mid-generation.
- **Graceful tool failures** — every tool returns an error string rather than raising. The agent reads the error, notes it in the Slack digest, and continues the run instead of aborting.

---

## License

MIT
