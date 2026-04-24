"""
app.py - Flask server for webhook-triggered agent runs + lightweight dashboard.

Routes:
  POST /webhook   - GitHub webhook receiver (HMAC-verified)
  POST /run       - Manual trigger (for testing or a dashboard button)
  GET  /health    - Liveness probe with last_run_at + open_issues count
  GET  /          - Minimal HTML status page

Design choices:
  - Every webhook returns 202 within milliseconds; the agent runs in a daemon thread.
    GitHub expects webhook responses in under 10 seconds.
  - HMAC-SHA256 with timing-safe comparison on every webhook.
  - 60-second debounce to absorb duplicate triggers (push + workflow_run for same commit).
"""

import hmac
import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify

import state

logger = logging.getLogger("helmsmen.app")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = Flask(__name__)

TRIGGER_EVENTS = {"push", "pull_request", "workflow_run", "check_run"}
DEBOUNCE_SECONDS = 60


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _verify_signature(payload: bytes, sig_header: str) -> bool:
    """Constant-time HMAC-SHA256 verification against GITHUB_WEBHOOK_SECRET."""
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        return False  # fail closed if secret not configured
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_header or "")


def _repo_from_env() -> tuple[str, str]:
    repo_str = os.environ.get("GITHUB_REPO", "")
    if "/" not in repo_str:
        raise RuntimeError("GITHUB_REPO must be in 'owner/repo' format.")
    owner, repo = repo_str.split("/", 1)
    return owner, repo


def _run_agent_safe(owner: str, repo: str) -> None:
    """Invoke the agent swallowing all exceptions so daemon threads can't crash silently."""
    from agent import run_agent
    try:
        result = run_agent(owner, repo)
        logger.info(f"Webhook-triggered run finished: {result['status']}")
    except Exception as e:
        logger.error(f"Webhook-triggered agent crashed: {e}", exc_info=True)


def _debounced() -> bool:
    """Return True if we fired a webhook run within the last DEBOUNCE_SECONDS."""
    last = state.get_last_webhook_at()
    if not last:
        return False
    return (datetime.now(timezone.utc) - last) < timedelta(seconds=DEBOUNCE_SECONDS)


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/webhook", methods=["POST"])
def webhook():
    if not os.environ.get("GITHUB_WEBHOOK_SECRET"):
        logger.warning("Webhook called but GITHUB_WEBHOOK_SECRET is not set - rejecting.")
        return jsonify({"error": "webhook secret not configured"}), 503

    payload = request.get_data()
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_signature(payload, sig):
        logger.warning("Webhook rejected: invalid signature.")
        return jsonify({"error": "invalid signature"}), 401

    event = request.headers.get("X-GitHub-Event", "")
    if event not in TRIGGER_EVENTS:
        return jsonify({"status": "ignored", "event": event}), 200

    if _debounced():
        logger.info(f"Webhook ({event}) debounced - already fired within {DEBOUNCE_SECONDS}s.")
        return jsonify({"status": "debounced", "event": event}), 202

    try:
        owner, repo = _repo_from_env()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    state.set_last_webhook_at()
    threading.Thread(target=_run_agent_safe, args=(owner, repo), daemon=True).start()
    logger.info(f"Webhook ({event}) triggered agent run for {owner}/{repo}.")
    return jsonify({"status": "triggered", "event": event}), 202


@app.route("/run", methods=["POST"])
def manual_run():
    """Manually fire the agent. Handy for local testing or a dashboard button."""
    try:
        owner, repo = _repo_from_env()
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 500

    threading.Thread(target=_run_agent_safe, args=(owner, repo), daemon=True).start()
    return jsonify({"status": "triggered", "owner": owner, "repo": repo}), 202


@app.route("/health", methods=["GET"])
def health():
    s = state.load_state()
    return jsonify({
        "status": "ok",
        "last_run_at": s.get("last_run_at"),
        "last_webhook_at": s.get("last_webhook_at"),
        "open_issues_count": len(s.get("open_issues", {})),
        "repo": os.environ.get("GITHUB_REPO"),
    })


@app.route("/", methods=["GET"])
def dashboard():
    s = state.load_state()
    open_issues = s.get("open_issues", {})
    rows = "".join(
        f"<tr><td>{fp}</td><td><a href='{entry['url']}' target='_blank'>{entry['url']}</a></td>"
        f"<td>{entry['created_at']}</td></tr>"
        for fp, entry in open_issues.items()
    ) or "<tr><td colspan='3'><i>no tracked issues</i></td></tr>"

    repo = os.environ.get("GITHUB_REPO", "(not set)")

    return f"""<!doctype html>
<html><head><title>Helmsmen</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2em auto; padding: 0 1em; }}
  h1 {{ color: #0969da; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
  th, td {{ border: 1px solid #d0d7de; padding: 8px; text-align: left; font-size: 14px; }}
  th {{ background: #f6f8fa; }}
  .meta {{ background: #f6f8fa; padding: 1em; border-radius: 6px; }}
  button {{ background: #2da44e; color: white; border: 0; padding: 8px 16px;
           border-radius: 6px; cursor: pointer; font-size: 14px; }}
</style></head>
<body>
  <h1>Helmsmen - DevOps Autopilot</h1>
  <div class="meta">
    <b>Repository:</b> {repo}<br>
    <b>Last run:</b> {s.get('last_run_at') or 'never'}<br>
    <b>Last webhook:</b> {s.get('last_webhook_at') or 'never'}<br>
    <b>Tracked issues:</b> {len(open_issues)}
  </div>
  <p><button onclick="fetch('/run',{{method:'POST'}}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))">Run now</button></p>
  <h2>Tracked issues (deduplication cache)</h2>
  <table>
    <tr><th>Fingerprint</th><th>Issue URL</th><th>Created</th></tr>
    {rows}
  </table>
</body></html>"""
