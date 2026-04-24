"""
run.py - CLI entry point for Helmsmen.

Modes:
  python run.py --once                 # run agent once, print result, exit
  python run.py --schedule             # start cron loop (blocks forever)
  python run.py --webhook              # start Flask server + background scheduler
  python run.py --once --repo foo/bar  # override GITHUB_REPO env var

Examples:
  # Quick local test
  python run.py --once --repo octocat/Hello-World

  # Production cron
  python run.py --schedule

  # Webhook-driven + hourly safety net
  python run.py --webhook
"""

import argparse
import json
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _split_repo(repo_str: str) -> tuple[str, str]:
    if not repo_str or "/" not in repo_str:
        print("ERROR: --repo or GITHUB_REPO must be in 'owner/repo' format.", file=sys.stderr)
        sys.exit(1)
    owner, repo = repo_str.split("/", 1)
    return owner, repo


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="helmsmen",
        description="Helmsmen - DevOps Autopilot Agent",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="Run agent once and exit")
    mode.add_argument("--schedule", action="store_true", help="Run on cron schedule (blocks)")
    mode.add_argument("--webhook", action="store_true", help="Start Flask webhook server")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPO"),
                        help="owner/repo (falls back to GITHUB_REPO env var)")
    parser.add_argument("--hours", type=float,
                        default=float(os.environ.get("SCHEDULE_HOURS", "1")),
                        help="Scheduler interval in hours (default 1)")
    args = parser.parse_args()

    owner, repo = _split_repo(args.repo)

    if args.once:
        from agent import run_agent
        result = run_agent(owner, repo)
        print("\n" + json.dumps(result, indent=2))
        sys.exit(0 if result["status"] == "success" else 1)

    if args.schedule:
        from scheduler import start_blocking_scheduler
        print(f"Scheduling Helmsmen every {args.hours}h for {owner}/{repo}")
        start_blocking_scheduler(owner, repo, interval_hours=args.hours)
        return

    if args.webhook:
        from app import app
        from scheduler import start_background_scheduler
        # Start cron safety-net alongside webhook listener
        _scheduler = start_background_scheduler(owner, repo, interval_hours=args.hours)
        port = int(os.environ.get("PORT", "5000"))
        print(f"Helmsmen listening on :{port} for {owner}/{repo}")
        app.run(host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
