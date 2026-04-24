"""
scheduler.py - APScheduler integration.

Two modes:
  - BlockingScheduler   : for `python run.py --schedule` (scheduler IS the process)
  - BackgroundScheduler : for `python run.py --webhook`  (Flask blocks the main thread)

max_instances=1 ensures a long-running agent can't be overtaken by the next tick.
coalesce=True merges missed firings into one catch-up run on resume.
"""

import logging
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger("helmsmen.scheduler")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _run_job(owner: str, repo: str) -> None:
    """Job function invoked by the scheduler on every tick."""
    # Deferred import to avoid circular imports when app.py also imports this module.
    from agent import run_agent
    logger.info(f"Scheduled check starting for {owner}/{repo}")
    try:
        result = run_agent(owner, repo)
        logger.info(
            f"Check done: status={result['status']} "
            f"iterations={result['iterations']} "
            f"duration={result['duration_sec']}s "
            f"issues_created={result['issues_created']} "
            f"issues_skipped={result['issues_skipped']}"
        )
    except Exception as e:
        logger.error(f"Agent run crashed: {e}", exc_info=True)


def _common_job_kwargs(owner: str, repo: str, interval_hours: float) -> dict:
    return {
        "func": _run_job,
        "args": [owner, repo],
        "trigger": "interval",
        "hours": interval_hours,
        "id": "helmsmen_check",
        "max_instances": 1,     # never overlap runs
        "coalesce": True,       # merge backlogged firings
        "misfire_grace_time": 300,  # 5-min grace window
        "replace_existing": True,
    }


def start_blocking_scheduler(owner: str, repo: str, interval_hours: float = 1.0) -> None:
    """Blocking mode - process lives for the scheduler only. Call from --schedule."""
    scheduler = BlockingScheduler()
    scheduler.add_job(**_common_job_kwargs(owner, repo, interval_hours))
    logger.info(f"BlockingScheduler started: {owner}/{repo} every {interval_hours}h")
    # Fire once immediately so you don't wait an hour for first check
    scheduler.add_job(_run_job, args=[owner, repo], id="helmsmen_first_run")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped.")


def start_background_scheduler(owner: str, repo: str,
                               interval_hours: float = 1.0) -> BackgroundScheduler:
    """Background mode - non-blocking. Flask holds the main thread. Call from --webhook."""
    scheduler = BackgroundScheduler()
    scheduler.add_job(**_common_job_kwargs(owner, repo, interval_hours))
    scheduler.start()
    logger.info(f"BackgroundScheduler started: {owner}/{repo} every {interval_hours}h")
    return scheduler  # caller MUST hold reference (GC could kill the thread otherwise)
