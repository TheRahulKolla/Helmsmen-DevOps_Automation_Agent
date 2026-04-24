"""
Tracks:
  - open_issues    : problems we already reported (prevents duplicates)
  - last_run_at    : when we last ran the agent
  - last_ci_run_id : last GitHub Actions run ID we saw
  - last_webhook_at: when a webhook last triggered us (for debounce)
"""

import os, json, threading
from datetime import datetime, timezone, timedelta

STATE_FILE = "helmsmen_state.json"
_STATE_LOCK = threading.Lock() # A lock so that 2 webhooks doen't overwrite on another

_DEFAULT = {
    "last_run_at": None,
    "open_issues": {},
    "last_ci_run_id": None,
    "last_webhook_at": None,
}

def _prune_old_issues(state: dict, ttl_days: int = 30) -> None:
    """
    remove issue entries older than ttl days, if not the open_issues dict will go grow forever"""

    cutoff= datetime.now(timezone.utc) - timedelta(days=ttl_days)
    to_delete = []

    for fingerprint, entry in state.get("open_issues", {}).items():
        try:
            created = datetime.fromisoformat(entry["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if created < cutoff:
                to_delete.append(fingerprint)
        except (KeyError, ValueError):
            to_delete.append(fingerprint)

    for fp in to_delete:
        del state["open_issues"][fp]

def _load_unlocked() -> dict:
    """
    Read JSON file from disk
    """

    if not os.path.exists(STATE_FILE):
        return dict(_DEFAULT)
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (json.JSONDecodeError, OSError):
        # corrputed file - start fresh
        return dict(_DEFAULT)
    
    for key, default_val in _DEFAULT.items():
        state.setdefault(key,default_val)
    
    _prune_old_issues(state)
    return state

def _save_unlocked(state: dict) -> None:
    """
    Write state to disk - No lock acquired
    """
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state,f,indent=2)


def load_state() -> dict:
    """ Load state from disk. Safe to call from any thread"""
    with _STATE_LOCK:
        return _load_unlocked()
    
def save_state(state: dict) -> None:
   """ Save a full state disk to dict"""
   with _STATE_LOCK:
       _save_unlocked(state)

def has_open_issue(fingerprint: str) -> bool:
    """
    return true is issue has created
    """
    state = load_state()
    return fingerprint in state.get("open_issues", {})


def get_issue_url(fingerprint: str) -> str | None:
    """Return the URL of a previously created issue, or None."""
    state = load_state()
    entry = state.get("open_issues", {}).get(fingerprint)
    return entry["url"] if entry else None


def record_issue(fingerprint: str, url: str) -> None:
    """Save a newly created issue so we don't create it again next run."""
    with _STATE_LOCK:
        state = _load_unlocked()
        state["open_issues"][fingerprint] = {
            "url": url,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_unlocked(state)


def set_last_run() -> None:
    """Stamp the current time as last_run_at. Called at start of each agent run."""
    with _STATE_LOCK:
        state = _load_unlocked()
        state["last_run_at"] = datetime.now(timezone.utc).isoformat()
        _save_unlocked(state)


def get_last_ci_run_id() -> str | None:
    return load_state().get("last_ci_run_id")


def set_last_ci_run_id(run_id: str) -> None:
    with _STATE_LOCK:
        state = _load_unlocked()
        state["last_ci_run_id"] = str(run_id)
        _save_unlocked(state)


def get_last_webhook_at() -> datetime | None:
    """Return when the last webhook fired, or None. Used for debounce."""
    ts = load_state().get("last_webhook_at")
    if not ts:
        return None
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def set_last_webhook_at() -> None:
    """Record that a webhook just fired. Used to debounce rapid pushes."""
    with _STATE_LOCK:
        state = _load_unlocked()
        state["last_webhook_at"] = datetime.now(timezone.utc).isoformat()
        _save_unlocked(state)
