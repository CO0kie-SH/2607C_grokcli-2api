"""Maintainer leader election (Redis) so only one process runs background jobs.

File / single-worker mode: this process always leads.
Multi-worker + Redis: SET NX lock with periodic renew.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from config import MAINTAINER_LEADER, MAINTAINER_LEADER_RENEW, MAINTAINER_LEADER_TTL, WORKERS

_lock = threading.Lock()
_is_leader = False
_leader_id: str | None = None
_renew_thread: threading.Thread | None = None
_stop = threading.Event()
_started = False


def _want_force_leader() -> bool | None:
    """None = auto, True = force lead, False = never lead."""
    v = (MAINTAINER_LEADER or "auto").lower()
    if v in ("1", "true", "yes", "on", "always"):
        return True
    if v in ("0", "false", "no", "off", "never"):
        return False
    return None  # auto


def is_leader() -> bool:
    with _lock:
        return _is_leader


def status() -> dict[str, Any]:
    lid = None
    is_lead = False
    with _lock:
        lid = _leader_id
        is_lead = _is_leader
    # Always surface the redis lock owner so non-leader workers can show cluster state.
    try:
        from store.redis_client import get_str, key, redis_enabled
        if redis_enabled():
            remote = get_str(key("lock", "maintainer_leader"))
            if remote:
                lid = remote
                # this process is leader only if ids match
                # keep local is_lead as-is
    except Exception:
        pass
    return {
        "is_leader": is_lead,
        "leader_id": lid,
        "mode": MAINTAINER_LEADER or "auto",
        "workers": WORKERS,
        "ttl_sec": MAINTAINER_LEADER_TTL,
        "renew_sec": MAINTAINER_LEADER_RENEW,
    }


def try_become_leader() -> bool:
    """Attempt to acquire leadership. Idempotent."""
    global _is_leader, _leader_id, _renew_thread, _started

    force = _want_force_leader()
    if force is False:
        with _lock:
            _is_leader = False
        return False
    if force is True or WORKERS <= 1:
        with _lock:
            _is_leader = True
            _leader_id = "local"
        return True

    # auto + multi-worker → need Redis
    try:
        from store.redis_client import (
            key,
            redis_enabled,
            renew_if_owner,
            set_nx_ex,
            worker_id,
        )
    except Exception:
        # No redis module path — fall back to local lead only if single worker
        with _lock:
            _is_leader = WORKERS <= 1
            _leader_id = "local-fallback" if _is_leader else None
        return _is_leader

    if not redis_enabled():
        with _lock:
            # Multi-worker without redis should have been rejected at startup;
            # be conservative: do not start maintainers.
            _is_leader = False
            _leader_id = None
        return False

    wid = worker_id()
    lock_key = key("lock", "maintainer_leader")
    acquired = set_nx_ex(lock_key, wid, MAINTAINER_LEADER_TTL)
    if not acquired:
        # Maybe we already own it (restart race)
        from store.redis_client import get_str

        cur = get_str(lock_key)
        if cur == wid:
            acquired = renew_if_owner(lock_key, wid, MAINTAINER_LEADER_TTL)

    with _lock:
        _is_leader = bool(acquired)
        _leader_id = wid if acquired else None
        if acquired and not _started:
            _started = True
            _stop.clear()

            def _renew_loop() -> None:
                while not _stop.wait(MAINTAINER_LEADER_RENEW):
                    ok = renew_if_owner(lock_key, wid, MAINTAINER_LEADER_TTL)
                    if not ok:
                        with _lock:
                            global _is_leader
                            _is_leader = False
                        break

            _renew_thread = threading.Thread(
                target=_renew_loop, name="g2a-leader-renew", daemon=True
            )
            _renew_thread.start()
    return bool(acquired)


def release_leader() -> None:
    """Best-effort release (shutdown)."""
    global _is_leader, _started
    _stop.set()
    force = _want_force_leader()
    if force is True or WORKERS <= 1:
        with _lock:
            _is_leader = False
        return
    try:
        from store.redis_client import compare_and_delete, key, redis_enabled, worker_id

        if redis_enabled() and _leader_id:
            compare_and_delete(key("lock", "maintainer_leader"), worker_id())
    except Exception:
        pass
    with _lock:
        _is_leader = False
        _started = False


def should_start_maintainers() -> bool:
    """Call once at process startup after try_become_leader()."""
    force = _want_force_leader()
    if force is False:
        with _lock:
            global _is_leader
            _is_leader = False
        return False
    if force is True:
        with _lock:
            _is_leader = True
            global _leader_id
            _leader_id = _leader_id or "forced"
        return True
    if WORKERS <= 1:
        with _lock:
            _is_leader = True
            _leader_id = _leader_id or "local"
        return True
    return try_become_leader()
