"""Admin settings (password hash, flags, account pool)."""

from __future__ import annotations

import hashlib
import os
import hmac
import json
import secrets
import threading
import time
from typing import Any

from config import ACCOUNT_MODE, ADMIN_PASSWORD, DATA_DIR, SETTINGS_FILE

_lock = threading.RLock()

# All modes treat accounts equally — no "primary" account concept.
VALID_ACCOUNT_MODES = ("round_robin", "random", "least_used")
DEFAULT_ACCOUNT_MODE = "round_robin"
# Legacy mode name migrated to round_robin
_LEGACY_MODES = {"primary": "round_robin"}

# In-memory settings cache + deferred dirty flush so probe/refresh of hundreds
# of accounts doesn't rewrite settings.json on every single account touch.
_mem: dict[str, Any] | None = None
_mem_dirty = False
_flush_timer: threading.Timer | None = None
_FLUSH_DELAY_SEC = 1.0


def _ensure() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


_mem_mtime_ns: int | None = None
_MEM_STAT_MIN_INTERVAL = 0.5
_mem_stat_at = 0.0


def _pg_settings():
    try:
        from store.settings_pg import enabled

        if enabled():
            from store import settings_pg

            return settings_pg
    except Exception:
        return None
    return None


def _file_mtime_ns() -> int | None:
    try:
        st = SETTINGS_FILE.stat()
        return getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
    except OSError:
        return None


# Scalar / JSON keys that must survive multi-worker restarts via app_settings.
# (account_pool / admin_password / sessions have dedicated tables or Redis.)
_PG_SCALAR_KEYS = (
    "account_mode",
    "token_maintain_enabled",
    "model_health_enabled",
    "reasoning_compat",
    "outbound_max_tools",
    "outbound_tool_gap_sec",
    "history_compact_enabled",
    "sse_keepalive",
    "conversation_affinity_enabled",
    "default_model",
    "cooldown_default_sec",
    "cooldown_auth_sec",
    "cooldown_rate_limit_sec",
    "cooldown_server_error_sec",
    "cooldown_max_sec",
    "soft_model_block_ttl_sec",
    "durable_model_block_ttl_sec",
    "probe_fail_kick_streak",
    "probe_fail_disable_streak",
    "probe_kick_cooldown_sec",
    "max_failover_attempts",
    # Protocol registration (MoeMail / YesCaptcha / proxy) — admin UI config
    "registration_config",
)


def _load_disk() -> dict[str, Any]:
    _ensure()
    # PostgreSQL: compose a settings-shaped dict from durable tables.
    pg = _pg_settings()
    if pg is not None:
        try:
            data: dict[str, Any] = {}
            admin = pg.get_setting("admin_password")
            if isinstance(admin, dict):
                data.update(admin)
            for key in _PG_SCALAR_KEYS:
                try:
                    fv = pg.get_setting(key)
                except Exception:
                    fv = None
                if fv is not None:
                    data[key] = fv
            # Prefer dedicated pool table over any legacy blob
            data["account_pool"] = pg.get_account_pool_state()
            # Keep sessions only when Redis is unavailable
            try:
                from store.redis_client import redis_enabled

                if not redis_enabled():
                    sessions = pg.get_setting("sessions")
                    if isinstance(sessions, dict):
                        data["sessions"] = sessions
            except Exception:
                pass
            data["updated_at"] = time.time()
            return data
        except Exception:
            pass
    if not SETTINGS_FILE.is_file():
        return {}
    try:
        data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _load() -> dict[str, Any]:
    """Return the live in-memory settings map (revalidates file mtime)."""
    global _mem, _mem_mtime_ns, _mem_stat_at
    with _lock:
        now = time.time()
        # Optimization: re-read settings.json when another process rewrote it
        # (multi-worker shared volume without PG). Sticky cache caused lost
        # cooldowns / mode changes across workers.
        if _mem is not None and _pg_settings() is None:
            if now - _mem_stat_at >= _MEM_STAT_MIN_INTERVAL:
                _mem_stat_at = now
                mt = _file_mtime_ns()
                if mt is not None and _mem_mtime_ns is not None and mt != _mem_mtime_ns:
                    _mem = _load_disk()
                    _mem_mtime_ns = mt
        if _mem is None:
            _mem = _load_disk()
            _mem_mtime_ns = _file_mtime_ns()
            _mem_stat_at = now
        return _mem


def _write_disk(data: dict[str, Any]) -> None:
    global _mem_mtime_ns
    pg = _pg_settings()
    if pg is not None:
        try:
            # Split durable pieces into PG tables / app_settings rows.
            for key in _PG_SCALAR_KEYS:
                if key not in data:
                    continue
                try:
                    val = data.get(key)
                    if key in ("token_maintain_enabled", "model_health_enabled"):
                        val = bool(val)
                    pg.set_setting(key, val)
                except Exception:
                    pass
            admin = {
                k: data[k]
                for k in (
                    "admin_password_hash",
                    "admin_password_salt",
                )
                if k in data
            }
            if admin:
                pg.set_setting("admin_password", admin)
            # account_pool is owned exclusively by the account_pool table when PG is on.
            # Never rewrite it from in-memory JSON blobs on settings flush.
            # sessions prefer Redis; if present and no redis, keep a side key
            if isinstance(data.get("sessions"), dict):
                try:
                    from store.redis_client import redis_enabled

                    if not redis_enabled():
                        pg.set_setting("sessions", data["sessions"])
                except Exception:
                    pg.set_setting("sessions", data.get("sessions") or {})
            # Mirror non-pool settings only (no account_pool JSON storage).
            try:
                _ensure()
                tmp = SETTINGS_FILE.with_suffix(".tmp")
                mirror = {
                    k: v
                    for k, v in data.items()
                    if k not in ("account_pool",)
                }
                tmp.write_text(
                    json.dumps(mirror, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                tmp.replace(SETTINGS_FILE)
                _mem_mtime_ns = _file_mtime_ns()
            except Exception:
                pass
            return
        except Exception:
            pass
    _ensure()
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_FILE)
    _mem_mtime_ns = _file_mtime_ns()


def _schedule_flush_locked() -> None:
    global _flush_timer, _mem_dirty
    _mem_dirty = True
    if _flush_timer is not None:
        return

    def _flush() -> None:
        global _flush_timer, _mem_dirty
        with _lock:
            _flush_timer = None
            if not _mem_dirty or _mem is None:
                _mem_dirty = False
                return
            snapshot = json.loads(json.dumps(_mem))  # deep-ish copy via json
            _mem_dirty = False
        try:
            _write_disk(snapshot)
        except Exception:
            # re-mark dirty so a later touch retries
            with _lock:
                _mem_dirty = True
                if _flush_timer is None:
                    _schedule_flush_locked()

    t = threading.Timer(_FLUSH_DELAY_SEC, _flush)
    t.daemon = True
    _flush_timer = t
    t.start()


def _save(data: dict[str, Any], *, immediate: bool = False) -> None:
    """
    Persist settings. Default is coalesced (1s) to avoid thrashing disk when
    model probes / quota checks touch hundreds of pool entries.
    """
    global _mem
    with _lock:
        _mem = data
        if immediate:
            # cancel pending timer
            global _flush_timer, _mem_dirty
            if _flush_timer is not None:
                try:
                    _flush_timer.cancel()
                except Exception:
                    pass
                _flush_timer = None
            _mem_dirty = False
            snapshot = json.loads(json.dumps(data))
            _write_disk(snapshot)
        else:
            _schedule_flush_locked()


def flush_settings() -> None:
    """Force any deferred settings writes to disk (call on shutdown if needed)."""
    global _flush_timer, _mem_dirty
    with _lock:
        if _flush_timer is not None:
            try:
                _flush_timer.cancel()
            except Exception:
                pass
            _flush_timer = None
        if _mem is None:
            _mem_dirty = False
            return
        snapshot = json.loads(json.dumps(_mem))
        _mem_dirty = False
    _write_disk(snapshot)


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000
    ).hex()


def is_setup_needed() -> bool:
    if ADMIN_PASSWORD:
        return False
    data = _load()
    return not data.get("admin_password_hash")


def has_admin_password() -> bool:
    if ADMIN_PASSWORD:
        return True
    data = _load()
    return bool(data.get("admin_password_hash"))


def set_admin_password(password: str) -> None:
    if len(password) < 4:
        raise ValueError("密码至少 4 位")
    salt = secrets.token_hex(16)
    with _lock:
        data = _load()
        data["admin_password_hash"] = _hash_password(password, salt)
        data["admin_password_salt"] = salt
        data["updated_at"] = time.time()
        _save(data, immediate=True)


def change_admin_password(*, current: str, new_password: str) -> None:
    """Change admin password after verifying current credentials.

    If GROK2API_ADMIN_PASSWORD is set from env, the env password still works
    as an alternate login; stored hash is updated for non-env logins.
    """
    if not verify_admin_password(current or ""):
        raise ValueError("当前密码不正确")
    if not new_password or len(new_password) < 4:
        raise ValueError("新密码至少 4 位")
    if current == new_password:
        raise ValueError("新密码不能与当前密码相同")
    set_admin_password(new_password)


def verify_admin_password(password: str) -> bool:
    if not password:
        return False
    # Env password always works if set
    if ADMIN_PASSWORD and secrets.compare_digest(password, ADMIN_PASSWORD):
        return True
    data = _load()
    salt = data.get("admin_password_salt")
    expected = data.get("admin_password_hash")
    if not salt or not expected:
        return False
    got = _hash_password(password, salt)
    return hmac.compare_digest(got, expected)


def _redis_admin_sessions() -> bool:
    try:
        from store.redis_client import redis_enabled

        return redis_enabled()
    except Exception:
        return False


def create_session_token() -> str:
    token = secrets.token_urlsafe(32)
    if _redis_admin_sessions():
        try:
            from store.sessions_redis import admin_session_put

            admin_session_put(token)
            return token
        except Exception:
            pass
    with _lock:
        data = _load()
        sessions = data.setdefault("sessions", {})
        now = time.time()
        sessions = {
            k: v
            for k, v in sessions.items()
            if isinstance(v, (int, float)) and now - float(v) < 7 * 86400
        }
        sessions[token] = now
        data["sessions"] = sessions
        _save(data, immediate=True)
    return token


def verify_session_token(token: str | None) -> bool:
    if not token:
        return False
    if _redis_admin_sessions():
        try:
            from store.sessions_redis import admin_session_get, admin_session_touch

            if admin_session_get(token):
                admin_session_touch(token)
                return True
            # fall through: token may still live in settings.json (pre-migration)
        except Exception:
            pass
    with _lock:
        data = _load()
        sessions = data.get("sessions") or {}
        ts = sessions.get(token)
        if ts is None:
            return False
        if time.time() - float(ts) > 7 * 86400:
            sessions.pop(token, None)
            data["sessions"] = sessions
            _save(data, immediate=True)
            return False
        # sliding refresh — coalesce to avoid rewrite-per-request
        sessions[token] = time.time()
        data["sessions"] = sessions
        _save(data, immediate=False)
        return True


def revoke_session(token: str | None) -> None:
    if not token:
        return
    if _redis_admin_sessions():
        try:
            from store.sessions_redis import admin_session_delete

            admin_session_delete(token)
        except Exception:
            pass
    with _lock:
        data = _load()
        sessions = data.get("sessions") or {}
        if token in sessions:
            sessions.pop(token, None)
            data["sessions"] = sessions
            _save(data, immediate=True)


def _normalize_mode(mode: str | None) -> str:
    mode = (mode or "").strip().lower()
    mode = _LEGACY_MODES.get(mode, mode)
    if mode not in VALID_ACCOUNT_MODES:
        return DEFAULT_ACCOUNT_MODE
    return mode


def get_account_mode() -> str:
    # Env override wins when set
    if ACCOUNT_MODE:
        return _normalize_mode(ACCOUNT_MODE)
    data = _load()
    return _normalize_mode(str(data.get("account_mode") or DEFAULT_ACCOUNT_MODE))


def set_account_mode(mode: str) -> str:
    raw = (mode or "").strip().lower()
    raw = _LEGACY_MODES.get(raw, raw)
    if raw not in VALID_ACCOUNT_MODES:
        raise ValueError(
            f"Invalid account_mode. Use one of: {', '.join(VALID_ACCOUNT_MODES)}"
        )
    mode = raw
    with _lock:
        data = _load()
        data["account_mode"] = mode
        # Drop legacy preferred-account setting if present
        data.pop("preferred_account_id", None)
        data["updated_at"] = time.time()
        _save(data, immediate=True)
    return mode


def get_account_pool_state() -> dict[str, Any]:
    """Load account pool status.

    PostgreSQL is the only durable source for account status/cooldown.
    JSON/file is no longer used as pool storage when DATABASE_URL is set.
    """
    pg = _pg_settings()
    if pg is not None:
        try:
            state = pg.get_account_pool_state()
            # Keep mem cache aligned, but never treat file JSON as authority.
            with _lock:
                data = _load()
                data["account_pool"] = state
            return dict(state) if isinstance(state, dict) else {}
        except Exception:
            pass
    data = _load()
    pool = data.get("account_pool") or {}
    return dict(pool) if isinstance(pool, dict) else {}


# Account rotation status fields that must hit PostgreSQL/file on every change.
# (Derived UI status: normal / cooldown / disabled / quota-disabled.)
_POOL_STATUS_KEYS = frozenset(
    {
        "enabled",
        "weight",
        "disabled_for_quota",
        "disabled_reason",
        "disabled_source",
        "quota_disabled_at",
        "quota_source",
        "cooldown_until",
        "cooldown_sec",
        "cooldown_count",
        "blocked_models",
        "last_error",
        "last_status_code",
        "consecutive_fails",
        "probe_fail_streak",
        "last_probe",
        "last_quota",
        "last_probe_ok_at",
        "last_probe_fail_at",
    }
)


def _patch_is_status(patch: dict[str, Any]) -> bool:
    return any(k in _POOL_STATUS_KEYS for k in (patch or {}))


def save_account_pool_state(state: dict[str, Any]) -> None:
    try:
        from account_pool import invalidate_pool_summary_cache
        invalidate_pool_summary_cache()
    except Exception:
        pass
    pg = _pg_settings()
    if pg is not None:
        try:
            pg.save_account_pool_state(state if isinstance(state, dict) else {})
            # keep in-process mem coherent
            with _lock:
                data = _load()
                data["account_pool"] = state
                data["updated_at"] = time.time()
            return
        except Exception:
            pass
    with _lock:
        data = _load()
        data["account_pool"] = state
        data["updated_at"] = time.time()
        # Full pool rewrite is status-bearing → flush immediately when no PG.
        _save(data, immediate=True)


def patch_account_pool_meta(account_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    """Update one account's pool meta.

    PostgreSQL path: every patch is committed immediately (field-level upsert).
    File path: status fields flush immediately; pure counter bumps may coalesce.
    """
    try:
        from account_pool import invalidate_pool_summary_cache
        invalidate_pool_summary_cache()
    except Exception:
        pass
    if not account_id:
        return {}
    if not isinstance(patch, dict) or not patch:
        return {}
    pg = _pg_settings()
    if pg is not None:
        try:
            meta = pg.patch_pool_meta(account_id, patch)
            with _lock:
                data = _load()
                pool = data.setdefault("account_pool", {})
                if isinstance(pool, dict):
                    pool[account_id] = meta
            return meta
        except Exception:
            # Fall through to file/memory so status is never silently dropped.
            pass
    with _lock:
        data = _load()
        pool = data.setdefault("account_pool", {})
        if not isinstance(pool, dict):
            pool = {}
            data["account_pool"] = pool
        meta = dict(pool.get(account_id) or {})
        for k, v in patch.items():
            if v is None:
                meta.pop(k, None)
            else:
                meta[k] = v
        # Derived status label for operators / debugging (always recompute).
        meta["pool_status"] = _derive_pool_status(meta)
        pool[account_id] = meta
        data["updated_at"] = time.time()
        # Every account status mutation flushes immediately (no delayed buffer).
        _save(data, immediate=True)
        return meta


def _derive_pool_status(meta: dict[str, Any]) -> str:
    """Canonical status string persisted with pool meta."""
    if not isinstance(meta, dict):
        return "normal"
    if meta.get("disabled_for_quota"):
        return "quota_disabled"
    if meta.get("enabled") is False:
        return "disabled"
    try:
        if int(meta.get("cooldown_count") or 0) > 0:
            return "cooldown"
    except (TypeError, ValueError):
        pass
    until = meta.get("cooldown_until")
    try:
        if until is not None and float(until) > time.time():
            return "cooldown"
    except (TypeError, ValueError):
        pass
    blocked = meta.get("blocked_models") or {}
    if isinstance(blocked, dict) and blocked:
        return "model_blocked"
    return "normal"


def touch_account_stats(
    account_id: str,
    *,
    success: bool = True,
    error: str = "",
    cooldown_until: float | None = None,
    clear_cooldown: bool = False,
    consecutive_fails: int | None = None,
    last_status_code: int | None = None,
    cooldown_sec: float | None = None,
    preserve_cooldown: bool = False,
) -> dict[str, Any] | None:
    """Update per-account pool stats + status.

    Source of truth for rotation status (normal / cooldown / disabled) is always
    PostgreSQL (or settings file when PG is off). Redis only mirrors hot counters
    and a short TTL copy of cooldown_until for multi-worker reads.

    preserve_cooldown=True (live request success): never clear/rewrite cooldown
    fields or force pool_status away from cooldown — only counters / last_used.
    """
    if not account_id:
        return None

    now = time.time()
    # When preserving cooldown on live success, never ask Redis to clear it.
    if preserve_cooldown:
        clear_cooldown = False

    durable_patch: dict[str, Any] = {
        "last_used_at": now,
    }
    if consecutive_fails is not None:
        durable_patch["consecutive_fails"] = int(consecutive_fails)
    elif success and not preserve_cooldown:
        durable_patch["consecutive_fails"] = 0
    elif success and preserve_cooldown:
        # Still reset fail streak counters, but do not touch cooldown fields.
        durable_patch["consecutive_fails"] = 0

    if success:
        # Do not wipe last_error while cooling — it explains why account is cooling.
        if not preserve_cooldown:
            durable_patch["last_error"] = None
        if clear_cooldown and not preserve_cooldown:
            durable_patch["cooldown_until"] = None
            durable_patch["cooldown_sec"] = None
    else:
        if error:
            durable_patch["last_error"] = error
        if last_status_code is not None:
            durable_patch["last_status_code"] = int(last_status_code)
        if cooldown_until is not None:
            durable_patch["cooldown_until"] = float(cooldown_until)
        if cooldown_sec is not None:
            durable_patch["cooldown_sec"] = float(cooldown_sec)

    # Mirror hot counters in Redis. When preserve_cooldown, do not clear redis CD
    # and do not overwrite redis cooldown key with None.
    try:
        from store.pool_redis import touch_stats
        from store.redis_client import redis_enabled

        if redis_enabled():
            touch_stats(
                account_id,
                success=success,
                error=("" if (success and preserve_cooldown) else error),
                cooldown_until=(None if preserve_cooldown else cooldown_until),
                clear_cooldown_flag=False if preserve_cooldown else clear_cooldown,
                consecutive_fails=consecutive_fails if consecutive_fails is not None else (0 if success else None),
                last_status_code=None if (success and preserve_cooldown) else last_status_code,
                cooldown_sec=None if preserve_cooldown else cooldown_sec,
            )
    except Exception:
        pass

    # Always persist counters to durable store NOW.
    pg = _pg_settings()
    if pg is not None:
        cur: dict[str, Any] = {}
        try:
            from store.settings_pg import get_pool_meta_many

            cur = (get_pool_meta_many([account_id]) or {}).get(account_id) or {}
        except Exception:
            try:
                with _lock:
                    cur = dict((_load().get("account_pool") or {}).get(account_id) or {})
            except Exception:
                cur = {}
        if not isinstance(cur, dict):
            cur = {}

        # If currently cooling and preserve_cooldown: only bump counters / last_used.
        cur_until = cur.get("cooldown_until")
        cur_cooling = False
        try:
            cur_cooling = cur_until is not None and float(cur_until) > now
        except (TypeError, ValueError):
            cur_cooling = False

        durable_patch["request_count"] = int(cur.get("request_count") or 0) + 1
        if success:
            durable_patch["success_count"] = int(cur.get("success_count") or 0) + 1
        else:
            durable_patch["fail_count"] = int(cur.get("fail_count") or 0) + 1

        if preserve_cooldown and (cur_cooling or success):
            # Explicitly keep durable cooldown / status; do not re-derive to normal.
            if cur_cooling:
                durable_patch.pop("last_error", None)  # keep existing reason
                # Do not set cooldown_until/sec in patch at all (leave row as-is).
                durable_patch["pool_status"] = "cooldown"
            else:
                merged_for_status = dict(cur)
                for k, v in durable_patch.items():
                    if v is None:
                        merged_for_status.pop(k, None)
                    else:
                        merged_for_status[k] = v
                durable_patch["pool_status"] = _derive_pool_status(merged_for_status)
            return patch_account_pool_meta(account_id, durable_patch)

        merged_for_status = dict(cur)
        for k, v in durable_patch.items():
            if v is None:
                merged_for_status.pop(k, None)
            else:
                merged_for_status[k] = v
        durable_patch["pool_status"] = _derive_pool_status(merged_for_status)
        return patch_account_pool_meta(account_id, durable_patch)

    # No PostgreSQL: update file-backed pool immediately for status fields.
    with _lock:
        data = _load()
        pool = data.setdefault("account_pool", {})
        if not isinstance(pool, dict):
            pool = {}
            data["account_pool"] = pool
        meta = dict(pool.get(account_id) or {}) if isinstance(pool.get(account_id), dict) else {}
        meta.setdefault("enabled", True)
        meta.setdefault("weight", 1)
        meta["request_count"] = int(meta.get("request_count") or 0) + 1
        meta["last_used_at"] = now
        cur_cooling = False
        try:
            cu = meta.get("cooldown_until")
            cur_cooling = cu is not None and float(cu) > now
        except (TypeError, ValueError):
            cur_cooling = False
        if success:
            meta["success_count"] = int(meta.get("success_count") or 0) + 1
            meta["consecutive_fails"] = 0
            if not preserve_cooldown:
                meta.pop("last_error", None)
            if clear_cooldown and not preserve_cooldown:
                meta.pop("cooldown_until", None)
                meta.pop("cooldown_sec", None)
        else:
            meta["fail_count"] = int(meta.get("fail_count") or 0) + 1
            if consecutive_fails is not None:
                meta["consecutive_fails"] = int(consecutive_fails)
            else:
                meta["consecutive_fails"] = int(meta.get("consecutive_fails") or 0) + 1
            if error:
                meta["last_error"] = error
            if last_status_code is not None:
                meta["last_status_code"] = int(last_status_code)
            if cooldown_until is not None:
                meta["cooldown_until"] = float(cooldown_until)
            if cooldown_sec is not None:
                meta["cooldown_sec"] = float(cooldown_sec)
        if preserve_cooldown and cur_cooling:
            meta["pool_status"] = "cooldown"
        else:
            meta["pool_status"] = _derive_pool_status(meta)
        pool[account_id] = meta
        data["updated_at"] = now
        _save(data, immediate=True)
        return meta


def _env_bool(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


def _get_feature_flag(key: str, env_name: str, default: bool = True) -> bool:
    """Runtime flag: settings store overrides env default."""
    data = _load()
    if key in data and data.get(key) is not None:
        return bool(data.get(key))
    return _env_bool(env_name, default)


def _set_feature_flag(key: str, enabled: bool) -> bool:
    enabled = bool(enabled)
    with _lock:
        data = _load()
        data[key] = enabled
        data["updated_at"] = time.time()
        _save(data, immediate=True)
    # also mirror into PG app_settings when available so multi-worker sees it
    pg = _pg_settings()
    if pg is not None:
        try:
            pg.set_setting(key, enabled)
        except Exception:
            pass
    return enabled


def get_token_maintain_enabled() -> bool:
    return _get_feature_flag("token_maintain_enabled", "GROK2API_TOKEN_MAINTAIN", True)


def set_token_maintain_enabled(enabled: bool) -> bool:
    val = _set_feature_flag("token_maintain_enabled", enabled)
    try:
        import token_maintainer
        if val:
            # Prefer current leader; if this process can lead, start here.
            try:
                from store.leader import is_leader, should_start_maintainers, try_become_leader
                can = is_leader() or should_start_maintainers() or try_become_leader()
            except Exception:
                can = True
            if can:
                token_maintainer.start_background()
                token_maintainer.request_run_soon(force=False)
            else:
                # Signal any leader via wakeup path: request_run_soon is local-only,
                # so also poke redis leader lock owner by writing a flag.
                try:
                    from store.redis_client import key, redis_enabled, set_ex
                    if redis_enabled():
                        set_ex(key("flag", "token_maintain_on"), "1", 60)
                except Exception:
                    pass
        else:
            token_maintainer.stop_background()
            try:
                from store.redis_client import delete, key, redis_enabled
                if redis_enabled():
                    delete(key("flag", "token_maintain_on"))
            except Exception:
                pass
    except Exception:
        pass
    return val


def get_model_health_enabled() -> bool:
    return _get_feature_flag("model_health_enabled", "GROK2API_MODEL_HEALTH", True)


def set_model_health_enabled(enabled: bool) -> bool:
    val = _set_feature_flag("model_health_enabled", enabled)
    try:
        import model_health
        if val:
            try:
                from store.leader import is_leader, should_start_maintainers, try_become_leader
                can = is_leader() or should_start_maintainers() or try_become_leader()
            except Exception:
                can = True
            if can:
                model_health.start_background()
                model_health.request_run_soon()
            else:
                try:
                    from store.redis_client import key, redis_enabled, set_ex
                    if redis_enabled():
                        set_ex(key("flag", "model_health_on"), "1", 60)
                except Exception:
                    pass
        else:
            model_health.stop_background()
            try:
                from store.redis_client import delete, key, redis_enabled
                if redis_enabled():
                    delete(key("flag", "model_health_on"))
            except Exception:
                pass
    except Exception:
        pass
    return val


# ── runtime tunable settings (admin UI) ─────────────────────────────────────

_VALID_REASONING = ("off", "think_tag", "content")


def _get_setting_value(key: str, default: Any = None) -> Any:
    data = _load()
    if key in data and data.get(key) is not None:
        return data.get(key)
    return default


def _set_setting_value(key: str, value: Any) -> Any:
    with _lock:
        data = _load()
        data[key] = value
        data["updated_at"] = time.time()
        _save(data, immediate=True)
    pg = _pg_settings()
    if pg is not None:
        try:
            pg.set_setting(key, value)
        except Exception:
            pass
    return value


def get_reasoning_compat() -> str:
    """Effective reasoning_compat: settings override, else env/config."""
    raw = _get_setting_value("reasoning_compat", None)
    if raw is None or str(raw).strip() == "":
        try:
            from config import REASONING_COMPAT

            raw = REASONING_COMPAT
        except Exception:
            raw = "off"
    mode = str(raw or "off").strip().lower()
    if mode not in _VALID_REASONING:
        return "off"
    return mode


def set_reasoning_compat(mode: str) -> str:
    m = (mode or "off").strip().lower()
    if m not in _VALID_REASONING:
        raise ValueError(f"reasoning_compat 必须是: {', '.join(_VALID_REASONING)}")
    _set_setting_value("reasoning_compat", m)
    # Hot-update config module so new requests pick it up without restart.
    try:
        import config as _cfg

        _cfg.REASONING_COMPAT = m
    except Exception:
        pass
    return m


def get_outbound_max_tools() -> int:
    raw = _get_setting_value("outbound_max_tools", None)
    if raw is None:
        try:
            import history_compact as hc

            return int(getattr(hc, "OUTBOUND_MAX_TOOLS", 1) or 0)
        except Exception:
            return 1
    try:
        v = int(raw)
    except (TypeError, ValueError):
        v = 1
    return max(0, min(64, v))


def set_outbound_max_tools(value: int | str) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError) as e:
        raise ValueError("outbound_max_tools 必须是整数 0–64") from e
    v = max(0, min(64, v))
    _set_setting_value("outbound_max_tools", v)
    try:
        import history_compact as hc

        hc.OUTBOUND_MAX_TOOLS = v
    except Exception:
        pass
    return v


def get_outbound_tool_gap_sec() -> float:
    raw = _get_setting_value("outbound_tool_gap_sec", None)
    if raw is None:
        try:
            import history_compact as hc

            return float(getattr(hc, "OUTBOUND_TOOL_GAP_SEC", 0.08) or 0.0)
        except Exception:
            return 0.08
    try:
        v = float(raw)
    except (TypeError, ValueError):
        v = 0.08
    return max(0.0, min(2.0, v))


def set_outbound_tool_gap_sec(value: float | str) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as e:
        raise ValueError("outbound_tool_gap_sec 必须是数字 0–2") from e
    v = max(0.0, min(2.0, v))
    _set_setting_value("outbound_tool_gap_sec", v)
    try:
        import history_compact as hc

        hc.OUTBOUND_TOOL_GAP_SEC = v
    except Exception:
        pass
    return v


def get_history_compact_enabled() -> bool:
    raw = _get_setting_value("history_compact_enabled", None)
    if raw is None:
        try:
            import history_compact as hc

            return bool(getattr(hc, "HISTORY_COMPACT_ENABLED", False))
        except Exception:
            return False
    return bool(raw)


def set_history_compact_enabled(enabled: bool) -> bool:
    val = bool(enabled)
    _set_setting_value("history_compact_enabled", val)
    try:
        import history_compact as hc

        hc.HISTORY_COMPACT_ENABLED = val
    except Exception:
        pass
    return val


def get_sse_keepalive() -> float:
    raw = _get_setting_value("sse_keepalive", None)
    if raw is None:
        try:
            from config import SSE_KEEPALIVE_INTERVAL

            return float(SSE_KEEPALIVE_INTERVAL or 8.0)
        except Exception:
            return 8.0
    try:
        v = float(raw)
    except (TypeError, ValueError):
        v = 8.0
    return max(2.0, min(120.0, v))


def set_sse_keepalive(value: float | str) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError) as e:
        raise ValueError("sse_keepalive 必须是数字 2–120") from e
    v = max(2.0, min(120.0, v))
    _set_setting_value("sse_keepalive", v)
    try:
        import config as _cfg

        _cfg.SSE_KEEPALIVE_INTERVAL = v
    except Exception:
        pass
    return v


def get_conversation_affinity_enabled() -> bool:
    raw = _get_setting_value("conversation_affinity_enabled", None)
    if raw is None:
        try:
            return bool(
                __import__("os")
                .getenv("GROK2API_CONVERSATION_AFFINITY", "1")
                .lower()
                not in ("0", "false", "no", "off")
            )
        except Exception:
            return True
    return bool(raw)


def set_conversation_affinity_enabled(enabled: bool) -> bool:
    val = bool(enabled)
    _set_setting_value("conversation_affinity_enabled", val)
    # conversation_affinity reads env each call in some paths; also set env
    # for process-local modules that cache on import.
    try:
        import os

        os.environ["GROK2API_CONVERSATION_AFFINITY"] = "1" if val else "0"
    except Exception:
        pass
    try:
        import conversation_affinity as ca

        if hasattr(ca, "_enabled_cache"):
            ca._enabled_cache = None  # type: ignore[attr-defined]
    except Exception:
        pass
    return val


def get_default_model_setting() -> str:
    raw = _get_setting_value("default_model", None)
    if raw is None or str(raw).strip() == "":
        try:
            from config import DEFAULT_MODEL

            return str(DEFAULT_MODEL or "grok-4.5")
        except Exception:
            return "grok-4.5"
    return str(raw).strip()


def set_default_model_setting(model: str) -> str:
    m = (model or "").strip()
    if not m:
        raise ValueError("default_model 不能为空")
    if len(m) > 128:
        raise ValueError("default_model 过长")
    _set_setting_value("default_model", m)
    try:
        import config as _cfg

        _cfg.DEFAULT_MODEL = m
    except Exception:
        pass
    return m


def apply_runtime_settings_to_modules() -> None:
    """Push persisted settings into in-process modules (call on startup)."""
    try:
        set_reasoning_compat(get_reasoning_compat())
    except Exception:
        pass
    try:
        set_outbound_max_tools(get_outbound_max_tools())
    except Exception:
        pass
    try:
        set_outbound_tool_gap_sec(get_outbound_tool_gap_sec())
    except Exception:
        pass
    try:
        set_history_compact_enabled(get_history_compact_enabled())
    except Exception:
        pass
    try:
        set_sse_keepalive(get_sse_keepalive())
    except Exception:
        pass
    try:
        set_conversation_affinity_enabled(get_conversation_affinity_enabled())
    except Exception:
        pass
    try:
        set_default_model_setting(get_default_model_setting())
    except Exception:
        pass
    # Hydrate registration secrets (YesCaptcha / MoeMail / proxy) from DB into
    # process env so adapter modules that read env/config at call time work.
    try:
        apply_registration_config_to_runtime()
    except Exception:
        pass


# ── protocol registration config (MoeMail / YesCaptcha / proxy) ────────────

_REG_CONFIG_KEYS = (
    "base_url",
    "api_key",
    "domain",
    "prefix",
    "expiry_ms",
    "yescaptcha_key",
    "proxy",
    "proxy_username",
    "proxy_password",
    "count",
    "concurrency",
    "stagger_ms",
)

_REG_SECRET_KEYS = frozenset(
    {"api_key", "yescaptcha_key", "proxy_password"}
)


def _mask_secret(value: str | None) -> str:
    s = (value or "").strip()
    if not s:
        return ""
    if len(s) <= 8:
        return "****"
    return f"{s[:4]}…{s[-4:]}"


def _env_registration_defaults() -> dict[str, Any]:
    """Build defaults from env / config (non-secret fields always; secrets only as presence)."""
    out: dict[str, Any] = {}
    try:
        from config import (
            MOEMAIL_API_KEY,
            MOEMAIL_BASE_URL,
            MOEMAIL_DOMAIN,
            MOEMAIL_EXPIRY_MS,
            XAI_PROXY,
            XAI_PROXY_PASSWORD,
            XAI_PROXY_USERNAME,
        )

        if MOEMAIL_BASE_URL:
            out["base_url"] = str(MOEMAIL_BASE_URL)
        if MOEMAIL_DOMAIN:
            out["domain"] = str(MOEMAIL_DOMAIN)
        if MOEMAIL_EXPIRY_MS is not None:
            out["expiry_ms"] = int(MOEMAIL_EXPIRY_MS)
        if MOEMAIL_API_KEY:
            out["api_key"] = str(MOEMAIL_API_KEY)
        if XAI_PROXY:
            out["proxy"] = str(XAI_PROXY)
        if XAI_PROXY_USERNAME:
            out["proxy_username"] = str(XAI_PROXY_USERNAME)
        if XAI_PROXY_PASSWORD:
            out["proxy_password"] = str(XAI_PROXY_PASSWORD)
    except Exception:
        pass
    yes = (
        os.environ.get("GROK2API_YESCAPTCHA_KEY")
        or os.environ.get("YESCAPTCHA_API_KEY")
        or ""
    ).strip()
    if yes:
        out["yescaptcha_key"] = yes
    return out


def _normalize_registration_config(
    raw: dict[str, Any] | None,
    *,
    merge_env: bool = True,
) -> dict[str, Any]:
    """Sanitize registration config; optionally fill missing fields from env."""
    cfg: dict[str, Any] = {}
    src = raw if isinstance(raw, dict) else {}
    env = _env_registration_defaults() if merge_env else {}

    def _pick_str(key: str, max_len: int = 512) -> str:
        val = src.get(key)
        if val is None or str(val).strip() == "":
            val = env.get(key, "")
        s = str(val or "").strip()
        return s[:max_len]

    cfg["base_url"] = _pick_str("base_url", 256)
    cfg["api_key"] = _pick_str("api_key", 512)
    cfg["domain"] = _pick_str("domain", 128).lstrip("@").strip(".")
    cfg["prefix"] = _pick_str("prefix", 64)
    cfg["yescaptcha_key"] = _pick_str("yescaptcha_key", 512)
    cfg["proxy"] = _pick_str("proxy", 512)
    cfg["proxy_username"] = _pick_str("proxy_username", 256)
    cfg["proxy_password"] = _pick_str("proxy_password", 512)

    # expiry_ms — official MoeMail presets only
    expiry_raw = src.get("expiry_ms", env.get("expiry_ms", 3600000))
    try:
        expiry = int(expiry_raw)
    except (TypeError, ValueError):
        expiry = 3600000
    presets = {0, 3600000, 86400000, 259200000}
    if expiry not in presets:
        # nearest timed preset
        timed = (3600000, 86400000, 259200000)
        expiry = min(timed, key=lambda p: abs(p - expiry))
    cfg["expiry_ms"] = expiry

    def _int_field(key: str, default: int, lo: int, hi: int) -> int:
        raw_v = src.get(key, default)
        try:
            v = int(raw_v)
        except (TypeError, ValueError):
            v = default
        return max(lo, min(hi, v))

    cfg["count"] = _int_field("count", 1, 1, 10_000)
    cfg["concurrency"] = _int_field("concurrency", 3, 1, 10)
    cfg["stagger_ms"] = _int_field("stagger_ms", 400, 0, 10_000)
    return cfg


def get_registration_config(*, include_secrets: bool = True) -> dict[str, Any]:
    """Effective registration config: DB override merged with env defaults."""
    stored = _get_setting_value("registration_config", None)
    if not isinstance(stored, dict):
        stored = {}
    cfg = _normalize_registration_config(stored, merge_env=True)
    if include_secrets:
        return cfg
    public = dict(cfg)
    for k in _REG_SECRET_KEYS:
        if public.get(k):
            public[k] = _mask_secret(str(public[k]))
            public[f"{k}_set"] = True
        else:
            public[k] = ""
            public[f"{k}_set"] = False
    public["configured"] = {
        "moemail": bool(cfg.get("api_key")),
        "yescaptcha": bool(cfg.get("yescaptcha_key")),
        "proxy": bool(cfg.get("proxy")),
    }
    return public


def set_registration_config(
    patch: dict[str, Any] | None,
    *,
    replace: bool = False,
) -> dict[str, Any]:
    """Persist registration config to DB/settings and apply to runtime.

    Secret fields that arrive empty / masked keep the previously stored value
    so the admin form can re-save non-secret edits without re-typing keys.
    """
    if patch is not None and not isinstance(patch, dict):
        raise ValueError("registration_config must be an object")
    patch = dict(patch or {})

    current_stored = _get_setting_value("registration_config", None)
    if not isinstance(current_stored, dict):
        current_stored = {}

    if replace:
        base: dict[str, Any] = {}
    else:
        base = dict(current_stored)

    for key in _REG_CONFIG_KEYS:
        if key not in patch:
            continue
        val = patch.get(key)
        if key in _REG_SECRET_KEYS:
            s = "" if val is None else str(val).strip()
            # Keep previous secret when UI sends blank or already-masked value
            if not s or "…" in s or s == "****" or set(s) <= {"*"}:
                if key in current_stored and current_stored.get(key):
                    base[key] = current_stored[key]
                continue
            base[key] = s
            continue
        if val is None:
            base.pop(key, None)
            continue
        base[key] = val

    cfg = _normalize_registration_config(base, merge_env=False)
    # Drop empty optional strings to keep the row small
    cleaned = {
        k: v
        for k, v in cfg.items()
        if not (isinstance(v, str) and v == "" and k not in ("expiry_ms",))
    }
    # Always keep numeric defaults
    for k in ("expiry_ms", "count", "concurrency", "stagger_ms"):
        cleaned[k] = cfg[k]

    _set_setting_value("registration_config", cleaned)
    apply_registration_config_to_runtime(cleaned)
    return get_registration_config(include_secrets=True)


def apply_registration_config_to_runtime(cfg: dict[str, Any] | None = None) -> None:
    """Push registration secrets into env + config module for adapter use."""
    if cfg is None:
        cfg = get_registration_config(include_secrets=True)
    if not isinstance(cfg, dict):
        return

    def _set_env(name: str, value: str) -> None:
        if value:
            os.environ[name] = value

    api_key = str(cfg.get("api_key") or "").strip()
    base_url = str(cfg.get("base_url") or "").strip()
    domain = str(cfg.get("domain") or "").strip()
    yes = str(cfg.get("yescaptcha_key") or "").strip()
    proxy = str(cfg.get("proxy") or "").strip()
    proxy_user = str(cfg.get("proxy_username") or "").strip()
    proxy_pass = str(cfg.get("proxy_password") or "").strip()

    if api_key:
        _set_env("GROK2API_MOEMAIL_API_KEY", api_key)
        _set_env("MOEMAIL_API_KEY", api_key)
    if base_url:
        _set_env("GROK2API_MOEMAIL_BASE_URL", base_url)
    if domain:
        _set_env("GROK2API_MOEMAIL_DOMAIN", domain)
    if yes:
        _set_env("GROK2API_YESCAPTCHA_KEY", yes)
        _set_env("YESCAPTCHA_API_KEY", yes)
    if proxy:
        _set_env("GROK2API_XAI_PROXY", proxy)
    if proxy_user:
        _set_env("GROK2API_XAI_PROXY_USERNAME", proxy_user)
    if proxy_pass:
        _set_env("GROK2API_XAI_PROXY_PASSWORD", proxy_pass)
    if cfg.get("expiry_ms") is not None:
        try:
            _set_env("GROK2API_MOEMAIL_EXPIRY_MS", str(int(cfg["expiry_ms"])))
        except (TypeError, ValueError):
            pass

    try:
        import config as _cfg

        if api_key:
            _cfg.MOEMAIL_API_KEY = api_key
        if base_url:
            _cfg.MOEMAIL_BASE_URL = base_url
        if domain:
            _cfg.MOEMAIL_DOMAIN = domain
        if cfg.get("expiry_ms") is not None:
            try:
                _cfg.MOEMAIL_EXPIRY_MS = int(cfg["expiry_ms"])
            except (TypeError, ValueError):
                pass
        if proxy:
            _cfg.XAI_PROXY = proxy
        if proxy_user:
            _cfg.XAI_PROXY_USERNAME = proxy_user
        if proxy_pass:
            _cfg.XAI_PROXY_PASSWORD = proxy_pass
    except Exception:
        pass

    # Adapter caches YESCAPTCHA_KEY at import — refresh module attribute.
    try:
        import grok_build_adapter as gba

        if yes:
            gba.YESCAPTCHA_KEY = yes
    except Exception:
        pass


def resolve_registration_inputs(
    overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge request overrides on top of saved/env registration config."""
    base = get_registration_config(include_secrets=True)
    overrides = overrides if isinstance(overrides, dict) else {}
    merged = dict(base)
    for key in _REG_CONFIG_KEYS:
        if key not in overrides:
            continue
        val = overrides.get(key)
        if val is None:
            continue
        if isinstance(val, str) and not val.strip():
            continue
        if key in _REG_SECRET_KEYS and isinstance(val, str):
            s = val.strip()
            if "…" in s or s == "****" or set(s) <= {"*"}:
                continue
        merged[key] = val
    return _normalize_registration_config(merged, merge_env=True)


# ── pool rotation / cooldown policy ────────────────────────────────────────

def get_pool_policy() -> dict[str, Any]:
    """Effective pool rotation / cooldown policy for admin UI + runtime."""
    try:
        import account_pool as ap

        cd = ap.cooldown_defaults()
        return {
            "cooldown_default_sec": cd["default"],
            "cooldown_auth_sec": cd["auth"],
            "cooldown_rate_limit_sec": cd["rate_limit"],
            "cooldown_server_error_sec": cd["server_error"],
            "cooldown_max_sec": cd["max"],
            "soft_model_block_ttl_sec": cd["soft_block_ttl"],
            "durable_model_block_ttl_sec": cd.get("durable_block_ttl", 3600.0),
            "probe_fail_kick_streak": int(cd.get("probe_fail_kick_streak") or 2),
            "probe_fail_disable_streak": int(cd.get("probe_fail_disable_streak") or 4),
            "probe_kick_cooldown_sec": cd.get("probe_kick_cooldown_sec", 600.0),
            "max_failover_attempts": ap.max_failover_attempts(),
        }
    except Exception:
        return {
            "cooldown_default_sec": 20,
            "cooldown_auth_sec": 90,
            "cooldown_rate_limit_sec": 45,
            "cooldown_server_error_sec": 20,
            "cooldown_max_sec": 600,
            "soft_model_block_ttl_sec": 180,
            "durable_model_block_ttl_sec": 3600,
            "probe_fail_kick_streak": 2,
            "probe_fail_disable_streak": 4,
            "probe_kick_cooldown_sec": 600,
            "max_failover_attempts": 8,
        }


def set_pool_policy(patch: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(patch, dict):
        raise ValueError("pool policy must be an object")
    mapping = {
        "cooldown_default_sec": (1.0, 600.0),
        "cooldown_auth_sec": (5.0, 1800.0),
        "cooldown_rate_limit_sec": (5.0, 1800.0),
        "cooldown_server_error_sec": (1.0, 600.0),
        "cooldown_max_sec": (30.0, 3600.0),
        "soft_model_block_ttl_sec": (30.0, 3600.0),
        "durable_model_block_ttl_sec": (60.0, 86400.0),
        "probe_fail_kick_streak": (1.0, 20.0),
        "probe_fail_disable_streak": (2.0, 50.0),
        "probe_kick_cooldown_sec": (30.0, 7200.0),
        "max_failover_attempts": (1.0, 64.0),
    }
    for key, (lo, hi) in mapping.items():
        if key not in patch or patch[key] is None:
            continue
        try:
            val = float(patch[key])
        except (TypeError, ValueError) as e:
            raise ValueError(f"{key} 必须是数字") from e
        val = max(lo, min(hi, val))
        if key in (
            "max_failover_attempts",
            "probe_fail_kick_streak",
            "probe_fail_disable_streak",
        ):
            _set_setting_value(key, int(val))
        else:
            _set_setting_value(key, float(val))
    return get_pool_policy()


def update_runtime_settings(patch: dict[str, Any]) -> dict[str, Any]:
    """Apply a partial settings patch from admin UI. Returns effective public settings."""
    if not isinstance(patch, dict):
        raise ValueError("settings body must be an object")
    if "reasoning_compat" in patch and patch["reasoning_compat"] is not None:
        set_reasoning_compat(str(patch["reasoning_compat"]))
    if "outbound_max_tools" in patch and patch["outbound_max_tools"] is not None:
        set_outbound_max_tools(patch["outbound_max_tools"])
    if "outbound_tool_gap_sec" in patch and patch["outbound_tool_gap_sec"] is not None:
        set_outbound_tool_gap_sec(patch["outbound_tool_gap_sec"])
    if "history_compact_enabled" in patch and patch["history_compact_enabled"] is not None:
        set_history_compact_enabled(bool(patch["history_compact_enabled"]))
    if "sse_keepalive" in patch and patch["sse_keepalive"] is not None:
        set_sse_keepalive(patch["sse_keepalive"])
    if (
        "conversation_affinity_enabled" in patch
        and patch["conversation_affinity_enabled"] is not None
    ):
        set_conversation_affinity_enabled(bool(patch["conversation_affinity_enabled"]))
    if "default_model" in patch and patch["default_model"] is not None:
        set_default_model_setting(str(patch["default_model"]))
    if "account_mode" in patch and patch["account_mode"] is not None:
        set_account_mode(str(patch["account_mode"]))
    if "token_maintain_enabled" in patch and patch["token_maintain_enabled"] is not None:
        set_token_maintain_enabled(bool(patch["token_maintain_enabled"]))
    if "model_health_enabled" in patch and patch["model_health_enabled"] is not None:
        set_model_health_enabled(bool(patch["model_health_enabled"]))
    # Pool rotation / cooldown policy (nested or flat)
    pool_keys = (
        "cooldown_default_sec",
        "cooldown_auth_sec",
        "cooldown_rate_limit_sec",
        "cooldown_server_error_sec",
        "cooldown_max_sec",
        "soft_model_block_ttl_sec",
        "durable_model_block_ttl_sec",
        "probe_fail_kick_streak",
        "probe_fail_disable_streak",
        "probe_kick_cooldown_sec",
        "max_failover_attempts",
    )
    pool_patch: dict[str, Any] = {}
    nested = patch.get("pool_policy")
    if isinstance(nested, dict):
        pool_patch.update(nested)
    for k in pool_keys:
        if k in patch and patch[k] is not None:
            pool_patch[k] = patch[k]
    if pool_patch:
        set_pool_policy(pool_patch)
    if "registration_config" in patch and patch["registration_config"] is not None:
        set_registration_config(patch["registration_config"])
    return get_public_settings()


def get_public_settings() -> dict[str, Any]:
    data = _load()
    # Secrets stay full for admin session API (admin-auth only); UI masks display.
    reg = get_registration_config(include_secrets=True)
    return {
        "account_mode": get_account_mode(),
        "account_modes": list(VALID_ACCOUNT_MODES),
        "has_admin_password": has_admin_password(),
        "setup_needed": is_setup_needed(),
        "admin_password_from_env": bool(ADMIN_PASSWORD),
        "token_maintain_enabled": get_token_maintain_enabled(),
        "model_health_enabled": get_model_health_enabled(),
        "reasoning_compat": get_reasoning_compat(),
        "reasoning_compat_options": list(_VALID_REASONING),
        "outbound_max_tools": get_outbound_max_tools(),
        "outbound_tool_gap_sec": get_outbound_tool_gap_sec(),
        "history_compact_enabled": get_history_compact_enabled(),
        "sse_keepalive": get_sse_keepalive(),
        "conversation_affinity_enabled": get_conversation_affinity_enabled(),
        "default_model": get_default_model_setting(),
        "pool_policy": get_pool_policy(),
        "registration_config": reg,
        "updated_at": data.get("updated_at"),
    }
