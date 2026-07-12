"""PostgreSQL backend for auth account map (auth.json equivalent)."""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from store.pg import _ts, _unix, connection, json_dump, pg_enabled


def enabled() -> bool:
    return pg_enabled()


def read_auth_map() -> dict[str, Any]:
    if not enabled():
        return {}
    out: dict[str, Any] = {}
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, payload FROM accounts")
            for row in cur.fetchall():
                aid, payload = row[0], row[1]
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                if isinstance(payload, dict):
                    out[str(aid)] = payload
    return out


def _decode_payload(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return None
    return payload if isinstance(payload, dict) else None


def count_accounts() -> int:
    if not enabled():
        return 0
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM accounts")
            row = cur.fetchone()
    return int(row[0] or 0) if row else 0


def list_account_summaries(
    *,
    q: str = "",
    page: int = 1,
    page_size: int = 25,
) -> dict[str, Any]:
    """Paged account list for admin UI without loading the full auth map.

    Returns admin-safe fields only (no full access/refresh tokens).
    """
    if not enabled():
        return {
            "accounts": [],
            "total": 0,
            "page": 1,
            "page_size": page_size,
            "total_pages": 1,
            "q": q,
        }

    query = (q or "").strip().lower()
    try:
        page_i = max(1, int(page))
    except Exception:
        page_i = 1
    try:
        size_i = int(page_size)
    except Exception:
        size_i = 25
    if size_i <= 0 or size_i >= 10000:
        # "all" mode still streams only summary fields
        size_i = 0
    else:
        size_i = max(1, min(200, size_i))

    like = f"%{query}%" if query else None
    with connection() as conn:
        with conn.cursor() as cur:
            if like:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM accounts
                    WHERE lower(COALESCE(email,'')) LIKE %s
                       OR lower(id) LIKE %s
                       OR lower(COALESCE(user_id,'')) LIKE %s
                    """,
                    (like, like, like),
                )
            else:
                cur.execute("SELECT COUNT(*) FROM accounts")
            total = int((cur.fetchone() or [0])[0] or 0)

            if size_i == 0:
                size_i = total or 0
                page_i = 1
                total_pages = 1
                offset = 0
                limit = None
            else:
                total_pages = max(1, (total + size_i - 1) // size_i) if total else 1
                page_i = min(page_i, total_pages)
                offset = (page_i - 1) * size_i
                limit = size_i

            sql = """
                SELECT id, email, user_id, team_id, payload, expires_at
                FROM accounts
            """
            params: list[Any] = []
            if like:
                sql += """
                    WHERE lower(COALESCE(email,'')) LIKE %s
                       OR lower(id) LIKE %s
                       OR lower(COALESCE(user_id,'')) LIKE %s
                """
                params.extend([like, like, like])
            sql += " ORDER BY expires_at DESC NULLS LAST, updated_at DESC"
            if limit is not None:
                sql += " LIMIT %s OFFSET %s"
                params.extend([limit, offset])
            cur.execute(sql, params)
            rows = cur.fetchall()

    now = time.time()
    accounts: list[dict[str, Any]] = []
    for r in rows:
        aid = str(r[0])
        payload = _decode_payload(r[4]) or {}
        token = payload.get("key") or payload.get("access_token") or payload.get("token")
        # Skip empty credential rows (shouldn't happen)
        if not token and not payload.get("refresh_token"):
            # still show if email exists
            if not (r[1] or payload.get("email")):
                continue
        exp = _unix(r[5])
        if exp is None:
            # fall back to payload expires_at if column empty
            try:
                from oidc_auth import parse_expires_at

                exp = parse_expires_at(
                    payload.get("expires_at"),
                    token if isinstance(token, str) else None,
                )
            except Exception:
                exp = None
        expired = bool(exp is not None and now >= float(exp))
        tok = token if isinstance(token, str) else None
        if tok and len(tok) > 12:
            hint = tok[:6] + "..." + tok[-4:]
        elif tok:
            hint = "****"
        else:
            hint = ""
        accounts.append(
            {
                "id": aid,
                "email": r[1] or payload.get("email"),
                "user_id": r[2] or payload.get("user_id") or payload.get("principal_id"),
                "team_id": r[3] or payload.get("team_id"),
                "auth_mode": payload.get("auth_mode"),
                "create_time": payload.get("create_time"),
                "expires_at": exp,
                "expired": expired,
                "has_refresh_token": bool(payload.get("refresh_token")),
                "token_hint": hint,
                "first_name": payload.get("first_name"),
                "last_name": payload.get("last_name"),
                "principal_type": payload.get("principal_type"),
            }
        )

    return {
        "accounts": accounts,
        "total": total,
        "page": page_i,
        "page_size": size_i,
        "total_pages": max(1, (total + size_i - 1) // size_i) if size_i else 1,
        "q": (q or "").strip(),
    }


def write_auth_map(data: dict[str, Any]) -> None:
    """Replace full account set (import/export style)."""
    if not enabled():
        return
    data = data if isinstance(data, dict) else {}
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM accounts")
            existing = {r[0] for r in cur.fetchall()}
            incoming = set(data.keys())
            # upsert all
            for aid, entry in data.items():
                if not isinstance(entry, dict):
                    continue
                _upsert_one(cur, str(aid), entry)
            # delete removed
            for aid in existing - incoming:
                cur.execute("DELETE FROM accounts WHERE id = %s", (aid,))
                cur.execute("DELETE FROM account_pool WHERE account_id = %s", (aid,))
        conn.commit()


def mutate_auth_map(mutator: Callable[[dict[str, Any]], Any]) -> dict[str, Any]:
    """Transactional read-modify-write of the full map (compatible with file API)."""
    if not enabled():
        return {}
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, payload FROM accounts FOR UPDATE")
            data: dict[str, Any] = {}
            for aid, payload in cur.fetchall():
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        payload = {}
                if isinstance(payload, dict):
                    data[str(aid)] = payload
            mutator(data)
            # rewrite set
            cur.execute("SELECT id FROM accounts")
            existing = {r[0] for r in cur.fetchall()}
            incoming = set(data.keys())
            for aid, entry in data.items():
                if isinstance(entry, dict):
                    _upsert_one(cur, str(aid), entry)
            for aid in existing - incoming:
                cur.execute("DELETE FROM accounts WHERE id = %s", (aid,))
                cur.execute("DELETE FROM account_pool WHERE account_id = %s", (aid,))
        conn.commit()
    return data


def upsert_account(account_id: str, entry: dict[str, Any]) -> None:
    if not enabled() or not account_id or not isinstance(entry, dict):
        return
    with connection() as conn:
        with conn.cursor() as cur:
            _upsert_one(cur, account_id, entry)
        conn.commit()


def upsert_account_merged(
    account_id: str,
    entry: dict[str, Any],
    *,
    merge_same_user: bool = True,
) -> str:
    """Row-level upsert + optional same-user/token dedupe without rewriting whole table."""
    if not enabled() or not account_id or not isinstance(entry, dict):
        return account_id
    uid = entry.get("user_id") or entry.get("principal_id")
    token = entry.get("key")
    with connection() as conn:
        with conn.cursor() as cur:
            if merge_same_user and (uid or token):
                # Drop other rows that collide on user_id / access token.
                if uid and token:
                    cur.execute(
                        """
                        DELETE FROM accounts
                        WHERE id <> %s
                          AND (
                            user_id = %s
                            OR payload->>'user_id' = %s
                            OR payload->>'principal_id' = %s
                            OR payload->>'key' = %s
                          )
                        """,
                        (account_id, str(uid), str(uid), str(uid), str(token)),
                    )
                elif uid:
                    cur.execute(
                        """
                        DELETE FROM accounts
                        WHERE id <> %s
                          AND (
                            user_id = %s
                            OR payload->>'user_id' = %s
                            OR payload->>'principal_id' = %s
                          )
                        """,
                        (account_id, str(uid), str(uid), str(uid)),
                    )
                elif token:
                    cur.execute(
                        """
                        DELETE FROM accounts
                        WHERE id <> %s AND payload->>'key' = %s
                        """,
                        (account_id, str(token)),
                    )
                # Clean orphan pool rows for deleted accounts
                cur.execute(
                    """
                    DELETE FROM account_pool ap
                    WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = ap.account_id)
                    """
                )
            _upsert_one(cur, account_id, entry)
        conn.commit()
    return account_id


def delete_account(account_id: str) -> bool:
    if not enabled() or not account_id:
        return False
    with connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM accounts WHERE id = %s", (account_id,))
            deleted = cur.rowcount > 0
            cur.execute("DELETE FROM account_pool WHERE account_id = %s", (account_id,))
        conn.commit()
    return deleted


def _upsert_one(cur, account_id: str, entry: dict[str, Any]) -> None:
    email = entry.get("email")
    user_id = entry.get("user_id") or entry.get("principal_id")
    team_id = entry.get("team_id")
    expires_at = _ts(entry.get("expires_at"))
    cur.execute(
        """
        INSERT INTO accounts (id, email, user_id, team_id, payload, expires_at, updated_at)
        VALUES (%s, %s, %s, %s, %s::jsonb, %s, now())
        ON CONFLICT (id) DO UPDATE SET
          email = EXCLUDED.email,
          user_id = EXCLUDED.user_id,
          team_id = EXCLUDED.team_id,
          payload = EXCLUDED.payload,
          expires_at = EXCLUDED.expires_at,
          updated_at = now()
        """,
        (
            account_id,
            email,
            user_id,
            team_id,
            json_dump(entry),
            expires_at,
        ),
    )
    # Every account must have a durable pool status row in PostgreSQL.
    # Do not overwrite existing cooldown/status — only create defaults for new ids.
    cur.execute(
        """
        INSERT INTO account_pool (
          account_id, enabled, weight, disabled_for_quota, blocked_models,
          request_count, success_count, fail_count, extra, updated_at,
          pool_status, cooldown_count
        ) VALUES (
          %s, true, 1, false, '{}'::jsonb,
          0, 0, 0, '{}'::jsonb, now(),
          'normal', 0
        )
        ON CONFLICT (account_id) DO NOTHING
        """,
        (account_id,),
    )
