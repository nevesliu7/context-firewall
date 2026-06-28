import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException

from .audit_store import DB_PATH
from .policy_config import load_policy_config


@dataclass(frozen=True)
class UsageLimitResult:
    tenant_id: str
    estimated_tokens: int
    minute_requests_used: int
    minute_request_limit: int
    daily_tokens_used: int
    daily_token_limit: int


def init_usage_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS usage_counters (
                tenant_id TEXT NOT NULL,
                bucket_type TEXT NOT NULL,
                bucket_key TEXT NOT NULL,
                request_count INTEGER NOT NULL DEFAULT 0,
                estimated_tokens INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, bucket_type, bucket_key)
            )
            """
        )


def enforce_usage_limits(tenant_id: str, user_role: str, content: str) -> UsageLimitResult:
    init_usage_db()
    estimated_tokens = estimate_tokens(content)
    minute_limit = _int_setting("CFW_RATE_LIMIT_PER_MINUTE", "requests_per_minute_per_tenant", 120)
    daily_limit = _daily_token_limit(user_role)
    now = datetime.now(timezone.utc)
    minute_key = now.strftime("%Y%m%dT%H%M")
    day_key = now.strftime("%Y%m%d")

    if not usage_limits_enabled():
        return UsageLimitResult(
            tenant_id=tenant_id,
            estimated_tokens=estimated_tokens,
            minute_requests_used=0,
            minute_request_limit=minute_limit,
            daily_tokens_used=0,
            daily_token_limit=daily_limit,
        )

    with sqlite3.connect(DB_PATH) as conn:
        minute = _get_counter(conn, tenant_id, "minute", minute_key)
        day = _get_counter(conn, tenant_id, "day", day_key)
        next_minute_requests = minute["request_count"] + 1
        next_daily_tokens = day["estimated_tokens"] + estimated_tokens

        if next_minute_requests > minute_limit:
            raise HTTPException(
                status_code=429,
                detail={
                    "message": "Tenant request rate limit exceeded",
                    "tenant_id": tenant_id,
                    "limit": minute_limit,
                    "window": "minute",
                },
            )
        if next_daily_tokens > daily_limit:
            raise HTTPException(
                status_code=429,
                detail={
                    "message": "Tenant daily token budget exceeded",
                    "tenant_id": tenant_id,
                    "limit": daily_limit,
                    "estimated_tokens": next_daily_tokens,
                    "window": "day",
                },
            )

        _upsert_counter(conn, tenant_id, "minute", minute_key, 1, estimated_tokens, now)
        _upsert_counter(conn, tenant_id, "day", day_key, 1, estimated_tokens, now)

    return UsageLimitResult(
        tenant_id=tenant_id,
        estimated_tokens=estimated_tokens,
        minute_requests_used=next_minute_requests,
        minute_request_limit=minute_limit,
        daily_tokens_used=next_daily_tokens,
        daily_token_limit=daily_limit,
    )


def usage_summary(tenant_id: str | None = None) -> dict[str, object]:
    init_usage_db()
    now = datetime.now(timezone.utc)
    minute_key = now.strftime("%Y%m%dT%H%M")
    day_key = now.strftime("%Y%m%d")
    params: list[object] = [day_key, minute_key]
    tenant_filter = ""
    if tenant_id:
        tenant_filter = "AND tenant_id = ?"
        params.append(tenant_id)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            SELECT tenant_id, bucket_type, request_count, estimated_tokens, updated_at
            FROM usage_counters
            WHERE bucket_key IN (?, ?) {tenant_filter}
            ORDER BY tenant_id, bucket_type
            """,
            params,
        ).fetchall()
    return {
        "current_minute": minute_key,
        "current_day": day_key,
        "usage": [dict(row) for row in rows],
    }


def estimate_tokens(content: str) -> int:
    if not content:
        return 1
    return max(1, (len(content) + 3) // 4)


def usage_limits_enabled() -> bool:
    return os.getenv("CFW_USAGE_LIMITS_ENABLED", "true").lower() == "true"


def _get_counter(conn: sqlite3.Connection, tenant_id: str, bucket_type: str, bucket_key: str) -> dict[str, int]:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        """
        SELECT request_count, estimated_tokens
        FROM usage_counters
        WHERE tenant_id = ? AND bucket_type = ? AND bucket_key = ?
        """,
        (tenant_id, bucket_type, bucket_key),
    ).fetchone()
    if not row:
        return {"request_count": 0, "estimated_tokens": 0}
    return {"request_count": int(row["request_count"]), "estimated_tokens": int(row["estimated_tokens"])}


def _upsert_counter(
    conn: sqlite3.Connection,
    tenant_id: str,
    bucket_type: str,
    bucket_key: str,
    request_count: int,
    estimated_tokens: int,
    now: datetime,
) -> None:
    conn.execute(
        """
        INSERT INTO usage_counters (
            tenant_id, bucket_type, bucket_key, request_count, estimated_tokens, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id, bucket_type, bucket_key)
        DO UPDATE SET
            request_count = request_count + excluded.request_count,
            estimated_tokens = estimated_tokens + excluded.estimated_tokens,
            updated_at = excluded.updated_at
        """,
        (tenant_id, bucket_type, bucket_key, request_count, estimated_tokens, now.isoformat()),
    )


def _daily_token_limit(user_role: str) -> int:
    config = load_policy_config().get("usage_limits", {})
    role_limits = config.get("daily_estimated_tokens_by_role", {})
    env_role_key = f"CFW_DAILY_TOKEN_BUDGET_{user_role.upper()}"
    if os.getenv(env_role_key):
        return int(os.getenv(env_role_key, "0"))
    if user_role in role_limits:
        return int(role_limits[user_role])
    return _int_setting("CFW_DAILY_TOKEN_BUDGET_PER_TENANT", "daily_estimated_tokens_per_tenant", 200_000)


def _int_setting(env_name: str, policy_key: str, default: int) -> int:
    if os.getenv(env_name):
        return int(os.getenv(env_name, str(default)))
    config = load_policy_config().get("usage_limits", {})
    if policy_key in config:
        return int(config[policy_key])
    return default
