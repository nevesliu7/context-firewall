import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .aws_adapters import maybe_put_approval_ticket, maybe_put_audit_record, protect_text
from .models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    ApprovalTicket,
    AuditRecord,
    ScanRequest,
    ScanResponse,
)


DB_PATH = Path(__file__).resolve().parent.parent / "context_firewall.db"


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                user_role TEXT NOT NULL,
                app_name TEXT NOT NULL,
                destination TEXT NOT NULL,
                model_provider TEXT NOT NULL,
                purpose TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                policy_hit_count INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                sanitized_hash TEXT NOT NULL
            )
            """
        )
        _ensure_columns(
            conn,
            "audit_records",
            {
                "event_type": "TEXT DEFAULT 'scan'",
                "request_id": "TEXT DEFAULT ''",
                "user_id": "TEXT DEFAULT 'anonymous'",
                "source": "TEXT DEFAULT 'manual_paste'",
                "provider_route": "TEXT DEFAULT 'unknown'",
                "policy_version": "TEXT DEFAULT 'unknown'",
            },
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approval_tickets (
                ticket_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                user_role TEXT NOT NULL,
                destination TEXT NOT NULL,
                model_provider TEXT NOT NULL,
                purpose TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                finding_count INTEGER NOT NULL,
                policy_hit_count INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                sanitized_content TEXT NOT NULL,
                reason TEXT NOT NULL,
                reviewer TEXT,
                reviewer_note TEXT
            )
            """
        )


def save_audit_record(
    request: ScanRequest,
    response: ScanResponse,
    original_content: str,
    event_type: str = "scan",
    request_id: str | None = None,
) -> AuditRecord:
    init_db()
    record = AuditRecord(
        audit_id=response.audit_id,
        timestamp=response.timestamp,
        tenant_id=request.tenant_id,
        user_id=request.user_id,
        user_role=request.user_role,
        app_name=request.app_name,
        destination=request.destination,
        model_provider=request.model_provider,
        purpose=request.purpose,
        decision=response.decision,
        risk_score=response.risk_score,
        finding_count=len(response.findings),
        policy_hit_count=len(response.policy_hits),
        content_hash=hash_content(original_content),
        sanitized_hash=hash_content(response.sanitized_content),
        event_type=event_type,
        request_id=request_id or response.audit_id,
        source=request.source,
        provider_route=response.provider_route.route,
        policy_version=response.policy_version,
    )
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO audit_records (
                audit_id, timestamp, tenant_id, user_role, app_name, destination, model_provider,
                purpose, decision, risk_score, finding_count, policy_hit_count, content_hash, sanitized_hash,
                event_type, request_id, user_id, source, provider_route, policy_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.audit_id,
                record.timestamp.isoformat(),
                record.tenant_id,
                record.user_role,
                record.app_name,
                record.destination.value,
                record.model_provider,
                record.purpose,
                record.decision.value,
                record.risk_score,
                record.finding_count,
                record.policy_hit_count,
                record.content_hash,
                record.sanitized_hash,
                record.event_type,
                record.request_id,
                record.user_id,
                record.source,
                record.provider_route,
                record.policy_version,
            ),
        )
    maybe_put_audit_record(record.model_dump(mode="json"))
    return record


def create_approval_ticket(request: ScanRequest, response: ScanResponse, original_content: str) -> ApprovalTicket:
    init_db()
    reason = "; ".join(hit.reason for hit in response.policy_hits) or response.context_summary
    ticket = ApprovalTicket(
        tenant_id=request.tenant_id,
        requested_by=request.user_id,
        user_role=request.user_role,
        destination=request.destination,
        model_provider=request.model_provider,
        purpose=request.purpose,
        decision=response.decision,
        risk_score=response.risk_score,
        finding_count=len(response.findings),
        policy_hit_count=len(response.policy_hits),
        content_hash=hash_content(original_content),
        sanitized_content=protect_text(response.sanitized_content),
        reason=reason,
    )
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO approval_tickets (
                ticket_id, created_at, updated_at, status, tenant_id, requested_by, user_role,
                destination, model_provider, purpose, decision, risk_score, finding_count,
                policy_hit_count, content_hash, sanitized_content, reason, reviewer, reviewer_note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ticket.ticket_id,
                ticket.created_at.isoformat(),
                ticket.updated_at.isoformat(),
                ticket.status.value,
                ticket.tenant_id,
                ticket.requested_by,
                ticket.user_role,
                ticket.destination.value,
                ticket.model_provider,
                ticket.purpose,
                ticket.decision.value,
                ticket.risk_score,
                ticket.finding_count,
                ticket.policy_hit_count,
                ticket.content_hash,
                ticket.sanitized_content,
                ticket.reason,
                ticket.reviewer,
                ticket.reviewer_note,
            ),
        )
    maybe_put_approval_ticket(ticket.model_dump(mode="json"))
    return ticket


def list_audit_records(limit: int = 25) -> list[dict]:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM audit_records
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_approval_tickets(status: ApprovalStatus | None = None, limit: int = 25) -> list[dict]:
    init_db()
    sql = "SELECT * FROM approval_tickets"
    params: list[object] = []
    if status:
        sql += " WHERE status = ?"
        params.append(status.value)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def update_approval_ticket(ticket_id: str, decision: ApprovalDecisionRequest) -> dict | None:
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            UPDATE approval_tickets
            SET status = ?, updated_at = ?, reviewer = ?, reviewer_note = ?
            WHERE ticket_id = ?
            """,
            (decision.status.value, now, decision.reviewer, decision.note, ticket_id),
        )
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM approval_tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    return dict(row) if row else None


def audit_summary() -> dict[str, object]:
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        decisions = conn.execute(
            "SELECT decision, COUNT(*) AS count FROM audit_records GROUP BY decision"
        ).fetchall()
        routes = conn.execute(
            "SELECT provider_route, COUNT(*) AS count FROM audit_records GROUP BY provider_route"
        ).fetchall()
        pending = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_tickets WHERE status = 'pending'"
        ).fetchone()
    return {
        "decisions": {row["decision"]: row["count"] for row in decisions},
        "routes": {row["provider_route"]: row["count"] for row in routes},
        "pending_approvals": pending["count"] if pending else 0,
    }


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def json_hash(payload: dict) -> str:
    return hash_content(json.dumps(payload, sort_keys=True, separators=(",", ":")))
