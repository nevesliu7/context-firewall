from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class Decision(str, Enum):
    allow = "allow"
    redact = "redact"
    block = "block"
    review = "review"


class Destination(str, Enum):
    internal_llm = "internal_llm"
    external_llm = "external_llm"
    browser_extension = "browser_extension"
    agent_tool = "agent_tool"


class FindingType(str, Enum):
    pii = "pii"
    secret = "secret"
    regulated = "regulated"
    confidential = "confidential"
    prompt_injection = "prompt_injection"
    source_code = "source_code"


class ScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=80_000)
    destination: Destination = Destination.external_llm
    model_provider: str = Field(default="openai", max_length=80)
    user_role: str = Field(default="employee", max_length=80)
    user_id: str = Field(default="anonymous", max_length=160)
    purpose: str = Field(default="general_assistance", max_length=160)
    app_name: str = Field(default="manual_console", max_length=120)
    tenant_id: str = Field(default="demo-tenant", max_length=120)
    source: str = Field(default="manual_paste", max_length=160)
    strict_mode: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class Finding(BaseModel):
    type: FindingType
    label: str
    value_preview: str
    start: int
    end: int
    confidence: float = Field(ge=0, le=1)
    severity: Literal["low", "medium", "high", "critical"]
    redaction_token: str


class PolicyHit(BaseModel):
    id: str
    name: str
    severity: Literal["low", "medium", "high", "critical"]
    action: Decision
    reason: str


class ProviderRoute(BaseModel):
    route: Literal["approved_external_provider", "internal_model", "human_review", "blocked", "dry_run"]
    provider: str
    reason: str


class ScanResponse(BaseModel):
    audit_id: str
    timestamp: datetime
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    sanitized_content: str
    findings: list[Finding]
    policy_hits: list[PolicyHit]
    provider_route: ProviderRoute
    context_summary: str
    policy_version: str = "unknown"
    approval_ticket_id: str | None = None


class AuditRecord(BaseModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tenant_id: str
    user_id: str = "anonymous"
    user_role: str
    app_name: str
    destination: Destination
    model_provider: str
    purpose: str
    decision: Decision
    risk_score: int
    finding_count: int
    policy_hit_count: int
    content_hash: str
    sanitized_hash: str
    event_type: str = "scan"
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    source: str = "manual_paste"
    provider_route: str = "unknown"
    policy_version: str = "unknown"


class PolicySummary(BaseModel):
    id: str
    name: str
    action: Decision
    description: str


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "developer"]
    content: str | list[dict] | dict
    name: str | None = None
    tool_call_id: str | None = None


class GatewayRequest(BaseModel):
    messages: list[ChatMessage] = Field(..., min_length=1)
    model: str = Field(default="gpt-4.1-mini", max_length=120)
    destination: Destination = Destination.external_llm
    model_provider: str = Field(default="openai", max_length=80)
    user_role: str = Field(default="employee", max_length=80)
    user_id: str = Field(default="anonymous", max_length=160)
    tenant_id: str = Field(default="demo-tenant", max_length=120)
    purpose: str = Field(default="chat_completion", max_length=160)
    app_name: str = Field(default="llm_gateway", max_length=120)
    stream: bool = False
    dry_run: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class GatewayResponse(BaseModel):
    request_id: str
    forwarded: bool
    status: Literal["allowed", "redacted", "blocked", "review_required", "dry_run"]
    firewall: ScanResponse
    sanitized_messages: list[ChatMessage]
    provider_payload: dict
    provider_response: dict | None = None


class ApprovalStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"


class ApprovalTicket(BaseModel):
    ticket_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: ApprovalStatus = ApprovalStatus.pending
    tenant_id: str
    requested_by: str
    user_role: str
    destination: Destination
    model_provider: str
    purpose: str
    decision: Decision
    risk_score: int
    finding_count: int
    policy_hit_count: int
    content_hash: str
    sanitized_content: str
    reason: str
    reviewer: str | None = None
    reviewer_note: str | None = None


class ApprovalDecisionRequest(BaseModel):
    reviewer: str = Field(..., min_length=1, max_length=160)
    status: ApprovalStatus
    note: str = Field(default="", max_length=1000)


class PolicyUpdateRequest(BaseModel):
    updated_by: str = Field(..., min_length=1, max_length=160)
    reason: str = Field(..., min_length=1, max_length=1000)
    policy: dict
