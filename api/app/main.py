from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from mangum import Mangum

from .auth import auth_config_summary, auth_required, resolve_identity
from .aws_adapters import maybe_put_audit_export
from .audit_store import (
    audit_summary,
    create_approval_ticket,
    export_audit_records,
    init_db,
    list_approval_tickets,
    list_audit_records,
    save_audit_record,
    update_approval_ticket,
)
from .detectors import detect_findings
from .gateway import (
    gateway_to_scan_request,
    openai_compatible_error,
    openai_compatible_success,
    route_gateway_request,
)
from .models import (
    ApprovalDecisionRequest,
    ApprovalStatus,
    ChatMessage,
    Decision,
    Destination,
    GatewayRequest,
    GatewayResponse,
    PolicySummary,
    PolicyUpdateRequest,
    ScanRequest,
    ScanResponse,
)
from .policies import (
    calculate_risk_score,
    choose_decision,
    choose_provider_route,
    evaluate_policies,
    summarize_context,
)
from .policy_config import load_policy_config, policy_summaries, policy_version, save_policy_config, validate_policy_config
from .rbac import has_permission, require_any_permission, require_permission, rbac_enforced
from .redaction import redact_content
from .usage_limits import enforce_usage_limits, init_usage_db, usage_summary


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    init_usage_db()
    yield


app = FastAPI(title="Context Firewall API", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.2.0", "policy_version": policy_version()}


@app.post("/scan", response_model=ScanResponse)
def scan_context(request: ScanRequest) -> ScanResponse:
    enforce_usage_limits(request.tenant_id, request.user_role, request.content)
    response = run_firewall_scan(request)
    save_audit_record(request, response, request.content)
    return response


@app.post("/gateway/chat", response_model=GatewayResponse)
async def gateway_chat(request: GatewayRequest, authorization: str | None = Header(default=None)) -> GatewayResponse:
    identity = resolve_identity(authorization, request.tenant_id, request.user_id, request.user_role)
    resolved_request = request.model_copy(
        update={
            "tenant_id": identity.tenant_id,
            "user_id": identity.user_id,
            "user_role": identity.user_role,
            "metadata": {**request.metadata, "auth_source": identity.auth_source},
        }
    )
    scan_request = gateway_to_scan_request(resolved_request)
    enforce_usage_limits(scan_request.tenant_id, scan_request.user_role, scan_request.content)
    firewall = run_firewall_scan(scan_request)
    response = await _route_and_audit(resolved_request, scan_request, firewall)
    return response


@app.post("/v1/chat/completions")
async def openai_compatible_gateway(
    http_request: Request,
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
    x_cfw_app_name: str = Header(default="openai_compatible_gateway"),
    x_cfw_provider: str = Header(default="openai"),
    x_cfw_destination: Destination = Header(default=Destination.external_llm),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    payload = await http_request.json()
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    gateway_request = GatewayRequest(
        messages=[ChatMessage(**message) for message in payload.get("messages", [])],
        model=payload.get("model", "gpt-4.1-mini"),
        stream=bool(payload.get("stream", False)),
        metadata={key: str(value) for key, value in payload.get("metadata", {}).items()},
        model_provider=x_cfw_provider,
        destination=x_cfw_destination,
        tenant_id=identity.tenant_id,
        user_id=identity.user_id,
        user_role=identity.user_role,
        app_name=x_cfw_app_name,
        purpose="openai_compatible_chat_completion",
        dry_run=bool(payload.get("dry_run", True)),
    )
    scan_request = gateway_to_scan_request(gateway_request)
    enforce_usage_limits(scan_request.tenant_id, scan_request.user_role, scan_request.content)
    firewall = run_firewall_scan(scan_request)
    response = await _route_and_audit(gateway_request, scan_request, firewall)

    if response.status == "blocked":
        return JSONResponse(status_code=403, content=openai_compatible_error(response))
    if response.status == "review_required":
        return JSONResponse(status_code=409, content=openai_compatible_error(response))
    return JSONResponse(status_code=200, content=openai_compatible_success(response))


@app.get("/audit")
def audit(
    limit: int = 25,
    tenant_id: str | None = None,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> list[dict]:
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_any_permission(identity, ["audit:read_all", "audit:read_tenant"])
    return list_audit_records(limit=max(1, min(limit, 100)), tenant_id=_tenant_filter(identity, "audit:read_all", tenant_id))


@app.get("/audit/export")
def audit_export(
    format: str = "json",
    delivery: str = "download",
    limit: int = 1000,
    tenant_id: str | None = None,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
):
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_any_permission(identity, ["audit:export", "audit:read_tenant"])
    records = export_audit_records(
        limit=max(1, min(limit, 10_000)),
        tenant_id=_tenant_filter(identity, "audit:export", tenant_id),
    )
    if delivery not in {"download", "s3"}:
        raise HTTPException(status_code=400, detail="delivery must be download or s3")
    if format == "ndjson":
        body = "\n".join(json.dumps(record, sort_keys=True) for record in records)
        if delivery == "s3":
            delivered = maybe_put_audit_export(body + ("\n" if body else ""), "ndjson", "application/x-ndjson")
            return JSONResponse(content={"records": len(records), "delivery": delivered or "not_configured"})
        return PlainTextResponse(body + ("\n" if body else ""), media_type="application/x-ndjson")
    if format != "json":
        raise HTTPException(status_code=400, detail="format must be json or ndjson")
    if delivery == "s3":
        body = json.dumps({"records": records, "count": len(records)}, sort_keys=True)
        delivered = maybe_put_audit_export(body, "json", "application/json")
        return JSONResponse(content={"records": len(records), "delivery": delivered or "not_configured"})
    return JSONResponse(content={"records": records, "count": len(records)})


@app.get("/metrics/summary")
def metrics_summary(
    tenant_id: str | None = None,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> dict[str, object]:
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_any_permission(identity, ["metrics:read_all", "metrics:read_tenant"])
    return audit_summary(tenant_id=_tenant_filter(identity, "metrics:read_all", tenant_id))


@app.get("/metrics/usage")
def usage_metrics(
    tenant_id: str | None = None,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> dict[str, object]:
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_any_permission(identity, ["metrics:read_all", "metrics:read_tenant"])
    return usage_summary(tenant_id=_tenant_filter(identity, "metrics:read_all", tenant_id))


@app.get("/approvals")
def approvals(
    status: ApprovalStatus | None = None,
    limit: int = 25,
    tenant_id: str | None = None,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> list[dict]:
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_any_permission(identity, ["approval:read_all", "approval:read_tenant"])
    return list_approval_tickets(
        status=status,
        limit=max(1, min(limit, 100)),
        tenant_id=_tenant_filter(identity, "approval:read_all", tenant_id),
    )


@app.patch("/approvals/{ticket_id}")
def decide_approval(
    ticket_id: str,
    decision: ApprovalDecisionRequest,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> dict:
    identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    require_permission(identity, "approval:decide")
    updated = update_approval_ticket(ticket_id, decision)
    if not updated:
        raise HTTPException(status_code=404, detail="Approval ticket not found")
    return updated


@app.get("/policies", response_model=list[PolicySummary])
def policies() -> list[PolicySummary]:
    return policy_summaries()


@app.get("/config/effective-policy")
def effective_policy() -> dict:
    return load_policy_config()


@app.post("/config/validate-policy")
def validate_policy(
    request: PolicyUpdateRequest,
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> dict[str, object]:
    if rbac_enforced() or auth_required():
        identity = resolve_identity(authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
        require_permission(identity, "policy:write")
    return {"valid": not validate_policy_config(request.policy), "errors": validate_policy_config(request.policy)}


@app.put("/config/effective-policy")
def update_policy(
    request: PolicyUpdateRequest,
    x_cfw_admin_token: str = Header(default=""),
    authorization: str | None = Header(default=None),
    x_cfw_tenant_id: str = Header(default="demo-tenant"),
    x_cfw_user_id: str = Header(default="anonymous"),
    x_cfw_user_role: str = Header(default="employee"),
) -> dict[str, object]:
    _require_policy_admin(x_cfw_admin_token, authorization, x_cfw_tenant_id, x_cfw_user_id, x_cfw_user_role)
    try:
        result = save_policy_config(request.policy, request.updated_by, request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"saved": True, **result}


@app.get("/config/auth")
def auth_config() -> dict[str, object]:
    return auth_config_summary()


def run_firewall_scan(request: ScanRequest) -> ScanResponse:
    findings = detect_findings(request.content)
    risk_score = calculate_risk_score(findings, request)
    policy_hits = evaluate_policies(findings, request, risk_score)
    decision = choose_decision(policy_hits, findings)
    sanitized = redact_content(request.content, findings)
    provider_route = choose_provider_route(decision, request)

    response = ScanResponse(
        audit_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        decision=decision,
        risk_score=risk_score,
        sanitized_content=sanitized,
        findings=findings,
        policy_hits=policy_hits,
        provider_route=provider_route,
        context_summary=summarize_context(findings, risk_score),
        policy_version=policy_version(),
    )
    if response.decision == Decision.review:
        ticket = create_approval_ticket(request, response, request.content)
        response.approval_ticket_id = ticket.ticket_id
    return response


async def _route_and_audit(
    request: GatewayRequest,
    scan_request: ScanRequest,
    firewall: ScanResponse,
) -> GatewayResponse:
    try:
        response = await route_gateway_request(request, firewall)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    save_audit_record(
        scan_request,
        firewall,
        scan_request.content,
        event_type="gateway_chat_completion",
        request_id=response.request_id,
    )
    return response


def _tenant_filter(identity, read_all_permission: str, requested_tenant_id: str | None) -> str | None:
    if not rbac_enforced():
        return requested_tenant_id
    if has_permission(identity.user_role, read_all_permission):
        return requested_tenant_id
    return identity.tenant_id


def _require_policy_admin(
    token: str,
    authorization: str | None,
    tenant_id: str,
    user_id: str,
    user_role: str,
) -> None:
    expected = os.getenv("CFW_ADMIN_TOKEN", "dev-admin-token")
    if token and token == expected:
        return
    if authorization or auth_required() or rbac_enforced():
        identity = resolve_identity(authorization, tenant_id, user_id, user_role)
        require_permission(identity, "policy:write")
        return
    raise HTTPException(status_code=403, detail="Invalid policy admin token")


handler = Mangum(app)
