import json
import os
import time
from uuid import uuid4

import httpx

from .aws_adapters import get_provider_secret
from .detectors import detect_findings
from .models import (
    ChatMessage,
    Decision,
    Destination,
    GatewayRequest,
    GatewayResponse,
    ScanRequest,
    ScanResponse,
)
from .redaction import redact_content


def gateway_to_scan_request(request: GatewayRequest) -> ScanRequest:
    return ScanRequest(
        content=messages_to_text(request.messages),
        destination=request.destination,
        model_provider=request.model_provider,
        user_role=request.user_role,
        user_id=request.user_id,
        purpose=request.purpose,
        app_name=request.app_name,
        tenant_id=request.tenant_id,
        source="gateway_chat_completion",
        strict_mode=True,
        metadata=request.metadata,
    )


def messages_to_text(messages: list[ChatMessage]) -> str:
    parts: list[str] = []
    for index, message in enumerate(messages):
        parts.append(f"[{index}:{message.role}]")
        parts.append(_content_to_text(message.content))
    return "\n".join(parts)


def sanitize_messages(messages: list[ChatMessage]) -> list[ChatMessage]:
    sanitized: list[ChatMessage] = []
    for message in messages:
        content = _content_to_text(message.content)
        findings = detect_findings(content)
        sanitized.append(
            ChatMessage(
                role=message.role,
                content=redact_content(content, findings),
                name=message.name,
                tool_call_id=message.tool_call_id,
            )
        )
    return sanitized


def build_provider_payload(request: GatewayRequest, sanitized_messages: list[ChatMessage]) -> dict:
    return {
        "model": request.model,
        "messages": [message.model_dump(exclude_none=True) for message in sanitized_messages],
        "stream": request.stream,
        "metadata": {
            **request.metadata,
            "context_firewall": "enforced",
            "tenant_id": request.tenant_id,
            "user_id": request.user_id,
        },
    }


async def route_gateway_request(request: GatewayRequest, firewall: ScanResponse) -> GatewayResponse:
    request_id = str(uuid4())
    sanitized_messages = sanitize_messages(request.messages)
    provider_payload = build_provider_payload(request, sanitized_messages)

    if firewall.decision == Decision.block:
        return GatewayResponse(
            request_id=request_id,
            forwarded=False,
            status="blocked",
            firewall=firewall,
            sanitized_messages=sanitized_messages,
            provider_payload=provider_payload,
            provider_response=None,
        )

    if firewall.decision == Decision.review:
        return GatewayResponse(
            request_id=request_id,
            forwarded=False,
            status="review_required",
            firewall=firewall,
            sanitized_messages=sanitized_messages,
            provider_payload=provider_payload,
            provider_response=None,
        )

    if request.dry_run or os.getenv("CFW_FORWARD_MODE", "dry_run") != "live":
        return GatewayResponse(
            request_id=request_id,
            forwarded=False,
            status="dry_run" if firewall.decision == Decision.allow else "redacted",
            firewall=firewall,
            sanitized_messages=sanitized_messages,
            provider_payload=provider_payload,
            provider_response=_dry_run_response(request, firewall),
        )

    provider_response = await _forward_live(request, provider_payload)
    return GatewayResponse(
        request_id=request_id,
        forwarded=True,
        status="allowed" if firewall.decision == Decision.allow else "redacted",
        firewall=firewall,
        sanitized_messages=sanitized_messages,
        provider_payload=provider_payload,
        provider_response=provider_response,
    )


def openai_compatible_success(response: GatewayResponse) -> dict:
    status_text = "would forward" if not response.forwarded else "forwarded"
    if response.provider_response and response.forwarded:
        return response.provider_response
    return {
        "id": f"chatcmpl-{response.request_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": response.provider_payload.get("model", "unknown"),
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": f"Context Firewall {status_text} this request in {response.status} mode. No upstream model was called.",
                },
            }
        ],
        "firewall": response.firewall.model_dump(mode="json"),
    }


def openai_compatible_error(response: GatewayResponse) -> dict:
    return {
        "error": {
            "message": response.firewall.context_summary,
            "type": "context_firewall_policy_violation",
            "code": response.status,
        },
        "firewall": response.firewall.model_dump(mode="json"),
    }


def _content_to_text(content: str | list[dict] | dict) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, sort_keys=True)


def _dry_run_response(request: GatewayRequest, firewall: ScanResponse) -> dict:
    return {
        "mode": "dry_run",
        "provider": request.model_provider,
        "model": request.model,
        "decision": firewall.decision.value,
        "risk_score": firewall.risk_score,
        "message_count": len(request.messages),
    }


async def _forward_live(request: GatewayRequest, provider_payload: dict) -> dict:
    if request.destination != Destination.external_llm or request.model_provider.lower() != "openai":
        raise RuntimeError("Live forwarding currently supports only OpenAI-compatible external_llm requests.")
    api_key = get_provider_secret("openai")
    if not api_key:
        raise RuntimeError("OpenAI API key or CFW_OPENAI_SECRET_ID is required when CFW_FORWARD_MODE=live.")

    base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=provider_payload,
        )
        response.raise_for_status()
        return response.json()
