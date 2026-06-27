from collections import Counter
from typing import Any

from .models import Decision, Destination, Finding, FindingType, PolicyHit, ProviderRoute, ScanRequest
from .policy_config import (
    approved_providers_for,
    is_provider_approved,
    load_policy_config,
    policy_summaries,
    role_limit_for,
)


SEVERITY_WEIGHT = {
    "low": 8,
    "medium": 18,
    "high": 30,
    "critical": 45,
}

DECISION_PRECEDENCE = {
    Decision.allow: 0,
    Decision.redact: 1,
    Decision.review: 2,
    Decision.block: 3,
}


def calculate_risk_score(findings: list[Finding], request: ScanRequest) -> int:
    if not findings:
        return 0

    score = 0
    for finding in findings:
        score += int(SEVERITY_WEIGHT[finding.severity] * finding.confidence)

    type_counts = Counter(finding.type for finding in findings)
    score += min(type_counts[FindingType.secret] * 10, 25)
    score += min(type_counts[FindingType.regulated] * 12, 30)
    score += min(type_counts[FindingType.prompt_injection] * 8, 20)

    if request.destination == Destination.external_llm:
        score += 12
    if request.strict_mode:
        score += 8

    return min(score, 100)


def evaluate_policies(findings: list[Finding], request: ScanRequest, risk_score: int) -> list[PolicyHit]:
    config = load_policy_config()
    hits: list[PolicyHit] = []

    for rule in config.get("rules", []):
        if rule.get("system_rule") == "provider_allowlist":
            if not is_provider_approved(request.destination, request.model_provider):
                providers = ", ".join(approved_providers_for(request.destination)) or "none"
                hits.append(
                    PolicyHit(
                        id=rule["id"],
                        name=rule["name"],
                        severity=rule["severity"],
                        action=Decision(rule["action"]),
                        reason=f"Provider '{request.model_provider}' is not approved for {request.destination.value}. Approved providers: {providers}.",
                    )
                )
            continue

        match = rule.get("match", {})
        if _rule_matches(match, findings, request, risk_score):
            hits.append(
                PolicyHit(
                    id=rule["id"],
                    name=rule["name"],
                    severity=rule["severity"],
                    action=Decision(rule["action"]),
                    reason=_rule_reason(rule, findings, request, risk_score),
                )
            )

    role_hit = _role_limit_hit(request, risk_score)
    if role_hit:
        hits.append(role_hit)

    return _dedupe_policy_hits(hits)


def choose_decision(policy_hits: list[PolicyHit], findings: list[Finding]) -> Decision:
    if policy_hits:
        return max((hit.action for hit in policy_hits), key=lambda action: DECISION_PRECEDENCE[action])
    if findings:
        return Decision.redact
    return Decision.allow


def choose_provider_route(decision: Decision, request: ScanRequest) -> ProviderRoute:
    if decision == Decision.block:
        return ProviderRoute(route="blocked", provider="none", reason="Policy engine blocked outbound context.")
    if decision == Decision.review:
        return ProviderRoute(
            route="human_review",
            provider=request.model_provider,
            reason="Context requires approval before model routing.",
        )
    if decision == Decision.redact and request.destination == Destination.external_llm:
        return ProviderRoute(
            route="approved_external_provider",
            provider=request.model_provider,
            reason="Only sanitized context may be sent to the selected provider.",
        )
    if request.destination == Destination.internal_llm:
        return ProviderRoute(route="internal_model", provider=request.model_provider, reason="Internal destination selected.")
    return ProviderRoute(
        route="approved_external_provider",
        provider=request.model_provider,
        reason="No blocking policy was triggered.",
    )


def summarize_context(findings: list[Finding], risk_score: int) -> str:
    if not findings:
        return "No sensitive entities detected. Context can be routed under the default policy."

    counts = Counter(finding.type.value for finding in findings)
    parts = [f"{count} {kind.replace('_', ' ')}" for kind, count in sorted(counts.items())]
    return f"Detected {', '.join(parts)}. Aggregate risk score: {risk_score}/100."


def _rule_matches(match: dict[str, Any], findings: list[Finding], request: ScanRequest, risk_score: int) -> bool:
    if not match:
        return False

    destinations = match.get("destinations")
    if destinations and request.destination.value not in destinations:
        return False

    providers = match.get("providers")
    if providers and request.model_provider.lower() not in [str(provider).lower() for provider in providers]:
        return False

    roles = match.get("roles")
    if roles and request.user_role not in roles:
        return False

    not_roles = match.get("not_roles")
    if not_roles and request.user_role in not_roles:
        return False

    min_risk = match.get("min_risk")
    if min_risk is not None and risk_score < int(min_risk):
        return False

    types = {FindingType(kind) for kind in match.get("types", [])}
    labels = set(match.get("labels", []))
    severities = set(match.get("severities", []))

    if types and not any(finding.type in types for finding in findings):
        return False
    if labels and not any(finding.label in labels for finding in findings):
        return False
    if severities and not any(finding.severity in severities for finding in findings):
        return False

    return bool(types or labels or severities or min_risk is not None)


def _rule_reason(rule: dict[str, Any], findings: list[Finding], request: ScanRequest, risk_score: int) -> str:
    match = rule.get("match", {})
    matched = _matched_findings(match, findings)
    if matched:
        labels = ", ".join(sorted({finding.label for finding in matched}))
        return f"{rule.get('description', rule['name'])} Matched: {labels}."
    if match.get("min_risk") is not None:
        return f"{rule.get('description', rule['name'])} Current risk score is {risk_score}."
    return rule.get("description", rule["name"])


def _matched_findings(match: dict[str, Any], findings: list[Finding]) -> list[Finding]:
    types = {FindingType(kind) for kind in match.get("types", [])}
    labels = set(match.get("labels", []))
    severities = set(match.get("severities", []))

    matched = []
    for finding in findings:
        if types and finding.type in types:
            matched.append(finding)
        elif labels and finding.label in labels:
            matched.append(finding)
        elif severities and finding.severity in severities:
            matched.append(finding)
    return matched


def _role_limit_hit(request: ScanRequest, risk_score: int) -> PolicyHit | None:
    if request.destination != Destination.external_llm:
        return None
    limit = role_limit_for(request.user_role)
    if not limit:
        return None
    max_risk = int(limit.get("max_external_risk", 100))
    if risk_score <= max_risk:
        return None

    action = Decision(limit.get("on_exceed", "review"))
    return PolicyHit(
        id="ROLE-002",
        name="Role-based external routing threshold exceeded",
        severity="high",
        action=action,
        reason=f"Role '{request.user_role}' may only route external context up to risk {max_risk}; current risk is {risk_score}.",
    )


def _dedupe_policy_hits(hits: list[PolicyHit]) -> list[PolicyHit]:
    deduped: dict[str, PolicyHit] = {}
    for hit in hits:
        existing = deduped.get(hit.id)
        if not existing or DECISION_PRECEDENCE[hit.action] > DECISION_PRECEDENCE[existing.action]:
            deduped[hit.id] = hit
    return list(deduped.values())


POLICY_CATALOG = policy_summaries()

