import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from .models import Decision, Destination, PolicySummary


DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policies" / "default.json"


@lru_cache(maxsize=8)
def load_policy_config(policy_path: str | None = None) -> dict[str, Any]:
    path = Path(policy_path or os.getenv("CFW_POLICY_PATH") or DEFAULT_POLICY_PATH)
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def policy_version() -> str:
    return str(load_policy_config().get("version", "unknown"))


def approved_providers_for(destination: Destination) -> list[str]:
    approved = load_policy_config().get("approved_providers", {})
    return [str(provider).lower() for provider in approved.get(destination.value, [])]


def is_provider_approved(destination: Destination, provider: str) -> bool:
    providers = approved_providers_for(destination)
    return provider.lower() in providers


def role_limit_for(role: str) -> dict[str, Any] | None:
    limits = load_policy_config().get("role_limits", {})
    return limits.get(role)


def policy_summaries() -> list[PolicySummary]:
    summaries: list[PolicySummary] = []
    for rule in load_policy_config().get("rules", []):
        summaries.append(
            PolicySummary(
                id=rule["id"],
                name=rule["name"],
                action=Decision(rule["action"]),
                description=rule.get("description", ""),
            )
        )
    return summaries


def validate_policy_config(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy.get("version"), str) or not policy.get("version"):
        errors.append("version is required")
    if not isinstance(policy.get("approved_providers"), dict):
        errors.append("approved_providers must be an object")
    if not isinstance(policy.get("rules"), list) or not policy.get("rules"):
        errors.append("rules must be a non-empty list")
    usage_limits = policy.get("usage_limits", {})
    if usage_limits and not isinstance(usage_limits, dict):
        errors.append("usage_limits must be an object")
    if isinstance(usage_limits, dict):
        for key in ["requests_per_minute_per_tenant", "daily_estimated_tokens_per_tenant"]:
            if key in usage_limits:
                try:
                    if int(usage_limits[key]) <= 0:
                        errors.append(f"usage_limits.{key} must be positive")
                except (TypeError, ValueError):
                    errors.append(f"usage_limits.{key} must be an integer")
        role_usage_limits = usage_limits.get("daily_estimated_tokens_by_role", {})
        if role_usage_limits and not isinstance(role_usage_limits, dict):
            errors.append("usage_limits.daily_estimated_tokens_by_role must be an object")
        if isinstance(role_usage_limits, dict):
            for role, limit in role_usage_limits.items():
                try:
                    if int(limit) <= 0:
                        errors.append(f"usage_limits.daily_estimated_tokens_by_role.{role} must be positive")
                except (TypeError, ValueError):
                    errors.append(f"usage_limits.daily_estimated_tokens_by_role.{role} must be an integer")

    seen_ids: set[str] = set()
    for index, rule in enumerate(policy.get("rules", [])):
        prefix = f"rules[{index}]"
        rule_id = rule.get("id")
        if not rule_id:
            errors.append(f"{prefix}.id is required")
        elif rule_id in seen_ids:
            errors.append(f"{prefix}.id duplicates {rule_id}")
        seen_ids.add(rule_id)
        if rule.get("action") not in {"allow", "redact", "review", "block"}:
            errors.append(f"{prefix}.action must be allow, redact, review, or block")
        if rule.get("severity") not in {"low", "medium", "high", "critical"}:
            errors.append(f"{prefix}.severity must be low, medium, high, or critical")
        if "match" not in rule and "system_rule" not in rule:
            errors.append(f"{prefix} must define match or system_rule")
    return errors


def save_policy_config(policy: dict[str, Any], updated_by: str, reason: str) -> dict[str, str]:
    errors = validate_policy_config(policy)
    if errors:
        raise ValueError("; ".join(errors))

    path = Path(os.getenv("CFW_POLICY_PATH") or DEFAULT_POLICY_PATH)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = path.with_suffix(f".{timestamp}.bak.json")
    backup_path.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    policy["_metadata"] = {
        "updated_by": updated_by,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }
    path.write_text(json.dumps(policy, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    load_policy_config.cache_clear()
    return {"path": str(path), "backup_path": str(backup_path), "version": str(policy["version"])}
