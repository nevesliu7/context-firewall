import os

from fastapi import HTTPException

from .auth import AuthIdentity, auth_required


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "security_admin": {
        "audit:read_all",
        "audit:export",
        "approval:read_all",
        "approval:decide",
        "metrics:read_all",
        "policy:write",
    },
    "developer": {
        "audit:read_tenant",
        "approval:read_tenant",
        "metrics:read_tenant",
    },
    "support_agent": {
        "audit:read_tenant",
        "approval:read_tenant",
        "metrics:read_tenant",
    },
    "contractor": {
        "metrics:read_tenant",
    },
}


def rbac_enforced() -> bool:
    configured = os.getenv("CFW_RBAC_ENFORCED")
    if configured is not None:
        return configured.lower() == "true"
    return auth_required()


def has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


def require_permission(identity: AuthIdentity, permission: str) -> None:
    if not rbac_enforced():
        return
    if not has_permission(identity.user_role, permission):
        raise HTTPException(
            status_code=403,
            detail=f"Role '{identity.user_role}' is not allowed to perform '{permission}'",
        )


def require_any_permission(identity: AuthIdentity, permissions: list[str]) -> None:
    if not rbac_enforced():
        return
    if not any(has_permission(identity.user_role, permission) for permission in permissions):
        allowed = ", ".join(permissions)
        raise HTTPException(status_code=403, detail=f"Role '{identity.user_role}' needs one of: {allowed}")


def tenant_scope(identity: AuthIdentity, read_all_permission: str) -> str | None:
    if not rbac_enforced():
        return None
    if has_permission(identity.user_role, read_all_permission):
        return None
    return identity.tenant_id
