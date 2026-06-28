import os
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException


try:
    import jwt
    from jwt import PyJWKClient
except Exception:  # pragma: no cover - optional dependency guard
    jwt = None
    PyJWKClient = None


@dataclass(frozen=True)
class AuthIdentity:
    tenant_id: str
    user_id: str
    user_role: str
    auth_source: str
    claims: dict[str, Any]


def resolve_identity(
    authorization: str | None,
    fallback_tenant_id: str,
    fallback_user_id: str,
    fallback_user_role: str,
) -> AuthIdentity:
    if not authorization:
        if _auth_required():
            raise HTTPException(status_code=401, detail="Authorization header is required")
        return AuthIdentity(
            tenant_id=fallback_tenant_id,
            user_id=fallback_user_id,
            user_role=fallback_user_role,
            auth_source="demo_headers",
            claims={},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Authorization must be a Bearer token")

    claims = _decode_jwt(token)
    return AuthIdentity(
        tenant_id=_first_claim(claims, ["custom:tenant_id", "tenant_id", "org_id", "organization"], fallback_tenant_id),
        user_id=_first_claim(claims, ["sub", "email", "preferred_username", "username"], fallback_user_id),
        user_role=_role_from_claims(claims, fallback_user_role),
        auth_source="jwt",
        claims=claims,
    )


def auth_config_summary() -> dict[str, object]:
    return {
        "auth_required": auth_required(),
        "issuer": os.getenv("CFW_JWT_ISSUER", ""),
        "audience_configured": bool(os.getenv("CFW_JWT_AUDIENCE")),
        "jwks_url_configured": bool(_jwks_url()),
        "mode": "verified_jwt" if _jwks_url() and os.getenv("CFW_JWT_AUDIENCE") else "demo_or_unverified_jwt",
    }


def _decode_jwt(token: str) -> dict[str, Any]:
    if jwt is None:
        if auth_required():
            raise HTTPException(status_code=500, detail="PyJWT is required when auth is enforced")
        return _unsafe_decode_payload(token)

    issuer = os.getenv("CFW_JWT_ISSUER")
    audience = os.getenv("CFW_JWT_AUDIENCE")
    jwks_url = _jwks_url()

    if issuer and audience and jwks_url:
        signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(token)  # type: ignore[union-attr]
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512"],
            audience=audience,
            issuer=issuer,
        )

    if auth_required():
        raise HTTPException(status_code=500, detail="CFW_JWT_ISSUER, CFW_JWT_AUDIENCE, and JWKS URL are required")

    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False, "verify_iss": False})


def _unsafe_decode_payload(token: str) -> dict[str, Any]:
    import base64
    import json

    try:
        payload = token.split(".")[1]
        padded = payload + "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("utf-8")))
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid JWT payload") from exc


def _role_from_claims(claims: dict[str, Any], fallback: str) -> str:
    direct = _first_claim(claims, ["custom:role", "role", "user_role"], "")
    if direct:
        return direct
    groups = claims.get("cognito:groups") or claims.get("groups") or claims.get("roles") or []
    if isinstance(groups, str):
        groups = [groups]
    if "security-admin" in groups or "SecurityAdmins" in groups:
        return "security_admin"
    if "developer" in groups or "Developers" in groups:
        return "developer"
    if "support" in groups or "Support" in groups:
        return "support_agent"
    if "contractor" in groups or "Contractors" in groups:
        return "contractor"
    return fallback


def _first_claim(claims: dict[str, Any], keys: list[str], fallback: str) -> str:
    for key in keys:
        value = claims.get(key)
        if isinstance(value, str) and value:
            return value
    return fallback


def _jwks_url() -> str | None:
    explicit = os.getenv("CFW_JWKS_URL")
    if explicit:
        return explicit
    issuer = os.getenv("CFW_JWT_ISSUER", "").rstrip("/")
    if issuer:
        return f"{issuer}/.well-known/jwks.json"
    return None


def auth_required() -> bool:
    return os.getenv("CFW_AUTH_REQUIRED", "false").lower() == "true"


def _auth_required() -> bool:
    return auth_required()
