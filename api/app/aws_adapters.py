import base64
from datetime import datetime, timezone
import json
import os
from typing import Any
from uuid import uuid4


try:
    import boto3
except Exception:  # pragma: no cover - optional dependency guard
    boto3 = None


def aws_enabled() -> bool:
    return os.getenv("CFW_AWS_ENABLED", "false").lower() == "true"


def strict_aws() -> bool:
    return os.getenv("CFW_AWS_STRICT", "false").lower() == "true"


def get_provider_secret(provider: str) -> str | None:
    provider_key = provider.upper().replace("-", "_")
    env_value = os.getenv(f"{provider_key}_API_KEY")
    if env_value:
        return env_value

    secret_id = os.getenv(f"CFW_{provider_key}_SECRET_ID")
    if not secret_id:
        return None
    secret = read_secret(secret_id)
    if not secret:
        return None
    try:
        parsed = json.loads(secret)
        return parsed.get("api_key") or parsed.get("OPENAI_API_KEY") or parsed.get("token")
    except json.JSONDecodeError:
        return secret


def read_secret(secret_id: str) -> str | None:
    if boto3 is None:
        return _aws_failure("boto3 is required for Secrets Manager")
    try:
        client = boto3.client("secretsmanager")
        response = client.get_secret_value(SecretId=secret_id)
        if "SecretString" in response:
            return response["SecretString"]
        return base64.b64decode(response["SecretBinary"]).decode("utf-8")
    except Exception as exc:  # pragma: no cover - requires AWS
        return _aws_failure(f"Secrets Manager read failed: {exc}")


def protect_text(text: str) -> str:
    kms_key_id = os.getenv("CFW_KMS_KEY_ID")
    if not kms_key_id:
        return text
    if boto3 is None:
        return _aws_failure("boto3 is required for KMS") or text
    try:
        client = boto3.client("kms")
        response = client.encrypt(KeyId=kms_key_id, Plaintext=text.encode("utf-8"))
        ciphertext = base64.b64encode(response["CiphertextBlob"]).decode("ascii")
        return f"kms:v1:{ciphertext}"
    except Exception as exc:  # pragma: no cover - requires AWS
        return _aws_failure(f"KMS encryption failed: {exc}") or text


def maybe_put_audit_record(record: dict[str, Any]) -> None:
    if os.getenv("CFW_AUDIT_BACKEND", "sqlite").lower() != "dynamodb":
        return
    table_name = os.getenv("AUDIT_TABLE_NAME")
    if not table_name:
        _aws_failure("AUDIT_TABLE_NAME is required for DynamoDB audit backend")
        return
    _put_item(table_name, record)


def maybe_put_approval_ticket(ticket: dict[str, Any]) -> None:
    if os.getenv("CFW_APPROVAL_BACKEND", "sqlite").lower() != "dynamodb":
        return
    table_name = os.getenv("APPROVAL_TABLE_NAME")
    if not table_name:
        _aws_failure("APPROVAL_TABLE_NAME is required for DynamoDB approval backend")
        return
    _put_item(table_name, ticket)


def maybe_put_audit_export(body: str, extension: str, content_type: str) -> dict[str, str] | None:
    if os.getenv("CFW_AUDIT_EXPORT_BACKEND", "download").lower() != "s3":
        return None
    bucket = os.getenv("AUDIT_EXPORT_BUCKET")
    if not bucket:
        _aws_failure("AUDIT_EXPORT_BUCKET is required for S3 audit export delivery")
        return None
    if boto3 is None:
        _aws_failure("boto3 is required for S3 audit export delivery")
        return None

    key = f"exports/{datetime.now(timezone.utc).strftime('%Y/%m/%d/%H%M%S')}-{uuid4()}.{extension}"
    put_args: dict[str, Any] = {
        "Bucket": bucket,
        "Key": key,
        "Body": body.encode("utf-8"),
        "ContentType": content_type,
    }
    kms_key_id = os.getenv("CFW_KMS_KEY_ID")
    if kms_key_id:
        put_args["ServerSideEncryption"] = "aws:kms"
        put_args["SSEKMSKeyId"] = kms_key_id
    try:
        boto3.client("s3").put_object(**put_args)
        return {"bucket": bucket, "key": key}
    except Exception as exc:  # pragma: no cover - requires AWS
        _aws_failure(f"S3 audit export delivery failed: {exc}")
        return None


def _put_item(table_name: str, item: dict[str, Any]) -> None:
    if boto3 is None:
        _aws_failure("boto3 is required for DynamoDB")
        return
    try:
        table = boto3.resource("dynamodb").Table(table_name)
        table.put_item(Item=_stringify_values(item))
    except Exception as exc:  # pragma: no cover - requires AWS
        _aws_failure(f"DynamoDB put_item failed: {exc}")


def _stringify_values(item: dict[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {}
    for key, value in item.items():
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            normalized[key] = value
        else:
            normalized[key] = str(value)
    return normalized


def _aws_failure(message: str) -> None | str:
    if strict_aws():
        raise RuntimeError(message)
    return None
