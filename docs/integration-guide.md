# Integration Guide

## Drop-In OpenAI-Compatible Gateway

Point an OpenAI-compatible client at Context Firewall instead of the provider:

```text
base_url = http://localhost:8000/v1
endpoint = /chat/completions
```

Add enterprise context through headers:

```text
X-CFW-Tenant-Id: demo-tenant
X-CFW-User-Id: dev-1024
X-CFW-User-Role: developer
X-CFW-Provider: openai
X-CFW-Destination: external_llm
```

## Decision Behavior

- `allow`: payload can be routed as-is.
- `redact`: sanitized payload can be routed.
- `review`: request is not forwarded; sanitized ticket is created.
- `block`: request is not forwarded; policy error is returned.

## HTTP Behavior

- `200`: allowed, redacted, or dry-run request.
- `403`: blocked policy violation.
- `409`: review required.

## Safe Rollout Plan

1. Start with `dry_run: true` in payloads.
2. Compare current provider payloads with sanitized provider payloads.
3. Tune policy pack thresholds and false positives.
4. Turn on audit delivery and dashboards.
5. Enable live forwarding for one internal app.
6. Expand by tenant, role, and provider.

## Minimal Client Change

Before:

```python
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
```

After:

```python
client = OpenAI(
    api_key="unused-in-dry-run",
    base_url="http://localhost:8000/v1",
    default_headers={
        "X-CFW-Tenant-Id": "demo-tenant",
        "X-CFW-User-Id": "dev-1024",
        "X-CFW-User-Role": "developer",
        "X-CFW-Provider": "openai",
        "X-CFW-Destination": "external_llm",
    },
)
```

