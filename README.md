# Context Firewall

Context Firewall is an enforcement gateway for outbound LLM context. It sits between an application and a model provider, scans the request, applies tenant policy, redacts or blocks unsafe context, creates an audit record, and routes only policy-compliant payloads.

This is built as a gateway, not a chatbot.

## Why ChatGPT Alone Cannot Do This

ChatGPT can answer questions about safe handling, but it cannot enforce company policy across apps. A deployable firewall needs to know who sent the request, which provider is targeted, what tenant policy applies, whether approval is required, and whether the payload was actually forwarded.

## What Is Implemented

- OpenAI-compatible endpoint: `POST /v1/chat/completions`
- Native gateway endpoint: `POST /gateway/chat`
- Cognito/Okta-style Bearer JWT identity parsing with optional issuer/audience/JWKS verification
- Config-driven policy pack: `api/policies/default.json`
- PII, regulated identifier, secret, source-code-secret, confidential-context, and prompt-injection detectors
- Extended token detectors for GitHub, Google, Stripe, high-entropy secrets, internal IPs, and token fields
- Luhn validation for credit-card-like matches to reduce false positives
- Stable redaction tokens for sanitized provider payloads
- Provider allowlist enforcement by destination
- Role-based external routing thresholds
- Human-review ticket creation for review decisions
- Audit records with hashes and metadata only; raw sensitive content is not stored in audit
- Dry-run provider routing by default
- Optional live OpenAI-compatible forwarding through environment variables
- Optional Secrets Manager provider key lookup
- Optional KMS protection for approval artifacts
- Optional DynamoDB dual-write adapter for audit and approval records
- Policy admin API and UI with validation and backup creation
- React operations console for gateway payloads, findings, policy hits, audit, metrics, and pending approvals
- AWS deployment skeleton for API Gateway, Lambda, DynamoDB, CloudWatch, and Bedrock-facing routing
- GitHub Actions CI template and Dependabot configuration

## Run Locally

Backend:

```bash
cd api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd web
npm install
npm run dev
```

Open `http://localhost:5173`.

## Gateway Example

The OpenAI-compatible endpoint accepts normal chat-completions payloads plus company context in headers:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-CFW-Tenant-Id: demo-tenant" \
  -H "X-CFW-User-Id: dev-1024" \
  -H "X-CFW-User-Role: developer" \
  -H "X-CFW-Provider: openai" \
  -H "X-CFW-Destination: external_llm" \
  -d '{
    "model": "gpt-4.1-mini",
    "dry_run": true,
    "messages": [
      {"role": "user", "content": "Debug AWS key <redacted-demo-access-key>"}
    ]
  }'
```

Secrets return `403` with a policy violation. PII returns `200` in dry-run mode with sanitized provider payloads. Prompt injection returns `409` and creates a review ticket.

## Live Forwarding

The gateway is dry-run by default. To forward compliant requests to an OpenAI-compatible provider:

```bash
export CFW_FORWARD_MODE=live
export OPENAI_API_KEY=...
export OPENAI_BASE_URL=https://api.openai.com/v1
```

Only sanitized payloads are forwarded. Blocked and review-required requests are never forwarded.

Provider credentials can also come from Secrets Manager:

```bash
export CFW_AWS_ENABLED=true
export CFW_OPENAI_SECRET_ID=prod/context-firewall/openai
```

## Identity

Local mode accepts demo headers. Production should require verified JWTs:

```bash
export CFW_AUTH_REQUIRED=true
export CFW_JWT_ISSUER=https://your-domain.okta.com/oauth2/default
export CFW_JWT_AUDIENCE=api://context-firewall
export CFW_JWKS_URL=https://your-domain.okta.com/oauth2/default/v1/keys
```

Cognito works the same way with the user-pool issuer and JWKS URL.

## Policy Pack

`api/policies/default.json` controls:

- approved providers by destination
- role risk thresholds
- rule matches by finding type, label, severity, destination, provider, role, or minimum risk
- action precedence: `allow < redact < review < block`

Example rule:

```json
{
  "id": "SEC-001",
  "name": "Secrets cannot leave the tenant boundary",
  "severity": "critical",
  "action": "block",
  "match": {
    "types": ["secret"],
    "destinations": ["external_llm", "agent_tool", "browser_extension"]
  }
}
```

## API Surface

- `POST /v1/chat/completions`: OpenAI-compatible protected gateway
- `POST /gateway/chat`: native gateway response with firewall metadata
- `POST /scan`: direct scan for tools and diagnostics
- `GET /audit`: audit metadata
- `GET /approvals`: pending or historical review tickets
- `PATCH /approvals/{ticket_id}`: approve or reject a ticket
- `GET /metrics/summary`: decision and route counts
- `GET /config/effective-policy`: loaded policy pack
- `PUT /config/effective-policy`: validate, backup, and save a policy pack
- `GET /config/auth`: active auth configuration summary
- `GET /policies`: concise policy catalog

## Verification

```bash
cd api && .venv/bin/pytest -q
cd web && npm run build
```

The CI workflow template is included at `docs/ci/github-actions-ci.yml`. Move it to `.github/workflows/ci.yml` after authenticating GitHub with `workflow` scope.

Current test coverage validates:

- secret blocking
- provider allowlist blocking
- PII redaction
- Luhn-based credit-card filtering
- provider token and high-entropy secret detection
- JWT claim identity override
- policy validation
- OpenAI-compatible gateway enforcement
- dry-run non-forwarding
- review ticket creation
