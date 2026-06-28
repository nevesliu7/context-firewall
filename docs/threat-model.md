# Threat Model

## Protected Assets

- API keys, cloud credentials, tokens, private keys.
- PII and regulated identifiers.
- Confidential business plans, employee information, contracts, and internal-only material.
- Hidden system prompts and internal agent instructions.
- Tool outputs from internal systems.

## Threats

- Accidental copy/paste of secrets into external LLMs.
- Prompt injection in documents, web pages, tickets, or code comments.
- Employees sending private data to unapproved providers.
- Agents forwarding tool output without context minimization.
- Lack of auditability when model usage causes a data incident.
- Shadow AI clients bypassing approved provider and tenant policy.
- Review workflows storing raw sensitive context during escalation.
- One tenant reading another tenant's audit, approval, or usage metadata.
- Runaway usage causing unexpected model-provider cost.

## Controls

- Regex and structural detectors for high-confidence sensitive values.
- Policy engine with explainable actions.
- Redaction before external provider routing.
- Blocking for secrets and regulated identifiers.
- Audit records with hashes instead of raw sensitive content.
- Optional human review path for ambiguous high-risk content.
- OpenAI-compatible gateway endpoint so clients can be redirected through enforcement.
- Provider allowlists and role-based external routing thresholds.
- RBAC for audit, approval, metrics, policy admin, and audit export endpoints.
- Per-tenant request rate limits and daily estimated-token budgets.
- Audit export endpoint that emits metadata-only JSON or NDJSON.
- Approval tickets that store sanitized context only.

## Non-Goals

- It does not guarantee perfect DLP coverage.
- It does not replace legal, compliance, or security review.
- It does not store raw prompts for later replay.
- It does not provision real users or federate Okta tenants automatically; Terraform creates the Cognito pool and groups, and external IdP wiring remains an operator step.
