# Security Review Checklist

Use this checklist before moving Context Firewall from prototype to production.

## Identity

- Replace demo headers with verified Cognito, Okta, or enterprise IdP JWT claims.
- Set `CFW_AUTH_REQUIRED=true`.
- Set `CFW_RBAC_ENFORCED=true`.
- Configure `CFW_JWT_ISSUER`, `CFW_JWT_AUDIENCE`, and `CFW_JWKS_URL`.
- Confirm tenant, user, and role cannot be spoofed from client-controlled headers.
- Confirm `SecurityAdmins`, `Developers`, `Support`, and `Contractors` map correctly from Cognito/Okta groups.

## Policy

- Store policy packs in AWS AppConfig, S3 with object locking, or an internal signed registry.
- Require code review or security approval for policy changes.
- Keep policy backup and change reason.
- Test deny, redact, review, and allow paths for each role and provider.

## Data Handling

- Confirm raw prompts are not written to logs, audit records, traces, or approval tickets.
- Enable KMS encryption for approval artifacts with `CFW_KMS_KEY_ID`.
- Use per-tenant keys for high-isolation environments.
- Review CloudWatch log sampling and structured logging before production.

## Provider Routing

- Keep `CFW_FORWARD_MODE=dry_run` during rollout.
- Store provider keys in Secrets Manager using `CFW_OPENAI_SECRET_ID` or provider-specific secret IDs.
- Verify provider allowlists and model allowlists.
- Verify per-tenant request limits and daily token budgets before live rollout.

## Detection Quality

- Run false-positive tests against realistic internal documents and logs.
- Add allowlist exceptions for known test credentials.
- Track policy hit rate and manual review outcomes.
- Add regression tests for every detector change.
- Review the extended detector regression suite before changing regexes.

## AWS

- Use DynamoDB for audit and approval stores.
- Enable KMS encryption on DynamoDB tables.
- Send immutable audit exports to S3 or Security Lake.
- Verify `/audit/export` output contains metadata only, never raw prompts.
- Limit Lambda IAM permissions to specific tables, secrets, keys, and models.
- Add CloudWatch alarms for spikes in `block`, `review`, and provider errors.

## CI/CD

- Require backend tests and frontend build before merge.
- Add dependency scanning.
- Add secret scanning.
- Add infrastructure template linting before deploy.
- Build Docker images in CI.
- Deploy first to a dry-run staging environment.
