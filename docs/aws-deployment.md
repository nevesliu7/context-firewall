# AWS Deployment Notes

The local app uses SQLite so it can run without cloud credentials. Production should use managed AWS services and identity-bound enforcement.

## Suggested Services

- **API Gateway**: private or public gateway surface for `/v1/chat/completions`.
- **Lambda or ECS Fargate**: run the FastAPI enforcement service.
- **Cognito or enterprise IdP**: derive tenant, user, role, and group claims.
- **DynamoDB Audit Table**: append-only metadata records.
- **DynamoDB Approval Table**: sanitized review tickets.
- **KMS**: table encryption and tenant-specific artifact protection.
- **CloudWatch**: metrics by decision, policy id, provider, tenant, and route.
- **Secrets Manager**: provider API keys for live forwarding.
- **S3 Audit Export Bucket**: immutable NDJSON/JSON audit exports.
- **SQS + Step Functions**: review workflow for `review` decisions.
- **Bedrock**: internal model route after policy allows or redacts context.
- **AWS AppConfig or S3**: signed policy pack distribution.

## Deployment Steps

Terraform deployment:

1. Run `./scripts/package-lambda.sh` from the repository root.
2. Run `terraform init` in `infra/terraform`.
3. Run `terraform apply -var lambda_package_path=../../build/context-firewall-lambda.zip`.
4. Use the Terraform output `api_endpoint` for smoke tests.

The Terraform stack creates API Gateway, Lambda, Cognito, DynamoDB, KMS, Secrets Manager, S3 audit export storage, and CloudWatch alarms.

SAM deployment:

1. Package the API with dependencies.
2. Deploy `infra/aws/serverless-template.yaml`.

Production rollout:

1. Replace demo headers with JWT/Cognito claims.
2. Store policy packs in AppConfig or S3 and load them at cold start.
3. Keep `CFW_FORWARD_MODE=dry_run` until security reviews detector and policy behavior.
4. Enable `CFW_FORWARD_MODE=live` only after provider allowlists and audit delivery are verified.

## Environment Variables

- `CFW_POLICY_PATH`: optional local policy JSON path.
- `CFW_FORWARD_MODE`: `dry_run` or `live`.
- `OPENAI_API_KEY`: local fallback for live OpenAI-compatible forwarding.
- `CFW_OPENAI_SECRET_ID`: Secrets Manager secret id for provider credentials.
- `OPENAI_BASE_URL`: optional OpenAI-compatible base URL.
- `AUDIT_TABLE_NAME`: DynamoDB table name in AWS.
- `APPROVAL_TABLE_NAME`: DynamoDB approval table name in AWS.
- `CFW_AUDIT_BACKEND`: set to `dynamodb` for DynamoDB audit writes.
- `CFW_AUDIT_EXPORT_BACKEND`: set to `s3` to deliver `/audit/export?delivery=s3` exports to S3.
- `AUDIT_EXPORT_BUCKET`: S3 bucket for metadata-only audit exports.
- `CFW_APPROVAL_BACKEND`: set to `dynamodb` for DynamoDB approval writes.
- `CFW_KMS_KEY_ID`: optional KMS key id for approval artifact protection.
- `CFW_AUTH_REQUIRED`: require a verified Bearer JWT when true.
- `CFW_RBAC_ENFORCED`: enforce role permissions for audit, approval, metrics, and policy endpoints.
- `CFW_JWT_ISSUER`, `CFW_JWT_AUDIENCE`, `CFW_JWKS_URL`: Cognito/Okta JWT verification settings.
- `CFW_ADMIN_TOKEN`: token required for policy admin updates in local mode.
- `CFW_USAGE_LIMITS_ENABLED`: enable per-tenant request and token budget checks.
- `CFW_RATE_LIMIT_PER_MINUTE`: per-tenant request cap for each minute.
- `CFW_DAILY_TOKEN_BUDGET_PER_TENANT`: per-tenant daily estimated-token cap.

## IAM Notes

The enforcement function should have least-privilege access to:

- write audit records
- write and update approval tickets
- read policy packs
- emit metrics
- invoke only approved Bedrock models
- read provider secrets from Secrets Manager if live forwarding is enabled
- write immutable audit export objects to the configured S3 bucket
