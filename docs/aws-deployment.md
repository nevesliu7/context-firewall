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
- **SQS + Step Functions**: review workflow for `review` decisions.
- **Bedrock**: internal model route after policy allows or redacts context.
- **AWS AppConfig or S3**: signed policy pack distribution.

## Deployment Steps

1. Package the API with dependencies.
2. Deploy `infra/aws/serverless-template.yaml`.
3. Replace local SQLite storage with DynamoDB implementations.
4. Replace demo headers with JWT/Cognito claims.
5. Store policy packs in AppConfig or S3 and load them at cold start.
6. Keep `CFW_FORWARD_MODE=dry_run` until security reviews detector and policy behavior.
7. Enable `CFW_FORWARD_MODE=live` only after provider allowlists and audit delivery are verified.

## Environment Variables

- `CFW_POLICY_PATH`: optional local policy JSON path.
- `CFW_FORWARD_MODE`: `dry_run` or `live`.
- `OPENAI_API_KEY`: local fallback for live OpenAI-compatible forwarding.
- `CFW_OPENAI_SECRET_ID`: Secrets Manager secret id for provider credentials.
- `OPENAI_BASE_URL`: optional OpenAI-compatible base URL.
- `AUDIT_TABLE_NAME`: DynamoDB table name in AWS.
- `APPROVAL_TABLE_NAME`: DynamoDB approval table name in AWS.
- `CFW_AUDIT_BACKEND`: set to `dynamodb` for DynamoDB audit writes.
- `CFW_APPROVAL_BACKEND`: set to `dynamodb` for DynamoDB approval writes.
- `CFW_KMS_KEY_ID`: optional KMS key id for approval artifact protection.
- `CFW_AUTH_REQUIRED`: require a verified Bearer JWT when true.
- `CFW_JWT_ISSUER`, `CFW_JWT_AUDIENCE`, `CFW_JWKS_URL`: Cognito/Okta JWT verification settings.
- `CFW_ADMIN_TOKEN`: token required for policy admin updates in local mode.

## IAM Notes

The enforcement function should have least-privilege access to:

- write audit records
- write and update approval tickets
- read policy packs
- emit metrics
- invoke only approved Bedrock models
- read provider secrets from Secrets Manager if live forwarding is enabled
