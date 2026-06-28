# Terraform AWS Deployment

This deployment creates a production-shaped Context Firewall stack:

- HTTP API Gateway
- Lambda running the FastAPI/Mangum app
- Cognito user pool, app client, and security groups
- DynamoDB audit and approval tables
- KMS key for tables, approval artifacts, and secrets
- Secrets Manager secret for provider credentials
- S3 bucket with versioning and object lock for audit exports
- CloudWatch alarms for Lambda errors and throttles

## Package

From the repository root:

```bash
./scripts/package-lambda.sh
```

## Deploy

```bash
cd infra/terraform
terraform init
terraform apply \
  -var lambda_package_path=../../build/context-firewall-lambda.zip \
  -var admin_token='replace-with-a-long-random-value'
```

To use Okta instead of the Cognito pool created here, pass:

```bash
terraform apply \
  -var jwt_issuer='https://your-domain.okta.com/oauth2/default' \
  -var jwt_audience='api://context-firewall' \
  -var jwks_url='https://your-domain.okta.com/oauth2/default/v1/keys'
```

Keep `CFW_FORWARD_MODE=dry_run` until security review and provider allowlists are complete.

Use `/audit/export?format=ndjson&delivery=s3` to write metadata-only audit exports into the S3 bucket created by this stack.
