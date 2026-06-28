output "api_endpoint" {
  description = "HTTP API endpoint for Context Firewall."
  value       = aws_apigatewayv2_api.http.api_endpoint
}

output "cognito_user_pool_id" {
  description = "Cognito user pool id."
  value       = aws_cognito_user_pool.this.id
}

output "cognito_app_client_id" {
  description = "Cognito app client id used as the JWT audience."
  value       = aws_cognito_user_pool_client.this.id
}

output "audit_table_name" {
  description = "DynamoDB audit table name."
  value       = aws_dynamodb_table.audit.name
}

output "approval_table_name" {
  description = "DynamoDB approval table name."
  value       = aws_dynamodb_table.approval.name
}

output "kms_key_arn" {
  description = "KMS key used for approval artifacts and table encryption."
  value       = aws_kms_key.context.arn
}

output "openai_secret_id" {
  description = "Secrets Manager secret id for live OpenAI-compatible forwarding."
  value       = aws_secretsmanager_secret.openai.name
}

output "audit_export_bucket" {
  description = "S3 bucket for immutable audit exports."
  value       = aws_s3_bucket.audit_exports.bucket
}
