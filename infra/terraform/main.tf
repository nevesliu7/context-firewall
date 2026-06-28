data "aws_caller_identity" "current" {}

locals {
  name_prefix      = "${var.project_name}-${var.environment}"
  cognito_issuer   = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
  jwt_issuer       = var.jwt_issuer != "" ? var.jwt_issuer : local.cognito_issuer
  jwt_audience     = var.jwt_audience != "" ? var.jwt_audience : aws_cognito_user_pool_client.this.id
  jwks_url         = var.jwks_url != "" ? var.jwks_url : "${local.jwt_issuer}/.well-known/jwks.json"
  openai_secret_id = aws_secretsmanager_secret.openai.name
}

resource "aws_kms_key" "context" {
  description             = "Context Firewall tenant data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_kms_alias" "context" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.context.key_id
}

resource "aws_dynamodb_table" "audit" {
  name         = "${local.name_prefix}-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"
  range_key    = "timestamp"

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.context.arn
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_dynamodb_table" "approval" {
  name         = "${local.name_prefix}-approval"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "tenant_id"
  range_key    = "created_at"

  attribute {
    name = "tenant_id"
    type = "S"
  }

  attribute {
    name = "created_at"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.context.arn
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_s3_bucket" "audit_exports" {
  bucket              = "${local.name_prefix}-audit-exports-${data.aws_caller_identity.current.account_id}"
  object_lock_enabled = true

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "audit_exports" {
  bucket = aws_s3_bucket.audit_exports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_exports" {
  bucket = aws_s3_bucket.audit_exports.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.context.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_exports" {
  bucket = aws_s3_bucket.audit_exports.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 30
    }
  }
}

resource "aws_secretsmanager_secret" "openai" {
  name        = "${local.name_prefix}/openai"
  description = "OpenAI-compatible provider key for Context Firewall live forwarding"
  kms_key_id  = aws_kms_key.context.arn

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_secretsmanager_secret_version" "openai" {
  count     = var.openai_api_key == "" ? 0 : 1
  secret_id = aws_secretsmanager_secret.openai.id
  secret_string = jsonencode({
    api_key = var.openai_api_key
  })
}

resource "aws_cognito_user_pool" "this" {
  name = "${local.name_prefix}-users"

  schema {
    attribute_data_type = "String"
    mutable             = true
    name                = "tenant_id"
    required            = false

    string_attribute_constraints {
      max_length = 120
      min_length = 1
    }
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_cognito_user_pool_client" "this" {
  name                                 = "${local.name_prefix}-app"
  user_pool_id                         = aws_cognito_user_pool.this.id
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["email", "openid", "profile"]
  callback_urls                        = ["http://localhost:5173/callback"]
  logout_urls                          = ["http://localhost:5173"]
  supported_identity_providers         = ["COGNITO"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_SRP_AUTH"]
}

resource "aws_cognito_user_group" "security_admin" {
  name         = "SecurityAdmins"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Can administer policies, audit exports, and approval decisions."
}

resource "aws_cognito_user_group" "developer" {
  name         = "Developers"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Can use the gateway and read tenant-scoped operational metadata."
}

resource "aws_cognito_user_group" "support" {
  name         = "Support"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Can use the gateway and read tenant-scoped review queues."
}

resource "aws_cognito_user_group" "contractor" {
  name         = "Contractors"
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Restricted external routing and usage budget."
}

resource "aws_iam_role" "lambda" {
  name = "${local.name_prefix}-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda" {
  name = "${local.name_prefix}-lambda"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.audit.arn,
          aws_dynamodb_table.approval.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.context.arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.openai.arn
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.audit_exports.arn}/*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}-api"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.context.arn
}

resource "aws_lambda_function" "api" {
  function_name    = "${local.name_prefix}-api"
  role             = aws_iam_role.lambda.arn
  handler          = "app.main.handler"
  runtime          = "python3.12"
  filename         = var.lambda_package_path
  source_code_hash = filebase64sha256(var.lambda_package_path)
  timeout          = 20
  memory_size      = 512

  environment {
    variables = {
      AUDIT_TABLE_NAME                  = aws_dynamodb_table.audit.name
      AUDIT_EXPORT_BUCKET               = aws_s3_bucket.audit_exports.bucket
      APPROVAL_TABLE_NAME               = aws_dynamodb_table.approval.name
      CFW_AUDIT_BACKEND                 = "dynamodb"
      CFW_AUDIT_EXPORT_BACKEND          = "s3"
      CFW_APPROVAL_BACKEND              = "dynamodb"
      CFW_AWS_ENABLED                   = "true"
      CFW_AUTH_REQUIRED                 = tostring(var.auth_required)
      CFW_RBAC_ENFORCED                 = "true"
      CFW_FORWARD_MODE                  = "dry_run"
      CFW_JWT_ISSUER                    = local.jwt_issuer
      CFW_JWT_AUDIENCE                  = local.jwt_audience
      CFW_JWKS_URL                      = local.jwks_url
      CFW_KMS_KEY_ID                    = aws_kms_key.context.arn
      CFW_OPENAI_SECRET_ID              = local.openai_secret_id
      CFW_ADMIN_TOKEN                   = var.admin_token
      CFW_RATE_LIMIT_PER_MINUTE         = tostring(var.rate_limit_per_minute)
      CFW_DAILY_TOKEN_BUDGET_PER_TENANT = tostring(var.daily_token_budget_per_tenant)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]

  tags = {
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_apigatewayv2_api" "http" {
  name          = "${local.name_prefix}-http"
  protocol_type = "HTTP"

  cors_configuration {
    allow_headers = [
      "authorization",
      "content-type",
      "x-cfw-admin-token",
      "x-cfw-app-name",
      "x-cfw-destination",
      "x-cfw-provider",
      "x-cfw-tenant-id",
      "x-cfw-user-id",
      "x-cfw-user-role"
    ]
    allow_methods = ["GET", "POST", "PUT", "PATCH", "OPTIONS"]
    allow_origins = ["*"]
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "root" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "ANY /"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "proxy" {
  api_id    = aws_apigatewayv2_api.http.id
  route_key = "ANY /{proxy+}"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowExecutionFromApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.api.function_name
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  alarm_name          = "${local.name_prefix}-lambda-throttles"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Throttles"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.api.function_name
  }
}
