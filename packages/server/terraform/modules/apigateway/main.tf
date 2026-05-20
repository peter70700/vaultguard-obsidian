variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "cognito_user_pool_arn" { type = string }
variable "auth_lambda_invoke_arn" { type = string }
variable "auth_lambda_name" { type = string }
variable "files_lambda_invoke_arn" { type = string }
variable "files_lambda_name" { type = string }
variable "perms_lambda_invoke_arn" { type = string }
variable "perms_lambda_name" { type = string }
variable "audit_lambda_invoke_arn" { type = string }
variable "audit_lambda_name" { type = string }
variable "signup_lambda_invoke_arn" { type = string }
variable "signup_lambda_name" { type = string }
variable "billing_lambda_invoke_arn" { type = string }
variable "billing_lambda_name" { type = string }
variable "reencryption_lambda_invoke_arn" { type = string }
variable "reencryption_lambda_name" { type = string }
variable "vaults_lambda_invoke_arn" { type = string }
variable "vaults_lambda_name" { type = string }
variable "shares_lambda_invoke_arn" { type = string }
variable "shares_lambda_name" { type = string }
variable "domain_name" {
  type    = string
  default = ""
}

data "aws_region" "current" {}

locals {
  allowed_cors_origin = var.domain_name != "" ? "https://admin.${var.domain_name}" : "http://localhost:5173"
}

# ─── Account-level CloudWatch role for API Gateway logging ───────────────────

resource "aws_iam_role" "apigw_cloudwatch" {
  name = "vaultguard-${var.stage}-apigw-cloudwatch"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "apigateway.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "apigw_cloudwatch" {
  role       = aws_iam_role.apigw_cloudwatch.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "main" {
  cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch.arn
}

# ─── REST API ────────────────────────────────────────────────────────────────

resource "aws_api_gateway_rest_api" "vaultguard" {
  name        = "obsidian-vaultguard-${var.stage}"
  description = "Obsidian VaultGuard enterprise file permissions and encryption API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# ─── CORS Gateway Responses ─────────────────────────────────────────────────
# These add CORS headers to API Gateway's own error responses (e.g. missing
# OPTIONS methods, 401/403 from authorizer). Without these, the browser blocks
# even the error response and the client can't read the status code.

resource "aws_api_gateway_gateway_response" "cors_4xx" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  response_type = "DEFAULT_4XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'${local.allowed_cors_origin}'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'Content-Type,Authorization,X-VaultGuard-Session-Id'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'GET,POST,PUT,PATCH,DELETE,OPTIONS'"
  }

  # Match AWS's built-in default; otherwise the API silently re-applies it on
  # every refresh and Terraform shows perpetual drift.
  response_templates = {
    "application/json" = "{\"message\":$context.error.messageString}"
  }
}

resource "aws_api_gateway_gateway_response" "cors_5xx" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  response_type = "DEFAULT_5XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'${local.allowed_cors_origin}'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'Content-Type,Authorization,X-VaultGuard-Session-Id'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'GET,POST,PUT,PATCH,DELETE,OPTIONS'"
  }

  response_templates = {
    "application/json" = "{\"message\":$context.error.messageString}"
  }
}

# ─── Cognito Authorizer ─────────────────────────────────────────────────────

resource "aws_api_gateway_authorizer" "cognito" {
  name            = "vaultguard-cognito-${var.stage}"
  rest_api_id     = aws_api_gateway_rest_api.vaultguard.id
  type            = "COGNITO_USER_POOLS"
  provider_arns   = [var.cognito_user_pool_arn]
  identity_source = "method.request.header.Authorization"
}

# ─── Auth Endpoints ──────────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "auth" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "auth"
}

resource "aws_api_gateway_resource" "auth_login" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "login"
}

resource "aws_api_gateway_method" "auth_login_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_login.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_login_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_login.id
  http_method             = aws_api_gateway_method.auth_login_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "auth_session" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "session"
}

resource "aws_api_gateway_method" "auth_session_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_session.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_session_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_session.id
  http_method             = aws_api_gateway_method.auth_session_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "auth_refresh" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "refresh"
}

resource "aws_api_gateway_method" "auth_refresh_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_refresh.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_refresh_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_refresh.id
  http_method             = aws_api_gateway_method.auth_refresh_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "auth_forgot_password" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "forgot-password"
}

resource "aws_api_gateway_method" "auth_forgot_password_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_forgot_password.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "auth_forgot_password_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_forgot_password.id
  http_method             = aws_api_gateway_method.auth_forgot_password_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "auth_confirm_reset" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "confirm-reset"
}

resource "aws_api_gateway_method" "auth_confirm_reset_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_confirm_reset.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "auth_confirm_reset_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_confirm_reset.id
  http_method             = aws_api_gateway_method.auth_confirm_reset_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/recovery-codes — authenticated; stores hashed recovery codes
# generated client-side after MFA enrollment.
resource "aws_api_gateway_resource" "auth_recovery_codes" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "recovery-codes"
}

resource "aws_api_gateway_method" "auth_recovery_codes_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_recovery_codes.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_recovery_codes_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_recovery_codes.id
  http_method             = aws_api_gateway_method.auth_recovery_codes_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/recovery-codes/verify — UNAUTHENTICATED; user has lost their
# TOTP device, supplies email + one recovery code in exchange for an MFA
# reset (next login routes through MFA_SETUP). Rate-limited server-side.
resource "aws_api_gateway_resource" "auth_recovery_codes_verify" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth_recovery_codes.id
  path_part   = "verify"
}

resource "aws_api_gateway_method" "auth_recovery_codes_verify_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_recovery_codes_verify.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "auth_recovery_codes_verify_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_recovery_codes_verify.id
  http_method             = aws_api_gateway_method.auth_recovery_codes_verify_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "auth_revoke" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "revoke"
}

resource "aws_api_gateway_method" "auth_revoke_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_revoke.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_revoke_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_revoke.id
  http_method             = aws_api_gateway_method.auth_revoke_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/logout — end server-side session
resource "aws_api_gateway_resource" "auth_logout" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "logout"
}

resource "aws_api_gateway_method" "auth_logout_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_logout.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_logout_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_logout.id
  http_method             = aws_api_gateway_method.auth_logout_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# GET /auth/key-lease — get current key lease
resource "aws_api_gateway_resource" "auth_key_lease" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "key-lease"
}

resource "aws_api_gateway_method" "auth_key_lease_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_key_lease.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_key_lease_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_key_lease.id
  http_method             = aws_api_gateway_method.auth_key_lease_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/key-lease/scoped — issue path-scoped key lease
resource "aws_api_gateway_resource" "auth_key_lease_scoped" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth_key_lease.id
  path_part   = "scoped"
}

resource "aws_api_gateway_method" "auth_key_lease_scoped_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_key_lease_scoped.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_key_lease_scoped_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_key_lease_scoped.id
  http_method             = aws_api_gateway_method.auth_key_lease_scoped_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# GET /auth/leases — list active key leases
resource "aws_api_gateway_resource" "auth_leases" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "leases"
}

resource "aws_api_gateway_method" "auth_leases_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_leases.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_leases_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_leases.id
  http_method             = aws_api_gateway_method.auth_leases_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# GET /auth/heartbeat — session heartbeat
resource "aws_api_gateway_resource" "auth_heartbeat" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "heartbeat"
}

resource "aws_api_gateway_method" "auth_heartbeat_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_heartbeat.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_heartbeat_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_heartbeat.id
  http_method             = aws_api_gateway_method.auth_heartbeat_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/setup-zk — hybrid ZK setup (Phase 5)
resource "aws_api_gateway_resource" "auth_setup_zk" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "setup-zk"
}

resource "aws_api_gateway_method" "auth_setup_zk_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_setup_zk.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_setup_zk_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_setup_zk.id
  http_method             = aws_api_gateway_method.auth_setup_zk_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# GET /auth/wrapped-key — get wrapped encryption key
resource "aws_api_gateway_resource" "auth_wrapped_key" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "wrapped-key"
}

resource "aws_api_gateway_method" "auth_wrapped_key_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_wrapped_key.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_wrapped_key_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_wrapped_key.id
  http_method             = aws_api_gateway_method.auth_wrapped_key_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# POST /auth/recover — account recovery
resource "aws_api_gateway_resource" "auth_recover" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.auth.id
  path_part   = "recover"
}

resource "aws_api_gateway_method" "auth_recover_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.auth_recover.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "auth_recover_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.auth_recover.id
  http_method             = aws_api_gateway_method.auth_recover_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.auth_lambda_invoke_arn
}

# ─── Vault Metadata Overview Endpoint ────────────────────────────────────────

resource "aws_api_gateway_resource" "vault_overview" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "overview"
}

resource "aws_api_gateway_method" "vault_overview_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vault_overview.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vault_overview_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vault_overview.id
  http_method             = aws_api_gateway_method.vault_overview_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

# ─── Vault Sync Cursor Endpoint ──────────────────────────────────────────────
#
# Cheap polling cursor: clients call this every 30s to learn whether anything
# in the vault changed since their last sync. One DynamoDB GetItem per call,
# zero S3, zero permission scan.

resource "aws_api_gateway_resource" "vault_sync_cursor" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "sync-cursor"
}

resource "aws_api_gateway_method" "vault_sync_cursor_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vault_sync_cursor.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vault_sync_cursor_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vault_sync_cursor.id
  http_method             = aws_api_gateway_method.vault_sync_cursor_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

# ─── Files Endpoints ─────────────────────────────────────────────────────────
#
# All file routes live UNDER `/vaults/{vaultId}/`. The vault parent resource
# is defined in `vaults.tf`. Pre-vault deployments would have had `/files/...`
# at the root — that's deliberately gone now to enforce vault scope.

resource "aws_api_gateway_resource" "files" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "files"
}

resource "aws_api_gateway_method" "files_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.files.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "files_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.files.id
  http_method             = aws_api_gateway_method.files_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "files_sync" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.files.id
  path_part   = "sync"
}

resource "aws_api_gateway_method" "files_sync_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.files_sync.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "files_sync_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.files_sync.id
  http_method             = aws_api_gateway_method.files_sync_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "files_path" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.files.id
  path_part   = "{filePath+}"
}

resource "aws_api_gateway_method" "files_path_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.files_path.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.filePath" = true }
}

resource "aws_api_gateway_integration" "files_path_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.files_path.id
  http_method             = aws_api_gateway_method.files_path_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

# PUT /files/{filePath+} — write/update a file
resource "aws_api_gateway_method" "files_path_put" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.files_path.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.filePath" = true }
}

resource "aws_api_gateway_integration" "files_path_put" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.files_path.id
  http_method             = aws_api_gateway_method.files_path_put.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

# DELETE /files/{filePath+} — delete a file
resource "aws_api_gateway_method" "files_path_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.files_path.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.filePath" = true }
}

resource "aws_api_gateway_integration" "files_path_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.files_path.id
  http_method             = aws_api_gateway_method.files_path_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.files_lambda_invoke_arn
}

# ─── Permissions Endpoints ───────────────────────────────────────────────────
#
# Permission rules live under `/vaults/{vaultId}/permissions/...` — every rule
# is bound to a vault and can only be created/queried by members of that vault.

resource "aws_api_gateway_resource" "permissions" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "permissions"
}

resource "aws_api_gateway_method" "permissions_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "permissions_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions.id
  http_method             = aws_api_gateway_method.permissions_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

resource "aws_api_gateway_method" "permissions_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "permissions_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions.id
  http_method             = aws_api_gateway_method.permissions_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "permissions_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.permissions.id
  path_part   = "{id}"
}

resource "aws_api_gateway_method" "permissions_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions_id.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.id" = true }
}

resource "aws_api_gateway_integration" "permissions_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions_id.id
  http_method             = aws_api_gateway_method.permissions_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

# ─── Audit Endpoints (vault-scoped) ──────────────────────────────────────────

resource "aws_api_gateway_resource" "audit" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "audit"
}

resource "aws_api_gateway_method" "audit_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit.id
  http_method             = aws_api_gateway_method.audit_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_logs" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "logs"
}

resource "aws_api_gateway_method" "audit_logs_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_logs.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_logs_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_logs.id
  http_method             = aws_api_gateway_method.audit_logs_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_alerts" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "alerts"
}

resource "aws_api_gateway_method" "audit_alerts_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_alerts.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_alerts_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_alerts.id
  http_method             = aws_api_gateway_method.audit_alerts_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_user" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "user"
}

resource "aws_api_gateway_resource" "audit_user_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit_user.id
  path_part   = "{userId}"
}

resource "aws_api_gateway_method" "audit_user_id_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_user_id.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
    "method.request.path.userId"  = true
  }
}

resource "aws_api_gateway_integration" "audit_user_id_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_user_id.id
  http_method             = aws_api_gateway_method.audit_user_id_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_file" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "file"
}

resource "aws_api_gateway_resource" "audit_file_path" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit_file.id
  path_part   = "{path+}"
}

resource "aws_api_gateway_method" "audit_file_path_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_file_path.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
    "method.request.path.path"    = true
  }
}

resource "aws_api_gateway_integration" "audit_file_path_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_file_path.id
  http_method             = aws_api_gateway_method.audit_file_path_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_export" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "export"
}

resource "aws_api_gateway_method" "audit_export_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_export.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_export_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_export.id
  http_method             = aws_api_gateway_method.audit_export_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_bridge" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "bridge"
}

resource "aws_api_gateway_method" "audit_bridge_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_bridge.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_bridge_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_bridge.id
  http_method             = aws_api_gateway_method.audit_bridge_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "audit_report" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.audit.id
  path_part   = "report"
}

resource "aws_api_gateway_method" "audit_report_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.audit_report.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true
  }
}

resource "aws_api_gateway_integration" "audit_report_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.audit_report.id
  http_method             = aws_api_gateway_method.audit_report_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.audit_lambda_invoke_arn
}

# ─── Signup Endpoint (public, no auth) ───────────────────────────────────────

resource "aws_api_gateway_resource" "signup" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "signup"
}

resource "aws_api_gateway_method" "signup_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.signup.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "signup_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.signup.id
  http_method             = aws_api_gateway_method.signup_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.signup_lambda_invoke_arn
}

# CORS preflight for signup (public endpoint)
resource "aws_api_gateway_method" "signup_options" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.signup.id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "signup_options" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.signup.id
  http_method = aws_api_gateway_method.signup_options.http_method
  type        = "MOCK"

  request_templates = { "application/json" = "{\"statusCode\": 200}" }
}

resource "aws_api_gateway_method_response" "signup_options" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.signup.id
  http_method = aws_api_gateway_method.signup_options.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "signup_options" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.signup.id
  http_method = aws_api_gateway_method.signup_options.http_method
  status_code = aws_api_gateway_method_response.signup_options.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,Authorization,X-VaultGuard-Session-Id'"
    "method.response.header.Access-Control-Allow-Methods" = "'POST,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'${local.allowed_cors_origin}'"
  }
}

# ─── Billing Endpoints (authenticated) ──────────────────────────────────────

resource "aws_api_gateway_resource" "billing" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "billing"
}

resource "aws_api_gateway_resource" "billing_subscription" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.billing.id
  path_part   = "subscription"
}

resource "aws_api_gateway_method" "billing_subscription_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.billing_subscription.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "billing_subscription_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.billing_subscription.id
  http_method             = aws_api_gateway_method.billing_subscription_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.billing_lambda_invoke_arn
}

# POST /billing/subscription — sync seat count with Stripe
resource "aws_api_gateway_method" "billing_subscription_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.billing_subscription.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "billing_subscription_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.billing_subscription.id
  http_method             = aws_api_gateway_method.billing_subscription_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.billing_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "billing_checkout" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.billing.id
  path_part   = "checkout"
}

resource "aws_api_gateway_method" "billing_checkout_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.billing_checkout.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "billing_checkout_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.billing_checkout.id
  http_method             = aws_api_gateway_method.billing_checkout_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.billing_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "billing_portal" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.billing.id
  path_part   = "portal"
}

resource "aws_api_gateway_method" "billing_portal_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.billing_portal.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "billing_portal_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.billing_portal.id
  http_method             = aws_api_gateway_method.billing_portal_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.billing_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "billing_webhook" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.billing.id
  path_part   = "webhook"
}

resource "aws_api_gateway_method" "billing_webhook_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.billing_webhook.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "billing_webhook_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.billing_webhook.id
  http_method             = aws_api_gateway_method.billing_webhook_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.billing_lambda_invoke_arn
}

# ─── Re-encryption Endpoints ────────────────────────────────────────────────

resource "aws_api_gateway_resource" "reencryption" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "re-encryption"
}

resource "aws_api_gateway_resource" "reencryption_trigger" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.reencryption.id
  path_part   = "trigger"
}

resource "aws_api_gateway_method" "reencryption_trigger_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.reencryption_trigger.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "reencryption_trigger_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.reencryption_trigger.id
  http_method             = aws_api_gateway_method.reencryption_trigger_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.reencryption_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "reencryption_job_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.reencryption.id
  path_part   = "{jobId}"
}

resource "aws_api_gateway_method" "reencryption_job_id_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.reencryption_job_id.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.jobId" = true }
}

resource "aws_api_gateway_integration" "reencryption_job_id_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.reencryption_job_id.id
  http_method             = aws_api_gateway_method.reencryption_job_id_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.reencryption_lambda_invoke_arn
}

# ─── Lambda Permissions for API Gateway ──────────────────────────────────────

resource "aws_lambda_permission" "auth_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.auth_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "files_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.files_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "perms_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.perms_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "audit_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.audit_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "signup_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.signup_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "billing_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.billing_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

resource "aws_lambda_permission" "reencryption_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.reencryption_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

# ─── Deployment ──────────────────────────────────────────────────────────────

resource "aws_api_gateway_deployment" "vaultguard" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id

  depends_on = [
    # Auth
    aws_api_gateway_integration.auth_login_post,
    aws_api_gateway_integration.auth_session_post,
    aws_api_gateway_integration.auth_refresh_post,
    aws_api_gateway_integration.auth_revoke_post,
    aws_api_gateway_integration.auth_forgot_password_post,
    aws_api_gateway_integration.auth_confirm_reset_post,
    aws_api_gateway_integration.auth_logout_post,
    aws_api_gateway_integration.auth_key_lease_get,
    aws_api_gateway_integration.auth_key_lease_scoped_post,
    aws_api_gateway_integration.auth_leases_get,
    aws_api_gateway_integration.auth_heartbeat_get,
    aws_api_gateway_integration.auth_setup_zk_post,
    aws_api_gateway_integration.auth_wrapped_key_get,
    aws_api_gateway_integration.auth_recover_post,
    aws_api_gateway_integration.auth_recovery_codes_post,
    aws_api_gateway_integration.auth_recovery_codes_verify_post,
    # Users
    aws_api_gateway_integration.users_get,
    aws_api_gateway_integration.users_roles_get,
    aws_api_gateway_integration.users_invite_post,
    aws_api_gateway_integration.users_id_role_put,
    aws_api_gateway_integration.users_id_revoke_post,
    aws_api_gateway_integration.users_id_reactivate_post,
    aws_api_gateway_integration.users_id_resend_invite_post,
    aws_api_gateway_integration.users_id_activity_get,
    aws_api_gateway_integration.users_id_reset_mfa_post,
    # Files
    aws_api_gateway_integration.vault_overview_get,
    aws_api_gateway_integration.vault_sync_cursor_get,
    aws_api_gateway_integration.files_get,
    aws_api_gateway_integration.files_sync_post,
    aws_api_gateway_integration.files_path_get,
    aws_api_gateway_integration.files_path_put,
    aws_api_gateway_integration.files_path_delete,
    # Permissions
    aws_api_gateway_integration.permissions_get,
    aws_api_gateway_integration.permissions_post,
    aws_api_gateway_integration.permissions_delete,
    aws_api_gateway_integration.permissions_user_get,
    aws_api_gateway_integration.permissions_id_put,
    aws_api_gateway_integration.permissions_check_post,
    # Audit
    aws_api_gateway_integration.audit_get,
    aws_api_gateway_integration.audit_logs_get,
    aws_api_gateway_integration.audit_alerts_get,
    aws_api_gateway_integration.audit_user_id_get,
    aws_api_gateway_integration.audit_file_path_get,
    aws_api_gateway_integration.audit_export_post,
    aws_api_gateway_integration.audit_report_post,
    aws_api_gateway_integration.audit_bridge_post,
    # Orgs
    aws_api_gateway_integration.orgs_config_get,
    aws_api_gateway_integration.orgs_settings_get,
    aws_api_gateway_integration.orgs_settings_put,
    aws_api_gateway_integration.orgs_settings_delete,
    aws_api_gateway_integration.well_known_vaultguard_json_get,
    # Signup
    aws_api_gateway_integration.signup_post,
    aws_api_gateway_integration.signup_options,
    # Billing
    aws_api_gateway_integration.billing_subscription_get,
    aws_api_gateway_integration.billing_subscription_post,
    aws_api_gateway_integration.billing_checkout_post,
    aws_api_gateway_integration.billing_portal_post,
    aws_api_gateway_integration.billing_webhook_post,
    # Re-encryption
    aws_api_gateway_integration.reencryption_trigger_post,
    aws_api_gateway_integration.reencryption_job_id_get,
    # Vaults
    aws_api_gateway_integration.vaults_get,
    aws_api_gateway_integration.vaults_post,
    aws_api_gateway_integration.vaults_id_get,
    aws_api_gateway_integration.vaults_id_patch,
    aws_api_gateway_integration.vaults_id_delete,
    aws_api_gateway_integration.vaults_members_get,
    aws_api_gateway_integration.vaults_members_post,
    aws_api_gateway_integration.vaults_members_id_patch,
    aws_api_gateway_integration.vaults_members_id_delete,
    # Shares
    aws_api_gateway_integration.shares_post,
    aws_api_gateway_integration.shares_get,
    aws_api_gateway_integration.shares_id_get,
    aws_api_gateway_integration.shares_id_delete,
    # CORS — gateway error responses
    aws_api_gateway_gateway_response.cors_4xx,
    aws_api_gateway_gateway_response.cors_5xx,
  ]

  triggers = {
    # Hash ALL resource, method, integration, and integration_response IDs.
    # The CORS integration_response IDs are critical — the deployment must
    # capture the API state AFTER these are fully created. Including them
    # here creates an implicit dependency AND forces redeployment on change.
    redeployment = sha1(jsonencode([
      # All method integrations (Lambda)
      aws_api_gateway_integration.auth_login_post.id,
      aws_api_gateway_integration.auth_session_post.id,
      aws_api_gateway_integration.auth_refresh_post.id,
      aws_api_gateway_integration.auth_revoke_post.id,
      aws_api_gateway_integration.auth_forgot_password_post.id,
      aws_api_gateway_integration.auth_confirm_reset_post.id,
      aws_api_gateway_integration.auth_logout_post.id,
      aws_api_gateway_integration.auth_key_lease_get.id,
      aws_api_gateway_integration.auth_key_lease_scoped_post.id,
      aws_api_gateway_integration.auth_leases_get.id,
      aws_api_gateway_integration.auth_heartbeat_get.id,
      aws_api_gateway_integration.auth_setup_zk_post.id,
      aws_api_gateway_integration.auth_wrapped_key_get.id,
      aws_api_gateway_integration.auth_recover_post.id,
      aws_api_gateway_integration.auth_recovery_codes_post.id,
      aws_api_gateway_integration.auth_recovery_codes_verify_post.id,
      aws_api_gateway_integration.users_get.id,
      aws_api_gateway_integration.users_roles_get.id,
      aws_api_gateway_integration.users_invite_post.id,
      aws_api_gateway_integration.users_id_role_put.id,
      aws_api_gateway_integration.users_id_revoke_post.id,
      aws_api_gateway_integration.users_id_reactivate_post.id,
      aws_api_gateway_integration.users_id_resend_invite_post.id,
      aws_api_gateway_integration.users_id_activity_get.id,
      aws_api_gateway_integration.users_id_reset_mfa_post.id,
      aws_api_gateway_integration.vault_overview_get.id,
      aws_api_gateway_integration.vault_sync_cursor_get.id,
      aws_api_gateway_integration.files_get.id,
      aws_api_gateway_integration.files_sync_post.id,
      aws_api_gateway_integration.files_path_get.id,
      aws_api_gateway_integration.files_path_put.id,
      aws_api_gateway_integration.files_path_delete.id,
      aws_api_gateway_integration.permissions_get.id,
      aws_api_gateway_integration.permissions_post.id,
      aws_api_gateway_integration.permissions_delete.id,
      aws_api_gateway_integration.permissions_user_get.id,
      aws_api_gateway_integration.permissions_id_put.id,
      aws_api_gateway_integration.permissions_check_post.id,
      aws_api_gateway_integration.audit_get.id,
      aws_api_gateway_integration.audit_logs_get.id,
      aws_api_gateway_integration.audit_alerts_get.id,
      aws_api_gateway_integration.audit_user_id_get.id,
      aws_api_gateway_integration.audit_file_path_get.id,
      aws_api_gateway_integration.audit_export_post.id,
      aws_api_gateway_integration.audit_report_post.id,
      aws_api_gateway_integration.audit_bridge_post.id,
      aws_api_gateway_integration.orgs_config_get.id,
      aws_api_gateway_integration.orgs_settings_get.id,
      aws_api_gateway_integration.orgs_settings_put.id,
      aws_api_gateway_integration.orgs_settings_delete.id,
      aws_api_gateway_integration.well_known_vaultguard_json_get.id,
      aws_api_gateway_integration.signup_post.id,
      aws_api_gateway_integration.signup_options.id,
      aws_api_gateway_integration.billing_subscription_get.id,
      aws_api_gateway_integration.billing_subscription_post.id,
      aws_api_gateway_integration.billing_checkout_post.id,
      aws_api_gateway_integration.billing_portal_post.id,
      aws_api_gateway_integration.billing_webhook_post.id,
      aws_api_gateway_integration.reencryption_trigger_post.id,
      aws_api_gateway_integration.reencryption_job_id_get.id,
      # Vaults
      aws_api_gateway_integration.vaults_get.id,
      aws_api_gateway_integration.vaults_post.id,
      aws_api_gateway_integration.vaults_id_get.id,
      aws_api_gateway_integration.vaults_id_patch.id,
      aws_api_gateway_integration.vaults_id_delete.id,
      aws_api_gateway_integration.vaults_members_get.id,
      aws_api_gateway_integration.vaults_members_post.id,
      aws_api_gateway_integration.vaults_members_id_patch.id,
      aws_api_gateway_integration.vaults_members_id_delete.id,
      # Shares
      aws_api_gateway_integration.shares_post.id,
      aws_api_gateway_integration.shares_get.id,
      aws_api_gateway_integration.shares_id_get.id,
      aws_api_gateway_integration.shares_id_delete.id,
      # CORS OPTIONS — integrations AND integration responses
      values(aws_api_gateway_integration.cors_options)[*].id,
      values(aws_api_gateway_integration_response.cors_options)[*].id,
      values(aws_api_gateway_method_response.cors_options)[*].id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "vaultguard" {
  depends_on = [aws_api_gateway_account.main]

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  deployment_id = aws_api_gateway_deployment.vaultguard.id
  stage_name    = var.stage

  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      caller         = "$context.identity.caller"
      user           = "$context.identity.user"
      requestTime    = "$context.requestTime"
      httpMethod     = "$context.httpMethod"
      resourcePath   = "$context.resourcePath"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
    })
  }
}

resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/vaultguard-${var.stage}"
  retention_in_days = var.is_prod ? 365 : 7
}

resource "aws_api_gateway_method_settings" "vaultguard" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "*/*"

  settings {
    throttling_rate_limit  = 1000
    throttling_burst_limit = 2000
    metrics_enabled        = true
    logging_level          = "INFO"
    data_trace_enabled     = !var.is_prod
  }
}

output "api_url" {
  value = aws_api_gateway_stage.vaultguard.invoke_url
}

output "api_name" {
  value = aws_api_gateway_rest_api.vaultguard.name
}

output "api_execution_arn" {
  value = aws_api_gateway_rest_api.vaultguard.execution_arn
}

output "api_id" {
  value = aws_api_gateway_rest_api.vaultguard.id
}

output "api_stage_name" {
  value = aws_api_gateway_stage.vaultguard.stage_name
}
