# ─────────────────────────────────────────────────────────────────────────────
# Super-admin platform-stats endpoints — read-only, platform-operator-only.
# Cognito-authorized here; the Lambda additionally enforces the
# "platform-superadmin" group + SUPER_ADMIN_EMAILS allowlist (fail-closed).
# See infrastructure/lambda/superadmin/.
#
# Routes:
#   GET /superadmin/overview  — platform totals (orgs/users/vaults/storage/MRR)
#   GET /superadmin/orgs      — per-org roll-up
#   GET /superadmin/users     — paginated Cognito user listing
#   GET /superadmin/growth    — daily PlatformMetrics time series
#   GET /superadmin/costs     — AWS Cost Explorer monthly/daily spend
# ─────────────────────────────────────────────────────────────────────────────

variable "superadmin_lambda_invoke_arn" { type = string }
variable "superadmin_lambda_name" { type = string }

# ─── /superadmin ─────────────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "superadmin"
}

# ─── /superadmin/overview ────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin_overview" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.superadmin.id
  path_part   = "overview"
}

resource "aws_api_gateway_method" "superadmin_overview_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.superadmin_overview.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "superadmin_overview_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.superadmin_overview.id
  http_method             = aws_api_gateway_method.superadmin_overview_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.superadmin_lambda_invoke_arn
}

# ─── /superadmin/orgs ────────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin_orgs" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.superadmin.id
  path_part   = "orgs"
}

resource "aws_api_gateway_method" "superadmin_orgs_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.superadmin_orgs.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "superadmin_orgs_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.superadmin_orgs.id
  http_method             = aws_api_gateway_method.superadmin_orgs_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.superadmin_lambda_invoke_arn
}

# ─── /superadmin/users ───────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin_users" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.superadmin.id
  path_part   = "users"
}

resource "aws_api_gateway_method" "superadmin_users_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.superadmin_users.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "superadmin_users_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.superadmin_users.id
  http_method             = aws_api_gateway_method.superadmin_users_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.superadmin_lambda_invoke_arn
}

# ─── /superadmin/growth ──────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin_growth" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.superadmin.id
  path_part   = "growth"
}

resource "aws_api_gateway_method" "superadmin_growth_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.superadmin_growth.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "superadmin_growth_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.superadmin_growth.id
  http_method             = aws_api_gateway_method.superadmin_growth_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.superadmin_lambda_invoke_arn
}

# ─── /superadmin/costs ───────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "superadmin_costs" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.superadmin.id
  path_part   = "costs"
}

resource "aws_api_gateway_method" "superadmin_costs_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.superadmin_costs.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "superadmin_costs_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.superadmin_costs.id
  http_method             = aws_api_gateway_method.superadmin_costs_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.superadmin_lambda_invoke_arn
}

# ─── Lambda invoke permission ───────────────────────────────────────────────

resource "aws_lambda_permission" "superadmin_apigw" {
  statement_id  = "AllowAPIGatewayInvokeSuperadmin"
  action        = "lambda:InvokeFunction"
  function_name = var.superadmin_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}
