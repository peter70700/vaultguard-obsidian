# ─────────────────────────────────────────────────────────────────────────────
# VaultGuard's own connector authorization server (VAULTGUARD-49 / ADR-003)
#
# `.well-known/oauth-protected-resource` (in mcp.tf) names an authorization
# server. It used to name Cognito. It cannot: an AWS-generated Cognito discovery
# document can never advertise `offline_access`, and Cognito fails
# authentication outright on a client that requests a scope it has not
# associated -- so a ChatGPT connector following OpenAI's instruction gets an
# authorization error, and OpenAI's remedy for a late fix is recreating the app.
#
# These routes serve VaultGuard's own issuer instead. Everything is count-gated
# on `connector_oauth_resource`; empty (the default) creates nothing.
#
# Every route is `authorization = "NONE"` by protocol requirement -- discovery,
# authorize, reauthorize, callback, consent, token and revoke are all pre-authentication
# surfaces. The Lambda owns their authorization, not API Gateway.
# ─────────────────────────────────────────────────────────────────────────────

variable "connector_oauth_lambda_invoke_arn" {
  type    = string
  default = ""
}

variable "connector_oauth_lambda_name" {
  type    = string
  default = ""
}

check "connector_oauth_lambda_is_wired" {
  assert {
    condition = var.connector_oauth_resource == "" || (
      var.connector_oauth_lambda_invoke_arn != "" && var.connector_oauth_lambda_name != ""
    )
    error_message = "An enabled connector OAuth resource requires the connector authorization-server Lambda."
  }
}

# ─── RFC 8414 discovery ──────────────────────────────────────────────────────
# This is the document ChatGPT reads to decide whether the provider supports
# refresh. It is the entire reason this lane exists.

resource "aws_api_gateway_resource" "oauth_authorization_server" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.well_known_oauth[0].id
  path_part   = "oauth-authorization-server"
}

resource "aws_api_gateway_method" "oauth_authorization_server_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.oauth_authorization_server[0].id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "oauth_authorization_server_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.oauth_authorization_server[0].id
  http_method             = aws_api_gateway_method.oauth_authorization_server_get[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.connector_oauth_lambda_invoke_arn
}

# ─── /oauth/{action} ─────────────────────────────────────────────────────────
# authorize and callback are browser GETs; consent, token and revoke are POSTs.
# The Lambda routes on the exact path and refuses anything it does not own.

resource "aws_api_gateway_resource" "oauth" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "oauth"
}

resource "aws_api_gateway_resource" "oauth_action" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.oauth[0].id
  path_part   = "{action}"
}

resource "aws_api_gateway_method" "oauth_action_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.oauth_action[0].id
  http_method   = "GET"
  authorization = "NONE"

  request_parameters = { "method.request.path.action" = true }
}

resource "aws_api_gateway_integration" "oauth_action_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.oauth_action[0].id
  http_method             = aws_api_gateway_method.oauth_action_get[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.connector_oauth_lambda_invoke_arn
}

resource "aws_api_gateway_method" "oauth_action_post" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.oauth_action[0].id
  http_method   = "POST"
  authorization = "NONE"

  request_parameters = { "method.request.path.action" = true }
}

resource "aws_api_gateway_integration" "oauth_action_post" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.oauth_action[0].id
  http_method             = aws_api_gateway_method.oauth_action_post[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.connector_oauth_lambda_invoke_arn
}

resource "aws_lambda_permission" "connector_oauth_apigw" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.connector_oauth_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}

# ─── Rate limiting (MCP-3 infra half) ────────────────────────────────────────
#
# The stage-wide setting is 1000 rps / 2000 burst, and the regional WAF's
# rate-based rule is 2000 per IP. Both are far too permissive for these routes:
# `/oauth/authorize` writes a DynamoDB row per request and is reachable WITHOUT
# authentication, which is precisely the unbounded-growth vector the finding
# names. A specific `method_path` overrides the wildcard for that method only.
#
# These limits are deliberately low. A human completing a browser login makes a
# handful of requests; a connector refreshing a token makes one every few
# minutes. Nothing legitimate on these paths is high-volume.

resource "aws_api_gateway_method_settings" "connector_oauth_action" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "oauth/{action}/*"

  settings {
    throttling_rate_limit  = 20
    throttling_burst_limit = 40
    metrics_enabled        = true
    logging_level          = "INFO"
    # These paths carry authorization codes, PKCE verifiers and refresh tokens
    # in their bodies and query strings. Body logging must never be on here,
    # independently of the stage-wide setting.
    data_trace_enabled = false
  }
}

resource "aws_api_gateway_method_settings" "connector_oauth_discovery" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = ".well-known/oauth-authorization-server/GET"

  settings {
    # Discovery is cacheable and carries no secret, so it is looser than the
    # credential paths but still far below the stage default.
    throttling_rate_limit  = 100
    throttling_burst_limit = 200
    metrics_enabled        = true
    logging_level          = "INFO"
    data_trace_enabled     = false
  }
}
