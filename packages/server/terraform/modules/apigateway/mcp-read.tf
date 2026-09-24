# Single production MCP transport; its configured read/write composition uses
# this same route and connector identity. No additional public tool route.
# Separate production read transport. The Lambda validates VaultGuard's own
# connector credentials; the Cognito API authorizer cannot validate these tokens.
variable "mcp_read_enabled" {
  type    = bool
  default = false
}
variable "mcp_read_lambda_invoke_arn" {
  type    = string
  default = ""
}
variable "mcp_read_lambda_name" {
  type    = string
  default = ""
}

check "mcp_read_lambda_is_wired" {
  assert {
    condition = !var.mcp_read_enabled || (
      var.connector_oauth_resource != "" && var.mcp_read_lambda_invoke_arn != "" && var.mcp_read_lambda_name != ""
    )
    error_message = "An enabled MCP read route requires its explicit connector resource and authorized Lambda."
  }
}

resource "aws_api_gateway_resource" "mcp_read" {
  count       = var.mcp_read_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "mcp"
}

resource "aws_api_gateway_method" "mcp_read_post" {
  count         = var.mcp_read_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.mcp_read[0].id
  http_method   = "POST"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "mcp_read_post" {
  count                   = var.mcp_read_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.mcp_read[0].id
  http_method             = aws_api_gateway_method.mcp_read_post[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.mcp_read_lambda_invoke_arn
}
resource "aws_api_gateway_method" "mcp_read_get" {
  count         = var.mcp_read_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.mcp_read[0].id
  http_method   = "GET"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "mcp_read_get" {
  count                   = var.mcp_read_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.mcp_read[0].id
  http_method             = aws_api_gateway_method.mcp_read_get[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.mcp_read_lambda_invoke_arn
}
resource "aws_api_gateway_method" "mcp_read_delete" {
  count         = var.mcp_read_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.mcp_read[0].id
  http_method   = "DELETE"
  authorization = "NONE"
}
resource "aws_api_gateway_integration" "mcp_read_delete" {
  count                   = var.mcp_read_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.mcp_read[0].id
  http_method             = aws_api_gateway_method.mcp_read_delete[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.mcp_read_lambda_invoke_arn
}

resource "aws_lambda_permission" "mcp_read_apigw" {
  count         = var.mcp_read_enabled ? 1 : 0
  statement_id  = "AllowMcpReadAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.mcp_read_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*/mcp"
}

resource "aws_api_gateway_method_settings" "mcp_read" {
  count       = var.mcp_read_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "mcp/*"
  settings {
    throttling_rate_limit  = 20
    throttling_burst_limit = 40
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}
