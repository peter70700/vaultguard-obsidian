# ─────────────────────────────────────────────────────────────────────────────
# Share-link endpoints — opaque tokens that route teammates to a specific
# vault file. Every endpoint goes through the shared requireVaultMember
# gate; the token alone grants nothing. See infrastructure/lambda/shares/.
#
# Routes:
#   POST   /vaults/{vaultId}/shares                  — mint a share link
#   GET    /vaults/{vaultId}/shares                  — list this vault's shares
#   GET    /vaults/{vaultId}/shares/{shareId}        — resolve to (vaultId, relPath)
#   DELETE /vaults/{vaultId}/shares/{shareId}        — revoke
# ─────────────────────────────────────────────────────────────────────────────

# ─── /vaults/{vaultId}/shares ────────────────────────────────────────────────

resource "aws_api_gateway_resource" "shares" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "shares"
}

resource "aws_api_gateway_method" "shares_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.shares.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "shares_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.shares.id
  http_method             = aws_api_gateway_method.shares_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.shares_lambda_invoke_arn
}

resource "aws_api_gateway_method" "shares_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.shares.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "shares_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.shares.id
  http_method             = aws_api_gateway_method.shares_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.shares_lambda_invoke_arn
}

# ─── /vaults/{vaultId}/shares/{shareId} ──────────────────────────────────────

resource "aws_api_gateway_resource" "shares_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.shares.id
  path_part   = "{shareId}"
}

resource "aws_api_gateway_method" "shares_id_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.shares_id.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true,
    "method.request.path.shareId" = true,
  }
}

resource "aws_api_gateway_integration" "shares_id_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.shares_id.id
  http_method             = aws_api_gateway_method.shares_id_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.shares_lambda_invoke_arn
}

resource "aws_api_gateway_method" "shares_id_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.shares_id.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true,
    "method.request.path.shareId" = true,
  }
}

resource "aws_api_gateway_integration" "shares_id_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.shares_id.id
  http_method             = aws_api_gateway_method.shares_id_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.shares_lambda_invoke_arn
}

# ─── Lambda invoke permission ───────────────────────────────────────────────

resource "aws_lambda_permission" "shares_apigw" {
  statement_id  = "AllowAPIGatewayInvokeShares"
  action        = "lambda:InvokeFunction"
  function_name = var.shares_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}
