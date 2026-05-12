# ─────────────────────────────────────────────────────────────────────────────
# Vaults — first-class isolated namespaces inside an organization.
#
# Every file and permission rule is scoped to a vault. The vault entity itself
# (CRUD + membership) is served by the `vaults` Lambda; files and permissions
# Lambdas remain on their own routes, but those routes now live UNDER
# `/vaults/{vaultId}/...`.
#
# Routes defined here:
#   GET    /vaults                                      → vaults Lambda
#   POST   /vaults                                      → vaults Lambda
#   GET    /vaults/{vaultId}                            → vaults Lambda
#   PATCH  /vaults/{vaultId}                            → vaults Lambda
#   DELETE /vaults/{vaultId}                            → vaults Lambda
#   GET    /vaults/{vaultId}/members                    → vaults Lambda
#   POST   /vaults/{vaultId}/members                    → vaults Lambda
#   PATCH  /vaults/{vaultId}/members/{userId}           → vaults Lambda
#   DELETE /vaults/{vaultId}/members/{userId}           → vaults Lambda
#
# Files and permissions sub-routes live in main.tf and reference
# aws_api_gateway_resource.vaults_id.id as their parent.
# ─────────────────────────────────────────────────────────────────────────────

# ─── /vaults ────────────────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "vaults" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "vaults"
}

resource "aws_api_gateway_method" "vaults_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "vaults_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults.id
  http_method             = aws_api_gateway_method.vaults_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

resource "aws_api_gateway_method" "vaults_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "vaults_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults.id
  http_method             = aws_api_gateway_method.vaults_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

# ─── /vaults/{vaultId} ──────────────────────────────────────────────────────

resource "aws_api_gateway_resource" "vaults_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults.id
  path_part   = "{vaultId}"
}

resource "aws_api_gateway_method" "vaults_id_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_id.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vaults_id_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_id.id
  http_method             = aws_api_gateway_method.vaults_id_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

resource "aws_api_gateway_method" "vaults_id_patch" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_id.id
  http_method   = "PATCH"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vaults_id_patch" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_id.id
  http_method             = aws_api_gateway_method.vaults_id_patch.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

resource "aws_api_gateway_method" "vaults_id_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_id.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vaults_id_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_id.id
  http_method             = aws_api_gateway_method.vaults_id_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

# ─── /vaults/{vaultId}/members ──────────────────────────────────────────────

resource "aws_api_gateway_resource" "vaults_members" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "members"
}

resource "aws_api_gateway_method" "vaults_members_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_members.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vaults_members_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_members.id
  http_method             = aws_api_gateway_method.vaults_members_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

resource "aws_api_gateway_method" "vaults_members_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_members.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.vaultId" = true }
}

resource "aws_api_gateway_integration" "vaults_members_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_members.id
  http_method             = aws_api_gateway_method.vaults_members_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

# ─── /vaults/{vaultId}/members/{userId} ─────────────────────────────────────

resource "aws_api_gateway_resource" "vaults_members_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_members.id
  path_part   = "{userId}"
}

resource "aws_api_gateway_method" "vaults_members_id_patch" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_members_id.id
  http_method   = "PATCH"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true,
    "method.request.path.userId"  = true,
  }
}

resource "aws_api_gateway_integration" "vaults_members_id_patch" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_members_id.id
  http_method             = aws_api_gateway_method.vaults_members_id_patch.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

resource "aws_api_gateway_method" "vaults_members_id_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.vaults_members_id.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.vaultId" = true,
    "method.request.path.userId"  = true,
  }
}

resource "aws_api_gateway_integration" "vaults_members_id_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.vaults_members_id.id
  http_method             = aws_api_gateway_method.vaults_members_id_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.vaults_lambda_invoke_arn
}

# ─── Lambda invoke permission ───────────────────────────────────────────────

resource "aws_lambda_permission" "vaults_apigw" {
  statement_id  = "AllowAPIGatewayInvokeVaults"
  action        = "lambda:InvokeFunction"
  function_name = var.vaults_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}
