# ─────────────────────────────────────────────────────────────────────────────
# Connector OAuth authorization server (VAULTGUARD-49 / ADR-003)
#
# VaultGuard's own authorization server for remote MCP connectors. Cognito
# remains the identity provider; it stops being the authorization server,
# because an AWS-generated Cognito discovery document can never advertise
# `offline_access` and Cognito fails authentication outright on a client that
# requests a scope it has not associated with the app client.
#
# Everything here is `count`-gated on `connector_oauth_resource`. Empty (the
# default, and the current state of every checked-in tfvars) creates nothing.
#
# This is the OAuth surface only. The protected `/mcp` transport is a separate
# lane; nothing in this file grants access to vault content.
# ─────────────────────────────────────────────────────────────────────────────

variable "connector_oauth_resource" {
  description = "Exact HTTPS RFC 8707 resource identifier. Empty keeps the lane disabled."
  type        = string
  default     = ""
}

variable "connector_hosted_ui_domain" {
  description = "HTTPS origin of the Cognito hosted UI used for upstream login. No path, no trailing slash."
  type        = string
  default     = ""
}

variable "connector_identity_client_id" {
  description = "Cognito app client the authorization server's browser leg uses for upstream login."
  type        = string
  default     = ""
}

variable "connector_auth_table_name" {
  description = "Connector authorization state table. Must be <namespace>-auth; the Lambda re-checks."
  type        = string
  default     = ""
}

variable "connector_auth_table_arn" {
  type    = string
  default = ""
}

locals {
  connector_enabled   = var.connector_oauth_resource == "" ? 0 : 1
  connector_namespace = "vaultguard-connector-${var.stage}"
  # The Lambda derives and re-validates both of these. Terraform pins the exact
  # origin; the Lambda refuses anything that is not `<origin>/oauth` paired with
  # `<origin>/mcp`, and refuses the isolated `/gates` path outright.
  connector_issuer = var.connector_oauth_resource == "" ? "" : "${trimsuffix(var.connector_oauth_resource, "/mcp")}/oauth"
}

check "connector_oauth_inputs_are_complete" {
  assert {
    condition = var.connector_oauth_resource == "" || (
      var.connector_hosted_ui_domain != "" &&
      var.connector_identity_client_id != "" &&
      var.connector_auth_table_name == "${local.connector_namespace}-auth"
    )
    error_message = "Enabling connector OAuth requires a hosted-UI domain, an identity client, and the <namespace>-auth table."
  }
}

data "archive_file" "connector_oauth_lambda" {
  count = local.connector_enabled

  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/connector-oauth"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/connector-oauth.zip"
}

resource "aws_iam_role" "connector_oauth_lambda" {
  count = local.connector_enabled

  name               = "vaultguard-${var.stage}-connector-oauth-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "connector_oauth_logging" {
  count = local.connector_enabled

  role       = aws_iam_role.connector_oauth_lambda[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "connector_oauth_lambda" {
  count = local.connector_enabled

  # Connector authorization state: clients, grants, sessions, browser state and
  # the opaque credential rows. Every issuer write is conditional and several
  # are transactional, so TransactWriteItems is required, not optional.
  statement {
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:Query",
      "dynamodb:TransactWriteItems",
    ]
    resources = [var.connector_auth_table_arn, "${var.connector_auth_table_arn}/index/*"]
  }
  # Org status and the policyRevision invalidation counter (getActiveOrg reads
  # the orgId GSI, then the base table consistently).
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # Per-authorization audit (MCP-2).
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # VAULTGUARD-129: the user-revocation marker, read at every code and token
  # issuance, so a revoked user is issued nothing (isUserAccessRevoked).
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.revoked_keys_table_arn]
  }
  # Upstream identity only. ListUsers resolves a subject to its directory entry;
  # GetUser confirms the access token's own subject; RevokeToken destroys the
  # native refresh credential before connector consent proceeds. No Admin* write
  # action is granted -- this role can never modify the directory.
  statement {
    actions   = ["cognito-idp:ListUsers", "cognito-idp:GetUser", "cognito-idp:RevokeToken"]
    resources = [var.cognito_user_pool_arn]
  }
  # KMS — the DynamoDB tables use the customer-managed key. SD-12: never strip
  # this from a role that touches any DynamoDB table.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "connector_oauth_lambda" {
  count = local.connector_enabled

  name   = "vaultguard-${var.stage}-connector-oauth-lambda"
  role   = aws_iam_role.connector_oauth_lambda[0].id
  policy = data.aws_iam_policy_document.connector_oauth_lambda[0].json
}

resource "aws_lambda_function" "connector_oauth" {
  count = local.connector_enabled

  function_name = "vaultguard-connector-oauth-${var.stage}"
  description   = "VaultGuard's own OAuth authorization server for remote MCP connectors"
  role          = aws_iam_role.connector_oauth_lambda[0].arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.connector_oauth_lambda[0].output_path
  source_code_hash = data.archive_file.connector_oauth_lambda[0].output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      WORKSPACE_REVISIONS_TABLE    = var.workspace_revisions_table_name
      CONNECTOR_NAMESPACE          = local.connector_namespace
      CONNECTOR_AUTH_TABLE         = var.connector_auth_table_name
      CONNECTOR_ISSUER             = local.connector_issuer
      CONNECTOR_RESOURCE           = var.connector_oauth_resource
      CONNECTOR_HOSTED_UI_DOMAIN   = var.connector_hosted_ui_domain
      CONNECTOR_IDENTITY_CLIENT_ID = var.connector_identity_client_id
      CONNECTOR_SCOPE_PROFILE      = local.mcp_read_enabled ? var.workspace_mcp_profile : "legacy"
      CONNECTOR_WRITE_ADMISSION    = local.mcp_write_enabled ? "enabled" : ""
    })
  }

  depends_on = [aws_iam_role_policy.connector_oauth_lambda]

  tags = { Name = "vaultguard-connector-oauth-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "connector_oauth" {
  count = local.connector_enabled

  name              = "/aws/lambda/${aws_lambda_function.connector_oauth[0].function_name}"
  retention_in_days = local.log_retention
}

output "connector_oauth_function_invoke_arn" {
  value = var.connector_oauth_resource == "" ? "" : aws_lambda_function.connector_oauth[0].invoke_arn
}

output "connector_oauth_function_name" {
  value = var.connector_oauth_resource == "" ? "" : aws_lambda_function.connector_oauth[0].function_name
}

output "connector_authorization_server" {
  description = "VaultGuard's own issuer. Empty when the lane is disabled."
  value       = local.connector_issuer
}
