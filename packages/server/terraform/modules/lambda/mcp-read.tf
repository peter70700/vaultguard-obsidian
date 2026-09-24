# Production-shaped read host. Source preparation only: existing capability
# flags and connector configuration keep every resource disabled by default.
variable "mcp_cursor_key_secret_arn" {
  type        = string
  default     = ""
  description = "Explicit Secrets Manager ARN containing a 32-byte base64 MCP cursor key. No fallback secret."
}

data "aws_partition" "current" {}

locals {
  mcp_read_enabled     = var.connector_oauth_resource != "" && var.workspace_capabilities.remote_mcp && var.vaultguard_edition == "pro"
  mcp_read_count       = local.mcp_read_enabled ? 1 : 0
  mcp_read_only_count  = local.mcp_read_enabled && !local.mcp_write_enabled ? 1 : 0
  mcp_knowledge_prefix = "X3ZhdWx0Z3VhcmQta25vd2xlZGdl"
  mcp_read_env = {
    USER_POOL_ID                 = var.cognito_user_pool_id
    CONNECTOR_NAMESPACE          = local.connector_namespace
    CONNECTOR_AUTH_TABLE         = var.connector_auth_table_name
    CONNECTOR_ISSUER             = local.connector_issuer
    CONNECTOR_RESOURCE           = var.connector_oauth_resource
    CONNECTOR_HOSTED_UI_DOMAIN   = var.connector_hosted_ui_domain
    CONNECTOR_IDENTITY_CLIENT_ID = var.connector_identity_client_id
    CONNECTOR_SCOPE_PROFILE      = "workspace-read-v1"
    WORKSPACE_REVISIONS_TABLE    = var.workspace_revisions_table_name
    FILE_VERSIONS_TABLE          = var.file_versions_table_name
    MCP_CURSOR_KEY_SECRET_ARN    = var.mcp_cursor_key_secret_arn
    # VAULTGUARD-91: empty keeps create_web_handoff/get_handoff_status out of the
    # catalog; set, the host issues the ceremonies the web consumer completes.
    WORKSPACE_WEB_ORIGIN = var.workspace_web_origin
  }
}

check "mcp_read_handoff_origin_is_https" {
  assert {
    condition     = var.workspace_web_origin == "" || can(regex("^https://[A-Za-z0-9.-]+$", var.workspace_web_origin))
    error_message = "The web handoff origin must be empty or a bare HTTPS origin."
  }
}

check "mcp_read_inputs_are_explicit" {
  assert {
    condition = !local.mcp_read_enabled || (
      var.connector_auth_table_name == "${local.connector_namespace}-auth" &&
      startswith(var.mcp_cursor_key_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:")
    )
    error_message = "Enabling the MCP read host requires its connector table and an explicit cursor-key secret in this account and region."
  }
}

data "archive_file" "mcp_read_lambda" {
  count       = local.mcp_read_count
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/mcp-read"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/mcp-read.zip"
}

resource "aws_iam_role" "mcp_read_lambda" {
  count              = local.mcp_read_count
  name               = "vaultguard-${var.stage}-mcp-read-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "mcp_read_logging" {
  count      = local.mcp_read_count
  role       = aws_iam_role.mcp_read_lambda[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "mcp_read_lambda" {
  count = local.mcp_read_count

  # Live authority, exact revisions and governance reads. No vault-content,
  # permission, membership, grant, session-revocation or key mutations.
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchGetItem"]
    resources = [
      var.organizations_table_arn, "${var.organizations_table_arn}/index/*",
      var.subscriptions_table_arn,
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
      var.permissions_table_arn, "${var.permissions_table_arn}/index/*",
      var.vault_activity_table_arn, "${var.vault_activity_table_arn}/index/*",
      var.shares_table_arn, "${var.shares_table_arn}/index/*",
      var.audit_table_arn, "${var.audit_table_arn}/index/*",
      var.sessions_table_arn, "${var.sessions_table_arn}/index/*",
      var.user_keys_table_arn, "${var.user_keys_table_arn}/index/*",
      var.revoked_keys_table_arn,
      var.file_versions_table_arn, "${var.file_versions_table_arn}/index/*",
      var.workspace_revisions_table_arn,
      var.connector_auth_table_arn,
    ]
  }
  # The existing strong permission snapshot owner performs bounded primary-table
  # scans; GSIs cannot supply a strongly consistent authorization inventory.
  statement {
    actions   = ["dynamodb:Scan"]
    resources = [var.permissions_table_arn]
  }
  # Transaction members are authorized by item actions and ConditionCheckItem,
  # not a TransactWriteItems IAM action. These prefixes cannot modify grants,
  # clients, credentials or MCP-DELEGATION consent rows. MCP#* also carries the
  # bounded MCP#CONNECTOR-USE# last-use records (VAULTGUARD-91).
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.connector_auth_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["MCP#*", "MCP-QUOTA#*", "AUDIT#*"]
    }
  }
  statement {
    actions = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "${var.vault_bucket_arn}/vault/*",
      "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*",
      # Readable only through an exact committed logical version binding.
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtYXBwbHk/*",
    ]
  }
  statement {
    actions   = ["cognito-idp:ListUsers", "cognito-idp:AdminGetUser", "cognito-idp:AdminListGroupsForUser"]
    resources = [var.cognito_user_pool_arn]
  }
  # Reads existing wrapped vault keys; neither HTTP nor preparation generates
  # keys. The crypto owner supplies the vault-scoped encryption context.
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["vault-scope-dek"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:vaultId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:orgId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:scope"
      values   = ["false"]
    }
  }
  # Storage-service encryption uses its own context, separate from direct DEK
  # unwraps. Only the application's existing CMK can be used here.
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "dynamodb.${data.aws_region.current.name}.amazonaws.com",
        "s3.${data.aws_region.current.name}.amazonaws.com",
        "secretsmanager.${data.aws_region.current.name}.amazonaws.com",
      ]
    }
  }
  statement {
    actions   = ["kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.mcp_cursor_key_secret_arn]
  }
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["VaultGuard/MCP", "ObsidianVaultGuard"]
    }
  }
}

# VAULTGUARD-113: the HTTP host's own additions. The internal preparation role
# sources mcp_read_lambda, not this document, so it cannot write audit rows.
data "aws_iam_policy_document" "mcp_read_host" {
  count                   = local.mcp_read_count
  source_policy_documents = [data.aws_iam_policy_document.mcp_read_lambda[0].json, data.aws_iam_policy_document.mcp_inventory[0].json]
  # One canonical organization-audit event per tools/call, the rows query_audit
  # and the administrator audit API read by vault and time. The grant is PutItem
  # only, but IAM cannot require the writer's attribute_not_exists(pk) condition:
  # create-only is an application guarantee, and an unconditional PutItem under
  # this role could replace an existing audit item. That matches the documented
  # posture of the audit table: durable, not WORM or tamper-evident.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # VAULTGUARD-91: the ceremony handoff issuer writes exactly its pending
  # handoff, nonce pointer and creation-quota rows. It never opens, completes
  # or revokes one; only the independently authenticated web host does. The
  # preparation role never issues a handoff, so this lives on the host alone.
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.connector_auth_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WEB-HANDOFF#*", "WEB-HANDOFF-NONCE#*", "WEB-HANDOFF-QUOTA#*"]
    }
  }
}

resource "aws_iam_role_policy" "mcp_read_lambda" {
  count  = local.mcp_read_count
  name   = "vaultguard-${var.stage}-mcp-read-lambda"
  role   = aws_iam_role.mcp_read_lambda[0].id
  policy = data.aws_iam_policy_document.mcp_read_host[0].json
}

resource "aws_lambda_function" "mcp_read" {
  count                          = local.mcp_read_only_count
  function_name                  = "vaultguard-mcp-read-${var.stage}"
  description                    = "Authorized, bounded workspace read MCP host"
  role                           = aws_iam_role.mcp_read_lambda[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 512
  timeout                        = 30
  reserved_concurrent_executions = 10
  filename                       = data.archive_file.mcp_read_lambda[0].output_path
  source_code_hash               = data.archive_file.mcp_read_lambda[0].output_base64sha256
  environment { variables = merge(local.common_env, local.workspace_runtime_env, local.mcp_read_env) }
  depends_on = [aws_iam_role_policy.mcp_read_lambda, aws_iam_role_policy_attachment.mcp_read_logging]
}

resource "aws_cloudwatch_log_group" "mcp_read" {
  count             = local.mcp_read_only_count
  name              = "/aws/lambda/${aws_lambda_function.mcp_read[0].function_name}"
  retention_in_days = local.log_retention
}

# Internal materialization is a distinct execution role and handler. It has no
# API Gateway integration, Lambda URL or resource-based invoke permission.
resource "aws_iam_role" "mcp_read_prepare" {
  count              = local.mcp_read_count
  name               = "vaultguard-${var.stage}-mcp-read-prepare"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "mcp_read_prepare_logging" {
  count      = local.mcp_read_count
  role       = aws_iam_role.mcp_read_prepare[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "mcp_read_prepare" {
  count                   = local.mcp_read_count
  source_policy_documents = [data.aws_iam_policy_document.mcp_read_lambda[0].json, data.aws_iam_policy_document.mcp_inventory[0].json]
}

resource "aws_iam_role_policy" "mcp_read_prepare" {
  count  = local.mcp_read_count
  name   = "vaultguard-${var.stage}-mcp-read-prepare"
  role   = aws_iam_role.mcp_read_prepare[0].id
  policy = data.aws_iam_policy_document.mcp_read_prepare[0].json
}

resource "aws_lambda_function" "mcp_read_prepare" {
  count                          = local.mcp_read_only_count
  function_name                  = "vaultguard-mcp-read-prepare-${var.stage}"
  description                    = "Internal authorized read-inventory preparation; no HTTP route"
  role                           = aws_iam_role.mcp_read_prepare[0].arn
  handler                        = "handler.prepareHandler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 512
  timeout                        = 60
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.mcp_read_lambda[0].output_path
  source_code_hash               = data.archive_file.mcp_read_lambda[0].output_base64sha256
  environment { variables = merge(local.common_env, local.workspace_runtime_env, local.mcp_read_env) }
  depends_on = [aws_iam_role_policy.mcp_read_prepare, aws_iam_role_policy_attachment.mcp_read_prepare_logging]
}

resource "aws_cloudwatch_log_group" "mcp_read_prepare" {
  count             = local.mcp_read_only_count
  name              = "/aws/lambda/${aws_lambda_function.mcp_read_prepare[0].function_name}"
  retention_in_days = local.log_retention
}

output "mcp_read_enabled" { value = local.mcp_read_enabled }
output "mcp_read_function_invoke_arn" { value = local.mcp_write_enabled ? aws_lambda_function.mcp_write[0].invoke_arn : (local.mcp_read_enabled ? aws_lambda_function.mcp_read[0].invoke_arn : "") }
output "mcp_read_function_name" { value = local.mcp_write_enabled ? aws_lambda_function.mcp_write[0].function_name : (local.mcp_read_enabled ? aws_lambda_function.mcp_read[0].function_name : "") }

data "aws_iam_policy_document" "mcp_inventory" {
  count = local.mcp_read_count
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["KNOWLEDGE_ACCESS#*"]
    }
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/authorized-inventory/*"]
  }
  # The vault bucket uses SSE-KMS in addition to application envelope encryption.
  # S3 needs its own data key for this PutObject; no direct DEK creation is allowed.
  statement {
    actions   = ["kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}
