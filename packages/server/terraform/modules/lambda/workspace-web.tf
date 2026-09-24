variable "workspace_web_origin" {
  type        = string
  default     = ""
  description = "Explicit HTTPS browser origin for independently authenticated handoffs. Empty disables handoff consumption."
}
# Source-only browser read host. Existing capability controls remain disabled.
variable "workspace_web_cursor_key_secret_arn" {
  type        = string
  default     = ""
  description = "Explicit Secrets Manager ARN containing a 32-byte base64 web cursor key."
}
locals {
  workspace_web_enabled = var.workspace_capabilities.revision_reads && var.vaultguard_edition == "pro"
  workspace_web_count   = local.workspace_web_enabled ? 1 : 0
}
check "workspace_web_key_is_explicit" {
  assert {
    condition     = !local.workspace_web_enabled || startswith(var.workspace_web_cursor_key_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:")
    error_message = "Workspace browser reads require their explicit cursor-key secret in this account and region."
  }
}
data "archive_file" "workspace_web" {
  count       = local.workspace_web_count
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/workspace-web"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/workspace-web.zip"
}
resource "aws_iam_role" "workspace_web" {
  count              = local.workspace_web_count
  name               = "vaultguard-${var.stage}-workspace-web"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "workspace_web_logging" {
  count      = local.workspace_web_count
  role       = aws_iam_role.workspace_web[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "workspace_web" {
  count = local.workspace_web_count

  # Live human authority and exact reads; mutations have separate bounded grants.
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:BatchGetItem"]
    resources = [
      var.organizations_table_arn, "${var.organizations_table_arn}/index/*",
      var.subscriptions_table_arn,
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
      var.permissions_table_arn, "${var.permissions_table_arn}/index/*",
      var.vault_activity_table_arn, "${var.vault_activity_table_arn}/index/*",
      var.sessions_table_arn, "${var.sessions_table_arn}/index/*",
      var.user_keys_table_arn, "${var.user_keys_table_arn}/index/*",
      var.revoked_keys_table_arn,
      var.shares_table_arn, "${var.shares_table_arn}/index/*",
      var.file_versions_table_arn, "${var.file_versions_table_arn}/index/*",
      var.workspace_revisions_table_arn,
    ]
  }
  dynamic "statement" {
    for_each = var.connector_auth_table_arn == "" ? [] : [var.connector_auth_table_arn]
    content {
      actions   = ["dynamodb:GetItem", "dynamodb:ConditionCheckItem", "dynamodb:Query"]
      resources = [statement.value]
    }
  }
  dynamic "statement" {
    for_each = var.connector_auth_table_arn == "" ? [] : [var.connector_auth_table_arn]
    content {
      actions   = ["dynamodb:UpdateItem"]
      resources = [statement.value]
      condition {
        test     = "ForAllValues:StringLike"
        variable = "dynamodb:LeadingKeys"
        values   = ["CONNECTOR#GRANT#*", "CONNECTOR#SESSION#*", "WEB-HANDOFF#*", "TRANSFER-HANDOFF#*"]
      }
    }
  }
  dynamic "statement" {
    for_each = var.connector_auth_table_arn == "" ? [] : [var.connector_auth_table_arn]
    content {
      actions   = ["dynamodb:PutItem"]
      resources = [statement.value]
      condition {
        test     = "ForAllValues:StringLike"
        variable = "dynamodb:LeadingKeys"
        values   = ["CONNECTOR-REVOCATION#*"]
      }
    }
  }
  # The existing strong permission snapshot owner performs bounded primary-table
  # scans; GSIs cannot supply a strongly consistent authorization inventory.
  statement {
    actions   = ["dynamodb:Scan"]
    resources = [var.permissions_table_arn, var.vault_members_table_arn]
  }
  # VAULTGUARD-91: a recovery handoff completes only when the human's recovery
  # code set was stored after the handoff opened. Only the key attributes and
  # the creation instant may be requested, and only as a projection.
  statement {
    actions   = ["dynamodb:Query"]
    resources = [var.recovery_codes_table_arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "dynamodb:Attributes"
      values   = ["userId", "codeHash", "createdAt"]
    }
    condition {
      test     = "StringEqualsIfExists"
      variable = "dynamodb:Select"
      values   = ["SPECIFIC_ATTRIBUTES"]
    }
  }
  statement {
    actions = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "${var.vault_bucket_arn}/vault/*",
      "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQta25vd2xlZGdl/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*",
      # Exact committed logical versions may reference private apply candidates.
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtYXBwbHk/*",
    ]
  }
  # Only encrypted knowledge inventories/definitions/proposals, never canonical
  # content or authorization rows. All capabilities remain disabled by default.
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WEB-KNOWLEDGE#*", "WEB-CONTEXT#*", "PERSONAL-CONTEXT#*", "WORKSPACE#*"]
    }
  }
  statement {
    actions = ["s3:PutObject"]
    resources = [
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQta25vd2xlZGdl/*/authorized-inventory/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQta25vd2xlZGdl/*/context-version/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQta25vd2xlZGdl/*/context-overlay/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQta25vd2xlZGdl/*/context-proposal/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/collaboration-record/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/collaboration-handoff/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/approval-reviewer-proof/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/access-workflow/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/access-domain-write/*",
    ]
  }
  # Web proposal editing writes only encrypted exact-revision resolver chunks.
  dynamic "statement" {
    for_each = var.workspace_capabilities.web_editing && var.workspace_capabilities.revision_writes ? [1] : []
    content {
      actions   = ["s3:PutObject"]
      resources = ["${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/proposal-resolver-index/*"]
    }
  }
  statement {
    actions   = ["kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = compact([var.vaults_table_arn, var.sessions_table_arn, var.organizations_table_arn, var.connector_auth_table_arn, var.revoked_keys_table_arn])
  }
  # Source-only governed access host. Explicit editing + write capabilities
  # are required before canonical authority-domain mutations receive IAM rights.
  dynamic "statement" {
    for_each = var.workspace_capabilities.web_editing && var.workspace_capabilities.revision_writes ? [1] : []
    content {
      actions = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:ConditionCheckItem"]
      resources = [var.vaults_table_arn, var.vault_members_table_arn, var.permissions_table_arn,
        var.shares_table_arn, var.vault_activity_table_arn, var.leases_table_arn,
      var.audit_table_arn]
    }
  }
  # Native sync needs only the existing vault authorization lease/activity owners;
  # it receives no permission, membership, share or invitation mutation rights.
  dynamic "statement" {
    for_each = var.workspace_capabilities.first_party_sync && var.workspace_capabilities.revision_writes ? [1] : []
    content {
      actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:ConditionCheckItem"]
      resources = [var.vaults_table_arn, var.vault_activity_table_arn]
    }
  }
  # The canonical set-level owner resolves principals and assembles access
  # summaries with ListUsers; add-member proof uses AdminGetUser only.
  statement {
    actions   = ["cognito-idp:AdminGetUser", "cognito-idp:AdminListGroupsForUser", "cognito-idp:ListUsers"]
    resources = [var.cognito_user_pool_arn]
  }
  statement {
    actions   = ["dynamodb:Query", "dynamodb:Scan"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
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
  # Every exact history/export read records the canonical content-free audit.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # Actual publication owners: immutable candidates, logical versions, identity,
  # quota and writer-fence state. No rights exist while write/edit gates are off.
  dynamic "statement" {
    for_each = (var.workspace_capabilities.web_editing || var.workspace_capabilities.first_party_sync) && var.workspace_capabilities.revision_writes ? [1] : []
    content {
      actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
      resources = [var.workspace_revisions_table_arn, var.file_versions_table_arn, var.user_keys_table_arn, var.organizations_table_arn]
    }
  }
  # Publication reclaims an encrypted collaboration record it staged for a commit or
  # failure write that did not land, once it has proven that no row can ever reference
  # it (VAULTGUARD-128). Exact stored versions of that one artifact kind only, and only
  # while the publication write rights above exist.
  dynamic "statement" {
    for_each = (var.workspace_capabilities.web_editing || var.workspace_capabilities.first_party_sync) && var.workspace_capabilities.revision_writes ? [1] : []
    content {
      actions   = ["s3:DeleteObjectVersion"]
      resources = ["${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/collaboration-record/*"]
    }
  }
  statement {
    actions = ["s3:PutObject"]
    resources = [
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/browser-transfer/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/browser-upload/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/proposal-upload/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/collaboration-operations/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/collaboration-preview/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/transfer-handoff/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/apply-preparation-journal/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtY29sbGFib3JhdGlvbg/*/apply-preparation-ready/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtYXBwbHk/*",
      "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*",
    ]
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
    resources = [var.workspace_web_cursor_key_secret_arn]
  }
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ObsidianVaultGuard"]
    }
  }
}

resource "aws_iam_role_policy" "workspace_web" {
  count  = local.workspace_web_count
  name   = "vaultguard-${var.stage}-workspace-web"
  role   = aws_iam_role.workspace_web[0].id
  policy = data.aws_iam_policy_document.workspace_web[0].json
}
resource "aws_lambda_function" "workspace_web" {
  count                          = local.workspace_web_count
  function_name                  = "vaultguard-workspace-web-${var.stage}"
  description                    = "Authenticated bounded browser workspace reads"
  role                           = aws_iam_role.workspace_web[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 512
  timeout                        = 30
  reserved_concurrent_executions = 10
  filename                       = data.archive_file.workspace_web[0].output_path
  source_code_hash               = data.archive_file.workspace_web[0].output_base64sha256
  environment {
    variables = merge(local.common_env, local.workspace_runtime_env, {
      USER_POOL_ID                        = var.cognito_user_pool_id
      CONNECTOR_AUTH_TABLE                = var.connector_auth_table_name
      WORKSPACE_WEB_ORIGIN                = var.workspace_web_origin
      SIGNUP_LEGAL_VERSION                = var.signup_legal_version
      WORKSPACE_LEGAL_TERMS_URL           = var.signup_legal_version == "" ? "" : "https://example.com/terms"
      WORKSPACE_COHORT_CONTROL_TABLE      = var.workspace_revisions_table_name
      WORKSPACE_REVISIONS_TABLE           = var.workspace_revisions_table_name
      FILE_VERSIONS_TABLE                 = var.file_versions_table_name
      WORKSPACE_WEB_CURSOR_KEY_SECRET_ARN = var.workspace_web_cursor_key_secret_arn
    })
  }
  depends_on = [aws_iam_role_policy.workspace_web, aws_iam_role_policy_attachment.workspace_web_logging]
}
resource "aws_cloudwatch_log_group" "workspace_web" {
  count             = local.workspace_web_count
  name              = "/aws/lambda/${aws_lambda_function.workspace_web[0].function_name}"
  retention_in_days = local.log_retention
}
output "workspace_web_enabled" { value = local.workspace_web_enabled }
output "workspace_web_function_invoke_arn" { value = local.workspace_web_enabled ? aws_lambda_function.workspace_web[0].invoke_arn : "" }
output "workspace_web_function_name" { value = local.workspace_web_enabled ? aws_lambda_function.workspace_web[0].function_name : "" }
