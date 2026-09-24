# Source only. Admission, capability, edition and explicit owners all fail closed.
variable "workspace_mcp_profile" {
  type    = string
  default = "workspace-read-v1"
  validation {
    condition     = contains(["workspace-read-v1", "workspace-proposal-v1", "workspace-access-v1", "workspace-transfer-v1"], var.workspace_mcp_profile)
    error_message = "Use an existing reviewed connector admission profile."
  }
}
variable "mcp_transfer_nonce_key_secret_arn" {
  type    = string
  default = ""
}
locals {
  mcp_write_enabled = local.mcp_read_enabled && var.workspace_mcp_profile != "workspace-read-v1"
  mcp_write_count   = local.mcp_write_enabled ? 1 : 0
  mcp_write_env = merge(local.mcp_read_env, {
    CONNECTOR_SCOPE_PROFILE             = var.workspace_mcp_profile
    CONNECTOR_WRITE_ADMISSION           = "enabled"
    MCP_TRANSFER_NONCE_KEY_SECRET_ARN    = var.mcp_transfer_nonce_key_secret_arn
    WORKSPACE_COHORT_CONTROL_TABLE      = var.workspace_revisions_table_name
  })
}
check "mcp_write_owners_are_explicit" {
  assert {
    condition = !local.mcp_write_enabled || (
      var.workspace_mcp_write_admission && var.workspace_cohort_controls_enabled && var.workspace_capabilities.revision_reads && var.workspace_capabilities.revision_writes &&
      var.workspace_capabilities.projections && var.workspace_web_origin != "" &&
      startswith(var.mcp_transfer_nonce_key_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:")
    )
    error_message = "Write admission needs revision read/write and projection capabilities, the human web origin and a same-account nonce key. No capability is enabled implicitly."
  }
}
data "archive_file" "mcp_write" {
  count       = local.mcp_write_count
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/mcp-write"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/mcp-write.zip"
}
resource "aws_iam_role" "mcp_write" {
  count              = local.mcp_write_count
  name               = "vaultguard-${var.stage}-mcp-write"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "mcp_write_logging" {
  count      = local.mcp_write_count
  role       = aws_iam_role.mcp_write[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "mcp_write" {
  count = local.mcp_write_count
  source_policy_documents = [
    data.aws_iam_policy_document.mcp_read_host[0].json,
    data.aws_iam_policy_document.workspace_collaboration_storage.json,
  ]
  # Canonical revisions, identity, proposal/approval/context and coordination
  # owners. No DeleteItem or cohort CONTROL write belongs to this process.
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE#*", "IDENTITY#*", "WEB-CONTEXT#*"]
    }
  }
  # Exact-revision resolver metadata uses a create-only pointer row. Keep this
  # grant separate from canonical revision and identity mutations.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["PROPOSAL-INDEX#*"]
    }
  }
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-COHORT#*"]
    }
  }
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:ConditionCheckItem"]
    resources = [var.file_versions_table_arn]
  }
  # Existing writer leases, key-generation fences and organization quota CAS.
  # These permissions cannot create or rotate a vault DEK.
  statement {
    actions   = ["dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.user_keys_table_arn, var.organizations_table_arn]
  }
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn, var.connector_auth_table_arn]
  }
  statement {
    actions = ["s3:PutObject"]
    resources = [
      "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtYXBwbHk/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/context-version/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/context-proposal/*",
    ]
  }
  # Reclaim only the exact version of a staged collaboration record proved
  # unreferenced by the canonical publication owner (VAULTGUARD-128).
  statement {
    actions   = ["s3:DeleteObjectVersion"]
    resources = ["${var.vault_bucket_arn}/${local.collaboration_artifact_prefix}/*/collaboration-record/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*", var.vault_members_table_arn]
  }
  # Access/share changes keep the existing service's review, role and path gates.
  # Proposal-only admission receives no authority-domain mutation rights.
  dynamic "statement" {
    for_each = contains(["workspace-access-v1", "workspace-transfer-v1"], var.workspace_mcp_profile) ? [1] : []
    content {
      actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:ConditionCheckItem"]
      resources = [var.permissions_table_arn, var.vault_members_table_arn, var.shares_table_arn, var.leases_table_arn]
    }
  }
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.vaults_table_arn, var.vault_activity_table_arn]
  }
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.connector_auth_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["TRANSFER-HANDOFF#*", "TRANSFER-NONCE#*", "TRANSFER-QUOTA#*"]
    }
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.mcp_transfer_nonce_key_secret_arn]
  }
}
resource "aws_iam_role_policy" "mcp_write" {
  count  = local.mcp_write_count
  name   = "vaultguard-${var.stage}-mcp-write"
  role   = aws_iam_role.mcp_write[0].id
  policy = data.aws_iam_policy_document.mcp_write[0].json
}
resource "aws_lambda_function" "mcp_write" {
  count                          = local.mcp_write_count
  function_name                  = "vaultguard-mcp-write-${var.stage}"
  description                    = "Canonical delegated workspace proposal, publication and review host"
  role                           = aws_iam_role.mcp_write[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 1024
  timeout                        = 29
  reserved_concurrent_executions = 5
  filename                       = data.archive_file.mcp_write[0].output_path
  source_code_hash               = data.archive_file.mcp_write[0].output_base64sha256
  environment { variables = merge(local.common_env, local.workspace_runtime_env, local.mcp_write_env) }
  depends_on = [aws_iam_role_policy.mcp_write, aws_iam_role_policy_attachment.mcp_write_logging]
}
resource "aws_cloudwatch_log_group" "mcp_write" {
  count             = local.mcp_write_count
  name              = "/aws/lambda/${aws_lambda_function.mcp_write[0].function_name}"
  retention_in_days = local.log_retention
}
# Internal preparation uses the actual admission profile but never receives
# publication/access mutation rights or an HTTP/function-URL invoke grant.
resource "aws_iam_role" "mcp_write_prepare" {
  count              = local.mcp_write_count
  name               = "vaultguard-${var.stage}-mcp-write-prepare"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "mcp_write_prepare_logging" {
  count      = local.mcp_write_count
  role       = aws_iam_role.mcp_write_prepare[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "mcp_write_prepare" {
  count                   = local.mcp_write_count
  source_policy_documents = [data.aws_iam_policy_document.mcp_read_prepare[0].json]
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.mcp_transfer_nonce_key_secret_arn]
  }
}
resource "aws_iam_role_policy" "mcp_write_prepare" {
  count  = local.mcp_write_count
  name   = "vaultguard-${var.stage}-mcp-write-prepare"
  role   = aws_iam_role.mcp_write_prepare[0].id
  policy = data.aws_iam_policy_document.mcp_write_prepare[0].json
}
resource "aws_lambda_function" "mcp_write_prepare" {
  count                          = local.mcp_write_count
  function_name                  = "vaultguard-mcp-write-prepare-${var.stage}"
  role                           = aws_iam_role.mcp_write_prepare[0].arn
  handler                        = "handler.prepareHandler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 1024
  timeout                        = 60
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.mcp_write[0].output_path
  source_code_hash               = data.archive_file.mcp_write[0].output_base64sha256
  environment { variables = merge(local.common_env, local.workspace_runtime_env, local.mcp_write_env) }
  depends_on = [aws_iam_role_policy.mcp_write_prepare, aws_iam_role_policy_attachment.mcp_write_prepare_logging]
}
resource "aws_cloudwatch_log_group" "mcp_write_prepare" {
  count             = local.mcp_write_count
  name              = "/aws/lambda/${aws_lambda_function.mcp_write_prepare[0].function_name}"
  retention_in_days = local.log_retention
}

variable "workspace_mcp_write_admission" {
  type    = bool
  default = false
}
