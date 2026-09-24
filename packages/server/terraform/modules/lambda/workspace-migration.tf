variable "workspace_operator_environment_id" {
  type    = string
  default = ""
}
variable "workspace_migration_redaction_key_secret_arn" {
  type    = string
  default = ""
}
check "workspace_migration_owners" {
  assert {
    condition = !var.workspace_operator_enabled || (
      can(regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", var.workspace_operator_environment_id)) &&
      startswith(var.workspace_migration_redaction_key_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:") &&
      startswith(var.workspace_web_cursor_key_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:")
    )
    error_message = "Operator migration requires explicit source/environment identity, private redaction key and the SAME web adoption key."
  }
}
data "archive_file" "workspace_migration" {
  count       = var.workspace_operator_enabled ? 1 : 0
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/workspace-migration"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/workspace-migration.zip"
}
resource "aws_iam_role" "workspace_migration" {
  count              = var.workspace_operator_enabled ? 1 : 0
  name               = "vaultguard-${var.stage}-workspace-migration"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "workspace_migration_logging" {
  count      = var.workspace_operator_enabled ? 1 : 0
  role       = aws_iam_role.workspace_migration[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "workspace_migration" {
  count = var.workspace_operator_enabled ? 1 : 0
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.workspace_revisions_table_arn, var.user_keys_table_arn, var.vaults_table_arn, var.file_versions_table_arn]
  }
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["MIGRATION-RUN#*", "WORKSPACE-COHORT#*"]
    }
  }
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE#*"]
    }
  }
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = [var.user_keys_table_arn]
  }
  statement {
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [var.vault_bucket_arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["vault/*"]
    }
  }
  # Metadata HEADs need GetObject; source never reads vault bodies. No legacy
  # source writes, key rotation, permissions, policies or revision-head changes.
  statement {
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.vault_bucket_arn}/vault/*", "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*", "${var.vault_bucket_arn}/_vaultguard-workspace-shadow/*"]
  }
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${var.vault_bucket_arn}/_vaultguard-workspace-shadow/*"]
  }
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.workspace_migration_redaction_key_secret_arn, var.workspace_web_cursor_key_secret_arn]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com", "secretsmanager.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
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
      variable = "kms:EncryptionContext:orgId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:vaultId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:scope"
      values   = ["false"]
    }
  }
}
resource "aws_iam_role_policy" "workspace_migration" {
  count  = var.workspace_operator_enabled ? 1 : 0
  name   = "vaultguard-${var.stage}-workspace-migration"
  role   = aws_iam_role.workspace_migration[0].id
  policy = data.aws_iam_policy_document.workspace_migration[0].json
}
resource "aws_lambda_function" "workspace_migration" {
  count                          = var.workspace_operator_enabled ? 1 : 0
  function_name                  = "vaultguard-workspace-migration-${var.stage}"
  role                           = aws_iam_role.workspace_migration[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 1024
  timeout                        = 120
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.workspace_migration[0].output_path
  source_code_hash               = data.archive_file.workspace_migration[0].output_base64sha256
  environment {
    variables = merge(local.common_env, {
      WORKSPACE_OPERATOR_ENABLED                   = "true"
      WORKSPACE_REVISIONS_TABLE                    = var.workspace_revisions_table_name
      FILE_VERSIONS_TABLE                          = var.file_versions_table_name
      WORKSPACE_SOURCE_COMMIT                      = data.external.lambda_build.result.commit
      WORKSPACE_OPERATOR_ENVIRONMENT_ID            = var.workspace_operator_environment_id
      WORKSPACE_MIGRATION_REDACTION_KEY_SECRET_ARN = var.workspace_migration_redaction_key_secret_arn
      WORKSPACE_WEB_CURSOR_KEY_SECRET_ARN          = var.workspace_web_cursor_key_secret_arn
    })
  }
  depends_on = [aws_iam_role_policy.workspace_migration, aws_iam_role_policy_attachment.workspace_migration_logging]
}
resource "aws_cloudwatch_log_group" "workspace_migration" {
  count             = var.workspace_operator_enabled ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.workspace_migration[0].function_name}"
  retention_in_days = local.log_retention
}
