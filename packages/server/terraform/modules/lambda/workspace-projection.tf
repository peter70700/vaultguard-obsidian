# Explicit IAM-only bounded consumer/rebuild and separately disabled scheduled
# durable-head delivery. No product invoke policy, public route or provider credential.
locals {
  workspace_projection_count = var.workspace_capabilities.projections && var.vaultguard_edition == "pro" ? 1 : 0
}
check "workspace_projection_owners" {
  assert {
    condition = local.workspace_projection_count == 0 || (var.workspace_capabilities.revision_reads && var.workspace_cohort_controls_enabled)
    error_message = "Projection preparation needs revision reads and the shared cohort controls."
  }
}
data "archive_file" "workspace_projection" {
  count       = local.workspace_projection_count
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/workspace-projection"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/workspace-projection.zip"
}
resource "aws_iam_role" "workspace_projection" {
  count              = local.workspace_projection_count
  name               = "vaultguard-${var.stage}-workspace-projection"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "workspace_projection_logging" {
  count      = local.workspace_projection_count
  role       = aws_iam_role.workspace_projection[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "workspace_projection" {
  count = local.workspace_projection_count
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE#*", "LEXICAL#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-COHORT#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.file_versions_table_arn, var.user_keys_table_arn]
  }
  statement {
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${var.vault_bucket_arn}/vault/*", "${var.vault_bucket_arn}/_vaultguard-workspace-revisions/*",
      "${var.vault_bucket_arn}/X3ZhdWx0Z3VhcmQtYXBwbHk/*", "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*"]
  }
  statement {
    actions = ["s3:PutObject"]
    resources = ["${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/graph-revision/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/graph-file/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/graph-folder/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/graph-links/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/graph-progress/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/lexical-file/*",
      "${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/lexical-revision/*"]
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
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "workspace_projection" {
  count  = local.workspace_projection_count
  name   = "vaultguard-${var.stage}-workspace-projection"
  role   = aws_iam_role.workspace_projection[0].id
  policy = data.aws_iam_policy_document.workspace_projection[0].json
}
resource "aws_lambda_function" "workspace_projection" {
  count                          = local.workspace_projection_count
  function_name                  = "vaultguard-workspace-projection-${var.stage}"
  role                           = aws_iam_role.workspace_projection[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 1024
  timeout                        = 120
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.workspace_projection[0].output_path
  source_code_hash               = data.archive_file.workspace_projection[0].output_base64sha256
  environment {
    variables = merge(local.common_env, local.workspace_runtime_env, {
      WORKSPACE_REVISIONS_TABLE = var.workspace_revisions_table_name
      FILE_VERSIONS_TABLE = var.file_versions_table_name
    })
  }
  depends_on = [aws_iam_role_policy.workspace_projection, aws_iam_role_policy_attachment.workspace_projection_logging]
}
resource "aws_cloudwatch_log_group" "workspace_projection" {
  count             = local.workspace_projection_count
  name              = "/aws/lambda/${aws_lambda_function.workspace_projection[0].function_name}"
  retention_in_days = local.log_retention
}

variable "workspace_projection_delivery_enabled" {
  type    = bool
  default = false
}
check "workspace_projection_delivery_gate" {
  assert {
    condition     = !var.workspace_projection_delivery_enabled || local.workspace_projection_count == 1
    error_message = "Background projection delivery requires the explicit projection deployment."
  }
}
resource "aws_lambda_function" "workspace_projection_delivery" {
  count                          = local.workspace_projection_count
  function_name                  = "vaultguard-workspace-projection-delivery-${var.stage}"
  role                           = aws_iam_role.workspace_projection[0].arn
  handler                        = "handler.scheduledHandler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 1024
  timeout                        = 120
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.workspace_projection[0].output_path
  source_code_hash               = data.archive_file.workspace_projection[0].output_base64sha256
  environment {
    variables = merge(local.common_env, local.workspace_runtime_env, {
      WORKSPACE_REVISIONS_TABLE = var.workspace_revisions_table_name
      FILE_VERSIONS_TABLE       = var.file_versions_table_name
    })
  }
  depends_on = [aws_iam_role_policy.workspace_projection, aws_iam_role_policy_attachment.workspace_projection_logging]
}
resource "aws_cloudwatch_log_group" "workspace_projection_delivery" {
  count             = local.workspace_projection_count
  name              = "/aws/lambda/${aws_lambda_function.workspace_projection_delivery[0].function_name}"
  retention_in_days = local.log_retention
}
resource "aws_cloudwatch_event_rule" "workspace_projection_delivery" {
  count               = local.workspace_projection_count
  name                = "vaultguard-${var.stage}-workspace-projection-delivery"
  schedule_expression = "rate(1 minute)"
  state               = var.workspace_projection_delivery_enabled ? "ENABLED" : "DISABLED"
}
resource "aws_cloudwatch_event_target" "workspace_projection_delivery" {
  count = local.workspace_projection_count
  rule  = aws_cloudwatch_event_rule.workspace_projection_delivery[0].name
  arn   = aws_lambda_function.workspace_projection_delivery[0].arn
  input = jsonencode({ kind = "deliver_durable_projection_page" })
  retry_policy {
    maximum_event_age_in_seconds = 300
    maximum_retry_attempts       = 2
  }
}
resource "aws_lambda_permission" "workspace_projection_delivery" {
  count         = local.workspace_projection_count
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.workspace_projection_delivery[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.workspace_projection_delivery[0].arn
}
resource "aws_iam_role_policy" "workspace_projection_discovery" {
  count = local.workspace_projection_count
  name  = "vaultguard-${var.stage}-workspace-projection-discovery"
  role  = aws_iam_role.workspace_projection[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = "dynamodb:Query", Resource = "${var.workspace_revisions_table_arn}/index/workspace-record-type-index" },
    { Effect = "Allow", Action = ["dynamodb:GetItem", "dynamodb:UpdateItem"], Resource = var.workspace_revisions_table_arn,
      Condition = { "ForAllValues:StringEquals" = { "dynamodb:LeadingKeys" = ["PROJECTION-WORKER"] } } }
  ] })
}
