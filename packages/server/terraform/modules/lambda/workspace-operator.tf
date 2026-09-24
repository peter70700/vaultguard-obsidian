# Separate operator trust boundary. No public route, product invocation grant,
# automatic push destination, provider credential, table restore or destroy grant.
variable "workspace_operator_enabled" {
  type    = bool
  default = false
}
check "workspace_operator_fence" {
  assert {
    condition     = !var.workspace_operator_enabled || var.workspace_cohort_controls_enabled
    error_message = "The operator requires durable cohort/writer-fence participation."
  }
}
data "archive_file" "workspace_operator" {
  count       = var.workspace_operator_enabled ? 1 : 0
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/workspace-operator"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/workspace-operator.zip"
}
resource "aws_iam_role" "workspace_operator" {
  count              = var.workspace_operator_enabled ? 1 : 0
  name               = "vaultguard-${var.stage}-workspace-operator"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}
resource "aws_iam_role_policy_attachment" "workspace_operator_logging" {
  count      = var.workspace_operator_enabled ? 1 : 0
  role       = aws_iam_role.workspace_operator[0].name
  policy_arn = aws_iam_policy.lambda_logging.arn
}
data "aws_iam_policy_document" "workspace_operator" {
  count = var.workspace_operator_enabled ? 1 : 0
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE#*", "WORKSPACE-COHORT#*"]
    }
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-COHORT#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.user_keys_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["ORG#*#VAULT#*#SCOPE#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_economics_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-ECONOMICS#*", "WORKSPACE-ECONOMICS-RECEIPTS#*", "WORKSPACE-ECONOMICS-ALERTS#*", "WORKSPACE-ECONOMICS-DELIVERY#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.workspace_economics_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-ECONOMICS-POLICY#*"]
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
resource "aws_iam_role_policy" "workspace_operator" {
  count  = var.workspace_operator_enabled ? 1 : 0
  name   = "vaultguard-${var.stage}-workspace-operator"
  role   = aws_iam_role.workspace_operator[0].id
  policy = data.aws_iam_policy_document.workspace_operator[0].json
}
resource "aws_lambda_function" "workspace_operator" {
  count                          = var.workspace_operator_enabled ? 1 : 0
  function_name                  = "vaultguard-workspace-operator-${var.stage}"
  role                           = aws_iam_role.workspace_operator[0].arn
  handler                        = "handler.handler"
  runtime                        = "nodejs22.x"
  architectures                  = ["arm64"]
  memory_size                    = 256
  timeout                        = 60
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.workspace_operator[0].output_path
  source_code_hash               = data.archive_file.workspace_operator[0].output_base64sha256
  environment {
    variables = merge(local.common_env, {
      WORKSPACE_OPERATOR_ENABLED = "true"
      WORKSPACE_REVISIONS_TABLE  = var.workspace_revisions_table_name
      WORKSPACE_ECONOMICS_TABLE  = var.workspace_economics_table_name
    })
  }
  depends_on = [aws_iam_role_policy.workspace_operator, aws_iam_role_policy_attachment.workspace_operator_logging]
}
resource "aws_cloudwatch_log_group" "workspace_operator" {
  count             = var.workspace_operator_enabled ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.workspace_operator[0].function_name}"
  retention_in_days = local.log_retention
}
output "workspace_operator_function_arn" {
  description = "A separately authorized operator IAM principal may invoke this function. Product roles receive no invoke permission."
  value       = var.workspace_operator_enabled ? aws_lambda_function.workspace_operator[0].arn : ""
}
