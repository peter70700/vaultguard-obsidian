variable "workspace_revisions_table_name" { type = string }
variable "workspace_revisions_table_arn" { type = string }

data "archive_file" "workspace_recovery" {
  type        = "zip"
  source_dir  = "${data.external.lambda_build.result.directory}/workspace-recovery"
  output_path = "${path.module}/.build/${data.external.lambda_build.result.digest}/workspace-recovery.zip"
}

resource "aws_iam_role" "workspace_recovery" {
  name               = "vaultguard-${var.stage}-workspace-recovery"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "workspace_recovery_logging" {
  role       = aws_iam_role.workspace_recovery.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "workspace_recovery" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
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

resource "aws_iam_role_policy" "workspace_recovery" {
  role   = aws_iam_role.workspace_recovery.id
  policy = data.aws_iam_policy_document.workspace_recovery.json
}

resource "aws_lambda_function" "workspace_recovery" {
  depends_on                     = [aws_iam_role_policy.workspace_recovery, aws_iam_role_policy_attachment.workspace_recovery_logging, aws_iam_role_policy.workspace_recovery_failures]
  function_name                  = "vaultguard-workspace-recovery-${var.stage}"
  role                           = aws_iam_role.workspace_recovery.arn
  runtime                        = "nodejs22.x"
  handler                        = "handler.handler"
  timeout                        = 60
  memory_size                    = 256
  reserved_concurrent_executions = 1
  filename                       = data.archive_file.workspace_recovery.output_path
  source_code_hash               = data.archive_file.workspace_recovery.output_base64sha256
  dead_letter_config { target_arn = aws_sqs_queue.workspace_recovery_failures.arn }
  environment {
    variables = {
      STAGE                     = var.stage
      WORKSPACE_REVISIONS_TABLE = var.workspace_revisions_table_name
    }
  }
}

resource "aws_cloudwatch_log_group" "workspace_recovery" {
  name              = "/aws/lambda/${aws_lambda_function.workspace_recovery.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_event_rule" "workspace_recovery" {
  name                = "vaultguard-${var.stage}-workspace-recovery"
  schedule_expression = "rate(1 minute)"
}
resource "aws_cloudwatch_event_target" "workspace_recovery" {
  rule = aws_cloudwatch_event_rule.workspace_recovery.name
  arn  = aws_lambda_function.workspace_recovery.arn
  input = jsonencode({ kind = "recover_workspace_page" })
  dead_letter_config { arn = aws_sqs_queue.workspace_recovery_failures.arn }
  retry_policy {
    maximum_event_age_in_seconds = 300
    maximum_retry_attempts       = 2
  }
}
resource "aws_lambda_permission" "workspace_recovery" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.workspace_recovery.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.workspace_recovery.arn
}
output "workspace_recovery_function_name" { value = aws_lambda_function.workspace_recovery.function_name }
