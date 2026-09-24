# Scheduled recovery carries no credentials/content. Preparation invocations can
# contain bearer tokens and deliberately have NO async destination or DLQ.
resource "aws_sqs_queue" "workspace_recovery_failures" {
  name                      = "vaultguard-${var.stage}-workspace-recovery-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}
resource "aws_sqs_queue_policy" "workspace_recovery_failures" {
  queue_url = aws_sqs_queue.workspace_recovery_failures.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Sid    = "RecoveryScheduleOnly", Effect = "Allow", Principal = { Service = "events.amazonaws.com" },
      Action = "sqs:SendMessage", Resource = aws_sqs_queue.workspace_recovery_failures.arn,
    Condition = { ArnEquals = { "aws:SourceArn" = aws_cloudwatch_event_rule.workspace_recovery.arn } } },
    { Sid = "TransportEncryption", Effect = "Deny", Principal = "*", Action = "sqs:*",
    Resource = aws_sqs_queue.workspace_recovery_failures.arn, Condition = { Bool = { "aws:SecureTransport" = "false" } } }
  ] })
}
resource "aws_iam_role_policy" "workspace_recovery_failures" {
  name = "vaultguard-${var.stage}-workspace-recovery-failures"
  role = aws_iam_role.workspace_recovery.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "sqs:SendMessage",
  Resource = aws_sqs_queue.workspace_recovery_failures.arn }] })
}
resource "aws_lambda_function_event_invoke_config" "workspace_recovery" {
  function_name                = aws_lambda_function.workspace_recovery.function_name
  maximum_event_age_in_seconds = 300
  maximum_retry_attempts       = 2
}
output "workspace_recovery_failure_queue_name" { value = aws_sqs_queue.workspace_recovery_failures.name }
