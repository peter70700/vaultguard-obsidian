variable "workspace_recovery_failure_queue_name" { type = string }
resource "aws_cloudwatch_metric_alarm" "workspace_recovery_delivery" {
  alarm_name          = "VaultGuard-${var.stage}-WorkspaceRecoveryDeliveryFailure"
  alarm_description   = "Recovery event exhausted bounded retries. Inspect canonical recovery state before redrive; never replay a publication."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = var.workspace_recovery_failure_queue_name }
  alarm_actions       = [aws_sns_topic.admin.arn]
  ok_actions          = [aws_sns_topic.admin.arn]
}
# Content-free fixed vocabulary already emitted by canonical owners. No tenant,
# vault, path, credential, provider text or request IDs become metric dimensions.
resource "aws_cloudwatch_log_metric_filter" "workspace_failure" {
  for_each       = toset(var.lambda_log_group_names)
  name           = "WorkspaceOperationFailure"
  log_group_name = each.value
  pattern        = "{ ($.event = workspace_slo || $.event = workspace_cost_resources) && $.kind = operation && ($.outcome = failure || $.outcome = unavailable) }"
  metric_transformation {
    name      = "OperationFailure"
    namespace = "VaultGuard/Workspace/${var.stage}"
    value     = "1"
  }
}
resource "aws_cloudwatch_metric_alarm" "workspace_operation_failure" {
  alarm_name          = "VaultGuard-${var.stage}-WorkspaceOperationFailure"
  alarm_description   = "Operational trigger only, not acceptance of proposed SLOs; inspect content-free outcomes and canonical receipts."
  namespace           = "VaultGuard/Workspace/${var.stage}"
  metric_name         = "OperationFailure"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
  ok_actions          = [aws_sns_topic.admin.arn]
}
resource "aws_cloudwatch_log_metric_filter" "workspace_projection_lag" {
  for_each       = toset(var.lambda_log_group_names)
  name           = "WorkspaceProjectionLag"
  log_group_name = each.value
  pattern        = "{ ($.event = workspace_slo || $.event = workspace_cost_resources) && $.kind = gauge && $.gauge = projection_lag_ms }"
  metric_transformation {
    name      = "ProjectionLagMs"
    namespace = "VaultGuard/Workspace/${var.stage}"
    value     = "$.value"
    unit      = "Milliseconds"
  }
}
