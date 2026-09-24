variable "workspace_revisions_table_name" { type = string }

resource "aws_cloudwatch_metric_alarm" "workspace_recovery_throttles" {
  for_each            = toset(["ReadThrottleEvents", "WriteThrottleEvents"])
  alarm_name          = "VaultGuard-${var.stage}-WorkspaceRecovery-${each.value}"
  namespace           = "AWS/DynamoDB"
  metric_name         = each.value
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { TableName = var.workspace_revisions_table_name }
  alarm_actions       = [aws_sns_topic.admin.arn]
  ok_actions          = [aws_sns_topic.admin.arn]
}
resource "aws_cloudwatch_metric_alarm" "workspace_recovery_sweep" {
  alarm_name          = "VaultGuard-${var.stage}-WorkspaceRecoverySweepStalled"
  alarm_description   = "No complete workspace recovery scan in 15 minutes; inspect worker errors, throttling and table scan capacity."
  namespace           = "VaultGuard/WorkspaceRecovery"
  metric_name         = "SweepComplete"
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  dimensions          = { Stage = var.stage }
  alarm_actions       = [aws_sns_topic.admin.arn]
  ok_actions          = [aws_sns_topic.admin.arn]
}
