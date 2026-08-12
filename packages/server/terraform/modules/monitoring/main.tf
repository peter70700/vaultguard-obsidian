variable "stage" { type = string }
variable "admin_email" { type = string }
variable "kms_key_arn" { type = string }
variable "api_gateway_name" { type = string }
variable "api_gateway_stage" { type = string }

variable "lambda_function_names" {
  type        = list(string)
  description = <<-EOT
    Every Lambda in the deployment, including the Cognito Pre Authentication
    trigger. Each gets an Errors and a Throttles alarm. A function missing from
    this list is a function whose failures page nobody.
  EOT
}

variable "lambda_log_group_names" {
  type        = list(string)
  description = "Concrete Lambda log groups scanned for audit-delivery failures."
}

variable "reencryption_dlq_name" {
  type        = string
  description = "SQS dead-letter queue for dropped UserAccessRevoked events."
}

variable "reconciler_function_name" {
  type        = string
  description = "Nightly seat/user reconciliation job — alarmed on silence, not errors."
}

variable "detector_function_name" {
  type        = string
  description = "Scheduled anomaly-detection sweep — alarmed on silence, not errors."
}

variable "scheduled_job_silence_period_seconds" {
  type        = number
  default     = 172800 # 48h — two missed nightly runs, so one blip is not a page
  description = "Window over which a scheduled job must invoke at least once."
}

variable "detector_success_silence_period_seconds" {
  type        = number
  default     = 3600
  description = "Maximum allowed gap between successful anomaly-detector sweep heartbeats."
}

# ─── SNS Topic for Admin Notifications ───────────────────────────────────────

resource "aws_sns_topic" "admin" {
  name              = "obsidian-vaultguard-admin-${var.stage}"
  display_name      = "Obsidian VaultGuard Admin Alerts"
  kms_master_key_id = var.kms_key_arn

  tags = { Name = "obsidian-vaultguard-admin-${var.stage}" }
}

resource "aws_sns_topic_subscription" "admin_email" {
  count     = var.admin_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.admin.arn
  protocol  = "email"
  endpoint  = var.admin_email
}

# ─── CloudWatch Alarms ──────────────────────────────────────────────────────

# Alarm: backend recovery-code verification failures. Cognito password risk
# and brute-force telemetry remains a native Cognito operator surface; this
# custom metric does not claim to ingest direct plugin-to-Cognito failures.
resource "aws_cloudwatch_metric_alarm" "failed_auth" {
  alarm_name          = "vaultguard-${var.stage}-failed-auth-spike"
  alarm_description   = "High rate of backend recovery-code verification failures detected"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "FailedAuthentication"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 50
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-failed-auth-spike" }
}

# Alarm: authenticated requests rejected by expiry, max-age, or mandatory
# server-session policy. Revoked/cutoff/mismatched sessions use the distinct
# RevokedSessionAccess signal below because those are replay indicators.
resource "aws_cloudwatch_metric_alarm" "session_rejection" {
  alarm_name          = "vaultguard-${var.stage}-session-rejection-spike"
  alarm_description   = "High rate of authenticated requests rejected by session policy"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "SessionRejection"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-session-rejection-spike" }
}

# Alarm: Unusual file access volume (data exfiltration detection)
resource "aws_cloudwatch_metric_alarm" "data_exfil" {
  alarm_name          = "vaultguard-${var.stage}-unusual-file-access"
  alarm_description   = "Unusually high file access volume detected - possible data exfiltration"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "FileAccessCount"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 500
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-unusual-file-access" }
}

# Alarm: Permission changes outside business hours
resource "aws_cloudwatch_metric_alarm" "off_hours_perm" {
  alarm_name          = "vaultguard-${var.stage}-off-hours-perm-change"
  alarm_description   = "Permission changes detected outside business hours"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "OffHoursPermissionChange"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-off-hours-perm-change" }
}

# Alarm: Revoked session access attempts (token replay detection)
resource "aws_cloudwatch_metric_alarm" "revoked_session" {
  alarm_name          = "vaultguard-${var.stage}-revoked-session-access"
  alarm_description   = "Access attempted using revoked session - possible token replay attack"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "RevokedSessionAccess"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-revoked-session-access" }
}

# Alarm: KMS decrypt failures (unauthorized decryption attempts)
resource "aws_cloudwatch_metric_alarm" "kms_failures" {
  alarm_name          = "vaultguard-${var.stage}-kms-decrypt-failures"
  alarm_description   = "KMS decrypt failures detected - possible unauthorized decryption attempt"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "KMSDecryptFailure"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-kms-decrypt-failures" }
}

# Alarm: a durable vault mutation could not publish its activity/revision row.
# Clients fail over to a full scan while the pending outbox row is reconciled,
# but operators must investigate repeated occurrences.
resource "aws_cloudwatch_metric_alarm" "vault_mutation_reconciliation" {
  alarm_name          = "vaultguard-${var.stage}-mutation-reconciliation"
  alarm_description   = "Durable vault mutations are awaiting activity/cursor reconciliation"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "VaultMutationReconciliationRequired"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-mutation-reconciliation" }
}

# Alarm: API 4xx error spike (scanning / credential stuffing)
resource "aws_cloudwatch_metric_alarm" "api_4xx" {
  alarm_name        = "vaultguard-${var.stage}-api-4xx-spike"
  alarm_description = "Elevated API 4xx errors - possible scanning or credential stuffing"
  namespace         = "AWS/ApiGateway"
  metric_name       = "4XXError"
  dimensions = {
    ApiName = var.api_gateway_name
    Stage   = var.api_gateway_stage
  }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-api-4xx-spike" }
}

# ─── Operational alarm floor ────────────────────────────────────────────────
# Every alarm above this line is a SECURITY-signal alarm on the custom
# ObsidianVaultGuard namespace: it fires when something suspicious happens. None
# of them fire when the service is simply BROKEN. Before this block, a total
# backend outage produced no page at all — and because the only API alarm
# watched 4XX, an outage made the one existing alarm go quieter rather than
# louder. The alarms below are the availability floor.

# Alarm: a function is throwing. One alarm per Lambda so the alarm name itself
# names the failing component.
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = toset(var.lambda_function_names)

  alarm_name        = "vaultguard-${var.stage}-lambda-errors-${each.value}"
  alarm_description = "Lambda ${each.value} is returning errors"
  namespace         = "AWS/Lambda"
  metric_name       = "Errors"
  dimensions        = { FunctionName = each.value }

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]
  ok_actions    = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-lambda-errors-${each.value}" }
}

# Alarm: a function is being throttled — concurrency exhaustion, which presents
# to users as an outage while Errors stays flat.
resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  for_each = toset(var.lambda_function_names)

  alarm_name        = "vaultguard-${var.stage}-lambda-throttles-${each.value}"
  alarm_description = "Lambda ${each.value} is being throttled"
  namespace         = "AWS/Lambda"
  metric_name       = "Throttles"
  dimensions        = { FunctionName = each.value }

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-lambda-throttles-${each.value}" }
}

# Alarm: the API is returning 5xx — the single best "is the product up" signal.
resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name        = "vaultguard-${var.stage}-api-5xx"
  alarm_description = "API Gateway is returning 5xx errors - backend failing"
  namespace         = "AWS/ApiGateway"
  metric_name       = "5XXError"
  dimensions = {
    ApiName = var.api_gateway_name
    Stage   = var.api_gateway_stage
  }

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]
  ok_actions    = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-api-5xx" }
}

# Alarm: a UserAccessRevoked event was dead-lettered. Threshold is >= 1 because
# every single dropped revocation is a security-relevant event: a user was
# offboarded and their files were not re-encrypted. An operator must re-drive
# the queue; this alarm is the only thing that says so.
resource "aws_cloudwatch_metric_alarm" "reencryption_dlq_depth" {
  alarm_name        = "vaultguard-${var.stage}-reencryption-dlq-not-empty"
  alarm_description = "A user-revocation event was dead-lettered - offboarding re-encryption did NOT run. Re-drive the queue."
  namespace         = "AWS/SQS"
  metric_name       = "ApproximateNumberOfMessagesVisible"
  dimensions        = { QueueName = var.reencryption_dlq_name }

  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-reencryption-dlq-not-empty" }
}

# Alarm: a re-encryption job finished without completing every file. The
# handler's rotation fence already refuses to record a partial rotation as
# `completed`; this is what turns that correct bookkeeping into a page.
resource "aws_cloudwatch_metric_alarm" "reencryption_incomplete" {
  alarm_name          = "vaultguard-${var.stage}-reencryption-incomplete"
  alarm_description   = "A re-encryption job ended without rotating every file - offboarding is not fully enforced"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "ReEncryptionIncomplete"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-reencryption-incomplete" }
}

# Audit writes deliberately do not fail the business operation. Convert their
# fail-open log marker into an independent metric so silent evidence loss pages.
resource "aws_cloudwatch_log_metric_filter" "audit_delivery_failure" {
  for_each       = toset(var.lambda_log_group_names)
  name           = "vaultguard-${var.stage}-audit-delivery-failure"
  log_group_name = each.value
  pattern        = "\"[AUDIT_LOG_FAILURE]\""

  metric_transformation {
    # Metric-filter dimensions must be extracted from structured log fields;
    # this marker is deliberately a simple text pattern. Encode the stage in
    # the metric name instead of declaring an invalid constant dimension.
    name      = "AuditDeliveryFailure-${var.stage}"
    namespace = "ObsidianVaultGuard"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "audit_delivery_failure" {
  alarm_name          = "vaultguard-${var.stage}-audit-delivery-failure"
  alarm_description   = "A security/admin audit row could not be persisted"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "AuditDeliveryFailure-${var.stage}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
}

resource "aws_cloudwatch_metric_alarm" "detector_sweep_failed" {
  alarm_name          = "vaultguard-${var.stage}-detector-sweep-failed"
  alarm_description   = "The anomaly detector failed a complete sweep"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "DetectorSweepFailed"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
}

resource "aws_cloudwatch_metric_alarm" "detector_vault_failure" {
  alarm_name          = "vaultguard-${var.stage}-detector-vault-failure"
  alarm_description   = "One or more vaults were not evaluated during an anomaly-detector sweep"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "DetectorVaultFailure"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
}

# ─── Scheduled-job silence alarms ───────────────────────────────────────────
# These are the only alarms in this file that use `treat_missing_data =
# "breaching"`, and the inversion is the entire point. For every other alarm,
# "no data" means "nothing bad happened". For a cron job, "no data" means THE
# JOB STOPPED RUNNING — a broken EventBridge rule, a deleted permission, a
# disabled schedule. A job that silently stops is indistinguishable from a
# healthy one under `notBreaching`, which is how a nightly reconciliation can be
# dead for months without anyone noticing.

resource "aws_cloudwatch_metric_alarm" "reconciler_silence" {
  alarm_name        = "vaultguard-${var.stage}-reconciler-not-running"
  alarm_description = "Nightly seat/user reconciliation has not invoked - the billing backstop is dead"
  namespace         = "AWS/Lambda"
  metric_name       = "Invocations"
  dimensions        = { FunctionName = var.reconciler_function_name }

  statistic           = "Sum"
  period              = var.scheduled_job_silence_period_seconds
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.admin.arn]
  ok_actions    = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-reconciler-not-running" }
}

resource "aws_cloudwatch_metric_alarm" "detector_silence" {
  alarm_name        = "vaultguard-${var.stage}-detector-not-running"
  alarm_description = "Scheduled anomaly-detection sweep has not invoked - proactive alerting is dead (SD-09-F2)"
  namespace         = "AWS/Lambda"
  metric_name       = "Invocations"
  dimensions        = { FunctionName = var.detector_function_name }

  statistic           = "Sum"
  period              = var.scheduled_job_silence_period_seconds
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.admin.arn]
  ok_actions    = [aws_sns_topic.admin.arn]

  tags = { Name = "vaultguard-${var.stage}-detector-not-running" }
}

# Invocation alone is not health: the detector previously caught every
# per-vault failure and still returned success. This heartbeat is emitted only
# after every vault and alert write completes successfully.
resource "aws_cloudwatch_metric_alarm" "detector_success_silence" {
  alarm_name          = "vaultguard-${var.stage}-detector-no-successful-sweep"
  alarm_description   = "No complete successful anomaly-detection sweep heartbeat was observed"
  namespace           = "ObsidianVaultGuard"
  metric_name         = "DetectorSweepCompleted"
  dimensions          = { Stage = var.stage }
  statistic           = "Sum"
  period              = var.detector_success_silence_period_seconds
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
  ok_actions          = [aws_sns_topic.admin.arn]
}

resource "aws_cloudwatch_metric_alarm" "detector_any_error" {
  alarm_name          = "vaultguard-${var.stage}-detector-error"
  alarm_description   = "The anomaly-detector Lambda reported any failed sweep"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = var.detector_function_name }
  statistic           = "Sum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.admin.arn]
}

output "sns_topic_arn" {
  value = aws_sns_topic.admin.arn
}

output "reencryption_dlq_alarm_name" {
  value = aws_cloudwatch_metric_alarm.reencryption_dlq_depth.alarm_name
}
