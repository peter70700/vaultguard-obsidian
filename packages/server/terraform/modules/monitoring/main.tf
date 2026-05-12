variable "stage" { type = string }
variable "admin_email" { type = string }
variable "kms_key_arn" { type = string }
variable "api_gateway_name" { type = string }
variable "api_gateway_stage" { type = string }

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

# Alarm: High rate of failed authentication attempts (brute force detection)
resource "aws_cloudwatch_metric_alarm" "failed_auth" {
  alarm_name          = "vaultguard-${var.stage}-failed-auth-spike"
  alarm_description   = "High rate of failed authentication attempts detected - possible brute force attack"
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

output "sns_topic_arn" {
  value = aws_sns_topic.admin.arn
}
