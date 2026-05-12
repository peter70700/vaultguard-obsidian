variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "sender_email" { type = string }
variable "sender_domain" {
  description = "Verified SES domain identity (e.g. example.com)"
  type        = string
}
variable "kms_key_arn" { type = string }

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Domain identity (example.com) is verified externally via DNS.
# No per-address aws_ses_email_identity needed — the domain covers all
# addresses like noreply@, security@, support@, etc.

# ─── SES Configuration Set ─────────────────────────────────────────────────

resource "aws_ses_configuration_set" "main" {
  name = "vaultguard-${var.stage}"

  reputation_metrics_enabled = true

  delivery_options {
    tls_policy = "Require"
  }
}

# ─── IAM Policy Document (for Lambda roles to send email) ──────────────────

data "aws_iam_policy_document" "ses_send" {
  statement {
    sid    = "AllowSendEmail"
    effect = "Allow"

    actions = [
      "ses:SendEmail",
      "ses:SendRawEmail",
    ]

    resources = [
      "arn:aws:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:identity/${var.sender_domain}",
    ]

    condition {
      test     = "StringEquals"
      variable = "ses:ConfigurationSetName"
      values   = [aws_ses_configuration_set.main.name]
    }
  }
}

# ─── Outputs ───────────────────────────────────────────────────────────────

output "sender_email" {
  value = var.sender_email
}

output "configuration_set_name" {
  value = aws_ses_configuration_set.main.name
}

output "ses_send_policy_json" {
  value = data.aws_iam_policy_document.ses_send.json
}
