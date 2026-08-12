variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "production_hardening" { type = bool }
variable "account_id" { type = string }

resource "aws_kms_key" "master" {
  description             = "Master encryption key for Obsidian VaultGuard vault data and per-user data keys"
  enable_key_rotation     = true
  deletion_window_in_days = var.production_hardening ? 30 : 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowRootAccount"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      # CloudWatch must be able to use this key to publish alarm notifications.
      #
      # The alerting SNS topic (modules/monitoring) is encrypted with this CMK,
      # and CloudWatch alarms are its ONLY publisher — nothing else calls
      # sns:Publish on it. A KMS key policy does not grant anything implicitly:
      # the root statement above enables delegation to IAM principals *in this
      # account*, but an AWS service principal is not one of those and needs its
      # own statement. Without this, every alarm's Publish fails inside SNS and
      # the notification is dropped — the alarms evaluate and transition
      # normally, the email subscription stays confirmed, and no page is ever
      # delivered. That is a silent failure of the entire alerting path, which
      # is exactly the class of bug the alarms exist to prevent.
      #
      # Deliberately unconditioned, matching AWS's documented form for this
      # grant. A speculative SourceAccount/SourceArn condition that CloudWatch
      # does not populate would fail CLOSED and silently — restoring the very
      # outage-in-the-dark this statement removes — and the two actions are the
      # minimum SNS needs to encrypt a message under this key.
      {
        Sid       = "AllowCloudWatchAlarmsToPublishToEncryptedSns"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })

  tags = {
    Name = "obsidian-vaultguard/${var.stage}/master"
  }
}

resource "aws_kms_alias" "master" {
  name          = "alias/obsidian-vaultguard/${var.stage}/master"
  target_key_id = aws_kms_key.master.key_id
}

output "key_arn" {
  value = aws_kms_key.master.arn
}

output "key_id" {
  value = aws_kms_key.master.key_id
}
