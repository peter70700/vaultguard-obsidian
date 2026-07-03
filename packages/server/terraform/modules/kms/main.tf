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
