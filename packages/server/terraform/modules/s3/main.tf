variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "production_hardening" { type = bool }
variable "account_id" { type = string }
variable "region" { type = string }
variable "kms_key_arn" { type = string }
variable "kms_key_id" { type = string }
variable "domain_name" {
  type    = string
  default = ""
}

locals {
  allowed_cors_origin = var.domain_name != "" ? "https://admin.${var.domain_name}" : "http://localhost:5173"
}

resource "aws_s3_bucket" "vault" {
  bucket        = "obsidian-vaultguard-vault-${var.stage}-${var.account_id}-${var.region}"
  force_destroy = !var.production_hardening

  tags = {
    Name = "obsidian-vaultguard-vault-${var.stage}"
  }
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_id
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket = aws_s3_bucket.vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "enforce_ssl" {
  bucket = aws_s3_bucket.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceSSL"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.vault.arn,
          "${aws_s3_bucket.vault.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    id     = "transition-infrequent"
    status = "Enabled"
    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "cleanup-noncurrent-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days           = var.production_hardening ? 365 : 30
      newer_noncurrent_versions = var.production_hardening ? 10 : 3
    }
  }

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  cors_rule {
    allowed_methods = ["GET", "PUT", "HEAD"]
    allowed_origins = [local.allowed_cors_origin]
    allowed_headers = ["*"]
    max_age_seconds = 3600
  }
}

output "bucket_name" {
  value = aws_s3_bucket.vault.id
}

output "bucket_arn" {
  value = aws_s3_bucket.vault.arn
}
