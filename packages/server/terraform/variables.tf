variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-central-1"
}

variable "stage" {
  description = "Deployment stage (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.stage)
    error_message = "Stage must be one of: dev, staging, prod."
  }
}

variable "production_hardening" {
  description = <<-EOT
    Enable production-grade data-durability and log-privacy protections
    INDEPENDENTLY of the stage name. This exists because the live production
    stack (example.com) runs with stage="dev", so the historical
    `stage == "prod"` gate left production without these protections.

    When true (the default — secure by default): API Gateway request/response
    body tracing is DISABLED (so plaintext key-lease DEKs are never written to
    CloudWatch), the vault S3 bucket is force_destroy=false, DynamoDB tables get
    PITR + deletion protection, Secrets Manager / KMS use 30-day recovery
    windows, and S3 keeps 365-day / 10-version noncurrent history.

    Set to false ONLY for genuinely disposable stacks (ephemeral CI, throwaway
    local test envs) that must be torn down freely. Does NOT change any
    authentication posture — Cognito MFA and advanced-security remain gated on
    the stage name so enabling hardening never forces MFA on existing users.
  EOT
  type        = bool
  default     = true
}

variable "api_data_trace_enabled" {
  description = <<-EOT
    API Gateway request/response body tracing writes full bodies — including the
    plaintext GET /auth/key-lease DEK — to CloudWatch. SD-12 F8 splits this from
    production_hardening so a durability opt-out (production_hardening=false on a
    throwaway stack) can NEVER re-enable DEK logging. Defaults false (secure)
    unconditionally; set true ONLY for a debug stack that never sees real data.
  EOT
  type        = bool
  default     = false
}

variable "admin_email" {
  description = "Email address for admin SNS notifications"
  type        = string
  default     = ""
}

variable "cognito_callback_urls" {
  description = "OAuth callback URLs for the Obsidian plugin"
  type        = list(string)
  default     = ["obsidian://vaultguard/callback"]
}

variable "cognito_logout_urls" {
  description = "OAuth logout URLs for the Obsidian plugin"
  type        = list(string)
  default     = ["obsidian://vaultguard/logout"]
}

variable "key_lease_duration_seconds" {
  description = "Duration of encryption key leases in seconds. CE defaults to 4 hours."
  type        = number
  default     = 14400
}

variable "session_duration_seconds" {
  description = "Duration of user sessions in seconds"
  type        = number
  default     = 86400
}

variable "max_file_size_bytes" {
  description = "Maximum file upload size in bytes"
  type        = number
  default     = 10485760 # 10MB
}

variable "sender_email" {
  description = "From address for transactional emails (email Lambda + Cognito). On the dedicated transactional sending subdomain so its reputation is isolated from the apex (Google Workspace + website) and from the marketing lane (news.*)."
  type        = string
  default     = "noreply@mail.example.com"
}

variable "sender_domain" {
  description = "Verified SES sending identity for transactional mail. Kept in sync with the mail.<domain> subdomain the dns module provisions. The apex identity stays verified for rollback: flip this + sender_email back to the apex to revert."
  type        = string
  default     = "mail.example.com"
}

variable "domain_name" {
  description = "Custom domain name (e.g., example.com). Route53 hosted zone must already exist. Leave empty to use AWS default domains."
  type        = string
  default     = "example.com"
}

variable "vaultguard_edition" {
  description = "VaultGuard feature edition advertised by Lambda handlers. The public Community Edition export defaults to community."
  type        = string
  default     = "community"

  validation {
    condition     = contains(["community", "pro"], var.vaultguard_edition)
    error_message = "vaultguard_edition must be either community or pro."
  }
}

variable "vaultguard_allow_public_signup" {
  description = "When true, Community Edition keeps POST /signup open after the first organization is created."
  type        = bool
  default     = false
}

variable "super_admin_emails" {
  description = "Comma-separated lowercase emails allowed to call the /superadmin/* platform-stats API. Fail-closed: empty disables the API entirely. Set per-stage in environments/<stage>.tfvars."
  type        = string
  default     = ""
}

variable "billing_exempt_domains" {
  description = "Comma-separated email domains whose new orgs are billing-exempt (owner-domain match stamps the Subscriptions row comped=true at signup). Empty disables domain exemption. Set per-stage in environments/<stage>.tfvars."
  type        = string
  default     = ""
}

variable "turnstile_secret_arn" {
  description = "Secrets Manager ARN for the Cloudflare Turnstile secret key (JSON shape {\"secretKey\":\"...\"}). Empty on Community Edition disables CAPTCHA (fail-open). The root terraform/main.tf hardcodes the prod ARN at the module invocation; override via tfvars for non-prod stages or leave this default for CE deploys driven from the root."
  type        = string
  default     = ""
}

# ─── Google Workspace (inbound mail) ─────────────────────────────────────────
# Google Workspace site-verification TXT and DKIM TXT are managed manually
# in the Route 53 console; they are intentionally NOT modelled as terraform
# variables so a forgotten tfvars cannot destroy live email records.
