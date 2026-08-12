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
    windows, and S3 keeps 365-day / 100-version noncurrent history.

    Set to false ONLY for genuinely disposable stacks (ephemeral CI, throwaway
    local test envs) that must be torn down freely. Does NOT change any
    authentication posture — Cognito MFA and advanced-security use their own
    explicit inputs so enabling durability hardening never changes login policy.
  EOT
  type        = bool
  default     = true
}

variable "confirm_disposable_stack" {
  description = "Explicit acknowledgement required before disabling production_hardening. Set true only for a disposable stack whose data may be destroyed."
  type        = bool
  default     = false
}

check "disposable_stack_acknowledged" {
  assert {
    condition     = var.production_hardening || var.confirm_disposable_stack
    error_message = "production_hardening=false disables PITR/deletion protection, enables S3 force-destroy, and removes recovery windows. Set confirm_disposable_stack=true explicitly only for a disposable stack."
  }
}

variable "session_enforcement_mode" {
  description = "Server-session header policy for authenticated Lambdas. Keep observe until bootstrap/logout telemetry is reviewed, then select enforce explicitly."
  type        = string
  default     = "observe"

  validation {
    condition     = contains(["observe", "enforce"], var.session_enforcement_mode)
    error_message = "session_enforcement_mode must be either observe or enforce."
  }
}

variable "cognito_mfa_configuration" {
  description = "Explicit Cognito MFA posture. OPTIONAL is migration-safe; ON requires an operator-approved enrollment rollout."
  type        = string
  default     = "OPTIONAL"

  validation {
    condition     = contains(["OFF", "OPTIONAL", "ON"], var.cognito_mfa_configuration)
    error_message = "cognito_mfa_configuration must be OFF, OPTIONAL, or ON."
  }
}

variable "cognito_advanced_security_mode" {
  description = "Explicit Cognito threat-protection posture. AUDIT is the non-blocking production-safe baseline; ENFORCED requires an operator-approved rollout."
  type        = string
  default     = "AUDIT"

  validation {
    condition     = contains(["OFF", "AUDIT", "ENFORCED"], var.cognito_advanced_security_mode)
    error_message = "cognito_advanced_security_mode must be OFF, AUDIT, or ENFORCED."
  }
}

variable "legacy_api_cdn_enabled" {
  description = "Keep the legacy CloudFront API distribution until access logs prove no supported client still uses it. Set false only through the retirement runbook."
  type        = bool
  default     = true
}

variable "login_verification_mode" {
  description = "One-time login-permit posture. Keep disabled until the Cognito/Turnstile live feasibility gate is completed; observe and enforce require explicit operator selection."
  type        = string
  default     = "disabled"

  validation {
    condition     = contains(["disabled", "observe", "enforce"], var.login_verification_mode)
    error_message = "login_verification_mode must be disabled, observe, or enforce."
  }
}

variable "login_verification_client_ids" {
  description = "Explicit Cognito app-client IDs subject to login-permit observation/enforcement. Populate only after the managed client ID is known and before selecting observe/enforce."
  type        = list(string)
  default     = []
}

variable "login_verification_browser_url" {
  description = "Managed browser completion page for Obsidian human-verification handoff."
  type        = string
  default     = "https://auth.example.com/complete"
}

variable "turnstile_expected_hostnames" {
  description = "Exact Turnstile hostnames accepted for login/signup purpose-bound proofs."
  type        = list(string)
  default     = ["admin.example.com", "auth.example.com"]
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
  default     = 26214400 # 25 MiB
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
  description = "Stage-specific Secrets Manager ARN for the Cloudflare Turnstile secret key (JSON shape {\"secretKey\":\"...\"}). Required for Pro signup and observe/enforce login verification; empty is permitted only for Community Edition with those managed controls disabled."
  type        = string

  validation {
    condition = var.turnstile_secret_arn == "" || can(regex(
      "^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+$",
      var.turnstile_secret_arn,
    ))
    error_message = "Set turnstile_secret_arn to an explicit stage-specific Secrets Manager secret ARN, or explicitly set it to an empty string only for Community Edition with managed verification disabled."
  }
}

# ─── Meta advertising (Conversions API) ──────────────────────────────────────

variable "meta_dataset_id" {
  description = "Meta dataset / pixel ID used by the Conversions API. Public value (it also ships in landing/index.html). Empty — the default — makes every server-side Meta event a silent no-op, which is the required state for Community Edition and self-hosted deploys."
  type        = string
  default     = ""
}

variable "meta_capi_secret_arn" {
  description = "Secrets Manager ARN holding {\"accessToken\":\"...\"} for the Meta Conversions API. MUST be encrypted with the AWS-managed aws/secretsmanager key, NOT the project CMK: the signup Lambda's kms:Decrypt grant is pinned to kms:ViaService = dynamodb, so a CMK-encrypted secret is undecryptable there and the failure is swallowed silently. Empty disables all Meta events and drops the secretsmanager:GetSecretValue grant from both roles."
  type        = string
  default     = ""
}

# ─── Google Workspace (inbound mail) ─────────────────────────────────────────
# Google Workspace site-verification TXT and DKIM TXT are managed manually
# in the Route 53 console; they are intentionally NOT modelled as terraform
# variables so a forgotten tfvars cannot destroy live email records.
