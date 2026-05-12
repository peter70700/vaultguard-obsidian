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
  description = "Duration of encryption key leases in seconds"
  type        = number
  default     = 3600
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
  description = "From address for transactional emails"
  type        = string
  default     = "noreply@example.com"
}

variable "sender_domain" {
  description = "Verified SES domain identity"
  type        = string
  default     = "example.com"
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

# ─── Google Workspace (inbound mail) ─────────────────────────────────────────
# Inbound mail for the domain is handled by Google Workspace. Set these via
# terraform.tfvars or environment-specific tfvars once the Workspace tenant is
# provisioned. Outbound transactional mail continues to flow through SES.

variable "google_workspace_verification_token" {
  description = "Google site-verification token (the value after 'google-site-verification=') from admin.google.com. Empty until the Workspace tenant is being provisioned."
  type        = string
  default     = ""
}

variable "google_workspace_dkim_value" {
  description = "DKIM public key TXT value generated in Google Workspace Admin (Apps → Gmail → Authenticate email). Empty until the key has been generated."
  type        = string
  default     = ""
}
