# ─────────────────────────────────────────────────────────────────────────────
# Upstream identity for VaultGuard's own connector authorization server
# (VAULTGUARD-49 / ADR-003)
#
# Cognito remains the IDENTITY PROVIDER for remote MCP connectors. It stops
# being the AUTHORIZATION SERVER, because an AWS-generated discovery document
# can never advertise `offline_access` and Cognito fails authentication outright
# on a client that requests a scope it has not associated with the app client.
#
# This client exists only so VaultGuard's authorization server can log a human
# in before minting its own grant. It is never handed to a provider: its single
# callback is VaultGuard's own `/oauth/callback`, and its native refresh token is
# revoked before connector consent proceeds.
# ─────────────────────────────────────────────────────────────────────────────

data "aws_region" "current" {}

variable "connector_identity_callback_url" {
  description = "VaultGuard's own /oauth/callback. Empty creates no identity client."
  type        = string
  default     = ""

  validation {
    condition = var.connector_identity_callback_url == "" || (
      can(regex("^https://[^?#]+/oauth/callback$", var.connector_identity_callback_url)) &&
      !can(regex("[[:space:]@]", var.connector_identity_callback_url))
    )
    error_message = "connector_identity_callback_url must be empty or an exact HTTPS URL ending in /oauth/callback."
  }
}

variable "connector_cognito_as_authorization_server" {
  description = "SUPERSEDED by ADR-003. Kept false so enabling connector OAuth no longer widens the pool with an unused resource server."
  type        = bool
  default     = false
}

resource "aws_cognito_user_pool_client" "connector_identity" {
  count = var.connector_identity_callback_url == "" ? 0 : 1

  name         = "vaultguard-connector-identity-${var.stage}"
  user_pool_id = aws_cognito_user_pool.main.id

  # Public client: VaultGuard's authorization server runs the code flow with
  # PKCE from a Lambda that holds no client secret in Terraform state.
  generate_secret = false

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  # Identity only. No connector resource-server scope is granted here: this
  # client authenticates a human, it never authorizes MCP access.
  allowed_oauth_scopes         = ["openid", "aws.cognito.signin.user.admin"]
  supported_identity_providers = ["COGNITO"]

  callback_urls = [var.connector_identity_callback_url]

  # The native credential is short-lived and revoked immediately after the
  # identity is read, so it never outlives a single consent.
  access_token_validity  = 5
  id_token_validity      = 5
  refresh_token_validity = 1
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "hours"
  }

  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"

  # This client must never be usable to change the directory it authenticates.
  read_attributes  = ["email", "email_verified"]
  write_attributes = []

  explicit_auth_flows = ["ALLOW_REFRESH_TOKEN_AUTH"]
}

output "connector_identity_client_id" {
  value = var.connector_identity_callback_url == "" ? "" : aws_cognito_user_pool_client.connector_identity[0].id
}

output "connector_hosted_ui_domain" {
  description = "Hosted-UI origin for the upstream login leg. No path, no trailing slash."
  value       = "https://${aws_cognito_user_pool_domain.main.domain}.auth.${data.aws_region.current.name}.amazoncognito.com"
}
