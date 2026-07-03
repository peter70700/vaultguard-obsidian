variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "production_hardening" { type = bool }
variable "callback_urls" { type = list(string) }
variable "logout_urls" { type = list(string) }
variable "ses_sender_email" { type = string }
variable "ses_sender_arn" {
  type    = string
  default = ""
}

resource "aws_cognito_user_pool" "main" {
  name = "obsidian-vaultguard-${var.stage}"
  # Deletion protection is a pure durability guard (no auth impact) → hardening
  # flag. MFA/advanced-security below stay on is_prod so enabling hardening
  # never forces MFA enrollment on existing users.
  deletion_protection      = var.production_hardening ? "ACTIVE" : "INACTIVE"
  auto_verified_attributes = ["email"]

  # A self-service email change must be re-verified before it replaces the
  # verified address — otherwise email_verified could remain true for an
  # unproven address (the super-admin gate relies on this claim).
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # All user-facing emails are sent via our custom SES email handler
  # (infrastructure/lambda/email/handler.ts) — not through Cognito.
  # Admin-created users use MessageAction=SUPPRESS and invited users
  # receive a branded invitation email. Password resets generate a custom
  # code stored in DynamoDB and sent via SES.

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  schema {
    name                = "role"
    attribute_data_type = "String"
    required            = false
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  schema {
    name                = "org"
    attribute_data_type = "String"
    required            = false
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 128
    }
  }

  schema {
    name                = "orgRole"
    attribute_data_type = "String"
    required            = false
    mutable             = true

    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  mfa_configuration = var.is_prod ? "ON" : "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  user_pool_add_ons {
    advanced_security_mode = var.is_prod ? "ENFORCED" : "OFF"
  }

  tags = { Name = "obsidian-vaultguard-${var.stage}" }
}

resource "aws_cognito_user_pool_client" "plugin" {
  name         = "obsidian-vaultguard-plugin-${var.stage}"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false # Public client (native app)

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_CUSTOM_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  callback_urls                        = var.callback_urls
  logout_urls                          = var.logout_urls
  supported_identity_providers         = ["COGNITO"]

  access_token_validity  = 60 # minutes
  id_token_validity      = 60 # minutes
  refresh_token_validity = 30 # days

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  prevent_user_existence_errors = "ENABLED"

  # SECURITY (auth/tenant isolation): end users must NOT be able to self-write
  # the identity/authorization claims the backend trusts. custom:org (tenant
  # identity — shared/utils.ts:358), custom:role and custom:orgRole (org-admin
  # authority — extractRolesFromTokenPayload → rolesIncludeOrgAdmin) are
  # `mutable = true` at the pool level ONLY so server-side admin APIs
  # (AdminCreateUser in signup/handler.ts, AdminUpdateUserAttributes in
  # users/handler.ts) can set them — the admin API bypasses this per-client
  # attribute-permission list. Without an explicit write_attributes, Cognito
  # defaults a public client to "all mutable attributes writable", letting a
  # member call `cognito-idp update-user-attributes --access-token <t>
  # --user-attributes Name=custom:role,Value=admin` (self-promotion to org
  # admin) or Name=custom:org,Value=<victimOrg> (cross-tenant takeover). This
  # list denies every attribute NOT named; `email` stays writable to support
  # the self-service email change flow (re-verified via
  # user_attribute_update_settings above). Verified: zero non-admin
  # UpdateUserAttributes call sites exist in the codebase, so no legitimate
  # flow self-writes the custom claims through a user token.
  # NOTE: takes effect on `terraform apply`; until deployed the pool retains
  # the permissive default. Recommended defense-in-depth follow-up: a
  # pre-token-generation Lambda that re-derives these claims from a
  # server-authoritative membership record at every token mint.
  write_attributes = ["email"]
}

# Platform super-admin group — members can access the /superadmin/* platform
# stats API (still gated by the SUPER_ADMIN_EMAILS allowlist in the Lambda).
resource "aws_cognito_user_group" "platform_superadmin" {
  name         = "platform-superadmin"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = "Platform operators with access to the /superadmin/* stats API"
  precedence   = 0
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = "obsidian-vaultguard-${var.stage}"
  user_pool_id = aws_cognito_user_pool.main.id
}

output "user_pool_id" { value = aws_cognito_user_pool.main.id }
output "user_pool_arn" { value = aws_cognito_user_pool.main.arn }
output "client_id" { value = aws_cognito_user_pool_client.plugin.id }
