variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "callback_urls" { type = list(string) }
variable "logout_urls" { type = list(string) }
variable "ses_sender_email" { type = string }
variable "ses_sender_arn" {
  type    = string
  default = ""
}

resource "aws_cognito_user_pool" "main" {
  name                     = "obsidian-vaultguard-${var.stage}"
  deletion_protection      = var.is_prod ? "ACTIVE" : "INACTIVE"
  auto_verified_attributes = ["email"]

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
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = "obsidian-vaultguard-${var.stage}"
  user_pool_id = aws_cognito_user_pool.main.id
}

output "user_pool_id" { value = aws_cognito_user_pool.main.id }
output "user_pool_arn" { value = aws_cognito_user_pool.main.arn }
output "client_id" { value = aws_cognito_user_pool_client.plugin.id }
