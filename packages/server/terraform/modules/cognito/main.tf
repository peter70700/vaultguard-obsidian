variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "production_hardening" { type = bool }
variable "callback_urls" { type = list(string) }
variable "logout_urls" { type = list(string) }
variable "ses_sender_email" { type = string }
variable "sessions_table_name" { type = string }
variable "sessions_table_arn" { type = string }
variable "kms_key_arn" { type = string }
variable "turnstile_secret_arn" {
  type        = string
  default     = ""
  description = "Secrets Manager ARN containing the Turnstile secret used for account binding."
}
variable "login_verification_mode" {
  type        = string
  default     = "disabled"
  description = "Dedicated Pre Authentication permit posture."

  validation {
    condition     = contains(["disabled", "observe", "enforce"], var.login_verification_mode)
    error_message = "login_verification_mode must be disabled, observe, or enforce."
  }
}
variable "login_verification_client_ids" {
  type        = list(string)
  default     = []
  description = "Explicit managed app-client allowlist for login-permit enforcement."

  validation {
    condition = alltrue([
      for client_id in var.login_verification_client_ids :
      can(regex("^[a-z0-9]{20,128}$", client_id))
    ])
    error_message = "Every login verification client ID must be a Cognito app-client identifier."
  }
}
variable "mfa_configuration" {
  type        = string
  default     = "OPTIONAL"
  description = "Explicit user-pool MFA posture; independent of the deployment stage name."

  validation {
    condition     = contains(["OFF", "OPTIONAL", "ON"], var.mfa_configuration)
    error_message = "mfa_configuration must be OFF, OPTIONAL, or ON."
  }
}

variable "advanced_security_mode" {
  type        = string
  default     = "OFF"
  description = "Explicit Cognito advanced-security posture; AUDIT/ENFORCED may incur cost."

  validation {
    condition     = contains(["OFF", "AUDIT", "ENFORCED"], var.advanced_security_mode)
    error_message = "advanced_security_mode must be OFF, AUDIT, or ENFORCED."
  }
}

variable "ses_sender_arn" {
  type    = string
  default = ""
}

resource "aws_cognito_user_pool" "main" {
  name = "obsidian-vaultguard-${var.stage}"
  # Deletion protection is a pure durability guard (no auth impact). MFA and
  # advanced security have separate explicit inputs so stage naming cannot
  # silently select the live authentication posture.
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

  mfa_configuration = var.mfa_configuration

  software_token_mfa_configuration {
    enabled = true
  }

  # Feature plan must be stated explicitly, not left computed. Threat protection
  # (advanced_security_mode AUDIT/ENFORCED) is a PLUS-plan feature under AWS's
  # current Cognito feature-plan model, so setting the add-on while the pool sits
  # on ESSENTIALS either fails with InvalidParameterException or silently upgrades
  # the plan — and the per-MAU rate with it (eu-central-1 tier 1: ESSENTIALS
  # $0.0150, PLUS $0.0200). Deriving the tier here keeps the billing change
  # visible in `terraform plan` instead of landing as a surprise on the invoice.
  user_pool_tier = var.advanced_security_mode == "OFF" ? "ESSENTIALS" : "PLUS"

  user_pool_add_ons {
    advanced_security_mode = var.advanced_security_mode
  }

  lambda_config {
    pre_authentication = aws_lambda_function.pre_authentication.arn
  }

  tags = { Name = "obsidian-vaultguard-${var.stage}" }
}

# Dedicated trigger role and artifact. It can consume one permit row and read
# one provider secret; it has no Cognito admin or tenant-data permissions.
data "archive_file" "pre_authentication" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/auth"
  output_path = "${path.module}/.build/pre-authentication.zip"
}

data "aws_iam_policy_document" "pre_authentication_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "pre_authentication" {
  name               = "vaultguard-${var.stage}-cognito-pre-authentication"
  assume_role_policy = data.aws_iam_policy_document.pre_authentication_assume.json
}

data "aws_iam_policy_document" "pre_authentication" {
  statement {
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }
  statement {
    actions   = ["dynamodb:UpdateItem"]
    resources = [var.sessions_table_arn]
  }
  dynamic "statement" {
    for_each = var.turnstile_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.turnstile_secret_arn]
    }
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "pre_authentication" {
  name   = "cognito-pre-authentication"
  role   = aws_iam_role.pre_authentication.id
  policy = data.aws_iam_policy_document.pre_authentication.json
}

resource "aws_lambda_function" "pre_authentication" {
  function_name = "vaultguard-cognito-pre-authentication-${var.stage}"
  role          = aws_iam_role.pre_authentication.arn
  handler       = "handler.cognitoPreAuthenticationHandler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  timeout       = 10
  memory_size   = 128

  filename         = data.archive_file.pre_authentication.output_path
  source_code_hash = data.archive_file.pre_authentication.output_base64sha256

  environment {
    variables = {
      SESSIONS_TABLE                = var.sessions_table_name
      TURNSTILE_SECRET_ARN          = var.turnstile_secret_arn
      LOGIN_VERIFICATION_MODE       = var.login_verification_mode
      LOGIN_VERIFICATION_CLIENT_IDS = join(",", var.login_verification_client_ids)
      NODE_OPTIONS                  = "--enable-source-maps"
    }
  }

  lifecycle {
    precondition {
      condition = (
        var.login_verification_mode == "disabled" ||
        length(var.login_verification_client_ids) > 0
      )
      error_message = "observe/enforce login verification requires a non-empty managed app-client allowlist."
    }
    precondition {
      condition     = var.login_verification_mode == "disabled" || var.turnstile_secret_arn != ""
      error_message = "observe/enforce login verification requires an explicit stage-specific turnstile_secret_arn."
    }
  }
}

# Managed log group for the Pre Authentication trigger. Without this, Lambda
# auto-creates the group on first invoke with NEVER-EXPIRE retention, outside
# Terraform's control — unbounded cost and an unbounded retention window for a
# function that sees every login attempt. Retention matches the Lambda module's
# production_hardening gate rather than the stage name (SD-12-F12).
resource "aws_cloudwatch_log_group" "pre_authentication" {
  name              = "/aws/lambda/${aws_lambda_function.pre_authentication.function_name}"
  retention_in_days = var.production_hardening ? 365 : 7

  tags = { Name = "vaultguard-cognito-pre-authentication-${var.stage}" }
}

resource "aws_lambda_permission" "allow_cognito_pre_authentication" {
  statement_id  = "AllowCognitoPreAuthentication"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.pre_authentication.function_name
  principal     = "cognito-idp.amazonaws.com"
  source_arn    = aws_cognito_user_pool.main.arn
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
output "pre_authentication_function_name" { value = aws_lambda_function.pre_authentication.function_name }
