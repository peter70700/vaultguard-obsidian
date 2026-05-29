variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "kms_key_arn" { type = string }
variable "kms_key_id" { type = string }
variable "vault_bucket_name" { type = string }
variable "vault_bucket_arn" { type = string }
variable "permissions_table_name" { type = string }
variable "permissions_table_arn" { type = string }
variable "audit_table_name" { type = string }
variable "audit_table_arn" { type = string }
variable "alerts_table_name" { type = string }
variable "alerts_table_arn" { type = string }
variable "sessions_table_name" { type = string }
variable "sessions_table_arn" { type = string }
variable "user_keys_table_name" { type = string }
variable "user_keys_table_arn" { type = string }
variable "cognito_user_pool_arn" { type = string }
variable "cognito_user_pool_id" { type = string }
variable "cognito_client_id" { type = string }
variable "key_lease_duration_seconds" { type = number }
variable "session_duration_seconds" { type = number }
variable "max_file_size_bytes" { type = number }
variable "organizations_table_name" { type = string }
variable "organizations_table_arn" { type = string }
variable "subscriptions_table_name" { type = string }
variable "subscriptions_table_arn" { type = string }
variable "stripe_webhook_events_table_name" { type = string }
variable "stripe_webhook_events_table_arn" { type = string }
variable "leases_table_name" { type = string }
variable "leases_table_arn" { type = string }
variable "reencryption_jobs_table_name" { type = string }
variable "reencryption_jobs_table_arn" { type = string }
variable "revoked_keys_table_name" { type = string }
variable "revoked_keys_table_arn" { type = string }
variable "recovery_codes_table_name" { type = string }
variable "recovery_codes_table_arn" { type = string }
variable "recovery_attempts_table_name" { type = string }
variable "recovery_attempts_table_arn" { type = string }
variable "vaults_table_name" { type = string }
variable "vaults_table_arn" { type = string }
variable "vault_members_table_name" { type = string }
variable "vault_members_table_arn" { type = string }
variable "vault_activity_table_name" { type = string }
variable "vault_activity_table_arn" { type = string }
variable "shares_table_name" { type = string }
variable "shares_table_arn" { type = string }
variable "stripe_secret_arn" {
  type        = string
  default     = ""
  description = "ARN of the Secrets Manager secret containing Stripe keys. Empty on Community Edition — the billing lambda becomes an inert 404 stub."
}
variable "turnstile_secret_arn" {
  type        = string
  default     = ""
  description = "Secrets Manager ARN for Cloudflare Turnstile secret key. Leave empty to disable Turnstile (CE fail-open)."
}
variable "vaultguard_edition" {
  type        = string
  description = "Runtime feature edition reported by GET /orgs/{slug}/config and enforced by Pro-only handlers."

  validation {
    condition     = contains(["community", "pro"], var.vaultguard_edition)
    error_message = "vaultguard_edition must be either community or pro."
  }
}
variable "allow_public_signup" {
  type        = bool
  default     = false
  description = "When true, Community Edition keeps public signup open after the first org."
}
variable "sender_email" {
  type    = string
  default = "noreply@example.com"
}
variable "domain_name" {
  type    = string
  default = ""
}
variable "reconciler_schedule" {
  type        = string
  default     = "cron(0 3 * * ? *)"
  description = "EventBridge schedule expression for the nightly user-count reconciler. Override per-stage if desired."
}

data "aws_region" "current" {}

locals {
  common_env = {
    STAGE                   = var.stage
    VAULT_BUCKET            = var.vault_bucket_name
    PERMISSIONS_TABLE       = var.permissions_table_name
    AUDIT_TABLE             = var.audit_table_name
    ALERTS_TABLE            = var.alerts_table_name
    SESSIONS_TABLE          = var.sessions_table_name
    USER_KEYS_TABLE         = var.user_keys_table_name
    REVOKED_KEYS_TABLE      = var.revoked_keys_table_name
    RECOVERY_CODES_TABLE    = var.recovery_codes_table_name
    RECOVERY_ATTEMPTS_TABLE = var.recovery_attempts_table_name
    ORGANIZATIONS_TABLE     = var.organizations_table_name
    LEASES_TABLE            = var.leases_table_name
    VAULTS_TABLE            = var.vaults_table_name
    VAULT_MEMBERS_TABLE     = var.vault_members_table_name
    VAULT_ACTIVITY_TABLE    = var.vault_activity_table_name
    SHARES_TABLE            = var.shares_table_name
    # Every authenticated Lambda reads this in `assertSubscriptionAllowsAccess`
    # (the SaaS subscription gate). Signup also writes a `pending_checkout`
    # row here. Promoted to common_env so a new handler can't forget it.
    SUBSCRIPTIONS_TABLE  = var.subscriptions_table_name
    KMS_KEY_ID           = var.kms_key_id
    COGNITO_USER_POOL_ID = var.cognito_user_pool_id
    COGNITO_CLIENT_ID    = var.cognito_client_id
    VAULTGUARD_EDITION   = var.vaultguard_edition
    SENDER_EMAIL         = var.sender_email
    ALLOWED_CORS_ORIGIN  = var.domain_name != "" ? "https://admin.${var.domain_name}" : "http://localhost:5173"
    SHARE_BASE_URL       = var.domain_name != "" ? "https://share.${var.domain_name}" : "http://localhost:5176"
    NODE_OPTIONS         = "--enable-source-maps"
  }
  log_retention = var.is_prod ? 365 : 7
}

# ─── Lambda Source Packaging ─────────────────────────────────────────────────
# Uses compiled JS bundles from infrastructure/dist/ (run build-lambdas.mjs first)

data "archive_file" "auth_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/auth"
  output_path = "${path.module}/.build/auth.zip"
}

data "archive_file" "files_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/files"
  output_path = "${path.module}/.build/files.zip"
}

data "archive_file" "permissions_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/permissions"
  output_path = "${path.module}/.build/permissions.zip"
}

data "archive_file" "audit_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/audit"
  output_path = "${path.module}/.build/audit.zip"
}

data "archive_file" "billing_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/billing"
  output_path = "${path.module}/.build/billing.zip"
}

data "archive_file" "signup_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/signup"
  output_path = "${path.module}/.build/signup.zip"
}

data "archive_file" "users_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/users"
  output_path = "${path.module}/.build/users.zip"
}

data "archive_file" "reencryption_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/reencryption"
  output_path = "${path.module}/.build/reencryption.zip"
}

data "archive_file" "reconciler_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/reconciler"
  output_path = "${path.module}/.build/reconciler.zip"
}

data "archive_file" "vaults_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/vaults"
  output_path = "${path.module}/.build/vaults.zip"
}

data "archive_file" "shares_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/shares"
  output_path = "${path.module}/.build/shares.zip"
}

# ─── IAM Roles ───────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Base logging policy for all Lambdas
data "aws_iam_policy_document" "lambda_logging" {
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_policy" "lambda_logging" {
  name   = "vaultguard-${var.stage}-lambda-logging"
  policy = data.aws_iam_policy_document.lambda_logging.json
}

# ─── Auth Lambda ─────────────────────────────────────────────────────────────

resource "aws_iam_role" "auth_lambda" {
  name               = "vaultguard-${var.stage}-auth-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "auth_logging" {
  role       = aws_iam_role.auth_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "auth_lambda" {
  # SaaS subscription gate (`assertSubscriptionAllowsAccess` in shared/utils.ts)
  # reads the org's Subscriptions row on every authenticated request and
  # rejects pending_checkout / canceled orgs with HTTP 402. Every Lambda that
  # calls verifyActiveUser needs this grant. (Skipped on EDITION=community,
  # but the IAM permission itself is harmless to leave attached there.)
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  statement {
    actions = [
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminListGroupsForUser",
      "cognito-idp:AdminSetUserPassword",
      # Required by recovery-code verify: clears the user's MFA preference so
      # the next Cognito login routes through MFA_SETUP and the user can
      # enroll a fresh authenticator.
      "cognito-idp:AdminSetUserMFAPreference",
    ]
    resources = [var.cognito_user_pool_arn]
  }
  # Recovery codes: PutItem (store, atomically replace on re-enroll),
  # DeleteItem (single-use consumption via conditional check), Query (verify
  # ownership before consumption).
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
    resources = [var.recovery_codes_table_arn]
  }
  # Recovery attempts: rate-limit counter — UpdateItem with ADD on a numeric
  # attribute is the atomic increment. GetItem for the read-during-verify path.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:PutItem"]
    resources = [var.recovery_attempts_table_arn]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.sessions_table_arn, "${var.sessions_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.user_keys_table_arn, "${var.user_keys_table_arn}/index/*"]
  }
  # Revoked keys: Query during checkKeyRevocation (handleGetKeyLease — login
  # path), PutItem during handleRevoke. Without this, login returns 500.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
    resources = [var.revoked_keys_table_arn]
  }
  # Permissions: evaluatePermission (called by handleScopedKeyLease) reads the
  # user/role/wildcard permission rules through the userId-index and
  # role-index GSIs. Without these grants, scoped key-lease issuance 500s.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.permissions_table_arn, "${var.permissions_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    actions   = ["events:PutEvents"]
    resources = ["*"]
  }
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "auth_lambda" {
  name   = "auth-lambda-policy"
  role   = aws_iam_role.auth_lambda.id
  policy = data.aws_iam_policy_document.auth_lambda.json
}

resource "aws_lambda_function" "auth" {
  function_name = "vaultguard-auth-${var.stage}"
  description   = "Handles authentication, session management, and key lease issuance"
  role          = aws_iam_role.auth_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.auth_lambda.output_path
  source_code_hash = data.archive_file.auth_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      KMS_KEY_ARN                = var.kms_key_arn
      KEY_LEASE_DURATION_SECONDS = tostring(var.key_lease_duration_seconds)
      SESSION_DURATION_SECONDS   = tostring(var.session_duration_seconds)
      USER_POOL_ID               = var.cognito_user_pool_id
      CLIENT_ID                  = var.cognito_client_id
    })
  }

  tags = { Name = "vaultguard-auth-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "auth" {
  name              = "/aws/lambda/${aws_lambda_function.auth.function_name}"
  retention_in_days = local.log_retention
}

# ─── Files Lambda ────────────────────────────────────────────────────────────

resource "aws_iam_role" "files_lambda" {
  name               = "vaultguard-${var.stage}-files-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "files_logging" {
  role       = aws_iam_role.files_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "files_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  statement {
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:ListBucket",
      "s3:GetObjectVersion",
      "s3:ListBucketVersions",
    ]
    resources = [var.vault_bucket_arn, "${var.vault_bucket_arn}/*"]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  # Vaults table: GetItem for membership/cursor reads, UpdateItem to bump
  # the per-vault revision counter on every file mutation.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem"]
    resources = [var.vaults_table_arn, "${var.vaults_table_arn}/index/*"]
  }
  # Vault activity log: append on writes/deletes, query for delta sync.
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:Query"]
    resources = [var.vault_activity_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.permissions_table_arn, "${var.permissions_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.sessions_table_arn, "${var.sessions_table_arn}/index/*"]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.user_keys_table_arn, "${var.user_keys_table_arn}/index/*",
    ]
  }
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.revoked_keys_table_arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "files_lambda" {
  name   = "files-lambda-policy"
  role   = aws_iam_role.files_lambda.id
  policy = data.aws_iam_policy_document.files_lambda.json
}

resource "aws_lambda_function" "files" {
  function_name = "vaultguard-files-${var.stage}"
  description   = "Handles file upload, download, sync, and conflict resolution"
  role          = aws_iam_role.files_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 60

  filename         = data.archive_file.files_lambda.output_path
  source_code_hash = data.archive_file.files_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      VAULT_S3_BUCKET = var.vault_bucket_name
      MAX_FILE_SIZE   = tostring(var.max_file_size_bytes)
    })
  }

  tags = { Name = "vaultguard-files-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "files" {
  name              = "/aws/lambda/${aws_lambda_function.files.function_name}"
  retention_in_days = local.log_retention
}

# ─── Permissions Lambda ──────────────────────────────────────────────────────

resource "aws_iam_role" "permissions_lambda" {
  name               = "vaultguard-${var.stage}-perms-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "perms_logging" {
  role       = aws_iam_role.permissions_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "permissions_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.permissions_table_arn, "${var.permissions_table_arn}/index/*"]
  }
  # Vaults table: GetItem for membership, UpdateItem so permission mutations
  # can bump the vault revision counter (signals peer clients to refresh).
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:UpdateItem"]
    resources = [
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
    ]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  # Activity log: append a permission_changed row on every grant/update/revoke.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.vault_activity_table_arn]
  }
  statement {
    actions   = ["dynamodb:Query", "dynamodb:UpdateItem", "dynamodb:Scan"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "permissions_lambda" {
  name   = "perms-lambda-policy"
  role   = aws_iam_role.permissions_lambda.id
  policy = data.aws_iam_policy_document.permissions_lambda.json
}

resource "aws_lambda_function" "permissions" {
  function_name = "vaultguard-permissions-${var.stage}"
  description   = "Manages per-file permission grants, revocations, and inheritance"
  role          = aws_iam_role.permissions_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.permissions_lambda.output_path
  source_code_hash = data.archive_file.permissions_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = local.common_env
  }

  tags = { Name = "vaultguard-permissions-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "permissions" {
  name              = "/aws/lambda/${aws_lambda_function.permissions.function_name}"
  retention_in_days = local.log_retention
}

# ─── Audit Lambda ────────────────────────────────────────────────────────────

resource "aws_iam_role" "audit_lambda" {
  name               = "vaultguard-${var.stage}-audit-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "audit_logging" {
  role       = aws_iam_role.audit_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "audit_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.audit_table_arn, "${var.audit_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.alerts_table_arn, "${var.alerts_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.sessions_table_arn, "${var.sessions_table_arn}/index/*"]
  }
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.revoked_keys_table_arn]
  }
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "audit_lambda" {
  name   = "audit-lambda-policy"
  role   = aws_iam_role.audit_lambda.id
  policy = data.aws_iam_policy_document.audit_lambda.json
}

resource "aws_lambda_function" "audit" {
  function_name = "vaultguard-audit-${var.stage}"
  description   = "Queries audit logs, generates reports, and detects anomalies"
  role          = aws_iam_role.audit_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.audit_lambda.output_path
  source_code_hash = data.archive_file.audit_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = local.common_env
  }

  tags = { Name = "vaultguard-audit-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/${aws_lambda_function.audit.function_name}"
  retention_in_days = local.log_retention
}

# ─── Billing Lambda ──────────────────────────────────────────────────────────

resource "aws_iam_role" "billing_lambda" {
  name               = "vaultguard-${var.stage}-billing-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "billing_logging" {
  role       = aws_iam_role.billing_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "billing_lambda" {
  # Secrets Manager — retrieve Stripe keys.
  # Skipped on Community Edition where stripe_secret_arn = "" (billing is a
  # 404 stub there and never invokes Secrets Manager).
  dynamic "statement" {
    for_each = var.stripe_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.stripe_secret_arn]
    }
  }
  # KMS — decrypt the secret (encrypted with project master key)
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }
  # DynamoDB — audit
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.audit_table_arn, "${var.audit_table_arn}/index/*"]
  }
  # DynamoDB — subscriptions
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.subscriptions_table_arn, "${var.subscriptions_table_arn}/index/*"]
  }
  # DynamoDB — Stripe webhook dedup (PutItem only; TTL handles cleanup)
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.stripe_webhook_events_table_arn]
  }
  # DynamoDB — organizations
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # DynamoDB — shared auth guard for billing APIs
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn]
  }
  # SES — send billing emails
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "billing_lambda" {
  name   = "billing-lambda-policy"
  role   = aws_iam_role.billing_lambda.id
  policy = data.aws_iam_policy_document.billing_lambda.json
}

resource "aws_lambda_function" "billing" {
  function_name = "vaultguard-billing-${var.stage}"
  description   = "Stripe webhook handler and subscription management"
  role          = aws_iam_role.billing_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.billing_lambda.output_path
  source_code_hash = data.archive_file.billing_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      STRIPE_SECRET_ARN           = var.stripe_secret_arn
      STRIPE_WEBHOOK_EVENTS_TABLE = var.stripe_webhook_events_table_name
      BASE_URL                    = var.domain_name != "" ? "https://admin.${var.domain_name}" : ""
    })
  }

  tags = { Name = "vaultguard-billing-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "billing" {
  name              = "/aws/lambda/${aws_lambda_function.billing.function_name}"
  retention_in_days = local.log_retention
}

# ─── Signup Lambda ───────────────────────────────────────────────────────────

resource "aws_iam_role" "signup_lambda" {
  name               = "vaultguard-${var.stage}-signup-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "signup_logging" {
  role       = aws_iam_role.signup_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "signup_lambda" {
  # SaaS no-free-tier flow: every new org gets a Subscriptions row in
  # status='pending_checkout' at signup time. Without PutItem here the signup
  # Lambda 500s with "Member must not be null" on the table-name attribute.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.subscriptions_table_arn]
  }
  # Cognito — create users, groups, set passwords
  statement {
    actions = [
      "cognito-idp:AdminCreateUser",
      "cognito-idp:AdminSetUserPassword",
      "cognito-idp:AdminAddUserToGroup",
      "cognito-idp:AdminGetUser",
      "cognito-idp:CreateGroup",
    ]
    resources = [var.cognito_user_pool_arn]
  }
  # Secrets Manager — retrieve Cloudflare Turnstile secret key.
  # Skipped on Community Edition where turnstile_secret_arn = "" (signup
  # fails-open and never invokes Secrets Manager). Mirrors the billing
  # Lambda's Stripe-secret pattern at lines 627-633.
  dynamic "statement" {
    for_each = var.turnstile_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.turnstile_secret_arn]
    }
  }
  # DynamoDB — create org, permissions, audit, default vault + membership
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query"]
    resources = [
      var.permissions_table_arn, "${var.permissions_table_arn}/index/*",
      var.audit_table_arn, "${var.audit_table_arn}/index/*",
      var.organizations_table_arn, "${var.organizations_table_arn}/index/*",
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  # DynamoDB Scan — Community Edition hasAnyOrg() single-tenant gate and
  # /.well-known/vaultguard.json single-org discovery. Scoped to Organizations table.
  statement {
    actions   = ["dynamodb:Scan"]
    resources = [var.organizations_table_arn]
  }
  # KMS — decrypt DynamoDB table data (tables use KMS encryption)
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  # SES — send welcome email
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "signup_lambda" {
  name   = "signup-lambda-policy"
  role   = aws_iam_role.signup_lambda.id
  policy = data.aws_iam_policy_document.signup_lambda.json
}

resource "aws_lambda_function" "signup" {
  function_name = "vaultguard-signup-${var.stage}"
  description   = "Public signup and org provisioning"
  role          = aws_iam_role.signup_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.signup_lambda.output_path
  source_code_hash = data.archive_file.signup_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      USER_POOL_ID                   = var.cognito_user_pool_id
      CLIENT_ID                      = var.cognito_client_id
      VAULTGUARD_ALLOW_PUBLIC_SIGNUP = tostring(var.allow_public_signup)
      TURNSTILE_SECRET_ARN           = var.turnstile_secret_arn
    })
  }

  tags = { Name = "vaultguard-signup-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "signup" {
  name              = "/aws/lambda/${aws_lambda_function.signup.function_name}"
  retention_in_days = local.log_retention
}

# ─── Users Lambda ────────────────────────────────────────────────────────────

resource "aws_iam_role" "users_lambda" {
  name               = "vaultguard-${var.stage}-users-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "users_logging" {
  role       = aws_iam_role.users_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "users_lambda" {
  statement {
    actions = [
      "cognito-idp:AdminCreateUser",
      "cognito-idp:AdminGetUser",
      "cognito-idp:AdminSetUserPassword",
      "cognito-idp:AdminAddUserToGroup",
      "cognito-idp:AdminRemoveUserFromGroup",
      "cognito-idp:AdminDisableUser",
      "cognito-idp:AdminEnableUser",
      "cognito-idp:AdminListGroupsForUser",
      "cognito-idp:AdminUpdateUserAttributes",
      # Required by /users/{userId}/reset-mfa: clears the user's TOTP
      # preference so the next login routes to MFA_SETUP.
      "cognito-idp:AdminSetUserMFAPreference",
      "cognito-idp:CreateGroup",
      "cognito-idp:ListGroups",
      "cognito-idp:ListUsers",
      "cognito-idp:ListUsersInGroup",
    ]
    resources = [var.cognito_user_pool_arn]
  }
  # Recovery codes: admin reset-MFA wipes all stored codes for the target
  # user. Query to list, BatchWriteItem to delete in chunks.
  statement {
    actions   = ["dynamodb:Query", "dynamodb:BatchWriteItem", "dynamodb:DeleteItem"]
    resources = [var.recovery_codes_table_arn]
  }
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [
      var.organizations_table_arn, "${var.organizations_table_arn}/index/*",
      var.audit_table_arn, "${var.audit_table_arn}/index/*",
      var.sessions_table_arn, "${var.sessions_table_arn}/index/*",
    ]
  }
  # Revoked keys: PutItem when an admin revokes a user, DeleteItem on
  # reactivate. Mirrors the auth Lambda's grant — same table, narrower ops.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [var.revoked_keys_table_arn]
  }
  # Leases: handleRevoke queries userId-index to find the offboarded user's
  # active leases and updates each to status=revoked, so cached DEKs stop
  # being usable. Without this grant the offboarding flow 500s.
  statement {
    actions   = ["dynamodb:Query", "dynamodb:UpdateItem"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
  }
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["*"]
  }
  statement {
    actions   = ["events:PutEvents"]
    resources = ["*"]
  }
  # Secrets Manager — read Stripe secret for server-side seat sync after
  # invite/revoke/reactivate. Guarded for Community Edition where
  # stripe_secret_arn = "" (billing is a 404 stub and seat-sync is a no-op).
  dynamic "statement" {
    for_each = var.stripe_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.stripe_secret_arn]
    }
  }
  # DynamoDB — Subscriptions table for seat-sync helper (read the sub record,
  # update local quantity after Stripe accepts the new seat count).
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.subscriptions_table_arn]
  }
}

resource "aws_iam_role_policy" "users_lambda" {
  name   = "users-lambda-policy"
  role   = aws_iam_role.users_lambda.id
  policy = data.aws_iam_policy_document.users_lambda.json
}

resource "aws_lambda_function" "users" {
  function_name = "vaultguard-users-${var.stage}"
  description   = "User management — invite, roles, revoke, reactivate"
  role          = aws_iam_role.users_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.users_lambda.output_path
  source_code_hash = data.archive_file.users_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      USER_POOL_ID      = var.cognito_user_pool_id
      STRIPE_SECRET_ARN = var.stripe_secret_arn
    })
  }

  tags = { Name = "vaultguard-users-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "users" {
  name              = "/aws/lambda/${aws_lambda_function.users.function_name}"
  retention_in_days = local.log_retention
}

# ─── Re-encryption Lambda ───────────────────────────────────────────────────

resource "aws_iam_role" "reencryption_lambda" {
  name               = "vaultguard-${var.stage}-reencryption-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "reencryption_logging" {
  role       = aws_iam_role.reencryption_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "reencryption_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  # S3 — read/write vault files for re-encryption
  statement {
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [var.vault_bucket_arn, "${var.vault_bucket_arn}/*"]
  }
  # KMS — decrypt old DEKs and generate new DEKs
  statement {
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
  }
  # DynamoDB — re-encryption jobs table
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.reencryption_jobs_table_arn, "${var.reencryption_jobs_table_arn}/index/*"]
  }
  # DynamoDB — permissions (read affected paths)
  statement {
    actions   = ["dynamodb:Query"]
    resources = [var.permissions_table_arn, "${var.permissions_table_arn}/index/*"]
  }
  # DynamoDB — leases (recover old DEKs)
  statement {
    actions   = ["dynamodb:Query"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
  }
  # DynamoDB — user keys (Get current scope DEK, archive previous as ROTATED#,
  # insert new ACTIVE). Without this, every re-encryption job 500s during
  # the key-rotation step.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem"]
    resources = [var.user_keys_table_arn]
  }
  # DynamoDB — audit logging
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # DynamoDB — organizations (audit retention and org policy lookup)
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # DynamoDB — shared auth guard for manual trigger/status APIs
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn]
  }
  # Cognito — verify tokens
  statement {
    actions   = ["cognito-idp:GetUser"]
    resources = [var.cognito_user_pool_arn]
  }
}

resource "aws_iam_role_policy" "reencryption_lambda" {
  name   = "reencryption-lambda-policy"
  role   = aws_iam_role.reencryption_lambda.id
  policy = data.aws_iam_policy_document.reencryption_lambda.json
}

resource "aws_lambda_function" "reencryption" {
  function_name = "vaultguard-reencryption-${var.stage}"
  description   = "Re-encrypts vault files after user offboarding"
  role          = aws_iam_role.reencryption_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 300

  filename         = data.archive_file.reencryption_lambda.output_path
  source_code_hash = data.archive_file.reencryption_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      REENCRYPTION_JOBS_TABLE = var.reencryption_jobs_table_name
    })
  }

  tags = { Name = "vaultguard-reencryption-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "reencryption" {
  name              = "/aws/lambda/${aws_lambda_function.reencryption.function_name}"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_event_rule" "user_access_revoked" {
  name        = "vaultguard-${var.stage}-user-access-revoked"
  description = "Triggers re-encryption after VaultGuard user access revocation"

  event_pattern = jsonencode({
    source        = ["vaultguard.auth"]
    "detail-type" = ["UserAccessRevoked"]
  })
}

resource "aws_cloudwatch_event_target" "reencryption_user_access_revoked" {
  rule      = aws_cloudwatch_event_rule.user_access_revoked.name
  target_id = "vaultguard-reencryption-${var.stage}"
  arn       = aws_lambda_function.reencryption.arn
}

resource "aws_lambda_permission" "allow_eventbridge_reencryption" {
  statement_id  = "AllowExecutionFromUserAccessRevokedEvent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reencryption.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.user_access_revoked.arn
}

# ─── Reconciler Lambda ───────────────────────────────────────────────────────
# Nightly defense-in-depth job: re-derives ORGANIZATIONS_TABLE.currentUsers
# from Cognito ground truth and re-syncs Stripe seats via the existing
# syncStripeSeats helper from billing/handler. EventBridge-only — no API
# Gateway surface.

resource "aws_iam_role" "reconciler_lambda" {
  name               = "vaultguard-${var.stage}-reconciler-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "reconciler_logging" {
  role       = aws_iam_role.reconciler_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "reconciler_lambda" {
  # Cognito — list users across the pool, filter by `custom:org` in code
  # (Cognito ListUsers does not support filters on custom attributes).
  statement {
    actions   = ["cognito-idp:ListUsers"]
    resources = [var.cognito_user_pool_arn]
  }
  # Organizations — Scan for the all-orgs sweep, Query on orgId-index for the
  # ad-hoc single-org path, GetItem + UpdateItem for the drift fix.
  statement {
    actions   = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # Subscriptions — needed transitively by syncStripeSeats to read the org's
  # stripeSubscriptionId and upsert the local quantity record.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.subscriptions_table_arn, "${var.subscriptions_table_arn}/index/*"]
  }
  # Audit — one reconciler.org_reconciled row per active org per run.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # KMS — Organizations / Subscriptions / Audit tables are encrypted with the
  # project master key; without Decrypt/GenerateDataKey, the first table
  # access errors.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
  # Secrets Manager — Stripe key retrieval inside syncStripeSeats.
  # Skipped on Community Edition where stripe_secret_arn = "" (FEATURES.billing
  # is false at runtime so the helper is never called).
  dynamic "statement" {
    for_each = var.stripe_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.stripe_secret_arn]
    }
  }
}

resource "aws_iam_role_policy" "reconciler_lambda" {
  name   = "reconciler-lambda-policy"
  role   = aws_iam_role.reconciler_lambda.id
  policy = data.aws_iam_policy_document.reconciler_lambda.json
}

resource "aws_lambda_function" "reconciler" {
  function_name = "vaultguard-reconciler-${var.stage}"
  description   = "Nightly user-count + Stripe seat drift reconciler"
  role          = aws_iam_role.reconciler_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 300

  filename         = data.archive_file.reconciler_lambda.output_path
  source_code_hash = data.archive_file.reconciler_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      STRIPE_SECRET_ARN = var.stripe_secret_arn
      BASE_URL          = var.domain_name != "" ? "https://admin.${var.domain_name}" : ""
    })
  }

  tags = { Name = "vaultguard-reconciler-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "reconciler" {
  name              = "/aws/lambda/${aws_lambda_function.reconciler.function_name}"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_event_rule" "reconciler_schedule" {
  name                = "vaultguard-${var.stage}-reconciler-schedule"
  description         = "Nightly user-count + Stripe seat reconciliation"
  schedule_expression = var.reconciler_schedule
}

resource "aws_cloudwatch_event_target" "reconciler" {
  rule      = aws_cloudwatch_event_rule.reconciler_schedule.name
  target_id = "vaultguard-reconciler-${var.stage}"
  arn       = aws_lambda_function.reconciler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_reconciler" {
  statement_id  = "AllowExecutionFromReconcilerSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reconciler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reconciler_schedule.arn
}

# ─── Vaults Lambda ──────────────────────────────────────────────────────────

resource "aws_iam_role" "vaults_lambda" {
  name               = "vaultguard-${var.stage}-vaults-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "vaults_logging" {
  role       = aws_iam_role.vaults_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "vaults_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  # Vaults table — full CRUD
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"]
    resources = [var.vaults_table_arn, "${var.vaults_table_arn}/index/*"]
  }
  # VaultMembers table — full CRUD
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*"]
  }
  # Permissions table — write default member rules on vault create / member add/update/remove
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [var.permissions_table_arn]
  }
  # Leases table — revokeUserVaultLeases (called from member-remove and
  # role-downgrade flows) queries the userId-index to find the removed user's
  # active leases for the vault and updates each one to status=revoked.
  # Without this grant, member removal 500s on the lease-revocation step.
  statement {
    actions   = ["dynamodb:Query", "dynamodb:UpdateItem"]
    resources = [var.leases_table_arn, "${var.leases_table_arn}/index/*"]
  }
  # Vault activity log — member role changes alter effective permissions for
  # the whole vault, so append a permission_changed cursor event.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.vault_activity_table_arn]
  }
  # Audit logging
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # Organizations — read for org status checks
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # Shared auth guard
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn]
  }
  # Cognito — list users so we can enrich vault members with displayName /
  # email at read time. Without this, non-admin users (who can't hit the
  # admin-only /users endpoint) only see UUIDs in the file permission UI.
  statement {
    actions   = ["cognito-idp:ListUsers"]
    resources = [var.cognito_user_pool_arn]
  }
  # KMS — needed because tables use customer-managed keys
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "vaults_lambda" {
  name   = "vaults-lambda-policy"
  role   = aws_iam_role.vaults_lambda.id
  policy = data.aws_iam_policy_document.vaults_lambda.json
}

resource "aws_lambda_function" "vaults" {
  function_name = "vaultguard-vaults-${var.stage}"
  description   = "Vault CRUD and membership management"
  role          = aws_iam_role.vaults_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.vaults_lambda.output_path
  source_code_hash = data.archive_file.vaults_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      USER_POOL_ID = var.cognito_user_pool_id
    })
  }

  tags = { Name = "vaultguard-vaults-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "vaults" {
  name              = "/aws/lambda/${aws_lambda_function.vaults.function_name}"
  retention_in_days = local.log_retention
}

# ─── Shares Lambda ──────────────────────────────────────────────────────────
#
# Mints/lists/resolves/revokes opaque share-link tokens. The token itself
# carries no authority — every endpoint goes through the shared
# requireVaultMember gate, which is what makes share links "internal team
# only". See infrastructure/lambda/shares/handler.ts.

resource "aws_iam_role" "shares_lambda" {
  name               = "vaultguard-${var.stage}-shares-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "shares_logging" {
  role       = aws_iam_role.shares_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "shares_lambda" {
  # SaaS subscription gate — see auth_lambda for the full explainer.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.subscriptions_table_arn]
  }
  # Shares table — full CRUD + GSI query for listing per-vault.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.shares_table_arn, "${var.shares_table_arn}/index/*"]
  }
  # Vaults & members — read for requireVaultMember.
  statement {
    actions = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.vault_members_table_arn, "${var.vault_members_table_arn}/index/*",
    ]
  }
  # Permissions — evaluatePermission queries by userId/role/wildcard via GSIs
  # to enforce file-level read access on share mint and resolve.
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.permissions_table_arn, "${var.permissions_table_arn}/index/*"]
  }
  # Shared auth guard.
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.sessions_table_arn, var.revoked_keys_table_arn]
  }
  # Org status check (verifyActiveUser).
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.organizations_table_arn, "${var.organizations_table_arn}/index/*"]
  }
  # Audit logging.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # KMS — DynamoDB tables use the customer-managed key.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "shares_lambda" {
  name   = "shares-lambda-policy"
  role   = aws_iam_role.shares_lambda.id
  policy = data.aws_iam_policy_document.shares_lambda.json
}

resource "aws_lambda_function" "shares" {
  function_name = "vaultguard-shares-${var.stage}"
  description   = "Mints and resolves opaque share-link tokens for in-team file deep-links"
  role          = aws_iam_role.shares_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.shares_lambda.output_path
  source_code_hash = data.archive_file.shares_lambda.output_base64sha256

  tracing_config { mode = "Active" }

  environment {
    variables = local.common_env
  }

  tags = { Name = "vaultguard-shares-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "shares" {
  name              = "/aws/lambda/${aws_lambda_function.shares.function_name}"
  retention_in_days = local.log_retention
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "shares_function_invoke_arn" { value = aws_lambda_function.shares.invoke_arn }
output "shares_function_name" { value = aws_lambda_function.shares.function_name }

output "vaults_function_invoke_arn" { value = aws_lambda_function.vaults.invoke_arn }
output "vaults_function_name" { value = aws_lambda_function.vaults.function_name }

output "auth_function_invoke_arn" { value = aws_lambda_function.auth.invoke_arn }
output "auth_function_name" { value = aws_lambda_function.auth.function_name }

output "files_function_invoke_arn" { value = aws_lambda_function.files.invoke_arn }
output "files_function_name" { value = aws_lambda_function.files.function_name }

output "permissions_function_invoke_arn" { value = aws_lambda_function.permissions.invoke_arn }
output "permissions_function_name" { value = aws_lambda_function.permissions.function_name }

output "audit_function_invoke_arn" { value = aws_lambda_function.audit.invoke_arn }
output "audit_function_name" { value = aws_lambda_function.audit.function_name }

output "billing_function_invoke_arn" { value = aws_lambda_function.billing.invoke_arn }
output "billing_function_name" { value = aws_lambda_function.billing.function_name }

output "signup_function_invoke_arn" { value = aws_lambda_function.signup.invoke_arn }
output "signup_function_name" { value = aws_lambda_function.signup.function_name }

output "users_function_invoke_arn" { value = aws_lambda_function.users.invoke_arn }
output "users_function_name" { value = aws_lambda_function.users.function_name }

output "reencryption_function_invoke_arn" { value = aws_lambda_function.reencryption.invoke_arn }
output "reencryption_function_name" { value = aws_lambda_function.reencryption.function_name }

output "reconciler_function_arn" { value = aws_lambda_function.reconciler.arn }
output "reconciler_function_name" { value = aws_lambda_function.reconciler.function_name }
