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
variable "billing_exempt_domains" {
  type        = string
  default     = ""
  description = "Comma-separated email domains whose new orgs are billing-exempt (stamped comped=true at signup). Empty disables domain exemption."
}
variable "sender_email" {
  type    = string
  default = "noreply@example.com"
}
# Verified SES domain identity (e.g. example.com). Used to scope the
# Lambdas' ses:SendEmail/SendRawEmail to this one identity ARN instead of "*"
# (SD-12 F5) — mirrors modules/ses which grants send on the same identity.
variable "sender_domain" {
  type = string
}
variable "domain_name" {
  type    = string
  default = ""
}
variable "super_admin_emails" {
  type        = string
  default     = ""
  description = "Comma-separated lowercase emails allowed to call the /superadmin/* platform-stats API. Fail-closed: empty disables the API entirely."
}
variable "platform_metrics_table_name" {
  type        = string
  default     = ""
  description = "PlatformMetrics table name (daily platform snapshots). Empty on Community Edition roots — the superadmin snapshot becomes a no-op."
}
variable "platform_metrics_table_arn" {
  type        = string
  default     = ""
  description = "PlatformMetrics table ARN. Empty on Community Edition roots."
}
variable "superadmin_snapshot_schedule" {
  type        = string
  default     = "cron(0 3 * * ? *)"
  description = "EventBridge schedule expression for the daily platform-metrics snapshot."
}
variable "reconciler_schedule" {
  type        = string
  default     = "cron(0 3 * * ? *)"
  description = "EventBridge schedule expression for the nightly user-count reconciler. Override per-stage if desired."
}
variable "detector_schedule" {
  type        = string
  default     = "rate(15 minutes)"
  description = "EventBridge schedule expression for the SD-09-F2 security anomaly detector sweep."
}
variable "detector_lookback_minutes" {
  type        = number
  default     = 20
  description = "How far back (minutes) each detector run scans audit rows. Keep >= the detector_schedule cadence so consecutive runs leave no coverage gap; overlap is deduped by the idempotent alert id."
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

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

data "archive_file" "detector_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/detector"
  output_path = "${path.module}/.build/detector.zip"
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

data "archive_file" "superadmin_lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../../../infrastructure/dist/superadmin"
  output_path = "${path.module}/.build/superadmin.zip"
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
    resources = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
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
    resources = ["arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
  }
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["arn:aws:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:identity/${var.sender_domain}"]
  }
  # SD-09-F1: publish the custom security metrics that back the SNS alarms in
  # modules/monitoring (RevokedSessionAccess, KMSDecryptFailure,
  # FailedAuthentication). PutMetricData has no resource-level ARN, so the
  # namespace condition is the least-privilege boundary.
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ObsidianVaultGuard"]
    }
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/auth/handler.js")

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
  # SD-09-F1: publish the FileAccessCount + KMSDecryptFailure security metrics.
  # Namespace-scoped condition = least privilege (PutMetricData has no ARN).
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ObsidianVaultGuard"]
    }
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/files/handler.js")

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
  # DynamoDB SSE-KMS caller decrypt — REQUIRED, do not remove. Every VaultGuard
  # table is SSE-encrypted with the vault CMK (modules/dynamodb sets kms_key_arn
  # on all tables), and DynamoDB issues kms:Decrypt for the table key with the
  # CALLER's credentials — not a service grant, as SD-12 F6 assumed when it
  # removed this. Because DynamoDB caches table keys per principal and only
  # drops them after ~5 idle minutes, the removal surfaced as a DELAYED outage:
  # 2026-07-11, every permissions rules/access/batch route 500'd with
  # "not authorized to perform: kms:Decrypt" once the Permissions table key
  # went cold. kms:ViaService pins the grant to DynamoDB's use, so this role
  # still cannot decrypt vault-DEK ciphertexts directly — F6's least-privilege
  # intent is preserved (narrower than the pre-F6 unconditioned grant).
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
  # SD-09-F1: publish the OffHoursPermissionChange security metric (emitted from
  # recordVaultActivity when a permission mutation lands off-hours).
  # Namespace-scoped condition = least privilege (PutMetricData has no ARN).
  statement {
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ObsidianVaultGuard"]
    }
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/permissions/handler.js")

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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/audit/handler.js")

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
    resources = ["arn:aws:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:identity/${var.sender_domain}"]
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/billing/handler.js")

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
  # DynamoDB SSE-KMS caller decrypt — REQUIRED, do not remove. SD-12 dropped
  # this believing DynamoDB decrypts CMK-encrypted tables via a service grant;
  # in fact DynamoDB calls kms:Decrypt with the CALLER's credentials (proven by
  # the 2026-07-11 permissions-Lambda outage — see the twin comment on the
  # permissions role). The signup Lambda writes Organizations/Vaults/
  # VaultMembers/Permissions/Subscriptions rows, all CMK-encrypted, so without
  # this grant new-customer signup 500s on the first cold table key. ViaService
  # pins the grant to DynamoDB — no direct KMS use, and no GenerateDataKey
  # (which the pre-SD-12 over-grant had); least-privilege intent preserved.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
  # SES — send welcome email
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["arn:aws:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:identity/${var.sender_domain}"]
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/signup/handler.js")

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      USER_POOL_ID                   = var.cognito_user_pool_id
      CLIENT_ID                      = var.cognito_client_id
      VAULTGUARD_ALLOW_PUBLIC_SIGNUP = tostring(var.allow_public_signup)
      BILLING_EXEMPT_DOMAINS         = var.billing_exempt_domains
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
  # DynamoDB SSE-KMS caller decrypt — REQUIRED, do not remove. SD-12 dropped
  # this believing DynamoDB decrypts CMK-encrypted tables via a service grant;
  # in fact DynamoDB calls kms:Decrypt with the CALLER's credentials (proven by
  # the 2026-07-11 permissions-Lambda outage — see the twin comment on the
  # permissions role). The users Lambda reads/writes Organizations/Sessions/
  # Audit/Leases/Subscriptions rows, all CMK-encrypted, so without this grant
  # invite/revoke/list-user routes 500 on the first cold table key. Offboarding
  # crypto still lives in the reencryption Lambda (own KMS grant); ViaService
  # pins THIS grant to DynamoDB — no direct KMS use, and no GenerateDataKey
  # (which the pre-SD-12 over-grant had); least-privilege intent preserved.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["dynamodb.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
  statement {
    actions   = ["ses:SendEmail", "ses:SendRawEmail"]
    resources = ["arn:aws:ses:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:identity/${var.sender_domain}"]
  }
  statement {
    actions   = ["events:PutEvents"]
    resources = ["arn:aws:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"]
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/users/handler.js")

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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/reencryption/handler.js")

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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/reconciler/handler.js")

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

# ─── Security Anomaly Detector Lambda (SD-09-F2) ─────────────────────────────
# Proactive anomaly detection: runs the SAME detectAnomaliesForScope logic the
# audit dashboard uses (exported from audit/handler), across every vault on an
# EventBridge schedule, so alert rows are generated without an admin opening the
# dashboard. Complements the SD-09-F1 CloudWatch metric alarms. EventBridge-only
# — no API Gateway surface. Mirrors the reconciler wiring above.

resource "aws_iam_role" "detector_lambda" {
  name               = "vaultguard-${var.stage}-detector-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "detector_logging" {
  role       = aws_iam_role.detector_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "detector_lambda" {
  # Vaults — Scan to enumerate every (orgId, vaultId) pair to run detection on.
  statement {
    actions   = ["dynamodb:Scan"]
    resources = [var.vaults_table_arn]
  }
  # Audit — Query the vaultId-index for each vault's recent detection window.
  statement {
    actions   = ["dynamodb:Query"]
    resources = [var.audit_table_arn, "${var.audit_table_arn}/index/*"]
  }
  # Alerts — persist detected anomalies (idempotent PutItem with a condition).
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.alerts_table_arn]
  }
  # KMS — audit / alerts / vaults tables are SSE-KMS encrypted with the project
  # master key; without Decrypt/GenerateDataKey the first table access errors
  # (same rationale as the reconciler role).
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "detector_lambda" {
  name   = "detector-lambda-policy"
  role   = aws_iam_role.detector_lambda.id
  policy = data.aws_iam_policy_document.detector_lambda.json
}

resource "aws_lambda_function" "detector" {
  function_name = "vaultguard-detector-${var.stage}"
  description   = "Scheduled security anomaly detector (SD-09-F2)"
  role          = aws_iam_role.detector_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 512
  timeout       = 300

  filename         = data.archive_file.detector_lambda.output_path
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/detector/handler.js")

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      DETECTOR_LOOKBACK_MINUTES = tostring(var.detector_lookback_minutes)
    })
  }

  tags = { Name = "vaultguard-detector-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${aws_lambda_function.detector.function_name}"
  retention_in_days = local.log_retention
}

resource "aws_cloudwatch_event_rule" "detector_schedule" {
  name                = "vaultguard-${var.stage}-detector-schedule"
  description         = "Scheduled security anomaly detection sweep (SD-09-F2)"
  schedule_expression = var.detector_schedule
}

resource "aws_cloudwatch_event_target" "detector" {
  rule      = aws_cloudwatch_event_rule.detector_schedule.name
  target_id = "vaultguard-detector-${var.stage}"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_detector" {
  statement_id  = "AllowExecutionFromDetectorSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detector_schedule.arn
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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/vaults/handler.js")

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
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/shares/handler.js")

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

# ─── Super-admin Lambda ─────────────────────────────────────────────────────
#
# Platform-wide stats API (/superadmin/*) for platform operators. Access is
# double-gated: the Cognito "platform-superadmin" group AND the
# SUPER_ADMIN_EMAILS allowlist (fail-closed when empty). The same function
# also runs the daily PlatformMetrics snapshot when invoked by the
# EventBridge schedule (the handler detects event.source === "aws.events").
# Read-only over business tables; write access is limited to the
# PlatformMetrics table and the audit log.

resource "aws_iam_role" "superadmin_lambda" {
  name               = "vaultguard-${var.stage}-superadmin-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "superadmin_logging" {
  role       = aws_iam_role.superadmin_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

data "aws_iam_policy_document" "superadmin_lambda" {
  # Read-only sweep over the platform's business tables (+ their GSIs) for
  # the overview / orgs / growth aggregations. No write actions here — the
  # superadmin API must never mutate tenant data.
  statement {
    actions = ["dynamodb:Scan", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:BatchGetItem"]
    resources = [
      var.organizations_table_arn, "${var.organizations_table_arn}/index/*",
      var.subscriptions_table_arn, "${var.subscriptions_table_arn}/index/*",
      var.vaults_table_arn, "${var.vaults_table_arn}/index/*",
      var.sessions_table_arn, "${var.sessions_table_arn}/index/*",
      var.revoked_keys_table_arn,
    ]
  }
  # PlatformMetrics — daily snapshot writes + growth-series reads.
  # Gated on super_admin_emails (the feature's fail-closed switch, known at
  # plan time) rather than the table ARN, which is known-after-apply for a
  # freshly-created table and can't drive for_each. Community Edition roots
  # leave super_admin_emails = "" and skip the whole platform surface.
  dynamic "statement" {
    for_each = var.super_admin_emails != "" ? [1] : []
    content {
      actions   = ["dynamodb:PutItem", "dynamodb:Query"]
      resources = [var.platform_metrics_table_arn]
    }
  }
  # Cognito — user totals for /superadmin/users (ListUsers) and the super-admin
  # MFA-enrollment gate (AdminGetUser, reliable fallback when the token's `amr`
  # claim omits MFA — see assertSuperAdminMfaEnrolled in shared/utils.ts).
  statement {
    actions   = ["cognito-idp:ListUsers", "cognito-idp:AdminGetUser"]
    resources = [var.cognito_user_pool_arn]
  }
  # Cost Explorer — /superadmin/costs (monthly by SERVICE + daily totals).
  # CE only supports "*" as the resource.
  statement {
    actions   = ["ce:GetCostAndUsage"]
    resources = ["*"]
  }
  # Audit logging (logAudit in shared/utils.ts).
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # Secrets Manager — read Stripe secret so /superadmin/overview can report
  # live MRR (source: "stripe"). Skipped on Community Edition where
  # stripe_secret_arn = "" and revenue falls back to the local estimate.
  dynamic "statement" {
    for_each = var.stripe_secret_arn != "" ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.stripe_secret_arn]
    }
  }
  # KMS — DynamoDB tables use the customer-managed key.
  statement {
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "superadmin_lambda" {
  name   = "superadmin-lambda-policy"
  role   = aws_iam_role.superadmin_lambda.id
  policy = data.aws_iam_policy_document.superadmin_lambda.json
}

resource "aws_lambda_function" "superadmin" {
  function_name = "vaultguard-superadmin-${var.stage}"
  description   = "Platform-wide stats API for super-admins + daily PlatformMetrics snapshot"
  role          = aws_iam_role.superadmin_lambda.arn
  handler       = "handler.handler"
  runtime       = "nodejs22.x"
  architectures = ["arm64"]
  memory_size   = 256
  timeout       = 30

  filename         = data.archive_file.superadmin_lambda.output_path
  source_code_hash = filebase64sha256("${path.module}/../../../infrastructure/dist/superadmin/handler.js")

  tracing_config { mode = "Active" }

  environment {
    variables = merge(local.common_env, {
      SUPER_ADMIN_EMAILS     = var.super_admin_emails
      PLATFORM_METRICS_TABLE = var.platform_metrics_table_name
      STRIPE_SECRET_ARN      = var.stripe_secret_arn
    })
  }

  tags = { Name = "vaultguard-superadmin-${var.stage}" }
}

resource "aws_cloudwatch_log_group" "superadmin" {
  name              = "/aws/lambda/${aws_lambda_function.superadmin.function_name}"
  retention_in_days = local.log_retention
}

# The daily snapshot schedule only exists when the platform surface is enabled
# (super_admin_emails non-empty). Community Edition roots leave it empty and the
# Lambda's snapshot path is a no-op, so skip the EventBridge plumbing entirely.
# Gated on super_admin_emails (plan-time known) not the metrics ARN
# (known-after-apply), which cannot drive count.
resource "aws_cloudwatch_event_rule" "superadmin_snapshot_schedule" {
  count               = var.super_admin_emails != "" ? 1 : 0
  name                = "vaultguard-${var.stage}-superadmin-snapshot"
  description         = "Daily PlatformMetrics snapshot via the superadmin Lambda"
  schedule_expression = var.superadmin_snapshot_schedule
}

resource "aws_cloudwatch_event_target" "superadmin_snapshot" {
  count     = var.super_admin_emails != "" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.superadmin_snapshot_schedule[0].name
  target_id = "vaultguard-superadmin-${var.stage}"
  arn       = aws_lambda_function.superadmin.arn
}

resource "aws_lambda_permission" "allow_eventbridge_superadmin" {
  count         = var.super_admin_emails != "" ? 1 : 0
  statement_id  = "AllowExecutionFromSuperadminSnapshotSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.superadmin.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.superadmin_snapshot_schedule[0].arn
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "superadmin_function_invoke_arn" { value = aws_lambda_function.superadmin.invoke_arn }
output "superadmin_function_name" { value = aws_lambda_function.superadmin.function_name }

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
