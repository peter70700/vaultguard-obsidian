data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name
  is_prod     = var.stage == "prod"
  name_prefix = "vaultguard-${var.stage}"
}

# ─────────────────────────────────────────────────────────────────────────────
# KMS — Master Encryption Key
# ─────────────────────────────────────────────────────────────────────────────

module "kms" {
  source = "./modules/kms"

  production_hardening = var.production_hardening

  stage      = var.stage
  is_prod    = local.is_prod
  account_id = local.account_id
}

# ─────────────────────────────────────────────────────────────────────────────
# S3 — Vault File Storage
# ─────────────────────────────────────────────────────────────────────────────

module "s3" {
  source = "./modules/s3"

  production_hardening = var.production_hardening

  stage       = var.stage
  is_prod     = local.is_prod
  account_id  = local.account_id
  region      = local.region
  kms_key_arn = module.kms.key_arn
  kms_key_id  = module.kms.key_id
  domain_name = var.domain_name
}

# ─────────────────────────────────────────────────────────────────────────────
# DynamoDB Tables
# ─────────────────────────────────────────────────────────────────────────────

module "dynamodb" {
  source = "./modules/dynamodb"

  production_hardening = var.production_hardening

  stage       = var.stage
  is_prod     = local.is_prod
  kms_key_arn = module.kms.key_arn

  connector_oauth_resource = var.connector_oauth_resource
}

# ─────────────────────────────────────────────────────────────────────────────
# Cognito — User Pool
# ─────────────────────────────────────────────────────────────────────────────

module "cognito" {
  source = "./modules/cognito"

  production_hardening = var.production_hardening

  stage                    = var.stage
  is_prod                  = local.is_prod
  callback_urls            = var.cognito_callback_urls
  logout_urls              = var.cognito_logout_urls
  connector_oauth_resource = var.connector_oauth_resource
  connector_oauth_clients  = var.connector_oauth_clients
  # ADR-003: Cognito is the identity provider for connectors, not the
  # authorization server. This callback is VaultGuard's own, never a provider's.
  connector_identity_callback_url = var.connector_oauth_resource == "" ? "" : "${trimsuffix(var.connector_oauth_resource, "/mcp")}/oauth/callback"
  ses_sender_email                = var.sender_email
  mfa_configuration               = var.cognito_mfa_configuration
  advanced_security_mode          = var.cognito_advanced_security_mode
  login_verification_mode         = var.login_verification_mode
  login_verification_client_ids   = var.login_verification_client_ids
  sessions_table_name             = module.dynamodb.sessions_table_name
  sessions_table_arn              = module.dynamodb.sessions_table_arn
  kms_key_arn                     = module.kms.key_arn
  turnstile_secret_arn            = var.turnstile_secret_arn
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda Functions
# ─────────────────────────────────────────────────────────────────────────────

module "lambda" {
  # VAULTGUARD-49 / ADR-003: VaultGuard's own connector authorization server.
  connector_oauth_resource     = var.connector_oauth_resource
  connector_hosted_ui_domain   = module.cognito.connector_hosted_ui_domain
  connector_identity_client_id = module.cognito.connector_identity_client_id
  connector_auth_table_name    = module.dynamodb.connector_auth_table_name
  connector_auth_table_arn     = module.dynamodb.connector_auth_table_arn
  mcp_cursor_key_secret_arn    = var.mcp_cursor_key_secret_arn

  workspace_revisions_table_name               = module.dynamodb.workspace_revisions_table_name
  workspace_revisions_table_arn                = module.dynamodb.workspace_revisions_table_arn
  workspace_capabilities                       = var.workspace_capabilities
  workspace_web_cursor_key_secret_arn          = var.workspace_web_cursor_key_secret_arn
  workspace_web_origin                         = var.workspace_web_origin
  workspace_cohort_controls_enabled            = var.workspace_cohort_controls_enabled
  workspace_operator_enabled                   = var.workspace_operator_enabled
  workspace_operator_environment_id            = var.workspace_operator_environment_id
  workspace_migration_redaction_key_secret_arn = var.workspace_migration_redaction_key_secret_arn
  workspace_projection_delivery_enabled        = var.workspace_projection_delivery_enabled
  workspace_mcp_profile                        = var.workspace_mcp_profile
  workspace_mcp_write_admission                = var.workspace_mcp_write_admission
  mcp_transfer_nonce_key_secret_arn            = var.mcp_transfer_nonce_key_secret_arn
  workspace_cost_controls                      = var.workspace_cost_controls
  workspace_cost_telemetry                     = var.workspace_cost_telemetry
  workspace_slo_telemetry                      = var.workspace_slo_telemetry
  workspace_economics_table_name               = module.dynamodb.workspace_economics_table_name
  workspace_economics_table_arn                = module.dynamodb.workspace_economics_table_arn
  workspace_semantic_provider_profile          = var.workspace_semantic_provider_profile
  workspace_semantic_secret_arn                = var.workspace_semantic_secret_arn
  source                                       = "./modules/lambda"

  stage                            = var.stage
  is_prod                          = local.is_prod
  production_hardening             = var.production_hardening
  kms_key_arn                      = module.kms.key_arn
  kms_key_id                       = module.kms.key_id
  vault_bucket_name                = module.s3.bucket_name
  vault_bucket_arn                 = module.s3.bucket_arn
  permissions_table_name           = module.dynamodb.permissions_table_name
  permissions_table_arn            = module.dynamodb.permissions_table_arn
  audit_table_name                 = module.dynamodb.audit_table_name
  audit_table_arn                  = module.dynamodb.audit_table_arn
  alerts_table_name                = module.dynamodb.alerts_table_name
  alerts_table_arn                 = module.dynamodb.alerts_table_arn
  sessions_table_name              = module.dynamodb.sessions_table_name
  sessions_table_arn               = module.dynamodb.sessions_table_arn
  user_keys_table_name             = module.dynamodb.user_keys_table_name
  user_keys_table_arn              = module.dynamodb.user_keys_table_arn
  file_versions_table_name         = module.dynamodb.file_versions_table_name
  file_versions_table_arn          = module.dynamodb.file_versions_table_arn
  cognito_user_pool_arn            = module.cognito.user_pool_arn
  cognito_user_pool_id             = module.cognito.user_pool_id
  cognito_client_id                = module.cognito.client_id
  organizations_table_name         = module.dynamodb.organizations_table_name
  organizations_table_arn          = module.dynamodb.organizations_table_arn
  subscriptions_table_name         = module.dynamodb.subscriptions_table_name
  subscriptions_table_arn          = module.dynamodb.subscriptions_table_arn
  stripe_webhook_events_table_name = module.dynamodb.stripe_webhook_events_table_name
  stripe_webhook_events_table_arn  = module.dynamodb.stripe_webhook_events_table_arn
  leases_table_name                = module.dynamodb.leases_table_name
  leases_table_arn                 = module.dynamodb.leases_table_arn
  reencryption_jobs_table_name     = module.dynamodb.reencryption_jobs_table_name
  reencryption_jobs_table_arn      = module.dynamodb.reencryption_jobs_table_arn
  revoked_keys_table_name          = module.dynamodb.revoked_keys_table_name
  revoked_keys_table_arn           = module.dynamodb.revoked_keys_table_arn
  recovery_codes_table_name        = module.dynamodb.recovery_codes_table_name
  recovery_codes_table_arn         = module.dynamodb.recovery_codes_table_arn
  recovery_attempts_table_name     = module.dynamodb.recovery_attempts_table_name
  recovery_attempts_table_arn      = module.dynamodb.recovery_attempts_table_arn
  vaults_table_name                = module.dynamodb.vaults_table_name
  vaults_table_arn                 = module.dynamodb.vaults_table_arn
  vault_members_table_name         = module.dynamodb.vault_members_table_name
  vault_members_table_arn          = module.dynamodb.vault_members_table_arn
  vault_activity_table_name        = module.dynamodb.vault_activity_table_name
  vault_activity_table_arn         = module.dynamodb.vault_activity_table_arn
  shares_table_name                = module.dynamodb.shares_table_name
  shares_table_arn                 = module.dynamodb.shares_table_arn
  platform_metrics_table_name      = module.dynamodb.platform_metrics_table_name
  platform_metrics_table_arn       = module.dynamodb.platform_metrics_table_arn
  super_admin_emails               = var.super_admin_emails
  key_lease_duration_seconds       = var.key_lease_duration_seconds
  session_duration_seconds         = var.session_duration_seconds
  session_enforcement_mode         = var.session_enforcement_mode
  guest_sweep_mode                 = var.guest_sweep_mode
  login_verification_mode          = var.login_verification_mode
  login_verification_browser_url   = var.login_verification_browser_url
  turnstile_expected_hostnames     = join(",", var.turnstile_expected_hostnames)
  max_file_size_bytes              = var.max_file_size_bytes
  vaultguard_edition               = var.vaultguard_edition
  allow_public_signup              = var.vaultguard_allow_public_signup
  signup_legal_version             = var.signup_legal_version
  billing_exempt_domains           = var.billing_exempt_domains
  # Stage credentials are explicit inputs. Never fall back from an omitted
  # non-production value to the production Turnstile secret.
  turnstile_secret_arn = var.turnstile_secret_arn
  # Meta Conversions API. Both default to "" — Meta events stay off until an
  # operator sets them. See docs/META-CAPI-SETUP.md.
  meta_dataset_id      = var.meta_dataset_id
  meta_capi_secret_arn = var.meta_capi_secret_arn
  sender_email         = var.sender_email
  sender_domain        = var.sender_domain
  domain_name          = var.domain_name
}

# ─────────────────────────────────────────────────────────────────────────────
# API Gateway
# ─────────────────────────────────────────────────────────────────────────────

module "apigateway" {
  source = "./modules/apigateway"

  production_hardening   = var.production_hardening
  api_data_trace_enabled = var.api_data_trace_enabled

  stage                    = var.stage
  is_prod                  = local.is_prod
  cognito_user_pool_arn    = module.cognito.user_pool_arn
  connector_oauth_resource = module.cognito.connector_resource_identifier
  # VAULTGUARD-49 / ADR-003. This used to be `module.cognito.authorization_server_issuer`.
  # Cognito's discovery document is AWS-generated and can never advertise
  # `offline_access`; Cognito also fails authentication outright on a client that
  # requests a scope it has not associated, so a ChatGPT connector following
  # OpenAI's own instruction gets an authorization error rather than degrading.
  # OpenAI's remedy for adding the scope late is recreating the app, so the
  # issuer has to be right before any connector exists.
  connector_authorization_server    = module.lambda.connector_authorization_server
  connector_oauth_lambda_invoke_arn = module.lambda.connector_oauth_function_invoke_arn
  connector_oauth_lambda_name       = module.lambda.connector_oauth_function_name
  workspace_web_enabled             = module.lambda.workspace_web_enabled
  workspace_web_lambda_invoke_arn   = module.lambda.workspace_web_function_invoke_arn
  workspace_web_lambda_name         = module.lambda.workspace_web_function_name
  workspace_mcp_profile             = var.workspace_mcp_profile
  mcp_read_enabled                  = module.lambda.mcp_read_enabled
  mcp_read_lambda_invoke_arn        = module.lambda.mcp_read_function_invoke_arn
  mcp_read_lambda_name              = module.lambda.mcp_read_function_name
  auth_lambda_invoke_arn            = module.lambda.auth_function_invoke_arn
  auth_lambda_name                  = module.lambda.auth_function_name
  files_lambda_invoke_arn           = module.lambda.files_function_invoke_arn
  files_lambda_name                 = module.lambda.files_function_name
  perms_lambda_invoke_arn           = module.lambda.permissions_function_invoke_arn
  perms_lambda_name                 = module.lambda.permissions_function_name
  audit_lambda_invoke_arn           = module.lambda.audit_function_invoke_arn
  audit_lambda_name                 = module.lambda.audit_function_name
  signup_lambda_invoke_arn          = module.lambda.signup_function_invoke_arn
  signup_lambda_name                = module.lambda.signup_function_name
  billing_lambda_invoke_arn         = module.lambda.billing_function_invoke_arn
  billing_lambda_name               = module.lambda.billing_function_name
  users_lambda_invoke_arn           = module.lambda.users_function_invoke_arn
  users_lambda_name                 = module.lambda.users_function_name
  reencryption_lambda_invoke_arn    = module.lambda.reencryption_function_invoke_arn
  reencryption_lambda_name          = module.lambda.reencryption_function_name
  vaults_lambda_invoke_arn          = module.lambda.vaults_function_invoke_arn
  vaults_lambda_name                = module.lambda.vaults_function_name
  shares_lambda_invoke_arn          = module.lambda.shares_function_invoke_arn
  shares_lambda_name                = module.lambda.shares_function_name
  superadmin_lambda_invoke_arn      = module.lambda.superadmin_function_invoke_arn
  superadmin_lambda_name            = module.lambda.superadmin_function_name
  domain_name                       = var.domain_name
}

# ─────────────────────────────────────────────────────────────────────────────
# WAF — Web Application Firewall
# ─────────────────────────────────────────────────────────────────────────────

module "waf" {
  source = "./modules/waf"

  providers = {
    aws = aws.us_east_1
  }

  stage = var.stage
}

# ─────────────────────────────────────────────────────────────────────────────
# CloudFront — CDN Distribution
# ─────────────────────────────────────────────────────────────────────────────

module "cloudfront" {
  source = "./modules/cloudfront"
  count  = var.legacy_api_cdn_enabled ? 1 : 0

  stage             = var.stage
  api_gateway_url   = module.apigateway.api_url
  api_gateway_stage = var.stage
  waf_acl_arn       = module.waf.web_acl_arn
}

# Adding the retirement count changes the module address. Preserve the existing
# distribution at index zero so the default-enabled migration is state-only and
# cannot replace the CDN during an otherwise unrelated apply.
moved {
  from = module.cloudfront
  to   = module.cloudfront[0]
}

# ─────────────────────────────────────────────────────────────────────────────
# DNS & Certificates (only when custom domain is configured)
# ─────────────────────────────────────────────────────────────────────────────

module "dns" {
  source = "./modules/dns"
  count  = var.domain_name != "" ? 1 : 0

  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  stage       = var.stage
  domain_name = var.domain_name
}

# Map the API Gateway custom domain to the deployed stage
resource "aws_api_gateway_base_path_mapping" "api" {
  count = var.domain_name != "" ? 1 : 0

  api_id      = module.apigateway.api_id
  stage_name  = module.apigateway.api_stage_name
  domain_name = module.dns[0].api_custom_domain
}

# ─────────────────────────────────────────────────────────────────────────────
# Amplify — Landing Page & Admin Panel Hosting
# Managed via AWS Console (GitHub OAuth connection).
# Not in Terraform — Amplify apps are created and deployed from the console.
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# CloudWatch Monitoring & SNS Alerts
# ─────────────────────────────────────────────────────────────────────────────

module "monitoring" {
  workspace_recovery_failure_queue_name = module.lambda.workspace_recovery_failure_queue_name
  workspace_revisions_table_name        = module.dynamodb.workspace_revisions_table_name
  source                                = "./modules/monitoring"

  stage             = var.stage
  admin_email       = var.admin_email
  kms_key_arn       = module.kms.key_arn
  api_gateway_name  = module.apigateway.api_name
  api_gateway_stage = var.stage

  # The Cognito Pre Authentication trigger lives in the cognito module, not the
  # lambda module, so it has to be appended explicitly — it is on the login path
  # and is exactly the function whose failures must page.
  lambda_function_names = concat(
    module.lambda.all_function_names,
    [module.cognito.pre_authentication_function_name],
  )
  lambda_log_group_names = module.lambda.all_log_group_names

  reencryption_dlq_name    = module.lambda.reencryption_dlq_name
  reconciler_function_name = module.lambda.reconciler_function_name
  detector_function_name   = module.lambda.detector_function_name
}

# ─────────────────────────────────────────────────────────────────────────────
# SES — Transactional Email
# ─────────────────────────────────────────────────────────────────────────────

module "ses" {
  source = "./modules/ses"

  stage         = var.stage
  is_prod       = local.is_prod
  sender_email  = var.sender_email
  sender_domain = var.sender_domain
  kms_key_arn   = module.kms.key_arn
}
