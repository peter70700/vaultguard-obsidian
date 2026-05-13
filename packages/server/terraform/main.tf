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

  stage      = var.stage
  is_prod    = local.is_prod
  account_id = local.account_id
}

# ─────────────────────────────────────────────────────────────────────────────
# S3 — Vault File Storage
# ─────────────────────────────────────────────────────────────────────────────

module "s3" {
  source = "./modules/s3"

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

  stage       = var.stage
  is_prod     = local.is_prod
  kms_key_arn = module.kms.key_arn
}

# ─────────────────────────────────────────────────────────────────────────────
# Cognito — User Pool
# ─────────────────────────────────────────────────────────────────────────────

module "cognito" {
  source = "./modules/cognito"

  stage            = var.stage
  is_prod          = local.is_prod
  callback_urls    = var.cognito_callback_urls
  logout_urls      = var.cognito_logout_urls
  ses_sender_email = var.sender_email
}

# ─────────────────────────────────────────────────────────────────────────────
# Lambda Functions
# ─────────────────────────────────────────────────────────────────────────────

module "lambda" {
  source = "./modules/lambda"

  stage                            = var.stage
  is_prod                          = local.is_prod
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
  key_lease_duration_seconds       = var.key_lease_duration_seconds
  session_duration_seconds         = var.session_duration_seconds
  max_file_size_bytes              = var.max_file_size_bytes
  vaultguard_edition               = var.vaultguard_edition
  allow_public_signup              = var.vaultguard_allow_public_signup
  sender_email                     = var.sender_email
  domain_name                      = var.domain_name
}

# ─────────────────────────────────────────────────────────────────────────────
# API Gateway
# ─────────────────────────────────────────────────────────────────────────────

module "apigateway" {
  source = "./modules/apigateway"

  stage                          = var.stage
  is_prod                        = local.is_prod
  cognito_user_pool_arn          = module.cognito.user_pool_arn
  auth_lambda_invoke_arn         = module.lambda.auth_function_invoke_arn
  auth_lambda_name               = module.lambda.auth_function_name
  files_lambda_invoke_arn        = module.lambda.files_function_invoke_arn
  files_lambda_name              = module.lambda.files_function_name
  perms_lambda_invoke_arn        = module.lambda.permissions_function_invoke_arn
  perms_lambda_name              = module.lambda.permissions_function_name
  audit_lambda_invoke_arn        = module.lambda.audit_function_invoke_arn
  audit_lambda_name              = module.lambda.audit_function_name
  signup_lambda_invoke_arn       = module.lambda.signup_function_invoke_arn
  signup_lambda_name             = module.lambda.signup_function_name
  billing_lambda_invoke_arn      = module.lambda.billing_function_invoke_arn
  billing_lambda_name            = module.lambda.billing_function_name
  users_lambda_invoke_arn        = module.lambda.users_function_invoke_arn
  users_lambda_name              = module.lambda.users_function_name
  reencryption_lambda_invoke_arn = module.lambda.reencryption_function_invoke_arn
  reencryption_lambda_name       = module.lambda.reencryption_function_name
  vaults_lambda_invoke_arn       = module.lambda.vaults_function_invoke_arn
  vaults_lambda_name             = module.lambda.vaults_function_name
  shares_lambda_invoke_arn       = module.lambda.shares_function_invoke_arn
  shares_lambda_name             = module.lambda.shares_function_name
  domain_name                    = var.domain_name
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

  stage             = var.stage
  api_gateway_url   = module.apigateway.api_url
  api_gateway_stage = var.stage
  waf_acl_arn       = module.waf.web_acl_arn
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

  google_workspace_verification_token = var.google_workspace_verification_token
  google_workspace_dkim_value         = var.google_workspace_dkim_value
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
  source = "./modules/monitoring"

  stage             = var.stage
  admin_email       = var.admin_email
  kms_key_arn       = module.kms.key_arn
  api_gateway_name  = module.apigateway.api_name
  api_gateway_stage = var.stage
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
