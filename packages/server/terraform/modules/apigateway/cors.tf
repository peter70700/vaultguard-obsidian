# ─────────────────────────────────────────────────────────────────────────────
# CORS OPTIONS methods for all API resources
#
# Every resource that receives browser requests needs an OPTIONS method
# to handle CORS preflight. Without this, the browser blocks cross-origin
# requests from admin.example.com to api.example.com.
# ─────────────────────────────────────────────────────────────────────────────

locals {
  cors_resources = {
    vaults                     = aws_api_gateway_resource.vaults.id
    vaults_id                  = aws_api_gateway_resource.vaults_id.id
    vault_overview             = aws_api_gateway_resource.vault_overview.id
    vault_sync_cursor          = aws_api_gateway_resource.vault_sync_cursor.id
    vaults_members             = aws_api_gateway_resource.vaults_members.id
    vaults_members_id          = aws_api_gateway_resource.vaults_members_id.id
    orgs_config                = aws_api_gateway_resource.orgs_config.id
    orgs_settings              = aws_api_gateway_resource.orgs_settings.id
    well_known_vaultguard_json = aws_api_gateway_resource.well_known_vaultguard_json.id
    auth_login                 = aws_api_gateway_resource.auth_login.id
    auth_session               = aws_api_gateway_resource.auth_session.id
    auth_refresh               = aws_api_gateway_resource.auth_refresh.id
    auth_revoke                = aws_api_gateway_resource.auth_revoke.id
    auth_forgot_password       = aws_api_gateway_resource.auth_forgot_password.id
    auth_confirm_reset         = aws_api_gateway_resource.auth_confirm_reset.id
    auth_logout                = aws_api_gateway_resource.auth_logout.id
    auth_key_lease             = aws_api_gateway_resource.auth_key_lease.id
    auth_key_lease_scoped      = aws_api_gateway_resource.auth_key_lease_scoped.id
    auth_leases                = aws_api_gateway_resource.auth_leases.id
    auth_heartbeat             = aws_api_gateway_resource.auth_heartbeat.id
    auth_setup_zk              = aws_api_gateway_resource.auth_setup_zk.id
    auth_wrapped_key           = aws_api_gateway_resource.auth_wrapped_key.id
    auth_recover               = aws_api_gateway_resource.auth_recover.id
    auth_recovery_codes        = aws_api_gateway_resource.auth_recovery_codes.id
    auth_recovery_codes_verify = aws_api_gateway_resource.auth_recovery_codes_verify.id
    files                      = aws_api_gateway_resource.files.id
    files_sync                 = aws_api_gateway_resource.files_sync.id
    files_path                 = aws_api_gateway_resource.files_path.id
    # Note: /files/{filePath+}/restore-delete is served via the files_path resource
    # itself (suffix dispatch in the Lambda), so its OPTIONS preflight is covered by
    # the files_path CORS entry above. Greedy {filePath+} can't have child resources.
    files_deleted          = aws_api_gateway_resource.files_deleted.id
    files_decrypted        = aws_api_gateway_resource.files_decrypted.id
    files_decrypted_path   = aws_api_gateway_resource.files_decrypted_path.id
    permissions            = aws_api_gateway_resource.permissions.id
    permissions_id         = aws_api_gateway_resource.permissions_id.id
    permissions_check      = aws_api_gateway_resource.permissions_check.id
    permissions_access     = aws_api_gateway_resource.permissions_access.id
    audit                  = aws_api_gateway_resource.audit.id
    audit_logs             = aws_api_gateway_resource.audit_logs.id
    audit_alerts           = aws_api_gateway_resource.audit_alerts.id
    audit_user_id          = aws_api_gateway_resource.audit_user_id.id
    audit_file_path        = aws_api_gateway_resource.audit_file_path.id
    audit_export           = aws_api_gateway_resource.audit_export.id
    audit_report           = aws_api_gateway_resource.audit_report.id
    audit_bridge           = aws_api_gateway_resource.audit_bridge.id
    billing_subscription   = aws_api_gateway_resource.billing_subscription.id
    billing_checkout       = aws_api_gateway_resource.billing_checkout.id
    billing_portal         = aws_api_gateway_resource.billing_portal.id
    billing_webhook        = aws_api_gateway_resource.billing_webhook.id
    users                  = aws_api_gateway_resource.users.id
    users_invite           = aws_api_gateway_resource.users_invite.id
    users_roles            = aws_api_gateway_resource.users_roles.id
    users_id               = aws_api_gateway_resource.users_id.id
    users_id_role          = aws_api_gateway_resource.users_id_role.id
    users_id_profile       = aws_api_gateway_resource.users_id_profile.id
    users_id_revoke        = aws_api_gateway_resource.users_id_revoke.id
    users_id_reactivate    = aws_api_gateway_resource.users_id_reactivate.id
    users_id_resend_invite = aws_api_gateway_resource.users_id_resend_invite.id
    users_id_activity      = aws_api_gateway_resource.users_id_activity.id
    users_id_reset_mfa     = aws_api_gateway_resource.users_id_reset_mfa.id
    permissions_user_id    = aws_api_gateway_resource.permissions_user_id.id
    reencryption_trigger   = aws_api_gateway_resource.reencryption_trigger.id
    reencryption_job_id    = aws_api_gateway_resource.reencryption_job_id.id
    shares                 = aws_api_gateway_resource.shares.id
    shares_id              = aws_api_gateway_resource.shares_id.id
    # Note: signup already has OPTIONS defined in main.tf
  }
}

resource "aws_api_gateway_method" "cors_options" {
  for_each = local.cors_resources

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = each.value
  http_method   = "OPTIONS"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "cors_options" {
  for_each = local.cors_resources

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = each.value
  http_method = aws_api_gateway_method.cors_options[each.key].http_method
  type        = "MOCK"

  request_templates = { "application/json" = "{\"statusCode\": 200}" }
}

resource "aws_api_gateway_method_response" "cors_options" {
  for_each = local.cors_resources

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = each.value
  http_method = aws_api_gateway_method.cors_options[each.key].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }
}

resource "aws_api_gateway_integration_response" "cors_options" {
  for_each = local.cors_resources

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = each.value
  http_method = aws_api_gateway_method.cors_options[each.key].http_method
  status_code = aws_api_gateway_method_response.cors_options[each.key].status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,Authorization,X-VaultGuard-Session-Id,X-VG-Agent-Name,X-VG-Lease-Id'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET,POST,PUT,PATCH,DELETE,OPTIONS'"
    "method.response.header.Access-Control-Allow-Origin"  = "'${local.allowed_cors_origin}'"
  }
}
