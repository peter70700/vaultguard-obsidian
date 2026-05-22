# ─── Users Endpoints ─────────────────────────────────────────────────────────
# Routes requests to the users Lambda for user management operations.

variable "users_lambda_invoke_arn" { type = string }
variable "users_lambda_name" { type = string }

# /orgs/{orgId}/config and /orgs/{orgId}/settings
# The single path parameter accepts either an org slug or an org ID.
resource "aws_api_gateway_resource" "orgs" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "orgs"
}

resource "aws_api_gateway_resource" "orgs_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.orgs.id
  path_part   = "{orgId}"
}

resource "aws_api_gateway_resource" "orgs_config" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.orgs_id.id
  path_part   = "config"
}

resource "aws_api_gateway_method" "orgs_config_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.orgs_config.id
  http_method   = "GET"
  authorization = "NONE"

  request_parameters = {
    "method.request.path.orgId" = true
  }
}

resource "aws_api_gateway_integration" "orgs_config_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.orgs_config.id
  http_method             = aws_api_gateway_method.orgs_config_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.signup_lambda_invoke_arn
}

# /.well-known/vaultguard.json
# Single-org self-hosted deployments expose the same public config shape as
# /orgs/{orgId}/config without requiring a slug.
resource "aws_api_gateway_resource" "well_known" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = ".well-known"
}

resource "aws_api_gateway_resource" "well_known_vaultguard_json" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.well_known.id
  path_part   = "vaultguard.json"
}

resource "aws_api_gateway_method" "well_known_vaultguard_json_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.well_known_vaultguard_json.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "well_known_vaultguard_json_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.well_known_vaultguard_json.id
  http_method             = aws_api_gateway_method.well_known_vaultguard_json_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.signup_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "orgs_settings" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.orgs_id.id
  path_part   = "settings"
}

resource "aws_api_gateway_method" "orgs_settings_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.orgs_settings.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.orgId" = true
  }
}

resource "aws_api_gateway_integration" "orgs_settings_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.orgs_settings.id
  http_method             = aws_api_gateway_method.orgs_settings_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_method" "orgs_settings_put" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.orgs_settings.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.orgId" = true
  }
}

resource "aws_api_gateway_integration" "orgs_settings_put" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.orgs_settings.id
  http_method             = aws_api_gateway_method.orgs_settings_put.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_method" "orgs_settings_delete" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.orgs_settings.id
  http_method   = "DELETE"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = {
    "method.request.path.orgId" = true
  }
}

resource "aws_api_gateway_integration" "orgs_settings_delete" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.orgs_settings.id
  http_method             = aws_api_gateway_method.orgs_settings_delete.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "users"
}

# GET /users — list all users
resource "aws_api_gateway_method" "users_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "users_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users.id
  http_method             = aws_api_gateway_method.users_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

# /users/invite
resource "aws_api_gateway_resource" "users_invite" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users.id
  path_part   = "invite"
}

resource "aws_api_gateway_method" "users_invite_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_invite.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "users_invite_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_invite.id
  http_method             = aws_api_gateway_method.users_invite_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

# /users/roles — list assignable roles
resource "aws_api_gateway_resource" "users_roles" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users.id
  path_part   = "roles"
}

resource "aws_api_gateway_method" "users_roles_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_roles.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "users_roles_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_roles.id
  http_method             = aws_api_gateway_method.users_roles_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

# /users/{userId}/...
resource "aws_api_gateway_resource" "users_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users.id
  path_part   = "{userId}"
}

resource "aws_api_gateway_resource" "users_id_role" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "role"
}

resource "aws_api_gateway_method" "users_id_role_put" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_role.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_role_put" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_role.id
  http_method             = aws_api_gateway_method.users_id_role_put.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users_id_profile" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "profile"
}

resource "aws_api_gateway_method" "users_id_profile_put" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_profile.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_profile_put" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_profile.id
  http_method             = aws_api_gateway_method.users_id_profile_put.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users_id_revoke" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "revoke"
}

resource "aws_api_gateway_method" "users_id_revoke_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_revoke.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_revoke_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_revoke.id
  http_method             = aws_api_gateway_method.users_id_revoke_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users_id_reactivate" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "reactivate"
}

resource "aws_api_gateway_method" "users_id_reactivate_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_reactivate.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_reactivate_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_reactivate.id
  http_method             = aws_api_gateway_method.users_id_reactivate_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users_id_resend_invite" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "resend-invite"
}

resource "aws_api_gateway_method" "users_id_resend_invite_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_resend_invite.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_resend_invite_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_resend_invite.id
  http_method             = aws_api_gateway_method.users_id_resend_invite_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

resource "aws_api_gateway_resource" "users_id_activity" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "activity"
}

resource "aws_api_gateway_method" "users_id_activity_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_activity.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_activity_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_activity.id
  http_method             = aws_api_gateway_method.users_id_activity_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

# POST /users/{userId}/reset-mfa — admin-only; clears the user's TOTP MFA
# preference and wipes their recovery codes. Next login routes to MFA_SETUP.
resource "aws_api_gateway_resource" "users_id_reset_mfa" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.users_id.id
  path_part   = "reset-mfa"
}

resource "aws_api_gateway_method" "users_id_reset_mfa_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.users_id_reset_mfa.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "users_id_reset_mfa_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.users_id_reset_mfa.id
  http_method             = aws_api_gateway_method.users_id_reset_mfa_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.users_lambda_invoke_arn
}

# /vaults/{vaultId}/permissions/user/{userId} — get user-specific permissions
resource "aws_api_gateway_resource" "permissions_user" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.permissions.id
  path_part   = "user"
}

resource "aws_api_gateway_resource" "permissions_user_id" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.permissions_user.id
  path_part   = "{userId}"
}

resource "aws_api_gateway_method" "permissions_user_get" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions_user_id.id
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.userId" = true }
}

resource "aws_api_gateway_integration" "permissions_user_get" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions_user_id.id
  http_method             = aws_api_gateway_method.permissions_user_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

# POST /vaults/{vaultId}/permissions/check — check permission for a path
resource "aws_api_gateway_resource" "permissions_check" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.permissions.id
  path_part   = "check"
}

resource "aws_api_gateway_method" "permissions_check_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions_check.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "permissions_check_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions_check.id
  http_method             = aws_api_gateway_method.permissions_check_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

# POST /vaults/{vaultId}/permissions/access — effective access summary for a path
resource "aws_api_gateway_resource" "permissions_access" {
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.permissions.id
  path_part   = "access"
}

resource "aws_api_gateway_method" "permissions_access_post" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions_access.id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}

resource "aws_api_gateway_integration" "permissions_access_post" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions_access.id
  http_method             = aws_api_gateway_method.permissions_access_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

# /vaults/{vaultId}/permissions/{id} — PUT update, DELETE
resource "aws_api_gateway_method" "permissions_id_put" {
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.permissions_id.id
  http_method   = "PUT"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id

  request_parameters = { "method.request.path.id" = true }
}

resource "aws_api_gateway_integration" "permissions_id_put" {
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.permissions_id.id
  http_method             = aws_api_gateway_method.permissions_id_put.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.perms_lambda_invoke_arn
}

# Lambda permission for users
resource "aws_lambda_permission" "users_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.users_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/*"
}
