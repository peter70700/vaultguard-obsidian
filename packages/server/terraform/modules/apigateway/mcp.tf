# Isolated Phase 0 OAuth discovery lane. P0-003 owns the separate /mcp transport
# integration. An empty connector_oauth_resource (the default) creates nothing.

check "connector_authorization_server_is_explicit" {
  assert {
    condition = (
      var.connector_oauth_resource == "" ||
      (
        can(regex("^https://[^?#]+$", var.connector_authorization_server)) &&
        !can(regex("[[:space:]@]", var.connector_authorization_server))
      )
    )
    error_message = "An enabled connector OAuth resource requires an explicit HTTPS authorization-server issuer without a query or fragment."
  }
}

locals {
  connector_scope_names = [
    "workspace:read",
    "files:list",
    "files:read",
    "connector:read",
  ]
  connector_oauth_scopes = [
    for scope_name in local.connector_scope_names :
    "${var.connector_oauth_resource}/${scope_name}"
  ]
  # Explicit production read profile. The frozen default discovery remains the
  # original four resource-prefixed scopes while the read host is disabled.
  mcp_read_scope_names = [
    "workspace:read", "files:list", "files:read", "connector:read",
    "files:search", "history:read", "graph:read", "context:read",
    "semantic:read",
    "coordination:read", "access:read", "permissions:read", "members:read", "shares:read", "audit:read",
  ]
  mcp_proposal_scope_names = concat(local.mcp_read_scope_names, ["changes:read", "changes:propose", "changes:apply", "history:restore", "context:propose"])
  mcp_access_scope_names   = concat(local.mcp_proposal_scope_names, ["access:propose", "access:apply", "shares:write"])
  mcp_transfer_scope_names = concat(local.mcp_access_scope_names, ["transfers:prepare", "coordination:write"])
  mcp_scope_profiles = {
    workspace-read-v1     = local.mcp_read_scope_names
    workspace-proposal-v1 = local.mcp_proposal_scope_names
    workspace-access-v1   = local.mcp_access_scope_names
    workspace-transfer-v1 = local.mcp_transfer_scope_names
  }
}
variable "workspace_mcp_profile" {
  type    = string
  default = "workspace-read-v1"
  validation {
    condition     = contains(["workspace-read-v1", "workspace-proposal-v1", "workspace-access-v1", "workspace-transfer-v1"], var.workspace_mcp_profile)
    error_message = "Unsupported MCP admission profile."
  }
}

resource "aws_api_gateway_resource" "well_known_oauth" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = ".well-known"
}

resource "aws_api_gateway_resource" "oauth_protected_resource" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.well_known_oauth[0].id
  path_part   = "oauth-protected-resource"
}

resource "aws_api_gateway_method" "oauth_protected_resource_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.oauth_protected_resource[0].id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "oauth_protected_resource_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.oauth_protected_resource[0].id
  http_method = aws_api_gateway_method.oauth_protected_resource_get[0].http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = jsonencode({ statusCode = 200 })
  }
}

resource "aws_api_gateway_method_response" "oauth_protected_resource_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.oauth_protected_resource[0].id
  http_method = aws_api_gateway_method.oauth_protected_resource_get[0].http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Cache-Control"          = true
    "method.response.header.Content-Type"           = true
    "method.response.header.X-Content-Type-Options" = true
  }
}

resource "aws_api_gateway_integration_response" "oauth_protected_resource_get" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  resource_id = aws_api_gateway_resource.oauth_protected_resource[0].id
  http_method = aws_api_gateway_method.oauth_protected_resource_get[0].http_method
  status_code = aws_api_gateway_method_response.oauth_protected_resource_get[0].status_code

  response_parameters = {
    "method.response.header.Cache-Control"          = "'public, max-age=300'"
    "method.response.header.Content-Type"           = "'application/json'"
    "method.response.header.X-Content-Type-Options" = "'nosniff'"
  }

  response_templates = {
    "application/json" = jsonencode({
      resource              = var.connector_oauth_resource
      authorization_servers = [var.connector_authorization_server]
      scopes_supported      = var.mcp_read_enabled ? local.mcp_scope_profiles[var.workspace_mcp_profile] : local.connector_oauth_scopes
    })
  }
}
