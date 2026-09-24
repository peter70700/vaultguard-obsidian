variable "workspace_web_enabled" {
  type    = bool
  default = false
}
variable "workspace_web_lambda_invoke_arn" {
  type    = string
  default = ""
}
variable "workspace_web_lambda_name" {
  type    = string
  default = ""
}
check "workspace_web_lambda_is_wired" {
  assert {
    condition     = var.workspace_web_enabled == (var.workspace_web_lambda_name != "") && (!var.workspace_web_enabled || var.workspace_web_lambda_invoke_arn != "")
    error_message = "An enabled workspace read route requires its authenticated Lambda."
  }
}
resource "aws_api_gateway_resource" "workspace_web" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.vaults_id.id
  path_part   = "workspace"
}
resource "aws_api_gateway_resource" "workspace_web_tree" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "tree"
}
resource "aws_api_gateway_resource" "workspace_web_node" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "node"
}
resource "aws_api_gateway_resource" "workspace_web_text" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "text"
}
resource "aws_api_gateway_resource" "workspace_web_preview" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "preview"
}
resource "aws_api_gateway_resource" "workspace_web_asset" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "asset"
}
resource "aws_api_gateway_resource" "workspace_web_base" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "base"
}
locals {
  workspace_web_read_resources = var.workspace_web_lambda_name == "" ? {} : {
    tree    = aws_api_gateway_resource.workspace_web_tree[0].id
    node    = aws_api_gateway_resource.workspace_web_node[0].id
    text    = aws_api_gateway_resource.workspace_web_text[0].id
    preview = aws_api_gateway_resource.workspace_web_preview[0].id
    asset   = aws_api_gateway_resource.workspace_web_asset[0].id
    base    = aws_api_gateway_resource.workspace_web_base[0].id
  }
}
resource "aws_api_gateway_method" "workspace_web_read" {
  for_each      = local.workspace_web_read_resources
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = each.value
  http_method   = "GET"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "workspace_web_read" {
  for_each                = local.workspace_web_read_resources
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = each.value
  http_method             = aws_api_gateway_method.workspace_web_read[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.workspace_web_lambda_invoke_arn
}
resource "aws_lambda_permission" "workspace_web_apigw" {
  count         = var.workspace_web_enabled ? 1 : 0
  statement_id  = "AllowWorkspaceWebAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.workspace_web_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/GET/vaults/*/workspace/*"
}
resource "aws_api_gateway_method_settings" "workspace_web" {
  for_each    = local.workspace_web_read_resources
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "vaults/{vaultId}/workspace/${each.key}/GET"
  settings {
    throttling_rate_limit  = 10
    throttling_burst_limit = 20
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

# Body-bearing knowledge queries keep query text out of URLs/access logs.
resource "aws_api_gateway_resource" "workspace_web_knowledge" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "knowledge"
}
resource "aws_api_gateway_method" "workspace_web_knowledge" {
  count         = var.workspace_web_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.workspace_web_knowledge[0].id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "workspace_web_knowledge" {
  count                   = var.workspace_web_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.workspace_web_knowledge[0].id
  http_method             = aws_api_gateway_method.workspace_web_knowledge[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.workspace_web_lambda_invoke_arn
}
resource "aws_lambda_permission" "workspace_web_knowledge" {
  count         = var.workspace_web_enabled ? 1 : 0
  statement_id  = "AllowWorkspaceKnowledgeAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.workspace_web_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/POST/vaults/*/workspace/knowledge"
}
resource "aws_api_gateway_method_settings" "workspace_web_knowledge" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "vaults/{vaultId}/workspace/knowledge/POST"
  settings {
    throttling_rate_limit  = 2
    throttling_burst_limit = 4
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

# Body-bearing approvals queries keep query text out of URLs/access logs.
resource "aws_api_gateway_resource" "workspace_web_approvals" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "approvals"
}
resource "aws_api_gateway_method" "workspace_web_approvals" {
  count         = var.workspace_web_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.workspace_web_approvals[0].id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "workspace_web_approvals" {
  count                   = var.workspace_web_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.workspace_web_approvals[0].id
  http_method             = aws_api_gateway_method.workspace_web_approvals[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.workspace_web_lambda_invoke_arn
}
resource "aws_lambda_permission" "workspace_web_approvals" {
  count         = var.workspace_web_enabled ? 1 : 0
  statement_id  = "AllowWorkspaceApprovalsAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.workspace_web_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/POST/vaults/*/workspace/approvals"
}
resource "aws_api_gateway_method_settings" "workspace_web_approvals" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "vaults/{vaultId}/workspace/approvals/POST"
  settings {
    throttling_rate_limit  = 2
    throttling_burst_limit = 4
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

# Body-bearing access queries keep query text out of URLs/access logs.
resource "aws_api_gateway_resource" "workspace_web_access" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "access"
}
resource "aws_api_gateway_method" "workspace_web_access" {
  count         = var.workspace_web_enabled ? 1 : 0
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = aws_api_gateway_resource.workspace_web_access[0].id
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "workspace_web_access" {
  count                   = var.workspace_web_enabled ? 1 : 0
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = aws_api_gateway_resource.workspace_web_access[0].id
  http_method             = aws_api_gateway_method.workspace_web_access[0].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.workspace_web_lambda_invoke_arn
}
resource "aws_lambda_permission" "workspace_web_access" {
  count         = var.workspace_web_enabled ? 1 : 0
  statement_id  = "AllowWorkspaceAccessAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = var.workspace_web_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/POST/vaults/*/workspace/access"
}
resource "aws_api_gateway_method_settings" "workspace_web_access" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = "vaults/{vaultId}/workspace/access/POST"
  settings {
    throttling_rate_limit  = 2
    throttling_burst_limit = 4
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}

# P5-006 bounded human history/transfers/publication and account governance.
# P6-001 shares the existing disabled-by-default workspace deployment and authority.
resource "aws_api_gateway_resource" "workspace_web_sync" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "sync"
}
resource "aws_api_gateway_resource" "workspace_web_history" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "history"
}
resource "aws_api_gateway_resource" "workspace_web_transfers" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "transfers"
}
resource "aws_api_gateway_resource" "workspace_web_changes" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_web[0].id
  path_part   = "changes"
}
resource "aws_api_gateway_resource" "workspace_account" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_rest_api.vaultguard.root_resource_id
  path_part   = "workspace"
}
resource "aws_api_gateway_resource" "workspace_account_governance" {
  count       = var.workspace_web_enabled ? 1 : 0
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  parent_id   = aws_api_gateway_resource.workspace_account[0].id
  path_part   = "governance"
}
locals {
  workspace_browser_operation_resources = var.workspace_web_lambda_name == "" ? {} : {
    sync       = aws_api_gateway_resource.workspace_web_sync[0].id
    history    = aws_api_gateway_resource.workspace_web_history[0].id
    transfers  = aws_api_gateway_resource.workspace_web_transfers[0].id
    changes    = aws_api_gateway_resource.workspace_web_changes[0].id
    governance = aws_api_gateway_resource.workspace_account_governance[0].id
  }
}
resource "aws_api_gateway_method" "workspace_browser_operations" {
  for_each      = local.workspace_browser_operation_resources
  rest_api_id   = aws_api_gateway_rest_api.vaultguard.id
  resource_id   = each.value
  http_method   = "POST"
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "workspace_browser_operations" {
  for_each                = local.workspace_browser_operation_resources
  rest_api_id             = aws_api_gateway_rest_api.vaultguard.id
  resource_id             = each.value
  http_method             = aws_api_gateway_method.workspace_browser_operations[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = var.workspace_web_lambda_invoke_arn
}
resource "aws_lambda_permission" "workspace_browser_operations" {
  for_each      = local.workspace_browser_operation_resources
  statement_id  = "AllowWorkspaceBrowser${title(each.key)}"
  action        = "lambda:InvokeFunction"
  function_name = var.workspace_web_lambda_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = each.key == "governance" ? "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/POST/workspace/governance" : "${aws_api_gateway_rest_api.vaultguard.execution_arn}/*/POST/vaults/*/workspace/${each.key}"
}
resource "aws_api_gateway_method_settings" "workspace_browser_operations" {
  for_each    = local.workspace_browser_operation_resources
  rest_api_id = aws_api_gateway_rest_api.vaultguard.id
  stage_name  = aws_api_gateway_stage.vaultguard.stage_name
  method_path = each.key == "governance" ? "workspace/governance/POST" : "vaults/{vaultId}/workspace/${each.key}/POST"
  settings {
    throttling_rate_limit  = 2
    throttling_burst_limit = 4
    metrics_enabled        = true
    logging_level          = "OFF"
    data_trace_enabled     = false
  }
}
