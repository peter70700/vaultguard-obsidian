variable "workspace_cost_controls" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "budget-v1"], var.workspace_cost_controls)
    error_message = "Cost controls must be absent or budget-v1."
  }
}
variable "workspace_cost_telemetry" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "content-free-v1"], var.workspace_cost_telemetry)
    error_message = "Only content-free cost telemetry is supported."
  }
}
variable "workspace_economics_table_name" { type = string }
variable "workspace_economics_table_arn" { type = string }
variable "workspace_semantic_provider_profile" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "openai-embeddings-v1"], var.workspace_semantic_provider_profile)
    error_message = "Only the reviewed embeddings provider profile is supported."
  }
}
variable "workspace_semantic_secret_arn" {
  type    = string
  default = ""
}
locals {
  workspace_runtime_env = {
    WORKSPACE_SLO_TELEMETRY             = var.workspace_slo_telemetry
    WORKSPACE_COST_CONTROLS             = var.workspace_cost_controls
    WORKSPACE_COST_TELEMETRY            = var.workspace_cost_telemetry
    WORKSPACE_ECONOMICS_TABLE           = var.workspace_economics_table_name
    WORKSPACE_SEMANTIC_PROVIDER_PROFILE = var.workspace_semantic_provider_profile
    WORKSPACE_SEMANTIC_SECRET_ARN       = var.workspace_semantic_secret_arn
  }
  workspace_runtime_roles = concat(aws_iam_role.mcp_read_lambda[*].name, aws_iam_role.mcp_read_prepare[*].name,
  aws_iam_role.mcp_write[*].name, aws_iam_role.mcp_write_prepare[*].name, aws_iam_role.workspace_web[*].name, aws_iam_role.workspace_projection[*].name)
}
check "workspace_semantic_configuration" {
  assert {
    condition = (var.workspace_semantic_provider_profile == "" && var.workspace_semantic_secret_arn == "") || (
      var.workspace_semantic_provider_profile == "openai-embeddings-v1" && var.workspace_cost_controls == "budget-v1" &&
      startswith(var.workspace_semantic_secret_arn, "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:")
    )
    error_message = "Semantic indexing needs a reviewed profile, same-account secret and explicit budget control. Human consent remains independently required."
  }
}
data "aws_iam_policy_document" "workspace_economics" {
  statement {
    actions   = ["dynamodb:GetItem"]
    resources = [var.workspace_economics_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-ECONOMICS-POLICY#*"]
    }
  }
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_economics_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE-ECONOMICS#*", "WORKSPACE-ECONOMICS-RECEIPTS#*", "WORKSPACE-ECONOMICS-ALERTS#*"]
    }
  }
}
resource "aws_iam_role_policy" "workspace_economics" {
  count  = var.workspace_cost_controls == "budget-v1" ? length(local.workspace_runtime_roles) : 0
  name   = "vaultguard-${var.stage}-workspace-economics"
  role   = local.workspace_runtime_roles[count.index]
  policy = data.aws_iam_policy_document.workspace_economics.json
}
# HTTP semantic queries embed their query text after consent/budget checks;
# document indexing stays internal. The human governance host reads no secret.
data "aws_iam_policy_document" "workspace_semantic_read" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["SEMANTIC-POLICY#*", "SEMANTIC-INDEX#*"]
    }
  }
}
resource "aws_iam_role_policy" "workspace_semantic_query" {
  count  = local.mcp_read_count
  name   = "vaultguard-${var.stage}-workspace-semantic-query"
  role   = local.mcp_write_enabled ? aws_iam_role.mcp_write[0].id : aws_iam_role.mcp_read_lambda[0].id
  policy = data.aws_iam_policy_document.workspace_semantic_query.json
}
data "aws_iam_policy_document" "workspace_semantic_query" {
  source_policy_documents = [data.aws_iam_policy_document.workspace_semantic_read.json]
  dynamic "statement" {
    for_each = var.workspace_semantic_secret_arn == "" ? [] : [var.workspace_semantic_secret_arn]
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [statement.value]
    }
  }
}
data "aws_iam_policy_document" "workspace_semantic_prepare" {
  source_policy_documents = [data.aws_iam_policy_document.workspace_semantic_read.json]
  statement {
    actions   = ["dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["SEMANTIC-POLICY#*"]
    }
  }
  statement {
    actions   = ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["SEMANTIC-INDEX#*"]
    }
  }
  dynamic "statement" {
    for_each = var.workspace_semantic_secret_arn == "" ? [] : [var.workspace_semantic_secret_arn]
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [statement.value]
    }
  }
}
resource "aws_iam_role_policy" "workspace_semantic_prepare" {
  count  = local.mcp_read_count
  name   = "vaultguard-${var.stage}-workspace-semantic-prepare"
  role   = local.mcp_write_enabled ? aws_iam_role.mcp_write_prepare[0].id : aws_iam_role.mcp_read_prepare[0].id
  policy = data.aws_iam_policy_document.workspace_semantic_prepare.json
}
# Only the already authenticated human governance owner can grant/withdraw consent.
resource "aws_iam_role_policy" "workspace_semantic_consent" {
  count = local.workspace_web_count
  name  = "vaultguard-${var.stage}-workspace-semantic-consent"
  role  = aws_iam_role.workspace_web[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
    Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:ConditionCheckItem"], Resource = var.workspace_revisions_table_arn,
  Condition = { "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["SEMANTIC-POLICY#*"] } } }] })
}

variable "workspace_slo_telemetry" {
  type    = string
  default = ""
  validation {
    condition     = contains(["", "content-free-v1"], var.workspace_slo_telemetry)
    error_message = "Only content-free SLO telemetry is supported."
  }
}

variable "workspace_cohort_controls_enabled" {
  type        = bool
  default     = false
  description = "Explicit shared writer-fence/routing participation; not first-party sync activation. Keep enabled for any adopted cohort even while product capabilities are off."
}

check "workspace_writers_share_cohort_fence" {
  assert {
    condition     = !((var.workspace_capabilities.web_editing || var.workspace_capabilities.first_party_sync) && var.workspace_capabilities.revision_writes) || var.workspace_cohort_controls_enabled
    error_message = "All file, browser, MCP and rotation writers must participate in the canonical cohort fence before editing is enabled."
  }
}
resource "aws_iam_role_policy" "workspace_existing_writer_fence" {
  count = var.workspace_cohort_controls_enabled ? 2 : 0
  name  = "vaultguard-${var.stage}-workspace-cohort-read"
  role  = [aws_iam_role.files_lambda.id, aws_iam_role.reencryption_lambda.id][count.index]
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow",
    Action = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:ConditionCheckItem"], Resource = var.workspace_revisions_table_arn,
  Condition = { "ForAllValues:StringLike" = { "dynamodb:LeadingKeys" = ["WORKSPACE#*", "WORKSPACE-COHORT#*"] } } }] })
}
