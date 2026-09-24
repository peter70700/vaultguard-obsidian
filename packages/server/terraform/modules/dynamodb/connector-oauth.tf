# ─────────────────────────────────────────────────────────────────────────────
# Connector OAuth authorization state (VAULTGUARD-49 / ADR-003)
#
# VaultGuard's own connector authorization server keeps its clients, grants,
# sessions and opaque credential rows here. Production stopped naming Cognito as
# the connector authorization server because an AWS-generated discovery document
# can never advertise `offline_access`, which ChatGPT connectors check for.
#
# The table NAME is derived, not free: the Lambda validates that its auth table
# is exactly `${CONNECTOR_NAMESPACE}-auth`, and the namespace is
# `vaultguard-connector-${stage}`. It therefore deliberately does not follow the
# `VaultGuard-${stage}-X` convention used by the tenant tables.
#
# MCP-3: the TTL attribute is `ttl`, NOT `expiresAt`. Used authorization codes
# and rotated refresh tokens stay in the table past their expiry as replay
# tombstones, and a TTL on `expiresAt` would delete exactly that evidence. Only
# rows the issuer has finished with carry `ttl`.
# ─────────────────────────────────────────────────────────────────────────────

variable "connector_oauth_resource" {
  description = "Set to enable VaultGuard's own connector authorization server. Empty creates nothing."
  type        = string
  default     = ""
}

resource "aws_dynamodb_table" "connector_auth" {
  count = var.connector_oauth_resource == "" ? 0 : 1

  name         = "vaultguard-connector-${var.stage}-auth"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  tags = { Name = "vaultguard-connector-${var.stage}-auth" }
}

output "connector_auth_table_name" {
  value = var.connector_oauth_resource == "" ? "" : aws_dynamodb_table.connector_auth[0].name
}

output "connector_auth_table_arn" {
  value = var.connector_oauth_resource == "" ? "" : aws_dynamodb_table.connector_auth[0].arn
}
