# Economic reservations are ephemeral accounting, isolated from authoritative
# WorkspaceRevisions. Disabling controls never destroys either table.
resource "aws_dynamodb_table" "workspace_economics" {
  name                        = "VaultGuard-${var.stage}-WorkspaceEconomics"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }
  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }
  # Policies have no ttl. Receipt/ledger expiry is supplied by the canonical
  # owner only after its budget window and retry/reconciliation horizon.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  tags = { Name = "VaultGuard-${var.stage}-WorkspaceEconomics" }
}
output "workspace_economics_table_name" { value = aws_dynamodb_table.workspace_economics.name }
output "workspace_economics_table_arn" { value = aws_dynamodb_table.workspace_economics.arn }
