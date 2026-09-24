# P4 source integration only: a reusable policy supplement. It is NOT attached
# to mcp-read, a role, a route, a function, or a schedule. A future approved write
# host must combine it with canonical membership/permission/key read permissions.
# Constructing the service still requires disabled-by-default revision_writes.
locals {
  collaboration_artifact_prefix = replace(replace(replace(base64encode("_vaultguard-collaboration"), "=", ""), "+", "-"), "/", "_")
}

data "aws_iam_policy_document" "workspace_collaboration_storage" {
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:ConditionCheckItem"]
    resources = [var.workspace_revisions_table_arn]
    condition {
      test     = "ForAllValues:StringLike"
      variable = "dynamodb:LeadingKeys"
      values   = ["WORKSPACE#*"]
    }
  }
  statement {
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
    resources = ["${var.vault_bucket_arn}/${local.collaboration_artifact_prefix}/*"]
  }
  # VAULTGUARD-113: every committed workflow transition writes its canonical
  # organization-audit event in the same transaction. PutItem only; create-only
  # is the writer's attribute_not_exists(pk) condition, which IAM cannot require.
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.audit_table_arn]
  }
  # S3 SSE-KMS complements the application vault envelope; it cannot authorize
  # direct content-key creation. Existing vault crypto owns scoped key unwraps.
  statement {
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}

output "workspace_collaboration_storage_policy_json" {
  description = "Unattached collaboration storage supplement for a separately authorized write host."
  value       = data.aws_iam_policy_document.workspace_collaboration_storage.json
}
