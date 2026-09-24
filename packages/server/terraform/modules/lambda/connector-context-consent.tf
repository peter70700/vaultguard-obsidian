data "aws_iam_policy_document" "connector_context_consent" {
  count = local.connector_enabled
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.workspace_revisions_table_arn, var.vault_activity_table_arn, var.user_keys_table_arn]
  }
  statement {
    actions   = ["dynamodb:Scan"]
    resources = [var.permissions_table_arn]
  }
  statement {
    actions   = ["s3:GetObjectVersion"]
    resources = ["${var.vault_bucket_arn}/${local.mcp_knowledge_prefix}/*/context-version/*"]
  }
  statement {
    actions   = ["cognito-idp:AdminGetUser", "cognito-idp:AdminListGroupsForUser"]
    resources = [var.cognito_user_pool_arn]
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:purpose"
      values   = ["vault-scope-dek"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:orgId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:vaultId"
      values   = ["false"]
    }
    condition {
      test     = "Null"
      variable = "kms:EncryptionContext:scope"
      values   = ["false"]
    }
  }
  statement {
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.name}.amazonaws.com"]
    }
  }
}
resource "aws_iam_role_policy" "connector_context_consent" {
  count  = local.connector_enabled
  name   = "vaultguard-${var.stage}-connector-context-consent"
  role   = aws_iam_role.connector_oauth_lambda[0].id
  policy = data.aws_iam_policy_document.connector_context_consent[0].json
}
