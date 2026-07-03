variable "stage" { type = string }
variable "is_prod" { type = bool }
variable "production_hardening" { type = bool }
variable "kms_key_arn" { type = string }

locals {
  deletion_protection = var.production_hardening
  pitr_enabled        = var.production_hardening
}

# ─────────────────────────────────────────────────────────────────────────────
# Permissions Table
# PK: orgId#filePath  SK: principal (user#userId or role#roleName)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "permissions" {
  name         = "VaultGuard-${var.stage}-Permissions"
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
    attribute_name = "expiresAtTtl"
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
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "expiresAt"
    type = "S"
  }
  attribute {
    name = "userId"
    type = "S"
  }
  attribute {
    name = "role"
    type = "S"
  }

  # GSI: Query all permissions for a specific principal across all files
  global_secondary_index {
    name            = "principal-index"
    hash_key        = "sk"
    range_key       = "pk"
    projection_type = "ALL"
  }

  # GSI: Find permissions by org ordered by expiry
  global_secondary_index {
    name               = "org-expiry-index"
    hash_key           = "orgId"
    range_key          = "expiresAt"
    projection_type    = "INCLUDE"
    non_key_attributes = ["pk", "sk", "permissionLevel", "grantedBy"]
  }

  # GSI: Query by userId for user-specific rules
  global_secondary_index {
    name            = "userId-index"
    hash_key        = "userId"
    range_key       = "pk"
    projection_type = "ALL"
  }

  # GSI: Query by role for role-based rules
  global_secondary_index {
    name            = "role-index"
    hash_key        = "role"
    range_key       = "pk"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Permissions" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Audit Log Table
# PK: orgId#date  SK: timestamp#eventId
# GSIs:
#   - orgId-index for audit dashboard queries ordered by timestamp
#   - vaultId-index for vault-scoped audit queries ordered by timestamp
#   - userId-index for user activity
#   - resourcePath-index for file/resource history
# Legacy GSIs are retained for backwards compatibility.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "audit_log" {
  name         = "VaultGuard-${var.stage}-AuditLog"
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
    attribute_name = "expiresAtTtl"
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
  attribute {
    name = "userId"
    type = "S"
  }
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "vaultId"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }
  attribute {
    name = "filePath"
    type = "S"
  }
  attribute {
    name = "resourcePath"
    type = "S"
  }

  global_secondary_index {
    name            = "orgId-index"
    hash_key        = "orgId"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "vaultId-index"
    hash_key        = "vaultId"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "userId-index"
    hash_key        = "userId"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "resourcePath-index"
    hash_key        = "resourcePath"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  # GSI: Query all events by a specific user
  global_secondary_index {
    name               = "user-activity-index"
    hash_key           = "userId"
    range_key          = "sk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["action", "filePath", "ipAddress", "riskScore"]
  }

  # GSI: Query events by file path
  global_secondary_index {
    name               = "file-access-index"
    hash_key           = "filePath"
    range_key          = "sk"
    projection_type    = "INCLUDE"
    non_key_attributes = ["userId", "action", "ipAddress", "deviceId"]
  }

  tags = { Name = "VaultGuard-${var.stage}-AuditLog" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Alerts Table
# PK: id
# GSI: orgId-index for admin dashboard queries ordered by timestamp
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "alerts" {
  name         = "VaultGuard-${var.stage}-Alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "id"
    type = "S"
  }
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name            = "orgId-index"
    hash_key        = "orgId"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Alerts" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Sessions Table
# PK: sessionId  (auth handler creates/queries/updates by sessionId)
# GSI: userId-index (for listing/revoking all sessions for a user)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "sessions" {
  name         = "VaultGuard-${var.stage}-Sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "sessionId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "sessionId"
    type = "S"
  }
  attribute {
    name = "userId"
    type = "S"
  }

  # GSI: Query all sessions for a user (for revocation, listing)
  global_secondary_index {
    name            = "userId-index"
    hash_key        = "userId"
    range_key       = "sessionId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Sessions" }
}

# ─────────────────────────────────────────────────────────────────────────────
# User Keys Table (Envelope Encryption)
# PK: orgId#userId  SK: keyVersion
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "user_keys" {
  name         = "VaultGuard-${var.stage}-UserKeys"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

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
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "status"
    type = "S"
  }
  # Phase 6 (DEK-02, DEK-03): stable per-DEK identifier that travels with the
  # key from ACTIVE → ROTATED# and lives on S3 objects as
  # `x-amz-meta-vaultguard-key-id`. Used by Phase 7 cross-DEK restore to look
  # up the historical DEK that wrapped a noncurrent S3 version.
  attribute {
    name = "keyId"
    type = "S"
  }

  # GSI: Find all active keys across an org (for bulk rotation)
  global_secondary_index {
    name               = "org-status-index"
    hash_key           = "orgId"
    range_key          = "status"
    projection_type    = "INCLUDE"
    non_key_attributes = ["pk", "sk", "createdAt", "lastUsedAt"]
  }

  # GSI: Look up a DEK by its keyId (Phase 7 cross-DEK restore + S3-metadata-
  # tagged objects). Projection ALL so the Phase 7 lookup gets `orgId`,
  # `scope`, `vaultId`, `encryptedDataKey` for the KMS EncryptionContext.
  global_secondary_index {
    name            = "keyId-index"
    hash_key        = "keyId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-UserKeys" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Organizations Table
# PK: slug
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "organizations" {
  name         = "VaultGuard-${var.stage}-Organizations"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "slug"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "slug"
    type = "S"
  }
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "stripeCustomerId"
    type = "S"
  }

  global_secondary_index {
    name            = "orgId-index"
    hash_key        = "orgId"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "stripe-index"
    hash_key        = "stripeCustomerId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Organizations" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Subscriptions Table
# PK: orgId
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "subscriptions" {
  name         = "VaultGuard-${var.stage}-Subscriptions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "orgId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "stripeCustomerId"
    type = "S"
  }
  attribute {
    name = "stripeSubscriptionId"
    type = "S"
  }

  global_secondary_index {
    name            = "stripe-index"
    hash_key        = "stripeCustomerId"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "stripe-sub-index"
    hash_key        = "stripeSubscriptionId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Subscriptions" }
}

# ─────────────────────────────────────────────────────────────────────────────
# StripeWebhookEvents Table — Idempotency dedup for Stripe webhook retries
# PK: eventId (Stripe event.id, e.g. "evt_1Abc...")
# TTL: expiresAt (7 days)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "stripe_webhook_events" {
  name         = "VaultGuard-${var.stage}-StripeWebhookEvents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "eventId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "eventId"
    type = "S"
  }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  tags = { Name = "VaultGuard-${var.stage}-StripeWebhookEvents" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Leases Table (Encryption Key Leases)
# PK: leaseId
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "leases" {
  name         = "VaultGuard-${var.stage}-Leases"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "leaseId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "leaseId"
    type = "S"
  }
  attribute {
    name = "userId"
    type = "S"
  }

  # GSI: Query leases by userId (for concurrent lease enforcement and revocation)
  global_secondary_index {
    name            = "userId-index"
    hash_key        = "userId"
    range_key       = "leaseId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Leases" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Re-encryption Jobs Table
# PK: jobId
# Tracks server-side re-encryption jobs after user offboarding
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "reencryption_jobs" {
  name         = "VaultGuard-${var.stage}-ReEncryptionJobs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "jobId"

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  point_in_time_recovery {
    enabled = local.pitr_enabled
  }

  deletion_protection_enabled = local.deletion_protection

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "jobId"
    type = "S"
  }
  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "startedAt"
    type = "S"
  }

  global_secondary_index {
    name            = "orgId-index"
    hash_key        = "orgId"
    range_key       = "startedAt"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-ReEncryptionJobs" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Vaults Table
#
# Represents a named, isolated namespace inside an organization.
# Replaces the previous flat "everything in the org shares one keyspace" model.
#
# Each Obsidian-side vault binds to exactly one server-side Vault.
# Files for vaultId X live under S3 prefix `vault/{orgId}/{vaultId}/...`.
# Permission rules are scoped to a vault — rules in vault A do not leak to B.
#
# PK: orgId   SK: vaultId
# GSI:
#   - slug-index (orgId, slug) — human-readable URLs / lookups by slug
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "vaults" {
  name         = "VaultGuard-${var.stage}-Vaults"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "orgId"
  range_key    = "vaultId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "orgId"
    type = "S"
  }
  attribute {
    name = "vaultId"
    type = "S"
  }
  attribute {
    name = "slug"
    type = "S"
  }

  # GSI: lookup a vault by (orgId, slug). Used by plugin's slug-based binding.
  global_secondary_index {
    name            = "slug-index"
    hash_key        = "orgId"
    range_key       = "slug"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Vaults" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Vault Members Table
#
# A user is a member of a vault with a specific role (viewer/editor/admin).
# Org-level admins bypass this check. Org-level users without a membership
# row CANNOT access the vault, even read-only.
#
# PK: vaultId   SK: userId
# GSI:
#   - userId-index (userId, vaultId) — list all vaults a user belongs to
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "vault_members" {
  name         = "VaultGuard-${var.stage}-VaultMembers"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "vaultId"
  range_key    = "userId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "vaultId"
    type = "S"
  }
  attribute {
    name = "userId"
    type = "S"
  }

  # GSI: query all vaults this user is a member of.
  global_secondary_index {
    name            = "userId-index"
    hash_key        = "userId"
    range_key       = "vaultId"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-VaultMembers" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Vault Activity Log Table
#
# Every file write/delete appends a row here. Sync clients query "everything
# in this vault since timestamp X" to skip the full S3 listing scan when
# they're already mostly up-to-date.
#
# PK: vaultId   SK: sk (string, format: 15-digit-padded-epochMs#shortId)
#
# TTL: 14 days. Clients that fall further behind than the retention window
# fall back to a full-scan sync via the cursor-mismatch path.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "vault_activity" {
  name         = "VaultGuard-${var.stage}-VaultActivity"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "vaultId"
  range_key    = "sk"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "vaultId"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = { Name = "VaultGuard-${var.stage}-VaultActivity" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Revoked Keys Table
# PK: userId
#
# Single hash key. checkKeyRevocation in auth/handler.ts queries by userId
# and returns true if any item exists. handleRevoke writes one item per
# revocation containing userId, revokedAt, revokedBy, reason.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "revoked_keys" {
  name         = "VaultGuard-${var.stage}-RevokedKeys"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "userId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "userId"
    type = "S"
  }

  tags = { Name = "VaultGuard-${var.stage}-RevokedKeys" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Share Links Table
#
# Each row is an opaque pointer that lets a vault member route a teammate
# directly to a specific file (live target — resolved at click time).
# Tokens carry NO authority on their own; the resolve endpoint still goes
# through requireVaultMember, which is what makes them "internal team only".
#
# PK: shareId (24 random bytes, base64url — 32-char URL-safe)
# GSI: vaultId-index (vaultId, createdAt) — list active shares per vault
#
# TTL: native expiry via expiresAtTtl (epoch seconds). DynamoDB sweeps the
# row asynchronously; the resolve endpoint also re-checks expiresAt to
# avoid the (small) TTL eventual-consistency window.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "shares" {
  name         = "VaultGuard-${var.stage}-Shares"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "shareId"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "shareId"
    type = "S"
  }
  attribute {
    name = "vaultId"
    type = "S"
  }
  attribute {
    name = "createdAt"
    type = "S"
  }

  global_secondary_index {
    name            = "vaultId-index"
    hash_key        = "vaultId"
    range_key       = "createdAt"
    projection_type = "ALL"
  }

  tags = { Name = "VaultGuard-${var.stage}-Shares" }
}

# ─────────────────────────────────────────────────────────────────────────────
# MFA Recovery Codes Table
#
# Stores hashed single-use recovery codes per user. A user that loses their
# TOTP device redeems one of these codes; the verify endpoint then clears the
# user's MFA preference in Cognito so the next login routes through MFA_SETUP.
#
# PK: userId   SK: codeHash
# GSI: userId-index isn't needed — the partition key already targets one user.
#
# `usedAt` is set on consumption; rows are kept (audit) and TTL'd after 30
# days via `expiresAtTtl`. Re-enrollment writes a fresh batch; the verify
# handler refuses any row whose codeHash isn't present (single-use is
# enforced by an atomic conditional delete).
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "recovery_codes" {
  name         = "VaultGuard-${var.stage}-RecoveryCodes"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "userId"
  range_key    = "codeHash"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "userId"
    type = "S"
  }
  attribute {
    name = "codeHash"
    type = "S"
  }

  tags = { Name = "VaultGuard-${var.stage}-RecoveryCodes" }
}

# ─────────────────────────────────────────────────────────────────────────────
# MFA Recovery Attempts Table
#
# Per-user rate-limit counter for recovery-code verification attempts. One row
# per (userId, windowStart) bucket. Tracked separately from RecoveryCodes so
# a flood of bad attempts can't fill the codes partition.
#
# TTL: 1 hour past windowStart — the table auto-prunes.
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "recovery_attempts" {
  name         = "VaultGuard-${var.stage}-RecoveryAttempts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "userId"
  range_key    = "windowStart"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  ttl {
    attribute_name = "expiresAtTtl"
    enabled        = true
  }

  attribute {
    name = "userId"
    type = "S"
  }
  attribute {
    name = "windowStart"
    type = "N"
  }

  tags = { Name = "VaultGuard-${var.stage}-RecoveryAttempts" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Platform Metrics Table
#
# Daily platform-wide snapshots for the super-admin growth dashboard.
# The superadmin Lambda's scheduled (EventBridge) invocation writes one
# item per day: metric="daily", date="YYYY-MM-DD", plus counters
# {orgs, users, vaults, storageBytes, activeSubscriptions, mrrCents, computedAt}.
#
# PK: metric (S)   SK: date (S, YYYY-MM-DD)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "platform_metrics" {
  name         = "VaultGuard-${var.stage}-PlatformMetrics"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "metric"
  range_key    = "date"

  deletion_protection_enabled = local.deletion_protection
  point_in_time_recovery { enabled = local.pitr_enabled }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  attribute {
    name = "metric"
    type = "S"
  }
  attribute {
    name = "date"
    type = "S"
  }

  tags = { Name = "VaultGuard-${var.stage}-PlatformMetrics" }
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "platform_metrics_table_name" { value = aws_dynamodb_table.platform_metrics.name }
output "platform_metrics_table_arn" { value = aws_dynamodb_table.platform_metrics.arn }

output "shares_table_name" { value = aws_dynamodb_table.shares.name }
output "shares_table_arn" { value = aws_dynamodb_table.shares.arn }

output "vaults_table_name" { value = aws_dynamodb_table.vaults.name }
output "vaults_table_arn" { value = aws_dynamodb_table.vaults.arn }

output "vault_members_table_name" { value = aws_dynamodb_table.vault_members.name }
output "vault_members_table_arn" { value = aws_dynamodb_table.vault_members.arn }

output "vault_activity_table_name" { value = aws_dynamodb_table.vault_activity.name }
output "vault_activity_table_arn" { value = aws_dynamodb_table.vault_activity.arn }

output "permissions_table_name" { value = aws_dynamodb_table.permissions.name }
output "permissions_table_arn" { value = aws_dynamodb_table.permissions.arn }

output "audit_table_name" { value = aws_dynamodb_table.audit_log.name }
output "audit_table_arn" { value = aws_dynamodb_table.audit_log.arn }

output "alerts_table_name" { value = aws_dynamodb_table.alerts.name }
output "alerts_table_arn" { value = aws_dynamodb_table.alerts.arn }

output "sessions_table_name" { value = aws_dynamodb_table.sessions.name }
output "sessions_table_arn" { value = aws_dynamodb_table.sessions.arn }

output "user_keys_table_name" { value = aws_dynamodb_table.user_keys.name }
output "user_keys_table_arn" { value = aws_dynamodb_table.user_keys.arn }

output "organizations_table_name" { value = aws_dynamodb_table.organizations.name }
output "organizations_table_arn" { value = aws_dynamodb_table.organizations.arn }

output "subscriptions_table_name" { value = aws_dynamodb_table.subscriptions.name }
output "subscriptions_table_arn" { value = aws_dynamodb_table.subscriptions.arn }

output "stripe_webhook_events_table_name" { value = aws_dynamodb_table.stripe_webhook_events.name }
output "stripe_webhook_events_table_arn" { value = aws_dynamodb_table.stripe_webhook_events.arn }

output "leases_table_name" { value = aws_dynamodb_table.leases.name }
output "leases_table_arn" { value = aws_dynamodb_table.leases.arn }

output "reencryption_jobs_table_name" { value = aws_dynamodb_table.reencryption_jobs.name }
output "reencryption_jobs_table_arn" { value = aws_dynamodb_table.reencryption_jobs.arn }

output "revoked_keys_table_name" { value = aws_dynamodb_table.revoked_keys.name }
output "revoked_keys_table_arn" { value = aws_dynamodb_table.revoked_keys.arn }

output "recovery_codes_table_name" { value = aws_dynamodb_table.recovery_codes.name }
output "recovery_codes_table_arn" { value = aws_dynamodb_table.recovery_codes.arn }

output "recovery_attempts_table_name" { value = aws_dynamodb_table.recovery_attempts.name }
output "recovery_attempts_table_arn" { value = aws_dynamodb_table.recovery_attempts.arn }
