/**
 * VaultGuard — File Operations Lambda Handler
 *
 * Manages vault file CRUD operations with permission enforcement,
 * S3 versioning, and complete audit logging.
 *
 * All endpoints are scoped to a specific Vault — tenant isolation is now
 * enforced at TWO layers (orgId AND vaultId) and the S3 key embeds both:
 *   `vault/{orgId}/{vaultId}/{relativePath}`
 *
 * Endpoints:
 * - GET    /vaults/{vaultId}/files                 — List files in this vault
 * - GET    /vaults/{vaultId}/overview              — Metadata-only vault structure overview
 * - GET    /vaults/{vaultId}/files/{path+}         — Read content
 * - PUT    /vaults/{vaultId}/files/{path+}         — Write content
 * - DELETE /vaults/{vaultId}/files/{path+}         — Soft-delete
 * - GET    /vaults/{vaultId}/files/{path+}/history — Version history
 * - POST   /vaults/{vaultId}/files/sync            — Delta sync
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  S3Client,
  CopyObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
  DeleteObjectCommand,
  ListObjectVersionsCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { createHash } from 'node:crypto';
import { emitSecurityMetric } from '../shared/metrics';
import { DynamoWorkspaceCohortControl } from '../shared/workspace-cohort-control';
import { DurableWorkspaceCohortRouter, WorkspaceRoutingError, type WorkspaceCohortRoute } from '../shared/workspace-routing';
import type { WorkspaceScope } from '../workspace-revisions/types';
import { RevisionFileReadView } from './revision-read-view';
import { WorkspaceRevisionService } from '../workspace-revisions/service';
import { S3WorkspaceManifestStore } from '../workspace-revisions/manifest-store';
import { DynamoWorkspaceRevisionRepository } from '../workspace-revisions/head-store';
import {
  DynamoFileVersionStore,
  FILE_VERSION_METADATA,
  FileVersionIntegrityError,
  FileVersionNotFoundError,
  bindStorageVersion,
  createFileVersionDraft,
  fileVersionFromStorageObservation,
  exactFileVersionStorageKey,
  legacyFileId,
  legacyFileVersionId,
  makeFileId,
  makeFileVersionId,
  metadataForFileVersion,
  verifyCiphertextIntegrity,
  verifyPlaintextIntegrity,
  verifyStorageBinding,
  type FileVersionDraft,
  type FileVersionRecord as LogicalFileVersionRecord,
} from './file-version-service';
import {
  acquireVaultMutationPermit,
  releaseVaultMutationPermit,
} from '../shared/rotation-fence';
import {
  decryptCurrentVaultBlobForRead,
  decryptExactVaultVersion,
  encryptPlaintextWithActiveVaultKey,
  getActiveKeyIdForVault,
} from '../shared/vault-crypto';
import {
  bindAuthorizationGenerations,
  revalidateAuthorizationBeforeEgress,
  type AuthorizationGenerationBinding,
} from '../shared/authorization-generations';
import {
  docClient,
  verifyActiveUser,
  evaluatePermission,
  shouldRespectAdminBypassFor,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  getActiveOrg,
  checkStorageLimit,
  updateOrgStorageUsage,
  requireOrgId,
  requireVaultMember,
  assertVaultWritable,
  getVaultMembership,
  isAdmin,
  vaultRoleMeetsRequirement,
  sanitizeFilePath,
  beginVaultMutationIntent,
  commitVaultMutationIntent,
  abortVaultMutationIntent,
  listPendingVaultMutationIntents,
  getVaultCursor,
  queryVaultActivity,
  UserContext,
  VaultRecord,
  VaultActivityRecord,
  VaultMutationIntent,
  AuthError,
  GetCommand,
  QueryCommand,
} from '../shared/utils';

// ─── Configuration ───────────────────────────────────────────────────────────

const S3_BUCKET = process.env.VAULT_BUCKET || process.env.VAULT_S3_BUCKET!;
const S3_PREFIX_BASE = process.env.VAULT_S3_PREFIX || 'vault/';
const REGION = process.env.AWS_REGION || 'eu-west-1';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || '26214400', 10); // 25 MiB default
const DIRECT_TRANSFER_TTL_SECONDS = 5 * 60;
const DIRECT_TRANSFER_STAGING_PREFIX = '_vaultguard-transfers/';
const AES_GCM_ENVELOPE_OVERHEAD_BYTES = 28; // 12-byte nonce + 16-byte tag
const DIRECT_TRANSFER_MAX_ENCRYPTED_SIZE = MAX_FILE_SIZE + AES_GCM_ENVELOPE_OVERHEAD_BYTES;
const DEFAULT_OVERVIEW_LIMIT = 5000;
const MAX_OVERVIEW_LIMIT = 10000;

// Phase 6/7: the `user_keys` table holds per-`(orgId, scope, vaultId)`
// DEK metadata. Normal writes read only `keyId`; exact historical reads/restores
// resolve the matching wrapped DEK and unwrap it through the vault-bound KMS
// encryption context.
const FILE_VERSIONS_TABLE = process.env.FILE_VERSIONS_TABLE;
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE || 'UserKeysTable';

/**
 * Sentinel filename the plugin writes into every server-side folder so that
 * empty folders survive the round-trip — S3 has no native concept of an
 * empty directory, only objects whose keys happen to share a prefix. Without
 * this marker, an Obsidian folder with no files is invisible to the overview
 * endpoint and the admin panel renders the vault's structure incorrectly.
 *
 * Markers are filtered out of every user-facing listing (overview file
 * counts, file list, sync deltas) so they're never visible as "files" — they
 * exist only to carry the folder's existence.
 */
export const FOLDER_MARKER_NAME = '.vaultguard-folder';
const CLIENT_LOCAL_ONLY_PREFIXES = ['.obsidian/plugins/vaultguard'];

/** Returns true when `relativePath` (vault-scoped, no prefix) is a folder marker. */
function isFolderMarkerPath(relativePath: string): boolean {
  if (!relativePath) return false;
  const segments = relativePath.split('/').filter(Boolean);
  return segments.length > 0 && segments[segments.length - 1] === FOLDER_MARKER_NAME;
}

/** Returns true for plugin-local files that must never be served from S3. */
function isClientLocalOnlyPath(relativePath: string): boolean {
  const normalized = relativePath.replace(/^\/+/, '').replace(/\/+$/, '');
  return CLIENT_LOCAL_ONLY_PREFIXES.some(
    (prefix) => normalized === prefix || normalized.startsWith(prefix + '/')
  );
}

/** Returns the parent folder of a marker path, or '' for a root-level marker. */
function folderPathFromMarker(relativePath: string): string {
  const segments = relativePath.split('/').filter(Boolean);
  segments.pop();
  return segments.join('/');
}

/**
 * Permission-evaluation options for file operations. Carries the per-org
 * `respectAdminBypass` flag so that when `allowAdminPerFileRestrictions` is on,
 * per-file deny rules actually take effect on admins' reads/writes/deletes/lists.
 */
async function fileOpPermissionOptions(
  user: UserContext,
  vault: VaultRecord
): Promise<{ userAliases: string[]; respectAdminBypass: boolean }> {
  const respectAdminBypass = await shouldRespectAdminBypassFor(vault.orgId);
  return {
    userAliases: user.email ? [user.email] : [],
    respectAdminBypass,
  };
}

async function bindFileAuthorizationGenerations(
  user: UserContext,
  vault: VaultRecord,
): Promise<AuthorizationGenerationBinding> {
  const orgResult = await getActiveOrg(user.orgId, { consistentRead: true });
  if (!orgResult.allowed || !orgResult.org) {
    throw new AuthError('Organization access denied', 403);
  }
  return bindAuthorizationGenerations({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    subject: user.userId,
    membershipRevision: vault.membershipRevision ?? 0,
    permissionRevision: vault.permissionRevision ?? 0,
    policyRevision: orgResult.org.policyRevision ?? 0,
  });
}

/** Re-run the live membership, policy, and path permission owners before disclosure/commit. */
async function revalidateFileAuthorization(
  bound: AuthorizationGenerationBinding,
  user: UserContext,
  vaultId: string,
  filePath: string,
  action: 'read' | 'write',
  requiredRole: 'viewer' | 'admin',
  deniedStatus: number,
  deniedMessage: string,
  event: APIGatewayProxyEvent,
): Promise<void> {
  try {
    // Session/user revocation is owned by the existing route authenticator.
    // Reusing the initial UserContext would miss a logout during slow crypto.
    user = await verifyActiveUser(event);
    await revalidateAuthorizationBeforeEgress(bound, async () => {
      const pendingAuthorizationChange = (
        await listPendingVaultMutationIntents(vaultId, 100, { requireComplete: true })
      ).some((intent) => (
        intent.authorizationGenerations?.includes('membership') ||
        intent.authorizationGenerations?.includes('permission')
      ));
      if (pendingAuthorizationChange) {
        throw new AuthError(deniedMessage, deniedStatus);
      }
      const currentVault = await requireVaultMember(user, vaultId, requiredRole);
      const roles = await resolveFileOpRoles(user, currentVault);
      const currentOrg = await getActiveOrg(user.orgId, { consistentRead: true });
      if (!currentOrg.allowed || !currentOrg.org) throw new AuthError(deniedMessage, deniedStatus);
      const permission = await evaluatePermission(
        user.userId,
        roles,
        action,
        '/' + filePath,
        user.orgId,
        currentVault.vaultId,
        {
          userAliases: user.email ? [user.email] : [],
          respectAdminBypass: currentOrg.org.settings?.allowAdminPerFileRestrictions !== true,
        },
      );
      if (!permission.allowed) {
        throw new AuthError(deniedMessage, deniedStatus);
      }
      return bindFileAuthorizationGenerations(user, currentVault);
    });
  } catch {
    // Keep revocation and generation races absence-equivalent to the route's
    // ordinary deny response; never reveal whether bytes were already fetched.
    throw new AuthError(deniedMessage, deniedStatus, 'AUTHORIZATION_CHANGED');
  }
}

/**
 * Permission gate for a folder marker. Markers carry no content but their
 * mere presence in a delta leaks the folder path's name and structure. Gate
 * the marker on the same `read` permission the parent folder would require —
 * deny rules on `/secret/**` then keep `/secret/.vaultguard-folder` from
 * shipping to a member who shouldn't see that folder name at all.
 *
 * Root-level markers are always permitted: every vault member can see the
 * vault root itself, and there is no parent to evaluate against.
 */
async function canSeeFolderMarker(
  user: UserContext,
  vault: VaultRecord,
  markerPath: string
): Promise<boolean> {
  const folder = folderPathFromMarker(markerPath.replace(/^\/+/, ''));
  if (!folder) return true;
  // Probe with a synthetic file path under the folder so glob inheritance
  // (e.g. `pathPattern: /secret/**`) matches the same way it would for a
  // real file inside the folder.
  const probePath = `/${folder}/__vaultguard_marker_probe__`;
  // LF1: role-scoped deny rules bind on the vault-membership role, not
  // user.roles — otherwise a `{role:'editor',deny,read,/secret/**}` rule fails
  // to hide the `/secret` folder marker from an editor who is denied that folder.
  const permRoles = await resolveFileOpRoles(user, vault);
  const perm = await evaluatePermission(
    user.userId,
    permRoles,
    'read',
    probePath,
    user.orgId,
    vault.vaultId,
    await fileOpPermissionOptions(user, vault)
  );
  return perm.allowed;
}

/**
 * Phase 8 (Plan 08-01): sibling-resource matcher for the per-file server-side
 * decrypt endpoint. Distinct from the generic `/files/{path+}` resource so
 * audit, CloudWatch, and IAM policies can be targeted independently. Both
 * `{filePath+}` and `{path+}` proxy variants are accepted so the matcher is
 * resilient to API Gateway resource-name drift.
 */
const isReadDecryptedResource = (resource: string): boolean =>
  resource === '/vaults/{vaultId}/files-decrypted/{filePath+}' ||
  resource === '/vaults/{vaultId}/files-decrypted/{path+}';

function eventWithFilePathParameter(event: APIGatewayProxyEvent, filePath: string): APIGatewayProxyEvent {
  return {
    ...event,
    pathParameters: {
      ...(event.pathParameters ?? {}),
      filePath,
    },
  };
}

/**
 * Returns the vault-scoped S3 prefix: `vault/{orgId}/{vaultId}/`.
 *
 * BOTH parameters are required. This is the canonical guard rail for tenant
 * AND vault isolation: a missing orgId or vaultId raises an exception rather
 * than silently constructing an over-broad prefix.
 */
function vaultS3Prefix(orgId: string, vaultId: string): string {
  if (!orgId || !vaultId) {
    throw new Error('CRITICAL: vaultS3Prefix called without orgId+vaultId — isolation breach prevented');
  }
  return `${S3_PREFIX_BASE}${orgId}/${vaultId}/`;
}

interface DirectUploadMetadata {
  transferId: string;
  ownerUserId: string;
  orgId: string;
  vaultId: string;
  pathSha256: string;
  plaintextSize: number;
  encryptedSize: number;
  plaintextSha256: string;
  encryptedSha256: string;
  contentType: string;
  activeKeyId: string;
  issuedVersionId: string;
  issuedEtag: string;
  expiresAtMs: number;
}

function directTransferStagingKey(
  orgId: string,
  vaultId: string,
  userId: string,
  transferId: string
): string {
  return `${DIRECT_TRANSFER_STAGING_PREFIX}${orgId}/${vaultId}/${userId}/${transferId}`;
}

function sha256Hex(value: string | Buffer | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function checksumBase64FromHex(value: string): string {
  return Buffer.from(value, 'hex').toString('base64');
}

async function abortMutationIntentAfterDefiniteFailure(intent: VaultMutationIntent): Promise<void> {
  try {
    await abortVaultMutationIntent(intent);
  } catch (error) {
    // Leaving the intent pending is the fail-safe outcome: cursor clients will
    // reconcile instead of trusting an unchanged revision.
    console.error('[VAULT_MUTATION_INTENT_ABORT_FAILURE]', error, {
      vaultId: intent.vaultId,
      intentId: intent.intentId,
    });
  }
}

async function publishMutationIntentOrThrow(intent: VaultMutationIntent): Promise<void> {
  try {
    await commitVaultMutationIntent(intent);
  } catch (error) {
    await emitSecurityMetric('VaultMutationReconciliationRequired');
    console.error('[VAULT_MUTATION_INTENT_COMMIT_FAILURE]', error, {
      vaultId: intent.vaultId,
      intentId: intent.intentId,
      action: intent.action,
      path: intent.path,
    });
    throw new AuthError(
      'The file mutation is durable but sync publication requires reconciliation; retry sync before editing again.',
      503,
      'ACTIVITY_RECONCILIATION_REQUIRED',
    );
  }
}

const MUTATION_RECONCILIATION_GRACE_MS = 2 * 60 * 1000;

async function reconcilePendingMutationIntents(
  user: UserContext,
  vault: VaultRecord,
): Promise<VaultMutationIntent[]> {
  const pending = await listPendingVaultMutationIntents(vault.vaultId, 100);
  const now = Date.now();
  for (const intent of pending) {
    if (intent.orgId !== user.orgId || intent.vaultId !== vault.vaultId) {
      console.error('[VAULT_MUTATION_INTENT_SCOPE_MISMATCH]', {
        vaultId: vault.vaultId,
        intentId: intent.intentId,
      });
      continue;
    }
    if (now - intent.createdAtMs < MUTATION_RECONCILIATION_GRACE_MS) continue;

    try {
      let observed = intent.verification?.kind === 'permission-state';
      if (!observed) {
        const filePath = sanitizeFilePath(intent.path.replace(/^\/+/, ''));
        const key = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;
        const head = await headObjectOrNull({ Key: key });
        switch (intent.verification?.kind) {
          case 'object-metadata':
            observed = head?.Metadata?.['vaultguard-mutation-id'] === intent.intentId;
            break;
          case 'delete-head':
            observed = head === null;
            break;
          case 'restored-version':
            observed = head?.VersionId === intent.verification.versionId;
            break;
          default:
            observed = false;
        }
      }
      if (observed) {
        await commitVaultMutationIntent(intent);
      } else {
        await abortVaultMutationIntent(intent);
      }
    } catch (error) {
      console.error('[VAULT_MUTATION_INTENT_RECONCILE_FAILURE]', error, {
        vaultId: vault.vaultId,
        intentId: intent.intentId,
      });
    }
  }
  return listPendingVaultMutationIntents(vault.vaultId, 100);
}

function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function parseBoundedInteger(value: unknown, field: string, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new AuthError(`${field} must be an integer between 0 and ${maximum}`, 400);
  }
  return value;
}

function sanitizeDirectContentType(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > 160 || /[^\x20-\x7e]/.test(value)) {
    throw new AuthError('contentType is invalid', 400);
  }
  return value;
}

function encodeOpaqueCursor(value: Record<string, string | undefined>): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeOpaqueCursor(raw: string | undefined): Record<string, string | undefined> {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('shape');
    const out: Record<string, string | undefined> = {};
    for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (value !== undefined && typeof value !== 'string') throw new Error('value');
      out[key] = value;
    }
    return out;
  } catch {
    throw new AuthError('Invalid pagination cursor', 400);
  }
}

function parseRecoveryLimit(raw: string | undefined): number {
  if (!raw) return 50;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed < 1) throw new AuthError('limit must be at least 1', 400);
  return Math.min(parsed, 100);
}

function directUploadS3Metadata(input: DirectUploadMetadata): Record<string, string> {
  return {
    'transfer-id': input.transferId,
    'owner-user-id': input.ownerUserId,
    'org-id': input.orgId,
    'vault-id': input.vaultId,
    'path-sha256': input.pathSha256,
    operation: 'upload',
    'plaintext-size': String(input.plaintextSize),
    'encrypted-size': String(input.encryptedSize),
    'plaintext-sha256': input.plaintextSha256,
    'encrypted-sha256': input.encryptedSha256,
    'content-type': input.contentType,
    'active-key-id': input.activeKeyId,
    'issued-version-id': input.issuedVersionId,
    'issued-etag': input.issuedEtag,
    'expires-at-ms': String(input.expiresAtMs),
  };
}

function readDirectUploadMetadata(metadata: Record<string, string> | undefined): DirectUploadMetadata | null {
  if (!metadata) return null;
  const plaintextSize = Number(metadata['plaintext-size']);
  const encryptedSize = Number(metadata['encrypted-size']);
  const expiresAtMs = Number(metadata['expires-at-ms']);
  if (
    metadata.operation !== 'upload' ||
    !Number.isSafeInteger(plaintextSize) ||
    !Number.isSafeInteger(encryptedSize) ||
    !Number.isSafeInteger(expiresAtMs) ||
    !isSha256Hex(metadata['plaintext-sha256']) ||
    !isSha256Hex(metadata['encrypted-sha256'])
  ) {
    return null;
  }
  return {
    transferId: metadata['transfer-id'] || '',
    ownerUserId: metadata['owner-user-id'] || '',
    orgId: metadata['org-id'] || '',
    vaultId: metadata['vault-id'] || '',
    pathSha256: metadata['path-sha256'] || '',
    plaintextSize,
    encryptedSize,
    plaintextSha256: metadata['plaintext-sha256'],
    encryptedSha256: metadata['encrypted-sha256'],
    contentType: metadata['content-type'] || 'application/octet-stream',
    activeKeyId: metadata['active-key-id'] || '',
    issuedVersionId: metadata['issued-version-id'] || 'none',
    issuedEtag: metadata['issued-etag'] || 'none',
    expiresAtMs,
  };
}

const s3Client = new S3Client({ region: REGION });
const fileVersionStore = FILE_VERSIONS_TABLE
  ? new DynamoFileVersionStore(docClient, FILE_VERSIONS_TABLE)
  : null;

// Phase 7 (Plan 07-01): KMS client for cross-DEK restore. The restore endpoint
// reaches into the keyId-index GSI for a historical user_keys row, then asks
// KMS to unwrap that row's envelope with the row's EncryptionContext (orgId +
// scope + vaultId). Mirroring the s3Client singleton pattern keeps the cold
// start fast and avoids per-request client construction.
type S3VersionObservation = {
  VersionId?: string;
  ETag?: string;
  Metadata?: Record<string, string>;
  ContentType?: string;
  ContentLength?: number;
  LastModified?: Date;
};

function logicalLineageForHead(
  head: S3VersionObservation | null | undefined,
  user: UserContext,
  vault: VaultRecord,
  filePath: string,
): { fileId: string; parentFileVersionIds: string[] } {
  if (!head?.VersionId) {
    return { fileId: makeFileId(generateId()), parentFileVersionIds: [] };
  }
  const fileId =
    head.Metadata?.[FILE_VERSION_METADATA.fileId] ??
    legacyFileId(user.orgId, vault.vaultId, filePath);
  const parentFileVersionId =
    head.Metadata?.[FILE_VERSION_METADATA.fileVersionId] ??
    legacyFileVersionId(user.orgId, vault.vaultId, filePath, head.VersionId);
  return { fileId, parentFileVersionIds: [parentFileVersionId] };
}

function logicalVersionMetadata(
  draft: FileVersionDraft,
  existing: Record<string, string> = {},
): Record<string, string> {
  return { ...existing, ...metadataForFileVersion(draft) };
}

function requireLogicalVersionStore(): DynamoFileVersionStore {
  if (!fileVersionStore) {
    throw new AuthError('Logical file-version storage is not configured', 503);
  }
  return fileVersionStore;
}

async function putLogicalVersion(
  record: LogicalFileVersionRecord,
): Promise<LogicalFileVersionRecord> {
  return fileVersionStore ? fileVersionStore.putImmutable(record) : record;
}

async function findLogicalVersionByStorage(input: {
  orgId: string;
  vaultId: string;
  storageBucket: string;
  storageKey: string;
  storageVersionId: string;
}): Promise<LogicalFileVersionRecord | null> {
  return fileVersionStore
    ? fileVersionStore.findByStorageVersion(input)
    : null;
}

async function persistBoundFileVersion(
  draft: FileVersionDraft,
  input: {
    storageKey: string;
    storageVersionId?: string;
    storageEtag?: string | null;
  },
): Promise<LogicalFileVersionRecord> {
  const record = bindStorageVersion(draft, {
    storageBucket: S3_BUCKET,
    storageKey: input.storageKey,
    storageVersionId: input.storageVersionId ?? '',
    storageEtag: input.storageEtag,
  });
  return putLogicalVersion(record);
}

async function observeFileVersion(
  user: UserContext,
  vault: VaultRecord,
  filePath: string,
  observation: S3VersionObservation,
  options: {
    logicalRecord?: LogicalFileVersionRecord;
    state?: 'content' | 'tombstone';
    fallbackFileId?: string;
    fallbackFileVersionId?: string;
    parentFileVersionIds?: string[];
    actorIdentityId?: string;
  } = {},
): Promise<LogicalFileVersionRecord | null> {
  if (!observation.VersionId) return null;
  const storageKey = options.logicalRecord
    ? exactFileVersionStorageKey(options.logicalRecord, { orgId: user.orgId, vaultId: vault.vaultId }, S3_BUCKET, filePath)
    : vaultS3Prefix(user.orgId, vault.vaultId) + filePath;
  const metadataFileVersionId =
    observation.Metadata?.[FILE_VERSION_METADATA.fileVersionId];
  const existing = (storageKey !== vaultS3Prefix(user.orgId, vault.vaultId) + filePath ? options.logicalRecord : undefined) ?? (!fileVersionStore
    ? null
    : metadataFileVersionId
      ? await fileVersionStore.get(user.orgId, vault.vaultId, metadataFileVersionId)
      : await fileVersionStore.findByStorageVersion({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        storageBucket: S3_BUCKET,
        storageKey,
        storageVersionId: observation.VersionId,
      }));
  const storageObservation = {
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    storageBucket: S3_BUCKET,
    storageKey,
    storageVersionId: observation.VersionId,
    storageEtag: observation.ETag,
    contentType: observation.ContentType,
    ciphertextBytes:
      options.state === 'tombstone' ? 0 : (observation.ContentLength ?? 0),
    lastModified: observation.LastModified?.toISOString(),
    metadata: observation.Metadata,
    state: options.state,
    fallbackFileId: options.fallbackFileId,
    fallbackFileVersionId: options.fallbackFileVersionId,
    parentFileVersionIds: options.parentFileVersionIds,
    actorIdentityId: options.actorIdentityId,
  } as const;
  if (existing) {
    verifyStorageBinding(existing, storageObservation);
    return existing;
  }
  return putLogicalVersion(
    fileVersionFromStorageObservation(storageObservation),
  );
}

function readBoundedLogicalVersionId(
  value: string | undefined,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (
    value.trim().length === 0 ||
    value.length > 128 ||
    !/^fver_[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value) ||
    value.includes('..')
  ) {
    throw new AuthError(`${field} is invalid`, 400);
  }
  return value;
}

async function resolveReadVersion(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  filePath: string,
  view?: RevisionFileReadView,
): Promise<{
  storageVersionId?: string;
  logicalRecord?: LogicalFileVersionRecord;
  historical: boolean;
}> {
  const storageVersionId = event.queryStringParameters?.versionId;
  if (
    storageVersionId !== undefined &&
    (storageVersionId.trim().length === 0 ||
      storageVersionId.length > 1024 ||
      /[\r\n]/.test(storageVersionId))
  ) {
    throw new AuthError('versionId is invalid', 400);
  }
  const fileVersionId = readBoundedLogicalVersionId(
    event.queryStringParameters?.fileVersionId,
    'fileVersionId',
  );
  if (storageVersionId && fileVersionId) {
    throw new AuthError('Specify versionId or fileVersionId, not both', 400);
  }
  if (!fileVersionId) {
    if (!storageVersionId && view) {
      const record = await view.current(filePath);
      return { storageVersionId: record.storageVersionId, logicalRecord: record, historical: false };
    }
    return { storageVersionId, historical: Boolean(storageVersionId) };
  }
  const record = await requireLogicalVersionStore().require(
    user.orgId,
    vault.vaultId,
    fileVersionId,
  );
  if (record.path !== filePath || record.state !== 'content') {
    throw new FileVersionNotFoundError();
  }
  exactFileVersionStorageKey(record, { orgId: user.orgId, vaultId: vault.vaultId }, S3_BUCKET, filePath);
  return {
    storageVersionId: record.storageVersionId,
    logicalRecord: record,
    historical: true,
  };
}

function logicalVersionFields(record: LogicalFileVersionRecord | null | undefined) {
  if (!record) return {};
  return {
    fileId: record.fileId,
    fileVersionId: record.fileVersionId,
    plaintextSha256: record.plaintextSha256,
    ciphertextSha256: record.ciphertextSha256,
    integrity: record.integrity,
  };
}

function assertRequestedLogicalVersion(
  requested: LogicalFileVersionRecord | undefined | null,
  observed: LogicalFileVersionRecord | undefined | null,
): void {
  if (requested && (!observed || observed.fileVersionId !== requested.fileVersionId ||
    observed.fileId !== requested.fileId || observed.orgId !== requested.orgId || observed.vaultId !== requested.vaultId ||
    observed.path !== requested.path || observed.storageBucket !== requested.storageBucket || observed.storageKey !== requested.storageKey ||
    observed.storageVersionId !== requested.storageVersionId || observed.ciphertextBytes !== requested.ciphertextBytes ||
    observed.plaintextSha256 !== requested.plaintextSha256 || observed.ciphertextSha256 !== requested.ciphertextSha256)) {
    throw new FileVersionIntegrityError(
      'Requested logical version does not match the stored S3 version',
    );
  }
}

// ─── Types ───────────────────────────────────────────────────────────────────

/** File metadata returned in listings (never includes content). */
interface FileMetadata {
  path: string;
  size: number;
  lastModified: string;
  contentType: string;
  versionId: string;
  checksum: string;
  fileId?: string;
  fileVersionId?: string;
  plaintextSha256?: string | null;
  ciphertextSha256?: string | null;
}

/** A version history entry for a file. */
interface FileVersion {
  versionId: string;
  storageVersionId: string;
  fileId: string;
  fileVersionId: string;
  lastModified: string;
  size: number;
  isLatest: boolean;
  isDeleteMarker: boolean;
  plaintextSha256: string | null;
  ciphertextSha256: string | null;
  integrity: LogicalFileVersionRecord['integrity'];
  modifiedBy?: string;
}

/** Delta sync response item. */
interface SyncDelta {
  path: string;
  action: 'created' | 'modified' | 'deleted';
  lastModified: string;
  checksum: string;
  size: number;
  // BIN-A / D-04 (additive): the S3 object's ContentType, populated on WARM-path
  // deltas only (HeadObject already in hand). Old clients ignore it; cold-path
  // deltas omit it (ListObjectsV2 has no ContentType — L9), so clients treat it as
  // an optional hint and fall back to the authoritative GET-response contentType.
  contentType?: string;
}

interface VaultOverviewFileNode {
  type: 'file';
  name: string;
  path: string;
  size: number;
  lastModified: string;
}

interface VaultOverviewFolderNode {
  type: 'folder';
  name: string;
  path: string;
  fileCount: number;
  folderCount: number;
  totalSizeBytes: number;
  lastModified: string | null;
  children: VaultOverviewNode[];
}

type VaultOverviewNode = VaultOverviewFileNode | VaultOverviewFolderNode;

interface MutableVaultOverviewFolder {
  type: 'folder';
  name: string;
  path: string;
  fileCount: number;
  folderCount: number;
  totalSizeBytes: number;
  lastModified: string | null;
  children: Map<string, MutableVaultOverviewFolder | VaultOverviewFileNode>;
}

// ─── Main Handler ────────────────────────────────────────────────────────────

/**
 * Lambda entry point. Routes file operation requests based on
 * HTTP method and resource path.
 *
 * @param event - API Gateway proxy event
 * @returns API Gateway proxy result with JSON body
 */
export interface FilesCohortDependencies {
  readControl(scope: WorkspaceScope): Promise<WorkspaceCohortRoute>;
  /** Trusted composition loads and verifies the committed manifest through
   * WorkspaceRevisionService. The built-in adapter preserves file ACLs and
   * response contracts; unsupported inventory/sync surfaces fail closed. */
  readRevisionView?(scope: WorkspaceScope, route: WorkspaceCohortRoute): Promise<RevisionFileReadView>;
  /** Must preserve the path API's per-file permissions, response contract and
   * exact-version integrity checks. Membership is established before dispatch. */
  readRevision?(context: {
    event: APIGatewayProxyEvent; user: UserContext; vault: VaultRecord;
    requestId: string; route: WorkspaceCohortRoute;
  }): Promise<APIGatewayProxyResult>;
}

/** Dependency injection is trusted composition, never request-supplied routing. */
export function createFilesHandler(cohort: FilesCohortDependencies) {
  return (event: APIGatewayProxyEvent) => dispatchFiles(event, cohort);
}

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const tableName = process.env.WORKSPACE_COHORT_CONTROL_TABLE;
  // Default-off preserves existing deployments. A configured revision route
  // without its compatible adapter fails closed; it cannot fall through to S3.
  if (!tableName) return dispatchFiles(event);
  const readControl = (scope: WorkspaceScope) => new DynamoWorkspaceCohortControl({
      tableName, writerTableName: USER_KEYS_TABLE,
      send: command => docClient.send(command as Parameters<typeof docClient.send>[0]),
    }).read(scope);
  const cohort: FilesCohortDependencies = { readControl };
  const revisionTable = process.env.WORKSPACE_REVISIONS_TABLE;
  if (revisionTable && fileVersionStore) {
    cohort.readRevisionView = async (scope, route) => {
      const revisions = new WorkspaceRevisionService(
        new S3WorkspaceManifestStore({ bucket: S3_BUCKET, send: command => s3Client.send(command as Parameters<typeof s3Client.send>[0]) }),
        new DynamoWorkspaceRevisionRepository({ tableName: revisionTable, send: command => docClient.send(command as Parameters<typeof docClient.send>[0]) }),
        new DurableWorkspaceCohortRouter(scope, readControl).revisionGate(route),
      );
      const revision = await revisions.readCurrent(scope);
      if (!revision) throw new WorkspaceRoutingError('COHORT_CONTROL_UNAVAILABLE');
      return new RevisionFileReadView({ scope, bucket: S3_BUCKET, revision,
        requireVersion: (orgId, vaultId, id) => fileVersionStore.require(orgId, vaultId, id),
      });
    };
  }
  return dispatchFiles(event, cohort);
}

async function dispatchFiles(event: APIGatewayProxyEvent, cohort?: FilesCohortDependencies): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const resource = event.resource || '';

  try {
    // Authenticate all requests
    const user = await verifyActiveUser(event);

    // Enforce org membership — every file operation requires an org
    const orgId = requireOrgId(user);

    // Enforce org status (active, not suspended/cancelled)
    const orgCheck = await getActiveOrg(orgId);
    if (!orgCheck.allowed) {
      return formatError(403, orgCheck.reason || 'Organization access denied', requestId);
    }

    const vaultId = event.pathParameters?.vaultId || '';
    if (!vaultId) {
      return formatError(400, 'vaultId path parameter is required', requestId);
    }

    // Enforce vault membership. Reads only need viewer; writes/deletes need
    // editor — but we keep it permissive at the routing layer (viewer) and
    // let the per-action handlers + permission rules enforce the finer grain.
    const vault = await requireVaultMember(user, vaultId, 'viewer');

    // API Gateway greedy path resource is `/vaults/{vaultId}/files/{path+}`.
    const isFilePathResource =
      resource === '/vaults/{vaultId}/files/{path+}' ||
      resource === '/vaults/{vaultId}/files/{filePath+}';
    const actualPath = event.path || '';
    // Action suffixes (history/restore/restore-delete/direct transfer) ride the greedy
    // {path+} resource — API Gateway cannot define child resources under a
    // greedy segment — so they must be recognized from the path. But a bare
    // `endsWith` over the whole path shadows FILES whose name is an action
    // word (an extensionless root note called "history"/"overview"). The
    // plugin sends the file path as ONE percent-encoded segment, so in the
    // RAW event.path an action call always carries ≥2 segments after
    // `/files/` (encoded file + literal action) while a plain file read has
    // exactly one. Dispatch actions only on that ≥2-segment shape.
    const rawPathSegments = actualPath.replace(/\/+$/, '').split('/').filter(Boolean);
    const rawFilesIndex = rawPathSegments.indexOf('files');
    const rawFileSegments = rawFilesIndex >= 0 ? rawPathSegments.slice(rawFilesIndex + 1) : [];
    const rawActionSegment =
      rawFileSegments.length >= 2 ? rawFileSegments[rawFileSegments.length - 1] : '';
    const isRootDeletedFilePath = rawFileSegments.length === 1 && rawFileSegments[0] === 'deleted';
    const isDeletedStaticResource = resource === '/vaults/{vaultId}/files/deleted';
    const isDeletedRouteResource =
      isDeletedStaticResource || (isFilePathResource && isRootDeletedFilePath);
    const requestedFileOperation = (event.queryStringParameters?.operation || '').toLowerCase();
    const deletedFileEvent = isDeletedRouteResource
      ? eventWithFilePathParameter(event, 'deleted')
      : event;
    const isHistoryResource = isFilePathResource && rawActionSegment === 'history';
    const isDirectUploadIssueResource =
      isFilePathResource &&
      rawFileSegments.length >= 2 &&
      rawActionSegment === 'direct-upload';
    const isDirectUploadFinalizeResource =
      isFilePathResource &&
      rawFileSegments.length >= 4 &&
      rawFileSegments[rawFileSegments.length - 3] === 'direct-upload' &&
      rawActionSegment === 'finalize';
    const isDirectDownloadIssueResource =
      isFilePathResource &&
      rawFileSegments.length >= 2 &&
      rawActionSegment === 'direct-download';
    // The dispatch order below ensures the restore arms win over the generic
    // read/write/delete arms for the same resource string, and restore-delete
    // is matched by exact segment so it can never fall into the `restore` arm.
    const isRestoreDeleteResource = isFilePathResource && rawActionSegment === 'restore-delete';
    const isRestoreVersionResource = isFilePathResource && rawActionSegment === 'restore';
    // `/vaults/{vaultId}/overview` is its own resource; the path fallback (for
    // deployments routing it differently) must match the EXACT 3-segment shape,
    // not a suffix — `/files/overview` is a file named "overview".
    const isOverviewResource =
      resource === '/vaults/{vaultId}/overview' ||
      (rawPathSegments.length === 3 &&
        rawPathSegments[0] === 'vaults' &&
        rawPathSegments[2] === 'overview');
    // Static sibling of `{filePath+}` — `GET /vaults/{vaultId}/files/deleted`
    // remains the deleted-files listing for backward compatibility. A root file
    // literally named "deleted" is read through the explicit query operation
    // `?operation=read`; PUT/DELETE on the static resource are routed back to
    // the normal file handlers below.
    const isDeletedListResource =
      isDeletedRouteResource && requestedFileOperation !== 'read';
    const isDeletedFileReadResource =
      isDeletedRouteResource && requestedFileOperation === 'read';

    const pathApi = async (view?: RevisionFileReadView): Promise<APIGatewayProxyResult> => {
    if (view) {
      view.assertScope({ orgId, vaultId }, S3_BUCKET);
      const supported = (method === 'GET' && (resource === '/vaults/{vaultId}/files' ||
        isDeletedFileReadResource || isReadDecryptedResource(resource) ||
        (isFilePathResource && !isHistoryResource && !isDeletedListResource))) ||
        (method === 'POST' && isDirectDownloadIssueResource);
      // History, deleted lists, overview and sync need the full migration capture
      // and legacy cursor binding. Never answer those using a mutable fallback.
      if (!supported || isOverviewResource) throw new WorkspaceRoutingError('COHORT_CONTROL_UNAVAILABLE');
    }
    switch (true) {
      case method === 'GET' && resource === '/vaults/{vaultId}/files':
        return await handleListFiles(event, user, vault, requestId, view);

      case method === 'GET' && isOverviewResource:
        return await handleVaultOverview(event, user, vault, requestId);

      case method === 'GET' && isDeletedFileReadResource:
        return await handleReadFile(deletedFileEvent, user, vault, requestId, view);

      case method === 'GET' && isDeletedListResource:
        return await handleListDeleted(event, user, vault, requestId);

      case method === 'POST' && isRestoreDeleteResource:
        return await handleRestoreDelete(event, user, vault, requestId);

      case method === 'POST' && isRestoreVersionResource:
        return await handleRestoreVersion(event, user, vault, requestId);

      case method === 'POST' && isDirectUploadFinalizeResource:
        return await handleFinalizeDirectUpload(event, user, vault, requestId);

      case method === 'POST' && isDirectUploadIssueResource:
        return await handleIssueDirectUpload(event, user, vault, requestId);

      case method === 'POST' && isDirectDownloadIssueResource:
        return await handleIssueDirectDownload(event, user, vault, requestId, view);

      case method === 'GET' && isHistoryResource:
        return await handleGetHistory(event, user, vault, requestId);

      case method === 'GET' && isReadDecryptedResource(resource):
        return await handleReadDecrypted(event, user, vault, requestId, view);

      case method === 'GET' && isFilePathResource:
        return await handleReadFile(event, user, vault, requestId, view);

      case method === 'PUT' && isDeletedStaticResource:
        return await handleWriteFile(deletedFileEvent, user, vault, requestId);

      case method === 'PUT' && isFilePathResource:
        return await handleWriteFile(event, user, vault, requestId);

      case method === 'DELETE' && isDeletedStaticResource:
        return await handleDeleteFile(deletedFileEvent, user, vault, requestId);

      case method === 'DELETE' && isFilePathResource:
        return await handleDeleteFile(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/files/sync':
        return await handleSync(event, user, vault, requestId);

      case method === 'GET' && resource === '/vaults/{vaultId}/sync-cursor':
        return await handleSyncCursorGet(event, user, vault, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
    };
    if (method === 'GET' && resource === '/vaults/{vaultId}/sync-cursor') {
      const router = cohort ? new DurableWorkspaceCohortRouter({ orgId, vaultId }, scope => cohort.readControl(scope)) : null;
      const route = router ? await router.snapshot() : null;
      const mode = route?.mode === 'revision-read' ? 'workspace' : route?.mode === 'paused' ? 'paused' : 'legacy';
      const syncCompatibility = { mode, contractVersion: mode === 'workspace' ? 'vaultguard-sync-v2' : null,
        endpoint: mode === 'workspace' ? `/vaults/${encodeURIComponent(vaultId)}/workspace/sync` : null };
      // An activity counter from the old path owner is not a revision checkpoint.
      // No legacy reconciliation or content write is attempted in workspace mode.
      const result = mode === 'legacy' ? await handleSyncCursorGet(event, user, vault, requestId) :
        formatSuccess(200, { revision: null, lastChangedAt: null, reconciliationRequired: false, serverTime: new Date().toISOString() }, requestId);
      if (router && JSON.stringify(await router.snapshot()) !== JSON.stringify(route)) throw new WorkspaceRoutingError('COHORT_CHANGED');
      return { ...result, body: JSON.stringify({ ...JSON.parse(result.body), syncCompatibility }) };
    }
    if (!cohort) return await pathApi();
    const router = new DurableWorkspaceCohortRouter({ orgId, vaultId }, scope => cohort.readControl(scope));
    // Sync and signed exact downloads are reads despite their POST method.
    const read = method === 'GET' || (method === 'POST' &&
      (resource === '/vaults/{vaultId}/files/sync' || isDirectDownloadIssueResource));
    if (!read) return await router.write(pathApi);
    return await router.read(pathApi, async route => {
      if (cohort.readRevisionView) {
        const bound = await bindFileAuthorizationGenerations(user, vault);
        const result = await pathApi(await cohort.readRevisionView({ orgId, vaultId }, route));
        // A slow immutable lookup must not disclose metadata, bytes or a signed
        // URL after session revocation or a membership/policy change. Per-file
        // ACLs run inside the existing handlers; their generations are bound here.
        try {
          await revalidateAuthorizationBeforeEgress(bound, async () => {
            const currentUser = await verifyActiveUser(event);
            const pending = await listPendingVaultMutationIntents(vaultId, 100, { requireComplete: true });
            if (pending.some(intent => intent.authorizationGenerations?.some(kind => kind === 'membership' || kind === 'permission'))) throw new Error();
            const currentVault = await requireVaultMember(currentUser, vaultId, 'viewer');
            return bindFileAuthorizationGenerations(currentUser, currentVault);
          });
        } catch {
          throw new AuthError('File access changed during the request', isReadDecryptedResource(resource) ? 404 : 403);
        }
        return result;
      }
      if (!cohort.readRevision) throw new WorkspaceRoutingError('COHORT_CONTROL_UNAVAILABLE');
      return cohort.readRevision({ event, user, vault, requestId, route });
    });
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'statusCode' in err) {
      const typed = err as { statusCode: number; message: string; code?: string };
      return formatError(typed.statusCode, typed.message, requestId, typed.code);
    }

    console.error('[FILES_HANDLER_ERROR]', (err as Error).message);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── GET /vaults/{vaultId}/overview ───────────────────────────────────────────

/**
 * Builds a vault-level, metadata-only overview for admins. This endpoint never
 * reads S3 object bodies and intentionally omits content, key material,
 * checksums, ETags, and version IDs. File and folder names are still metadata,
 * so access is restricted to vault admins or org admins.
 */
async function handleVaultOverview(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Tighten this route beyond the handler-level viewer gate without using the
  // write-oriented archived-vault guard in requireVaultMember(..., 'admin').
  await requireVaultOverviewAdmin(user, vault);

  // Per-file rules bind here exactly as on every other file route. A vault
  // admin who is not an org admin is always subject to deny rules, and an org
  // admin is subject to them when `allowAdminPerFileRestrictions` is on. Only
  // an org admin under the default bypass skips the per-row evaluation, which
  // keeps the common case at one S3 round-trip per page.
  const permissionOptions = await fileOpPermissionOptions(user, vault);
  const callerBypassesFileRules = permissionOptions.respectAdminBypass && isAdmin(user);
  const permRoles = callerBypassesFileRules ? null : await resolveFileOpRoles(user, vault);
  const canSeeOverviewPath = async (relativePath: string): Promise<boolean> => {
    if (permRoles === null) return true;
    const perm = await evaluatePermission(
      user.userId,
      permRoles,
      'list',
      '/' + relativePath.replace(/^\/+/, ''),
      user.orgId,
      vault.vaultId,
      permissionOptions
    );
    return perm.allowed;
  };

  const limit = parseOverviewLimit(event.queryStringParameters?.limit);
  let continuationToken = event.queryStringParameters?.continuationToken || undefined;
  const root = createOverviewFolder('', '/');
  const extensionStats = new Map<string, { extension: string; count: number; totalSizeBytes: number }>();
  const largestFiles: VaultOverviewFileNode[] = [];
  let fileCount = 0;
  let totalSizeBytes = 0;
  let maxDepth = 0;
  let latestModified: string | null = null;
  let responseWasTruncated = false;

  do {
    const page = await s3Client.send(
      new ListObjectsV2Command({
        Bucket: S3_BUCKET,
        Prefix: vaultS3Prefix(user.orgId, vault.vaultId),
        MaxKeys: Math.min(1000, limit - fileCount),
        ContinuationToken: continuationToken,
      })
    );

    for (const obj of page.Contents || []) {
      if (fileCount >= limit) {
        responseWasTruncated = true;
        break;
      }

      const key = obj.Key || '';
      const relativePath = key.replace(vaultS3Prefix(user.orgId, vault.vaultId), '');
      if (!relativePath || relativePath.endsWith('/')) continue;
      if (isClientLocalOnlyPath(relativePath)) continue;

      const lastModified = obj.LastModified?.toISOString() || '';

      // Folder markers exist purely so empty folders survive the round-trip.
      // They register the folder in the tree but never contribute to the
      // file count, storage total, file-type stats, or "largest files" list.
      if (isFolderMarkerPath(relativePath)) {
        const folderPath = folderPathFromMarker(relativePath);
        // Probe with a synthetic child so glob inheritance (`/secret/**`)
        // hides the folder the same way it hides the files inside it.
        if (folderPath && !(await canSeeOverviewPath(`${folderPath}/__vaultguard_marker_probe__`))) continue;
        ensureOverviewFolder(root, folderPath, lastModified);
        latestModified = maxIsoTimestamp(latestModified, lastModified);
        const folderDepth = folderPath.split('/').filter(Boolean).length;
        maxDepth = Math.max(maxDepth, folderDepth);
        continue;
      }

      if (!(await canSeeOverviewPath(relativePath))) continue;

      const normalizedPath = `/${relativePath.replace(/^\/+/, '')}`;
      const size = obj.Size || 0;
      const fileNode: VaultOverviewFileNode = {
        type: 'file',
        name: normalizedPath.split('/').filter(Boolean).pop() || normalizedPath,
        path: normalizedPath,
        size,
        lastModified,
      };

      addFileToOverview(root, fileNode);
      addExtensionStat(extensionStats, normalizedPath, size);
      addLargestFile(largestFiles, fileNode);

      fileCount += 1;
      totalSizeBytes += size;
      maxDepth = Math.max(maxDepth, normalizedPath.split('/').filter(Boolean).length);
      latestModified = maxIsoTimestamp(latestModified, lastModified);
    }

    if (responseWasTruncated) break;
    continuationToken = page.NextContinuationToken || undefined;
  } while (continuationToken && fileCount < limit);

  if (continuationToken && fileCount >= limit) {
    responseWasTruncated = true;
  }

  const tree = finalizeOverviewFolder(root);
  const extensions = [...extensionStats.values()].sort((a, b) =>
    b.count - a.count || a.extension.localeCompare(b.extension)
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'vault.overview',
    resourcePath: `/vaults/${vault.vaultId}/overview`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      vaultId: vault.vaultId,
      fileCount,
      folderCount: tree.folderCount,
      totalSizeBytes,
      limit,
      truncated: responseWasTruncated,
    },
  });

  return formatSuccess(
    200,
    {
      vaultId: vault.vaultId,
      generatedAt: new Date().toISOString(),
      metadataOnly: true,
      fileCount,
      folderCount: tree.folderCount,
      totalSizeBytes,
      maxDepth,
      latestModified,
      extensions,
      largestFiles,
      tree,
      limit,
      isTruncated: responseWasTruncated,
      nextContinuationToken: responseWasTruncated ? continuationToken || null : null,
    },
    requestId
  );
}

async function requireVaultOverviewAdmin(user: UserContext, vault: VaultRecord): Promise<void> {
  if (isAdmin(user)) return;

  const membership = await getVaultMembership(vault.vaultId, user.userId);
  if (!membership || !vaultRoleMeetsRequirement(membership.role, 'admin')) {
    throw new AuthError('Vault admin required to inspect vault metadata.', 403);
  }
}

/**
 * LF1: the role namespace for per-file permission evaluation. Role-scoped rules
 * (e.g. {role:'editor', deny, read, /secret/**}) are authored and previewed
 * against the caller's VAULT membership role — that's what /permissions and the
 * admin panel evaluate. File ops used to pass user.roles (the org/Cognito
 * roles), so a role-scoped deny the UI showed as binding was silently NOT
 * enforced on reads/sync. Mirror resolvePermissionRolesForTarget: an org
 * admin/owner keeps their org roles (implicit admin bypass); a vault member
 * evaluates with their vault role alone. Compute ONCE per request (hoisted out
 * of the sync loops) — never fold the vault role into user.roles, since a vault
 * 'admin' would otherwise be misread as an ORG admin by rolesIncludeOrgAdmin.
 */
async function resolveFileOpRoles(user: UserContext, vault: VaultRecord): Promise<string[]> {
  // Twin of shared/utils `resolveVaultEvaluationRoles` (used by the auth
  // key-lease handler). Keep the two in sync — both must evaluate a
  // non-org-admin member on [membership.role], never user.roles.
  if (isAdmin(user)) return user.roles;
  const membership = await getVaultMembership(vault.vaultId, user.userId);
  if (membership) return [membership.role];
  return user.roles;
}

function parseOverviewLimit(rawLimit: string | undefined): number {
  if (!rawLimit) return DEFAULT_OVERVIEW_LIMIT;
  const parsed = Number.parseInt(rawLimit, 10);
  if (!Number.isInteger(parsed) || parsed < 1) return DEFAULT_OVERVIEW_LIMIT;
  return Math.min(parsed, MAX_OVERVIEW_LIMIT);
}

function parseFileListLimit(rawLimit: string | undefined): number {
  if (rawLimit === undefined || rawLimit === '') return 100;
  const normalized = rawLimit.trim();
  if (!/^\d+$/u.test(normalized)) return 100;
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed)) return 100;
  return Math.max(1, Math.min(parsed, 1000));
}

function normalizeFileListPrefix(rawPrefix: string | undefined): string {
  return (rawPrefix ?? '').replace(/^\/+/, '');
}

function createOverviewFolder(name: string, path: string): MutableVaultOverviewFolder {
  return {
    type: 'folder',
    name,
    path,
    fileCount: 0,
    folderCount: 0,
    totalSizeBytes: 0,
    lastModified: null,
    children: new Map(),
  };
}

function addFileToOverview(root: MutableVaultOverviewFolder, file: VaultOverviewFileNode): void {
  const segments = file.path.split('/').filter(Boolean);
  let current = root;
  const ancestors: MutableVaultOverviewFolder[] = [root];

  for (const folderName of segments.slice(0, -1)) {
    const folderPath = `${current.path === '/' ? '' : current.path}/${folderName}`;
    let child = current.children.get(folderName);
    if (!child || child.type !== 'folder') {
      child = createOverviewFolder(folderName, folderPath);
      current.children.set(folderName, child);
    }
    current = child;
    ancestors.push(current);
  }

  current.children.set(file.name, file);

  for (const folder of ancestors) {
    folder.fileCount += 1;
    folder.totalSizeBytes += file.size;
    folder.lastModified = maxIsoTimestamp(folder.lastModified, file.lastModified);
  }
}

/**
 * Walks the folder hierarchy implied by `folderPath` (slash-separated, no
 * leading slash) and ensures every segment exists in the overview tree.
 * Used for folder-marker objects so empty folders still appear in the tree
 * without contributing a file to fileCount/totalSizeBytes/etc.
 */
function ensureOverviewFolder(
  root: MutableVaultOverviewFolder,
  folderPath: string,
  lastModified: string
): void {
  const segments = folderPath.split('/').filter(Boolean);
  if (segments.length === 0) return;

  let current = root;
  for (const folderName of segments) {
    const childPath = `${current.path === '/' ? '' : current.path}/${folderName}`;
    let child = current.children.get(folderName);
    if (!child || child.type !== 'folder') {
      child = createOverviewFolder(folderName, childPath);
      current.children.set(folderName, child);
    }
    current = child;
    current.lastModified = maxIsoTimestamp(current.lastModified, lastModified);
  }
}

function addExtensionStat(
  stats: Map<string, { extension: string; count: number; totalSizeBytes: number }>,
  filePath: string,
  size: number
): void {
  const fileName = filePath.split('/').pop() || '';
  const dotIndex = fileName.lastIndexOf('.');
  const extension = dotIndex > 0 && dotIndex < fileName.length - 1
    ? fileName.slice(dotIndex + 1).toLowerCase()
    : '(none)';
  const current = stats.get(extension) || { extension, count: 0, totalSizeBytes: 0 };
  current.count += 1;
  current.totalSizeBytes += size;
  stats.set(extension, current);
}

function addLargestFile(largestFiles: VaultOverviewFileNode[], file: VaultOverviewFileNode): void {
  largestFiles.push(file);
  largestFiles.sort((a, b) => b.size - a.size || a.path.localeCompare(b.path));
  if (largestFiles.length > 10) largestFiles.length = 10;
}

function finalizeOverviewFolder(folder: MutableVaultOverviewFolder): VaultOverviewFolderNode {
  const finalizedChildren = [...folder.children.values()]
    .map((child) => child.type === 'folder' ? finalizeOverviewFolder(child) : child)
    .sort((a, b) => {
      if (a.type !== b.type) return a.type === 'folder' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

  const folderCount = finalizedChildren.reduce(
    (count, child) => count + (child.type === 'folder' ? 1 + child.folderCount : 0),
    0
  );

  return {
    type: 'folder',
    name: folder.name,
    path: folder.path,
    fileCount: folder.fileCount,
    folderCount,
    totalSizeBytes: folder.totalSizeBytes,
    lastModified: folder.lastModified,
    children: finalizedChildren,
  };
}

function maxIsoTimestamp(current: string | null, next: string): string | null {
  if (!next) return current;
  if (!current) return next;
  return next > current ? next : current;
}

// ─── GET /files ──────────────────────────────────────────────────────────────

/**
 * Lists all files the authenticated user has permission to see.
 * Returns only metadata (path, size, lastModified) — never file content.
 *
 * Query Parameters:
 * - prefix: Optional path prefix filter (e.g., '/engineering/')
 * - limit: Maximum number of results (default 100, max 1000)
 * - continuationToken: For pagination
 *
 * @param event - API Gateway event with optional query params
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns Array of FileMetadata objects the user can access
 */
async function handleListFiles(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string,
  view?: RevisionFileReadView,
): Promise<APIGatewayProxyResult> {
  const prefix = normalizeFileListPrefix(event.queryStringParameters?.prefix);
  const limit = parseFileListLimit(event.queryStringParameters?.limit);
  const continuationToken = event.queryStringParameters?.continuationToken;

  // Resolve request-scoped authorization inputs once. Rebuilding membership
  // roles and org policy for every S3 row is both wasteful and risks applying
  // a different policy snapshot within one page.
  const permRoles = await resolveFileOpRoles(user, vault);
  const permissionOptions = await fileOpPermissionOptions(user, vault);

  // One API cursor always maps to one complete S3 page. Asking S3 for more
  // than `limit` and breaking after enough authorized rows skips the
  // unprocessed tail because NextContinuationToken points past that tail.
  const revisionPage = view?.page(prefix, limit, continuationToken);
  const s3Response = revisionPage ? {
    Contents: revisionPage.paths.map(path => ({ Key: vaultS3Prefix(user.orgId, vault.vaultId) + path, Size: 0, LastModified: undefined as Date | undefined, ETag: '' })),
    NextContinuationToken: revisionPage.nextContinuationToken,
    IsTruncated: revisionPage.isTruncated,
  } : await s3Client.send(
    new ListObjectsV2Command({
      Bucket: S3_BUCKET,
      Prefix: vaultS3Prefix(user.orgId, vault.vaultId) + prefix,
      MaxKeys: limit,
      ContinuationToken: continuationToken || undefined,
    })
  );

  const files: FileMetadata[] = [];

  for (const obj of s3Response.Contents || []) {
    const relativePath = obj.Key!.replace(vaultS3Prefix(user.orgId, vault.vaultId), '');

    // Folder markers are an internal mechanism for preserving empty folders;
    // never expose them to file-listing consumers.
    if (isFolderMarkerPath(relativePath)) continue;
    if (isClientLocalOnlyPath(relativePath)) continue;

    // Check if user has 'list' or 'read' permission for this path
    const permResult = await evaluatePermission(
      user.userId,
      permRoles,
      'list',
      '/' + relativePath,
      user.orgId,
      vault.vaultId,
      permissionOptions
    );

    if (permResult.allowed) {
      // Content-derived fields (plaintextSha256 / ciphertextSha256 / version
      // ids) are only disclosed to callers who may READ the row. `list` and
      // `read` are independent actions, so a `deny read` + `allow list` rule
      // must still hide a digest of the denied content: SHA-256 of a short or
      // predictable note is dictionary-reversible offline.
      const readResult = await evaluatePermission(
        user.userId,
        permRoles,
        'read',
        '/' + relativePath,
        user.orgId,
        vault.vaultId,
        permissionOptions
      );
      // Resolve only authorized rows. Read exact object metadata: a logical
      // draft's createdAt can precede S3 LastModified and is not interchangeable
      // with the path API timestamp. A newer head cannot replace this version.
      const pinned = view ? await view.current(relativePath) : undefined;
      const head = await headObjectOrNull({
        Key: pinned?.storageKey ?? vaultS3Prefix(user.orgId, vault.vaultId) + relativePath,
        ...(pinned ? { VersionId: pinned.storageVersionId } : {}),
      });
      if (view && !head) throw new FileVersionNotFoundError();
      const logicalVersion = head
        ? await observeFileVersion(user, vault, relativePath, head, { logicalRecord: pinned })
        : null;
      assertRequestedLogicalVersion(pinned, logicalVersion);
      files.push({
        path: '/' + relativePath,
        size: view ? head?.ContentLength ?? 0 : obj.Size || 0,
        lastModified: (view ? head?.LastModified : obj.LastModified)?.toISOString() || '',
        contentType: head?.ContentType || 'application/octet-stream',
        versionId: head?.VersionId || '',
        checksum: (view ? head?.ETag : obj.ETag) || '',
        ...(readResult.allowed ? logicalVersionFields(logicalVersion) : {}),
      });
    }
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.list',
    resourcePath: prefix ? `/${prefix}` : '/',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      resultCount: files.length,
      prefix,
      workspaceRevisionId: view?.workspaceRevisionId ?? null,
    },
  });

  return formatSuccess(
    200,
    {
      files,
      count: files.length,
      nextContinuationToken: s3Response.NextContinuationToken || null,
      isTruncated: s3Response.IsTruncated || false,
    },
    requestId
  );
}

// ─── GET /vaults/{vaultId}/files/{path} ─────────────────────────────────────

/**
 * Reads a single file's content from S3 after verifying the user has
 * 'read' permission for the path.
 *
 * @param event - API Gateway event with path parameter
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns File content encoded as base64 with metadata
 */
async function handleReadFile(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string,
  view?: RevisionFileReadView,
): Promise<APIGatewayProxyResult> {
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(404, `File not found: ${filePath}`, requestId);
  }

  // Permission check
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(user.userId, permRoles, 'read', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.read.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { matchedRule: permResult.matchedRule?.id },
    });
    return formatError(403, 'Access denied: insufficient permissions to read this file', requestId);
  }

  const requestedVersion = await resolveReadVersion(event, user, vault, filePath, view);

  // Fetch from S3
  try {
    const s3Response = await s3Client.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET,
        Key: requestedVersion.logicalRecord?.storageKey ?? vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        ...(requestedVersion.storageVersionId
          ? { VersionId: requestedVersion.storageVersionId }
          : {}),
      })
    );

    const bodyBytes = await s3Response.Body?.transformToByteArray();
    const encryptedBody = bodyBytes ? Buffer.from(bodyBytes) : Buffer.alloc(0);
    const responseBody = encryptedBody;
    const logicalVersion = await observeFileVersion(user, vault, filePath, s3Response, { logicalRecord: requestedVersion.logicalRecord });
    assertRequestedLogicalVersion(requestedVersion.logicalRecord, logicalVersion);
    if (logicalVersion) {
      verifyCiphertextIntegrity(logicalVersion, encryptedBody, s3Response.Metadata);
    }

    const content = responseBody.toString('base64');

    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.read',
      resourcePath: '/' + filePath,
      outcome: 'success',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        size: s3Response.ContentLength,
        versionId: s3Response.VersionId,
        fileVersionId: logicalVersion?.fileVersionId,
        workspaceRevisionId: view?.workspaceRevisionId ?? null,
      },
    });
    // SD-09-F1: FileAccessCount backs the data-exfil alarm (Sum > 500 / 5min).
    // Fire-and-forget (void) — this is the hot read path; do not add
    // PutMetricData latency to the response.
    void emitSecurityMetric('FileAccessCount');

    return formatSuccess(
      200,
      {
        path: '/' + filePath,
        content,
        encoding: 'base64',
        contentType: s3Response.ContentType || 'application/octet-stream',
        size: s3Response.ContentLength,
        lastModified: s3Response.LastModified?.toISOString(),
        versionId: s3Response.VersionId,
        checksum: s3Response.ETag,
        historical: requestedVersion.historical,
        ...logicalVersionFields(logicalVersion),
      },
      requestId
    );
  } catch (err: unknown) {
    if (
      err &&
      typeof err === 'object' &&
      'name' in err &&
      ['NoSuchKey', 'NoSuchVersion', 'NotFound', 'MethodNotAllowed'].includes(
        (err as { name: string }).name,
      )
    ) {
      return formatError(404, `File not found: ${filePath}`, requestId);
    }
    throw err;
  }
}

// ─── GET /vaults/{vaultId}/files-decrypted/{path} ──────────────────────────

/**
 * Phase 8 (Plan 08-01): per-file server-side decrypt endpoint.
 *
 * Routed via `isReadDecryptedResource(resource)` in the top-level handler
 * dispatch. Sibling resource of `GET /vaults/{vaultId}/files/{path+}` used by
 * limited-access clients (users with any read-deny rule) who cannot receive a
 * vault-wide `/**` key lease but can still read individually permitted files.
 *
 * Trust pattern mirrors `handleResolveShare` (`infrastructure/lambda/shares/handler.ts`):
 *   1. `requireVaultMember(user, vaultId, 'viewer')` already ran at top-level dispatch.
 *   2. Per-file `evaluatePermission('read', '/' + relPath)` runs before any KMS/S3 work.
 *   3. Any deny path returns 404 (NOT 403) so token can't probe for existence (D-02).
 *   4. NoSuchKey from S3 also returns 404, indistinguishable from a permission deny.
 *   5. Success and deny each emit a distinct audit action so admins can spot probing.
 *
 * Plaintext bytes are zeroed in a `finally` after the base64 encode; the scope DEK is
 * zeroed inside `decryptCurrentVaultBlobForRead` (T-08-02, T-08-06).
 */
async function handleReadDecrypted(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string,
  view?: RevisionFileReadView,
): Promise<APIGatewayProxyResult> {
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  if (!filePath || isClientLocalOnlyPath(filePath)) {
    // 404 (not 403/400) — see D-02. Plugin-internal paths must never be served
    // through this endpoint.
    return formatError(404, 'File not found', requestId);
  }

  const requestedVersionId = event.queryStringParameters?.versionId;
  if (
    requestedVersionId !== undefined &&
    (typeof requestedVersionId !== 'string' ||
      requestedVersionId.trim().length === 0 ||
      requestedVersionId.length > 1024 ||
      /[\r\n]/.test(requestedVersionId))
  ) {
    return formatError(400, 'versionId is invalid', requestId);
  }

  // Per-file permission gate — 404 on deny (D-02). Audit BEFORE returning per T-08-05.
  // LF1: evaluate with the vault-membership role (resolveFileOpRoles), NOT
  // user.roles — this decrypt endpoint returns plaintext, so a role-scoped
  // read-deny evaluated against user.roles would silently be un-enforced and
  // leak the denied file's cleartext.
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(
    user.userId,
    permRoles,
    'read',
    '/' + filePath,
    user.orgId,
    vault.vaultId,
    await fileOpPermissionOptions(user, vault)
  );
  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.readDecrypted.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { matchedRule: permResult.matchedRule?.id ?? null },
    });
    return formatError(404, 'File not found', requestId);
  }
  const authorizationBinding = await bindFileAuthorizationGenerations(user, vault);

  const requestedVersion = await resolveReadVersion(event, user, vault, filePath, view);

  // Fetch ciphertext from S3.
  let s3Response;
  try {
    s3Response = await s3Client.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET,
        Key: requestedVersion.logicalRecord?.storageKey ?? vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        ...(requestedVersion.storageVersionId
          ? { VersionId: requestedVersion.storageVersionId }
          : {}),
      })
    );
  } catch (err: unknown) {
    const errorName = err && typeof err === 'object' && 'name' in err
      ? String((err as { name: unknown }).name)
      : '';
    const statusCode = err && typeof err === 'object' && '$metadata' in err
      ? (err as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode
      : undefined;
    if (
      errorName === 'NoSuchKey' ||
      errorName === 'NoSuchVersion' ||
      errorName === 'NotFound' ||
      errorName === 'MethodNotAllowed' ||
      statusCode === 404 ||
      statusCode === 405
    ) {
      // Indistinguishable from permission deny per D-02.
      return formatError(404, 'File not found', requestId);
    }
    throw err;
  }

  const bodyBytes = await s3Response.Body?.transformToByteArray();
  const ciphertext = bodyBytes ? Buffer.from(bodyBytes) : Buffer.alloc(0);
  const logicalVersion = await observeFileVersion(user, vault, filePath, s3Response, { logicalRecord: requestedVersion.logicalRecord });
  assertRequestedLogicalVersion(requestedVersion.logicalRecord, logicalVersion);
  if (logicalVersion) {
    verifyCiphertextIntegrity(logicalVersion, ciphertext, s3Response.Metadata);
  }

  // Reuse the existing scope-DEK unwrap helper (Phase 6/7 plumbing) — KMS Decrypt
  // with EncryptionContext is the tampering defense (T-08-03). Helper zeros the
  // DEK in its own finally; we zero the plaintext buffer below (T-08-06).
  // A revision's current file is still an exact stored version and can use a
  // historical cloud key. Keep its public historical flag false for compatibility.
  const { plaintext, keyId } = requestedVersion.storageVersionId
    ? await decryptExactVaultVersion(ciphertext, s3Response.Metadata, {
        orgId: user.orgId,
        vaultId: vault.vaultId,
      })
    : await decryptCurrentVaultBlobForRead(ciphertext, {
        orgId: user.orgId,
        vaultId: vault.vaultId,
      }, s3Response.Metadata);

  let content: string;
  try {
    await revalidateFileAuthorization(
      authorizationBinding,
      user,
      vault.vaultId,
      filePath,
      'read',
      'viewer',
      404,
      'File not found',
      event,
    );
    if (logicalVersion) verifyPlaintextIntegrity(logicalVersion, plaintext);
    content = plaintext.toString('base64');
  } finally {
    plaintext.fill(0);
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.readDecrypted',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      size: s3Response.ContentLength,
      versionId: s3Response.VersionId,
      fileVersionId: logicalVersion?.fileVersionId,
      keyId,
      historical: requestedVersion.historical,
      workspaceRevisionId: view?.workspaceRevisionId ?? null,
    },
  });
  // SD-09-F1: FileAccessCount (server-side decrypt read path). Fire-and-forget
  // (void) — hot path, no added response latency.
  void emitSecurityMetric('FileAccessCount');

  return formatSuccess(
    200,
    {
      path: '/' + filePath,
      content,
      encoding: 'base64',
      decrypted: true,
      encrypted: false,
      contentType: s3Response.ContentType || 'application/octet-stream',
      size: s3Response.ContentLength,
      lastModified: s3Response.LastModified?.toISOString(),
      versionId: s3Response.VersionId,
      historical: requestedVersion.historical,
      ...logicalVersionFields(logicalVersion),
    },
    requestId
  );
}

// ─── Direct encrypted transfer ───────────────────────────────────────────────

function isS3MissingError(error: unknown): boolean {
  const name = error && typeof error === 'object' && 'name' in error
    ? String((error as { name: unknown }).name)
    : '';
  return name === 'NotFound' || name === 'NoSuchKey' || name === 'NoSuchVersion';
}

async function headObjectOrNull(input: {
  Key: string;
  VersionId?: string;
  includeChecksum?: boolean;
}) {
  try {
    return await s3Client.send(
      new HeadObjectCommand({
        Bucket: S3_BUCKET,
        Key: input.Key,
        ...(input.VersionId ? { VersionId: input.VersionId } : {}),
        ...(input.includeChecksum ? { ChecksumMode: 'ENABLED' as const } : {}),
      })
    );
  } catch (error) {
    if (isS3MissingError(error)) return null;
    throw error;
  }
}

function directActionPath(event: APIGatewayProxyEvent, suffix: string): string {
  const raw = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  if (!raw.endsWith(suffix)) throw new AuthError('Invalid direct-transfer route', 404);
  const filePath = sanitizeFilePath(raw.slice(0, -suffix.length));
  if (!filePath) throw new AuthError('Missing file path', 400);
  if (isClientLocalOnlyPath(filePath) || isFolderMarkerPath(filePath)) {
    throw new AuthError(`File not found: ${filePath}`, 404);
  }
  return filePath;
}

function directFinalizeRoute(event: APIGatewayProxyEvent): { filePath: string; transferId: string } {
  const raw = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const match = raw.match(/^(.*)\/direct-upload\/([A-Za-z0-9_-]{8,128})\/finalize$/);
  if (!match) throw new AuthError('Invalid direct-upload finalization route', 404);
  const filePath = sanitizeFilePath(match[1]);
  if (!filePath || isClientLocalOnlyPath(filePath) || isFolderMarkerPath(filePath)) {
    throw new AuthError(`File not found: ${filePath || 'unknown'}`, 404);
  }
  return { filePath, transferId: match[2] };
}

async function requireDirectPermission(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  filePath: string,
  action: 'read' | 'write',
  auditAction: string,
  requestId: string
): Promise<APIGatewayProxyResult | null> {
  const roles = await resolveFileOpRoles(user, vault);
  const permission = await evaluatePermission(
    user.userId,
    roles,
    action,
    '/' + filePath,
    user.orgId,
    vault.vaultId,
    await fileOpPermissionOptions(user, vault)
  );
  if (permission.allowed) return null;
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: auditAction,
    resourcePath: '/' + filePath,
    outcome: 'denied',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { matchedRule: permission.matchedRule?.id },
  }, event);
  return formatError(403, `Access denied: insufficient permissions to ${action} this file`, requestId);
}

/** Issues a short-lived, single-object PUT capability for encrypted bytes. */
async function handleIssueDirectUpload(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  assertVaultWritable(vault);
  const filePath = directActionPath(event, '/direct-upload');
  const denied = await requireDirectPermission(
    event,
    user,
    vault,
    filePath,
    'write',
    'files.directUpload.issue.denied',
    requestId
  );
  if (denied) return denied;

  const body = parseBody(event);
  validateRequiredFields(body, [
    'plaintextSize',
    'encryptedSize',
    'plaintextSha256',
    'encryptedSha256',
    'contentType',
    'activeKeyId',
  ]);
  const plaintextSize = parseBoundedInteger(body.plaintextSize, 'plaintextSize', MAX_FILE_SIZE);
  const encryptedSize = parseBoundedInteger(
    body.encryptedSize,
    'encryptedSize',
    DIRECT_TRANSFER_MAX_ENCRYPTED_SIZE
  );
  if (encryptedSize !== plaintextSize + AES_GCM_ENVELOPE_OVERHEAD_BYTES) {
    return formatError(400, 'encryptedSize does not match the AES-GCM envelope size', requestId);
  }
  if (!isSha256Hex(body.plaintextSha256) || !isSha256Hex(body.encryptedSha256)) {
    return formatError(400, 'SHA-256 commitments must be 64 lowercase hexadecimal characters', requestId);
  }
  const contentType = sanitizeDirectContentType(body.contentType);
  const requestedKeyId = typeof body.activeKeyId === 'string' ? body.activeKeyId : '';
  if (!requestedKeyId || requestedKeyId.length > 256 || /[\r\n]/.test(requestedKeyId)) {
    return formatError(400, 'activeKeyId is invalid', requestId);
  }

  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);
  if (!activeKeyId || activeKeyId !== requestedKeyId) {
    return formatError(409, 'The active encryption key changed; renew the key lease and retry', requestId);
  }

  const expectedVersionId = typeof body.expectedVersionId === 'string'
    ? body.expectedVersionId
    : undefined;
  if (expectedVersionId && (expectedVersionId.length > 1024 || /[\r\n]/.test(expectedVersionId))) {
    return formatError(400, 'expectedVersionId is invalid', requestId);
  }
  if (body.hash !== undefined && !isSha256Hex(body.hash)) {
    return formatError(400, 'hash must be a lowercase SHA-256 digest when provided', requestId);
  }
  if (
    body.plaintextSize !== undefined &&
    (typeof body.plaintextSize !== 'number' ||
      !Number.isSafeInteger(body.plaintextSize) ||
      body.plaintextSize < 0 ||
      body.plaintextSize > MAX_FILE_SIZE)
  ) {
    return formatError(400, 'plaintextSize is invalid', requestId);
  }
  const canonicalKey = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;
  const current = await headObjectOrNull({ Key: canonicalKey });
  if (expectedVersionId && current?.VersionId !== expectedVersionId) {
    return formatError(409, 'Conflict: the remote file changed before direct upload issuance', requestId);
  }
  if (expectedVersionId && !current) {
    return formatError(409, 'Conflict: the expected remote file no longer exists', requestId);
  }

  const orgResult = await getActiveOrg(user.orgId);
  if (orgResult.org) {
    const additionalBytes = Math.max(0, encryptedSize - (current?.ContentLength || 0));
    const quota = checkStorageLimit(orgResult.org, additionalBytes);
    if (!quota.allowed) return formatError(402, quota.reason || 'Storage limit exceeded', requestId);
  }

  const transferId = generateId();
  const expiresAtMs = Date.now() + DIRECT_TRANSFER_TTL_SECONDS * 1000;
  const transfer: DirectUploadMetadata = {
    transferId,
    ownerUserId: user.userId,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    pathSha256: sha256Hex(filePath),
    plaintextSize,
    encryptedSize,
    plaintextSha256: body.plaintextSha256,
    encryptedSha256: body.encryptedSha256,
    contentType,
    activeKeyId,
    issuedVersionId: current?.VersionId || 'none',
    issuedEtag: current?.ETag || 'none',
    expiresAtMs,
  };
  const metadata = directUploadS3Metadata(transfer);
  const checksum = checksumBase64FromHex(transfer.encryptedSha256);
  const stagingKey = directTransferStagingKey(user.orgId, vault.vaultId, user.userId, transferId);
  const command = new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: stagingKey,
    ContentType: 'application/octet-stream',
    ChecksumSHA256: checksum,
    Metadata: metadata,
  });
  const url = await getSignedUrl(s3Client, command, { expiresIn: DIRECT_TRANSFER_TTL_SECONDS });
  const headers: Record<string, string> = {
    'content-type': 'application/octet-stream',
    'x-amz-checksum-sha256': checksum,
  };
  for (const [key, value] of Object.entries(metadata)) {
    headers[`x-amz-meta-${key}`] = value;
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.directUpload.issue',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { transferId, plaintextSize, encryptedSize, contentType, expiresAtMs },
  }, event);

  return formatSuccess(200, {
    transferId,
    url,
    method: 'PUT',
    headers,
    expiresAt: new Date(expiresAtMs).toISOString(),
  }, requestId);
}

function directUploadResult(
  filePath: string,
  transferId: string,
  versionId: string | undefined,
  checksum: string | undefined,
  encryptedSize: number,
  plaintextSha256: string,
  contentType: string,
  lastModified = new Date().toISOString(),
  logicalVersion?: LogicalFileVersionRecord | null,
) {
  return {
    path: '/' + filePath,
    hash: plaintextSha256,
    size: encryptedSize,
    versionId,
    checksum,
    contentType,
    lastModified,
    transferId,
    ...logicalVersionFields(logicalVersion),
  };
}

/** Validates and atomically promotes one isolated encrypted upload. */
async function handleFinalizeDirectUpload(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  assertVaultWritable(vault);
  const { filePath, transferId } = directFinalizeRoute(event);
  const denied = await requireDirectPermission(
    event,
    user,
    vault,
    filePath,
    'write',
    'files.directUpload.finalize.denied',
    requestId
  );
  if (denied) return denied;

  const body = parseBody(event);
  const stagingEtag = typeof body.stagingEtag === 'string' ? body.stagingEtag : '';
  if (!stagingEtag || stagingEtag.length > 256 || /[\r\n]/.test(stagingEtag)) {
    return formatError(400, 'stagingEtag is required', requestId);
  }

  const canonicalKey = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;
  const stagingKey = directTransferStagingKey(user.orgId, vault.vaultId, user.userId, transferId);
  // S3 returns the stored object checksum only when checksum mode is enabled.
  let staged = await headObjectOrNull({ Key: stagingKey, includeChecksum: true });

  // Idempotent retry after copy/delete: the final object carries transfer-id.
  if (!staged) {
    const finalHead = await headObjectOrNull({ Key: canonicalKey });
    if (
      finalHead?.Metadata?.['vaultguard-transfer-id'] === transferId &&
      finalHead.Metadata['modified-by'] === user.userId
    ) {
      const logicalVersion = await observeFileVersion(user, vault, filePath, finalHead);
      return formatSuccess(200, directUploadResult(
        filePath,
        transferId,
        finalHead.VersionId,
        finalHead.ETag,
        finalHead.ContentLength || 0,
        finalHead.Metadata['vaultguard-plaintext-sha256'] || '',
        finalHead.ContentType || 'application/octet-stream',
        finalHead.LastModified?.toISOString(),
        logicalVersion,
      ), requestId);
    }
    return formatError(410, 'Direct upload is missing or expired', requestId);
  }

  const transfer = readDirectUploadMetadata(staged.Metadata);
  if (!transfer) return formatError(409, 'Direct upload metadata is incomplete', requestId);
  if (
    transfer.transferId !== transferId ||
    transfer.ownerUserId !== user.userId ||
    transfer.orgId !== user.orgId ||
    transfer.vaultId !== vault.vaultId ||
    transfer.pathSha256 !== sha256Hex(filePath)
  ) {
    return formatError(403, 'Direct upload does not belong to this operation', requestId);
  }
  if (Date.now() > transfer.expiresAtMs) {
    return formatError(410, 'Direct upload capability expired before finalization', requestId);
  }
  if (
    staged.ContentLength !== transfer.encryptedSize ||
    staged.ETag !== stagingEtag ||
    staged.ChecksumSHA256 !== checksumBase64FromHex(transfer.encryptedSha256)
  ) {
    return formatError(409, 'Direct upload body failed size or checksum validation', requestId);
  }
  const expectedVersionId = typeof body.expectedVersionId === 'string'
    ? body.expectedVersionId
    : undefined;
  if (expectedVersionId && expectedVersionId !== transfer.issuedVersionId) {
    return formatError(409, 'Direct upload expected-version binding changed', requestId);
  }
  const mutationPermit = await acquireVaultMutationPermit({
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  try {
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);
  if (!activeKeyId || activeKeyId !== transfer.activeKeyId) {
    return formatError(409, 'The active encryption key changed before finalization', requestId);
  }

  const current = await headObjectOrNull({ Key: canonicalKey });
  if (current?.Metadata?.['vaultguard-transfer-id'] === transferId) {
    try {
      await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: stagingKey }));
    } catch {
      // Lifecycle expiry is the fallback; never fail an already-durable copy.
    }
    const logicalVersion = await observeFileVersion(user, vault, filePath, current);
    return formatSuccess(200, directUploadResult(
      filePath,
      transferId,
      current.VersionId,
      current.ETag,
      current.ContentLength || transfer.encryptedSize,
      transfer.plaintextSha256,
      transfer.contentType,
      current.LastModified?.toISOString(),
      logicalVersion,
    ), requestId);
  }
  if (
    (transfer.issuedVersionId === 'none' && current) ||
    (transfer.issuedVersionId !== 'none' &&
      (!current || current.VersionId !== transfer.issuedVersionId || current.ETag !== transfer.issuedEtag))
  ) {
    return formatError(409, 'Conflict: the remote file changed before finalization', requestId);
  }

  const orgResult = await getActiveOrg(user.orgId);
  const storageDelta = transfer.encryptedSize - (current?.ContentLength || 0);
  if (orgResult.org) {
    const quota = checkStorageLimit(orgResult.org, Math.max(0, storageDelta));
    if (!quota.allowed) return formatError(402, quota.reason || 'Storage limit exceeded', requestId);
  }

  const mutationIntent = await beginVaultMutationIntent({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: current ? 'modified' : 'created',
    path: '/' + filePath,
    actorUserId: user.userId,
    verification: { kind: 'object-metadata' },
  });
  const lineage = logicalLineageForHead(current, user, vault, filePath);
  const createdAt = new Date().toISOString();
  const logicalDraft = createFileVersionDraft({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    fileId: lineage.fileId,
    fileVersionId: makeFileVersionId(generateId()),
    parentFileVersionIds: lineage.parentFileVersionIds,
    contentType: transfer.contentType,
    plaintextBytes: transfer.plaintextSize,
    ciphertextBytes: transfer.encryptedSize,
    plaintextSha256: transfer.plaintextSha256,
    ciphertextSha256: transfer.encryptedSha256,
    cloudKeyId: transfer.activeKeyId,
    createdAt,
    actorIdentityId: user.userId,
    agentSessionId: user.sessionId,
  });
  let copied;
  try {
    copied = await s3Client.send(new CopyObjectCommand({
      Bucket: S3_BUCKET,
      Key: canonicalKey,
      CopySource: encodeURIComponent(`${S3_BUCKET}/${stagingKey}`),
      CopySourceIfMatch: staged.ETag,
      MetadataDirective: 'REPLACE',
      ContentType: transfer.contentType,
      Metadata: logicalVersionMetadata(logicalDraft, {
        'modified-by': user.userId,
        'modified-at': createdAt,
        'vaultguard-key-id': transfer.activeKeyId,
        'vaultguard-transfer-id': transferId,
        'vaultguard-plaintext-sha256': transfer.plaintextSha256,
        'vaultguard-plaintext-size': String(transfer.plaintextSize),
        'vaultguard-encrypted-sha256': transfer.encryptedSha256,
        'vaultguard-mutation-id': mutationIntent.intentId,
      }),
      ...(current?.ETag ? { IfMatch: current.ETag } : { IfNoneMatch: '*' }),
    }));
  } catch (error: unknown) {
    await abortMutationIntentAfterDefiniteFailure(mutationIntent);
    const name = error && typeof error === 'object' && 'name' in error
      ? String((error as { name: unknown }).name)
      : '';
    if (
      name === 'PreconditionFailed' ||
      name === 'ConditionalRequestConflict' ||
      name === 'NotFound'
    ) {
      return formatError(409, 'Conflict: direct upload promotion lost a concurrent update', requestId);
    }
    throw error;
  }

  const logicalVersion = await persistBoundFileVersion(logicalDraft, {
    storageKey: canonicalKey,
    storageVersionId: copied.VersionId,
    storageEtag: copied.CopyObjectResult?.ETag,
  });

  await publishMutationIntentOrThrow(mutationIntent);

  if (orgResult.org && storageDelta !== 0) {
    await updateOrgStorageUsage(orgResult.org.slug, storageDelta);
  }
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.directUpload.finalize',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      transferId,
      plaintextSize: transfer.plaintextSize,
      encryptedSize: transfer.encryptedSize,
      contentType: transfer.contentType,
      versionId: copied.VersionId,
      fileVersionId: logicalVersion.fileVersionId,
      keyId: transfer.activeKeyId,
    },
  }, event);

  try {
    await s3Client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key: stagingKey }));
  } catch {
    // The canonical copy is durable; lifecycle expiration handles abandoned staging.
  }
  staged = null;

  return formatSuccess(200, directUploadResult(
    filePath,
    transferId,
    copied.VersionId,
    copied.CopyObjectResult?.ETag,
    transfer.encryptedSize,
    transfer.plaintextSha256,
    transfer.contentType,
    copied.CopyObjectResult?.LastModified?.toISOString(),
    logicalVersion,
  ), requestId);
  } finally {
    await releaseVaultMutationPermit(mutationPermit);
  }
}

/** Issues a short-lived GET capability after current read authorization. */
async function handleIssueDirectDownload(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string,
  view?: RevisionFileReadView,
): Promise<APIGatewayProxyResult> {
  const filePath = directActionPath(event, '/direct-download');
  const denied = await requireDirectPermission(
    event,
    user,
    vault,
    filePath,
    'read',
    'files.directDownload.issue.denied',
    requestId
  );
  if (denied) return denied;
  const body = parseBody(event);
  let versionId = typeof body.versionId === 'string' && body.versionId.length > 0
    ? body.versionId
    : undefined;
  const requestedFileVersionId =
    typeof body.fileVersionId === 'string'
      ? readBoundedLogicalVersionId(body.fileVersionId, 'fileVersionId')
      : undefined;
  if (versionId && requestedFileVersionId) {
    return formatError(400, 'Specify versionId or fileVersionId, not both', requestId);
  }
  if (versionId && (versionId.length > 1024 || /[\r\n]/.test(versionId))) {
    return formatError(400, 'versionId is invalid', requestId);
  }
  let key = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;
  const requestedLogicalVersion = requestedFileVersionId
    ? await requireLogicalVersionStore().require(
        user.orgId,
        vault.vaultId,
        requestedFileVersionId,
      )
    : !versionId && view ? await view.current(filePath) : null;
  if (
    requestedLogicalVersion &&
    (requestedLogicalVersion.path !== filePath || requestedLogicalVersion.state !== 'content')
  ) {
    throw new FileVersionNotFoundError();
  }
  if (requestedLogicalVersion) key = exactFileVersionStorageKey(requestedLogicalVersion, { orgId: user.orgId, vaultId: vault.vaultId }, S3_BUCKET, filePath);
  versionId = requestedLogicalVersion?.storageVersionId ?? versionId;
  const head = await headObjectOrNull({ Key: key, VersionId: versionId });
  if (!head) return formatError(404, 'File not found', requestId);
  const logicalVersion = await observeFileVersion(user, vault, filePath, head, { logicalRecord: requestedLogicalVersion ?? undefined });
  assertRequestedLogicalVersion(requestedLogicalVersion, logicalVersion);
  const plaintextSha256 = head.Metadata?.['vaultguard-plaintext-sha256'];
  const encryptedSha256 = head.Metadata?.['vaultguard-encrypted-sha256'];
  const plaintextSize = Number(head.Metadata?.['vaultguard-plaintext-size']);
  if (!isSha256Hex(plaintextSha256) || !isSha256Hex(encryptedSha256) || !Number.isSafeInteger(plaintextSize) || plaintextSize < 0) {
    return formatError(
      409,
      'This version predates direct-transfer integrity metadata; use the normal download path',
      requestId
    );
  }
  const transferId = generateId();
  const expiresAtMs = Date.now() + DIRECT_TRANSFER_TTL_SECONDS * 1000;
  const url = await getSignedUrl(
    s3Client,
    new GetObjectCommand({ Bucket: S3_BUCKET, Key: key, ...(versionId ? { VersionId: versionId } : {}) }),
    { expiresIn: DIRECT_TRANSFER_TTL_SECONDS }
  );
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.directDownload.issue',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      transferId,
      versionId: head.VersionId,
      fileVersionId: logicalVersion?.fileVersionId,
      encryptedSize: head.ContentLength || 0,
      expiresAtMs,
      workspaceRevisionId: view?.workspaceRevisionId ?? null,
    },
  }, event);
  return formatSuccess(200, {
    transferId,
    url,
    method: 'GET',
    headers: {},
    expiresAt: new Date(expiresAtMs).toISOString(),
    versionId: head.VersionId,
    ...logicalVersionFields(logicalVersion),
    encryptedSize: head.ContentLength || 0,
    encryptedSha256,
    plaintextSize,
    plaintextSha256,
    contentType: head.ContentType || 'application/octet-stream',
  }, requestId);
}

// ─── Mutation Intent Mode (SD-06-F1) ─────────────────────────────────────────

/**
 * How strictly the server treats a write that does NOT declare a mutation
 * intent (none of `expectedVersionId`, `mustBeAbsent`, `force`).
 *
 * - `off` — no telemetry, no enforcement.
 * - `observe` — **the default.** Emits one `[MUTATION_INTENT_TELEMETRY]` line
 *   per intent-less AUTHORIZED write and changes nothing else: not the status,
 *   not the body, not a header.
 * - `enforce` — rejects intent-less writes with 428 Precondition Required.
 *
 * The mode gates the INTENT-LESS legacy lane ONLY. A DECLARED intent is always
 * honored — in `off`, in `observe` and in `enforce` alike.
 */
export type MutationIntentMode = 'off' | 'observe' | 'enforce';

/**
 * Which mutation intent a write declared. Resolved exactly once, in
 * `handleWriteFile`, before any S3 work.
 *
 * `legacy` means the caller declared nothing — today's every-fielded-client
 * lane, and the only lane the mode switch touches.
 */
type WriteIntent = 'expect-version' | 'must-be-absent' | 'force' | 'legacy';

/**
 * Resolves the mutation-intent mode from `MUTATION_INTENT_MODE`.
 *
 * **Scope ceiling — binding.** The default is `observe`, and observe never
 * rejects, so with no configuration change every intent-less write stays
 * byte-identical to today's. `enforce` is fully built and fully tested but
 * DORMANT: **no Terraform in this phase sets this variable** —
 * `grep -rn "MUTATION_INTENT_MODE" terraform/` being EMPTY is a recorded
 * verification gate for phase 16 (the 15-02 precedent). Flipping it is an
 * operator decision made against real adoption telemetry: no fielded plugin
 * declares an intent today (the body fields did not exist before this change),
 * so a premature flip would 428 every deployed client's writes until a plugin
 * release caught up — the 2026-07-11 production-incident class, where an audit
 * finding's wrong premise, applied confidently, took production down.
 *
 * **The env var is read live on every call — deliberately NOT captured in a
 * module-level const** like this file's other env constants, for two reasons:
 *   1. module-level constants resolve at Lambda cold start, which would make
 *      the mode untestable without module resets; and
 *   2. it would make the operator's flip take effect only after a cold start
 *      rather than on the very next invocation.
 * The cost is one `process.env` read per write request — free next to the
 * DynamoDB and S3 round trips already on that path.
 *
 * **Why this lives here and not in `shared/utils.ts`** beside its 15-02 sibling
 * `getSessionEnforcementMode`: every `tests/files-*.test.ts` harness stubs
 * `../infrastructure/lambda/shared/utils` WHOLESALE with an enumerated export
 * list, so a new import from that module would break those harnesses at import
 * time. The session helper is shared because two shared entry points consume
 * it; this one has exactly ONE consumer (`handleWriteFile`). Exported only so
 * `tests/files-write-intent-mode.test.ts` can pin it directly.
 */
export function getMutationIntentMode(): MutationIntentMode {
  const raw = (process.env.MUTATION_INTENT_MODE || '').trim().toLowerCase();
  if (raw === 'off' || raw === 'observe' || raw === 'enforce') {
    return raw;
  }
  return 'observe';
}

/**
 * SD-06-F1 observe-mode telemetry: ONE line per intent-less authorized write,
 * so the unknown lane can be measured before anyone considers the enforce flip.
 *
 * The payload is fixed at five non-secret fields. It must **never** carry the
 * concrete file path, the org id, the vault id, the email, a content hash or
 * any token: CloudWatch retention turns a convenience field into an
 * information-disclosure surface (SD-14 posture). `resource` is the API-Gateway
 * resource TEMPLATE (`/vaults/{vaultId}/files/{filePath+}`), never the concrete
 * path. The exact key set is pinned by `tests/files-write-intent-mode.test.ts`
 * so that adding a sixth field is a deliberate act, not a drive-by.
 *
 * Kept a named function rather than an inline `console.warn` so the key set has
 * exactly one home and the tests have one thing to pin.
 */
export function emitMutationIntentTelemetry(
  event: APIGatewayProxyEvent,
  user: UserContext
): void {
  console.warn('[MUTATION_INTENT_TELEMETRY]', {
    resource: event.resource || event.path || '',
    method: event.httpMethod,
    userId: user.userId,
    hasIntent: false,
    userAgent: getUserAgent(event),
  });
}

// ─── PUT /vaults/{vaultId}/files/{path} ─────────────────────────────────────

/**
 * Writes (creates or updates) a file in S3 after verifying 'write' permission.
 * S3 versioning preserves previous versions automatically.
 *
 * Request body:
 * - content: Base64-encoded file content
 * - contentType: MIME type (optional, defaults to 'text/markdown')
 * - expectedVersionId: For optimistic locking (optional). A string, or
 *   `null`/omitted for "no version". Any other type is a 400.
 * - mustBeAbsent: `true` when the client believes the path is unused — the PUT
 *   carries `IfNoneMatch: '*'` and a racing create gets a 409 (SD-06-F1)
 * - force: `true` for a deliberate unconditional overwrite (today's behaviour,
 *   now declared rather than inferred from an omission)
 *
 * At most ONE of `expectedVersionId` / `mustBeAbsent` / `force` may appear.
 *
 * @param event - API Gateway event with path parameter and file content in body
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns New file metadata including versionId
 */
async function handleWriteFile(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // LF2: archived vaults are read-only (legal-hold / retention freeze). The
  // dispatch-time membership check runs at 'viewer', which skips the archived
  // guard, so re-assert writability here before any S3 mutation.
  assertVaultWritable(vault);

  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(400, 'VaultGuard plugin files are local-only and cannot be stored in the server vault', requestId);
  }

  const body = parseBody(event);
  // Folder markers are zero-byte by design — content is allowed to be empty.
  if (!isFolderMarkerPath(filePath)) {
    validateRequiredFields(body, ['content']);
  }

  const content = (body.content as string | undefined) ?? '';
  const contentType = (body.contentType as string) || 'text/markdown';
  const rawExpectedVersionId = body.expectedVersionId;
  const expectedVersionId = typeof rawExpectedVersionId === 'string'
    ? rawExpectedVersionId
    : undefined;

  // ── SD-06-F1: declared mutation intent ────────────────────────────────────
  //
  // The caller may declare exactly ONE of `expectedVersionId`, `mustBeAbsent`
  // or `force`. The union is resolved once, here, before any S3 work, so every
  // lane below reads a single `writeIntent` value instead of re-deriving the
  // caller's meaning from an omission — today a deliberate force-overwrite and
  // a blind create are indistinguishable on the wire, which is the whole reason
  // a racing create can silently win.
  //
  // These 400s are reached BEFORE the permission check. That is deliberate and
  // safe: every one of them describes the caller's OWN request body and
  // discloses nothing about the vault, the path, or whether the object exists.
  // Rejecting a malformed body cheaply also keeps a garbage request off the
  // DynamoDB permission path entirely.

  // DECISION 2 — `expectedVersionId` had NO validation in this handler while
  // the direct/large lane validated it. The length / CR-LF rules below are that
  // lane's verbatim. Fielded clients send real S3 version ids; the only
  // behaviour change for them is that garbage input moves from 409 to 400.
  //
  // The TYPE rule is deliberately STRICTER than the direct lane's
  // treat-a-non-string-as-absent cast:
  //   undefined / null → field-absent (JSON clients legitimately serialize
  //                      `null` to mean "no version I know of")
  //   string           → validated below, non-empty enters the expect-version lane
  //   anything else    → 400
  // The direct lane's cast would silently turn a truthy non-string (a number, a
  // stray object) into an UNCONDITIONAL write. Pre-fix such a value was truthy,
  // entered the guarded lane and generally 409'd — so treating it as absent
  // would be a guard LOOSENING on a malformed input, and this handler must
  // never resolve ambiguity in favour of overwriting. It is also the same
  // strictness `mustBeAbsent` / `force` get: a wrong type is a client bug, and
  // a client bug must be loud, not silently downgraded.
  if (
    rawExpectedVersionId !== undefined &&
    rawExpectedVersionId !== null &&
    typeof rawExpectedVersionId !== 'string'
  ) {
    return formatError(400, 'expectedVersionId is invalid', requestId);
  }
  if (expectedVersionId && (expectedVersionId.length > 1024 || /[\r\n]/.test(expectedVersionId))) {
    return formatError(400, 'expectedVersionId is invalid', requestId);
  }

  // DECISION 1 — a field is "declared" ONLY when its value is the boolean
  // literal `true`. Literal `false` is treated as field-absent: a harmless
  // no-op, because an older or generated client may serialize its defaults.
  // Anything else ("yes", 1, null, {}) is a 400 naming the field, so a
  // client bug can never be silently downgraded into an unguarded write.
  const rawMustBeAbsent = body.mustBeAbsent;
  const rawForce = body.force;
  if (rawMustBeAbsent !== undefined && typeof rawMustBeAbsent !== 'boolean') {
    return formatError(400, 'mustBeAbsent must be a boolean', requestId);
  }
  if (rawForce !== undefined && typeof rawForce !== 'boolean') {
    return formatError(400, 'force must be a boolean', requestId);
  }
  const mustBeAbsent = rawMustBeAbsent === true;
  const force = rawForce === true;

  // DECISION 1 — two intents in one body is a contradiction, not a precedence
  // puzzle. Reject rather than pick a winner: whichever we picked would be a
  // guess about which one the client meant, and guessing is how ambiguity turns
  // into data loss.
  const declaredIntents = [
    expectedVersionId ? 'expectedVersionId' : '',
    mustBeAbsent ? 'mustBeAbsent' : '',
    force ? 'force' : '',
  ].filter((name) => name !== '');
  if (declaredIntents.length > 1) {
    return formatError(
      400,
      `Conflicting mutation intents (${declaredIntents.join(' + ')}): declare at most one of ` +
        'expectedVersionId, mustBeAbsent or force',
      requestId
    );
  }

  const writeIntent: WriteIntent = expectedVersionId
    ? 'expect-version'
    : mustBeAbsent
      ? 'must-be-absent'
      : force
        ? 'force'
        : 'legacy';

  // Decode content to check size
  const contentBuffer = Buffer.from(content, 'base64');
  if (contentBuffer.length > MAX_FILE_SIZE) {
    return formatError(413, `File size exceeds maximum allowed (${MAX_FILE_SIZE} bytes)`, requestId);
  }

  // Storage quota enforcement
  const orgCheck = await getActiveOrg(user.orgId);
  if (orgCheck.allowed && orgCheck.org) {
    const storageCheck = checkStorageLimit(orgCheck.org, contentBuffer.length);
    if (!storageCheck.allowed) {
      return formatError(402, storageCheck.reason || 'Storage limit exceeded', requestId);
    }
  }

  // Permission check
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(user.userId, permRoles, 'write', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.write.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { matchedRule: permResult.matchedRule?.id },
    });
    return formatError(403, 'Access denied: insufficient permissions to write this file', requestId);
  }

  // ── SD-06-F1 mode switch — the INTENT-LESS legacy lane, and nothing else ──
  //
  // DECISION 3, placement. This sits immediately AFTER the permission check and
  // BEFORE any S3 work, deliberately: observe-mode telemetry then counts only
  // AUTHORIZED intent-less writes. An unauthorized caller was already 403'd
  // above and never reaches this line, so the adoption numbers the operator
  // will read before considering the flip measure real client behaviour rather
  // than denied noise. (The 15-02 placement-honesty note, mirrored.)
  //
  // A DECLARED intent is honored in EVERY mode — including `off`. The mode
  // gates nothing but this legacy lane; the intent lanes below sit outside it
  // on purpose, so turning telemetry off can never turn a guard off.
  if (writeIntent === 'legacy') {
    const intentMode = getMutationIntentMode();
    if (intentMode === 'enforce') {
      // DORMANT branch. Reachable only through MUTATION_INTENT_MODE, which no
      // Terraform in phase 16 sets. 428 and not 409: fielded clients
      // string-match /conflict|409/i into their blocked/conflict machinery and
      // would misroute a 409 into a state they never retry out of. Not 400
      // either: that conflates with malformed requests in every dashboard.
      return formatError(
        428,
        'Precondition required: this write must declare a mutation intent ' +
          '(expectedVersionId, mustBeAbsent, or force)',
        requestId
      );
    }
    if (intentMode === 'observe') {
      emitMutationIntentTelemetry(event, user);
    }
    // 'off' — silent, and byte-identical to today's behaviour.
  }

  // Optimistic locking: check current version if expectedVersionId is provided.
  // The matching ETag is sent as IfMatch on the PUT to close the HEAD->PUT race.
  //
  // SD-06-F1: the guard is now the RESOLVED lane rather than the bare presence
  // of `expectedVersionId`, so it is unmistakable that `must-be-absent` and
  // `force` skip this HEAD entirely. Nothing inside the block changed.
  let currentEtag: string | undefined;
  let currentHead: S3VersionObservation | null = null;
  if (writeIntent === 'expect-version') {
    try {
      const headResponse = await s3Client.send(
        new HeadObjectCommand({
          Bucket: S3_BUCKET,
          Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        })
      );
      currentHead = headResponse;

      if (headResponse.VersionId && headResponse.VersionId !== expectedVersionId) {
        return formatError(
          409,
          'Conflict: file has been modified since your last read. ' +
            `Expected version ${expectedVersionId}, current version ${headResponse.VersionId}`,
          requestId
        );
      }
      currentEtag = headResponse.ETag;
      if (!currentEtag) {
        return formatError(
          409,
          'Conflict: current checksum is unavailable for guarded write',
          requestId
        );
      }
    } catch (err: unknown) {
      // A guarded write cannot silently recreate a path deleted by another client.
      if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NotFound') {
        return formatError(
          409,
          'Conflict: file has been modified or deleted since your last read. ' +
            `Expected version ${expectedVersionId}, current version is missing`,
          requestId
        );
      }
      throw err;
    }
  }
  if (fileVersionStore && (writeIntent === 'force' || writeIntent === 'legacy')) {
    currentHead = await headObjectOrNull({
      Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
    });
  }

  // Phase 6 (Plan 06-02): annotate the object with the DEK keyId so Phase 7's
  // cross-DEK restore endpoint can match noncurrent versions back to their DEK.
  const mutationPermit = await acquireVaultMutationPermit({
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  try {
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);
  const lineage = logicalLineageForHead(currentHead, user, vault, filePath);
  const createdAt = new Date().toISOString();
  const plaintextSha256 = isSha256Hex(body.hash) ? body.hash : null;
  const plaintextBytes = typeof body.plaintextSize === 'number' ? body.plaintextSize : null;
  const ciphertextSha256 = sha256Hex(contentBuffer);
  const logicalDraft = createFileVersionDraft({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    fileId: lineage.fileId,
    fileVersionId: makeFileVersionId(generateId()),
    parentFileVersionIds: lineage.parentFileVersionIds,
    contentType,
    plaintextBytes,
    ciphertextBytes: contentBuffer.byteLength,
    plaintextSha256,
    ciphertextSha256,
    cloudKeyId: activeKeyId,
    createdAt,
    actorIdentityId: user.userId,
    agentSessionId: user.sessionId,
  });

  // SD-06-F1 (DECISION 5) — the S3 precondition, resolved per lane:
  //   expect-version  → IfMatch (unchanged; the HEAD above already 409s when
  //                     the ETag is missing, so it is non-empty here)
  //   must-be-absent  → IfNoneMatch: '*' — and NO pre-HEAD. The condition is
  //                     the authority either way; a HEAD would buy nothing but
  //                     a nicer error message at the cost of a round trip on
  //                     every create.
  //   force / legacy  → unconditional. `force` says so explicitly; `legacy` is
  //                     exactly today's behaviour, preserved.
  // This is deliberately the same shape as the already-deployed direct/large
  // lane's finalize CopyObject (`current?.ETag ? IfMatch : IfNoneMatch: '*'`),
  // so a future reader sees one pattern for absence-safety, not two.
  const writeCondition: { IfMatch?: string; IfNoneMatch?: string } =
    writeIntent === 'expect-version' && currentEtag
      ? { IfMatch: currentEtag }
      : writeIntent === 'must-be-absent'
        ? { IfNoneMatch: '*' }
        : {};

  const activityAction =
    writeIntent === 'must-be-absent'
      ? 'created'
      : writeIntent === 'expect-version' || writeIntent === 'force'
        ? 'modified'
        : expectedVersionId ? 'modified' : 'created';
  const mutationIntent = await beginVaultMutationIntent({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: activityAction,
    path: '/' + filePath,
    actorUserId: user.userId,
    verification: { kind: 'object-metadata' },
  });

  // Write to S3
  let putResponse;
  try {
    putResponse = await s3Client.send(
      new PutObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        Body: contentBuffer,
        ChecksumSHA256: checksumBase64FromHex(ciphertextSha256),
        ContentType: contentType,
        Metadata: logicalVersionMetadata(logicalDraft, {
          'modified-by': user.userId,
          'modified-at': createdAt,
          'vaultguard-mutation-id': mutationIntent.intentId,
          ...(activeKeyId ? { 'vaultguard-key-id': activeKeyId } : {}),
        }),
        ...writeCondition,
      })
    );
  } catch (err: unknown) {
    await abortMutationIntentAfterDefiniteFailure(mutationIntent);
    const name = err && typeof err === 'object' && 'name' in err ? (err as { name: string }).name : '';
    if (
      writeIntent === 'expect-version' &&
      (name === 'PreconditionFailed' ||
        name === 'ConditionalRequestConflict' ||
        name === 'NotFound')
    ) {
      return formatError(
        409,
        'Conflict: file has been modified or deleted since your write began',
        requestId
      );
    }
    // SD-06-F1 — the create lane gets its OWN branch, not a widened version of
    // the update lane's. Its error-name set differs (`ConditionalRequestConflict`
    // is what S3 returns when two conditional writes race) and its message
    // differs on purpose: clients do not need the distinction, but humans
    // reading an audit trail do. `NotFound` is deliberately NOT mapped here —
    // a NotFound on an `IfNoneMatch: '*'` create means something else is wrong,
    // and flattening it into a 409 would hide a real fault.
    if (
      writeIntent === 'must-be-absent' &&
      (name === 'PreconditionFailed' || name === 'ConditionalRequestConflict')
    ) {
      return formatError(
        409,
        'Conflict: this file was created on another device before your create completed',
        requestId
      );
    }
    throw err;
  }

  const logicalVersion = await persistBoundFileVersion(logicalDraft, {
    storageKey: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
    storageVersionId: putResponse.VersionId,
    storageEtag: putResponse.ETag,
  });

  await publishMutationIntentOrThrow(mutationIntent);

  // Track storage usage (best-effort, non-blocking)
  const orgResult = await getActiveOrg(user.orgId);
  if (orgResult.org) {
    await updateOrgStorageUsage(orgResult.org.slug, contentBuffer.length);
  }

  // Record on the activity log so other clients can see this change without
  // re-listing the entire vault. The `created` vs `modified` distinction is
  // best-effort: we treat the absence of an `expectedVersionId` as a hint
  // that the client believes the file is new. Receivers don't differentiate
  // anyway — both apply via download.
  //
  // SD-06-F1 (DECISION 6): for a DECLARED intent it is no longer a hint. A
  // `must-be-absent` write that reached this line provably CREATED the object
  // (`IfNoneMatch: '*'` succeeded, so nothing was there); `expect-version` and
  // `force` provably replaced one. Only the intent-less legacy lane keeps the
  // old heuristic, unchanged.
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.write',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      size: contentBuffer.length,
      versionId: putResponse.VersionId,
      fileVersionId: logicalVersion.fileVersionId,
      contentType,
      ...(activeKeyId ? { keyId: activeKeyId } : {}),
    },
  });

  return formatSuccess(
    200,
    {
      path: '/' + filePath,
      size: contentBuffer.length,
      versionId: putResponse.VersionId,
      lastModified: createdAt,
      checksum: putResponse.ETag,
      ...logicalVersionFields(logicalVersion),
    },
    requestId
  );
  } finally {
    await releaseVaultMutationPermit(mutationPermit);
  }
}

// ─── DELETE /vaults/{vaultId}/files/{path} ──────────────────────────────────

/**
 * Soft-deletes a file by placing an S3 delete marker.
 * The file remains recoverable through version history.
 * Only users with 'delete' permission on the path can perform this operation.
 *
 * Optional JSON body:
 * - expectedVersionId: current S3 version the client believes it is deleting.
 *   When present, the server rejects stale deletes with 409 instead of placing
 *   a delete marker over a newer peer write.
 *
 * @param event - API Gateway event with path parameter
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns Confirmation with the delete marker version ID
 */
async function handleDeleteFile(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // LF2: archived vaults are read-only — reject deletes before any S3 mutation.
  assertVaultWritable(vault);

  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  const body = parseBody(event);
  const expectedVersionId =
    typeof body.expectedVersionId === 'string' && body.expectedVersionId.trim().length > 0
      ? body.expectedVersionId.trim()
      : undefined;
  if (body.expectedVersionId !== undefined && !expectedVersionId) {
    return formatError(400, 'expectedVersionId must be a non-empty string when provided', requestId);
  }

  // Permission check
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(user.userId, permRoles, 'delete', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.delete.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { matchedRule: permResult.matchedRule?.id },
    });
    return formatError(403, 'Access denied: insufficient permissions to delete this file', requestId);
  }

  // Verify file exists and capture size/version for storage tracking and
  // optional optimistic delete locking.
  let fileSize = 0;
  let currentEtag: string | undefined;
  let currentHead: S3VersionObservation | null = null;
  try {
    const headResult = await s3Client.send(
      new HeadObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      })
    );
    currentHead = headResult;
    fileSize = headResult.ContentLength || 0;
    currentEtag = headResult.ETag;
    if (expectedVersionId) {
      if (!headResult.VersionId || headResult.VersionId !== expectedVersionId) {
        return formatError(
          409,
          'Conflict: file has been modified since your last read. ' +
            `Expected version ${expectedVersionId}, current version ${headResult.VersionId ?? 'is unavailable'}`,
          requestId
        );
      }
      if (!currentEtag) {
        return formatError(
          409,
          'Conflict: current checksum is unavailable for guarded delete',
          requestId
        );
      }
    }
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NotFound') {
      if (expectedVersionId) {
        return formatError(
          409,
          'Conflict: file has been modified or deleted since your last read. ' +
            `Expected version ${expectedVersionId}, current version is missing`,
          requestId
        );
      }
      return formatError(404, `File not found: ${filePath}`, requestId);
    }
    throw err;
  }

  // Phase 6 (Plan 06-02): record the keyId active at delete time so the audit
  // log has chain-of-custody for which DEK protected the now-hidden version.
  const mutationPermit = await acquireVaultMutationPermit({
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  try {
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);
  const lineage = logicalLineageForHead(currentHead, user, vault, filePath);
  const deletedAt = new Date().toISOString();
  const tombstoneDraft = createFileVersionDraft({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    fileId: lineage.fileId,
    fileVersionId: makeFileVersionId(generateId()),
    parentFileVersionIds: lineage.parentFileVersionIds,
    state: 'tombstone',
    createdAt: deletedAt,
    actorIdentityId: user.userId,
    agentSessionId: user.sessionId,
  });
  const mutationIntent = await beginVaultMutationIntent({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'deleted',
    path: '/' + filePath,
    actorUserId: user.userId,
    verification: { kind: 'delete-head' },
  });

  // Soft delete (S3 versioning creates a delete marker). For guarded deletes,
  // IfMatch closes the HEAD→DELETE race: if a newer write lands after the HEAD,
  // S3 rejects the delete instead of hiding the newer object.
  let deleteResponse;
  try {
    deleteResponse = await s3Client.send(
      new DeleteObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        ...(expectedVersionId && currentEtag ? { IfMatch: currentEtag } : {}),
      })
    );
  } catch (err: unknown) {
    await abortMutationIntentAfterDefiniteFailure(mutationIntent);
    const name = err && typeof err === 'object' && 'name' in err ? (err as { name: string }).name : '';
    if (expectedVersionId && (name === 'PreconditionFailed' || name === 'NotFound')) {
      return formatError(
        409,
        'Conflict: file has been modified or deleted since your delete began',
        requestId
      );
    }
    throw err;
  }

  const tombstone = await persistBoundFileVersion(tombstoneDraft, {
    storageKey: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
    storageVersionId: deleteResponse.VersionId,
  });

  await publishMutationIntentOrThrow(mutationIntent);

  // Decrement storage usage
  if (fileSize > 0) {
    const orgResult = await getActiveOrg(user.orgId);
    if (orgResult.org) {
      await updateOrgStorageUsage(orgResult.org.slug, -fileSize);
    }
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.delete',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      deleteMarkerVersionId: deleteResponse.VersionId,
      fileVersionId: tombstone.fileVersionId,
      softDelete: true,
      freedBytes: fileSize,
      ...(activeKeyId ? { keyId: activeKeyId } : {}),
    },
  });

  return formatSuccess(
    200,
    {
      path: '/' + filePath,
      deleted: true,
      deleteMarkerVersionId: deleteResponse.VersionId,
      fileId: tombstone.fileId,
      fileVersionId: tombstone.fileVersionId,
      deletedAt,
      recoverable: true,
      message: 'File soft-deleted. Previous versions remain accessible via history.',
    },
    requestId
  );
  } finally {
    await releaseVaultMutationPermit(mutationPermit);
  }
}

// ─── GET /vaults/{vaultId}/files/{path}/history ─────────────────────────────

/**
 * Returns the version history of a file from S3 versioning.
 * Requires 'read' permission on the file path.
 *
 * @param event - API Gateway event with path parameter
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns Array of FileVersion objects ordered by date (newest first)
 */
async function handleGetHistory(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Extract path — remove '/history' suffix from the path parameter
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath.replace(/\/history$/, ''));
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(404, `File not found: ${filePath}`, requestId);
  }

  // Permission check
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(user.userId, permRoles, 'read', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.history.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
    });
    return formatError(403, 'Access denied: insufficient permissions', requestId);
  }

  const limit = parseRecoveryLimit(event.queryStringParameters?.limit);
  const cursor = decodeOpaqueCursor(event.queryStringParameters?.cursor);
  const pathDigest = sha256Hex(filePath);
  if (
    Object.keys(cursor).length > 0 &&
    (cursor.kind !== 'history' || cursor.path !== pathDigest)
  ) {
    return formatError(400, 'Pagination cursor does not belong to this file history', requestId);
  }

  // Fetch one bounded version-history page from S3.
  const versionsResponse = await s3Client.send(
    new ListObjectVersionsCommand({
      Bucket: S3_BUCKET,
      Prefix: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      MaxKeys: limit,
      KeyMarker: cursor.keyMarker,
      VersionIdMarker: cursor.versionIdMarker,
    })
  );

  const versions: FileVersion[] = [];
  const storageKey = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;

  // Process object versions
  for (const version of versionsResponse.Versions || []) {
    if (version.Key === storageKey && version.VersionId) {
      const persisted = await findLogicalVersionByStorage({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        storageBucket: S3_BUCKET,
        storageKey,
        storageVersionId: version.VersionId,
      });
      const head = persisted || !fileVersionStore
        ? null
        : await headObjectOrNull({ Key: storageKey, VersionId: version.VersionId });
      const logicalVersion =
        persisted ??
        (await putLogicalVersion(
          fileVersionFromStorageObservation({
            orgId: user.orgId,
            vaultId: vault.vaultId,
            path: filePath,
            storageBucket: S3_BUCKET,
            storageKey,
            storageVersionId: version.VersionId,
            storageEtag: head?.ETag,
            contentType: head?.ContentType,
            ciphertextBytes: head?.ContentLength ?? version.Size ?? 0,
            lastModified: version.LastModified?.toISOString(),
            metadata: head?.Metadata,
          }),
        ));
      versions.push({
        versionId: version.VersionId,
        storageVersionId: version.VersionId,
        fileId: logicalVersion.fileId,
        fileVersionId: logicalVersion.fileVersionId,
        lastModified: version.LastModified?.toISOString() || '',
        size: version.Size || 0,
        isLatest: version.IsLatest || false,
        isDeleteMarker: false,
        plaintextSha256: logicalVersion.plaintextSha256,
        ciphertextSha256: logicalVersion.ciphertextSha256,
        integrity: logicalVersion.integrity,
      });
    }
  }

  // Process delete markers
  for (const marker of versionsResponse.DeleteMarkers || []) {
    if (marker.Key === storageKey && marker.VersionId) {
      const persisted = await findLogicalVersionByStorage({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        storageBucket: S3_BUCKET,
        storageKey,
        storageVersionId: marker.VersionId,
      });
      const logicalVersion =
        persisted ??
        (await putLogicalVersion(
          fileVersionFromStorageObservation({
            orgId: user.orgId,
            vaultId: vault.vaultId,
            path: filePath,
            storageBucket: S3_BUCKET,
            storageKey,
            storageVersionId: marker.VersionId,
            ciphertextBytes: 0,
            lastModified: marker.LastModified?.toISOString(),
            state: 'tombstone',
          }),
        ));
      versions.push({
        versionId: marker.VersionId,
        storageVersionId: marker.VersionId,
        fileId: logicalVersion.fileId,
        fileVersionId: logicalVersion.fileVersionId,
        lastModified: marker.LastModified?.toISOString() || '',
        size: 0,
        isLatest: marker.IsLatest || false,
        isDeleteMarker: true,
        plaintextSha256: null,
        ciphertextSha256: null,
        integrity: 'tombstone',
      });
    }
  }

  // Sort by date (newest first)
  versions.sort((a, b) => new Date(b.lastModified).getTime() - new Date(a.lastModified).getTime());

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.history',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { versionCount: versions.length, hasMore: versionsResponse.IsTruncated === true },
  });

  const nextCursor =
    versionsResponse.IsTruncated && versionsResponse.NextKeyMarker
      ? encodeOpaqueCursor({
          kind: 'history',
          path: pathDigest,
          keyMarker: versionsResponse.NextKeyMarker,
          versionIdMarker: versionsResponse.NextVersionIdMarker,
        })
      : null;

  return formatSuccess(
    200,
    {
      path: '/' + filePath,
      versions,
      items: versions,
      count: versions.length,
      cursor: nextCursor,
      hasMore: nextCursor !== null,
      partial: false,
    },
    requestId
  );
}

// ─── POST /vaults/{vaultId}/files/{path}/restore-delete ─────────────────────

/**
 * Restores a soft-deleted file by removing the current S3 delete marker.
 *
 * S3 versioning semantics: a delete marker IS a version. Removing the
 * `IsLatest === true` delete marker via `DeleteObjectCommand({ VersionId })`
 * re-promotes the prior non-marker version as the new head — no ciphertext
 * is touched, no DEK lookup happens, no re-encryption is needed (the prior
 * version is already encrypted with the current DEK because the delete
 * itself was not a re-encryption boundary).
 *
 * Permission gate (per Phase 5 / UND-02):
 *   1. verifyActiveUser — already done by the top-level dispatcher
 *   2. requireVaultMember(user, vaultId, 'admin') — admin role required
 *   3. evaluatePermission('write', '/' + relPath) — per-path ACL check
 *
 * Audit:
 *   - success: action 'files.restore.softDelete' with metadata
 *     { removedDeleteMarkerVersionId, restoredVersionId }
 *   - denied:  action 'files.restore.softDelete.denied' with outcome 'denied'
 *
 * Responses:
 *   - 200 { path, versionId, restoredFrom } on success
 *   - 404 if the current head is not a delete marker (file not soft-deleted)
 *   - 409 if every version is a delete marker (pathological state)
 *   - 403 on permission denial (audited)
 *   - AuthError statusCode for non-member / non-admin (typically 401/403/404)
 */
async function handleRestoreDelete(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // The greedy `{filePath+}` path parameter ends in `/restore-delete` — strip
  // the suffix to recover the actual file path.
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  if (!rawPath.endsWith('/restore-delete')) {
    return formatError(404, 'Invalid restore-delete path', requestId);
  }
  const filePath = sanitizeFilePath(rawPath.slice(0, -'/restore-delete'.length));
  if (!filePath) {
    return formatError(400, 'Missing file path', requestId);
  }
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(404, `File not found: ${filePath}`, requestId);
  }

  // Upgrade the dispatcher's viewer-level membership check to 'admin' for
  // this destructive recovery operation. Org admins bypass the role check
  // inside requireVaultMember (see shared/utils.ts:1704). On failure we
  // emit a files.restore.softDelete.denied audit row before propagating
  // the typed error to the top-level dispatcher (T-05-03 mitigation).
  try {
    await requireVaultMember(user, vault.vaultId, 'admin');
  } catch (err: unknown) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.restore.softDelete.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'role_check_failed' },
    }, event);
    throw err;
  }

  // Per-path ACL check — write action, since restore re-promotes content at
  // the path and a denied 'write' rule should block restore the same way it
  // blocks an overwrite. LF1: evaluate on the vault-membership role, not user.roles.
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(
    user.userId,
    permRoles,
    'write',
    '/' + filePath,
    user.orgId,
    vault.vaultId,
    await fileOpPermissionOptions(user, vault)
  );
  if (!permResult.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.restore.softDelete.denied',
      resourcePath: '/' + filePath,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { matchedRule: permResult.matchedRule?.id },
    }, event);
    return formatError(403, 'Access denied: insufficient permissions to restore this file', requestId);
  }

  const key = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;

  // Find the current delete marker via ListObjectVersionsCommand. The Prefix
  // returns anything starting with `key`, so we filter to exact-key matches
  // (e.g. a sibling file whose key starts with the same characters).
  const mutationPermit = await acquireVaultMutationPermit({
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  try {
  const listRes = await s3Client.send(
    new ListObjectVersionsCommand({
      Bucket: S3_BUCKET,
      Prefix: key,
      MaxKeys: 100,
    })
  );

  const markers = (listRes.DeleteMarkers ?? []).filter((m) => m.Key === key);
  const versions = (listRes.Versions ?? []).filter((v) => v.Key === key);

  const currentMarker = markers.find((m) => m.IsLatest === true);
  if (!currentMarker || !currentMarker.VersionId) {
    return formatError(404, 'File is not soft-deleted', requestId);
  }

  // Pathological-state defense (PATTERNS open Q7): if every version is a
  // delete marker (no recoverable content version exists), bail out with 409
  // before touching anything. In normal S3 use this can't happen — the
  // first PUT must have been a non-marker version — but a corrupted history
  // or hand-edited bucket could land us here.
  const priorNonMarker = versions
    .filter((v) => v.VersionId && v.VersionId !== currentMarker.VersionId)
    .sort((a, b) => {
      const aT = a.LastModified instanceof Date ? a.LastModified.getTime() : 0;
      const bT = b.LastModified instanceof Date ? b.LastModified.getTime() : 0;
      return bT - aT;
    })[0];
  if (!priorNonMarker || !priorNonMarker.VersionId) {
    return formatError(409, 'No recoverable prior version', requestId);
  }

  // A version-list row does not carry object metadata. Read the exact prior
  // version before lazily materializing it so a post-P1-003 object keeps the
  // fileVersionId and integrity commitments written with its ciphertext. This
  // is metadata-only and does not rewrite historical content.
  const priorObservation = fileVersionStore
    ? await headObjectOrNull({ Key: key, VersionId: priorNonMarker.VersionId })
    : null;

  const restoredLogicalVersion =
    (await findLogicalVersionByStorage({
      orgId: user.orgId,
      vaultId: vault.vaultId,
      storageBucket: S3_BUCKET,
      storageKey: key,
      storageVersionId: priorNonMarker.VersionId,
    })) ??
    (await putLogicalVersion(
      fileVersionFromStorageObservation({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        path: filePath,
        storageBucket: S3_BUCKET,
        storageKey: key,
        storageVersionId: priorNonMarker.VersionId,
        storageEtag: priorObservation?.ETag,
        contentType: priorObservation?.ContentType,
        ciphertextBytes: priorObservation?.ContentLength ?? priorNonMarker.Size ?? 0,
        lastModified: priorNonMarker.LastModified?.toISOString(),
        metadata: priorObservation?.Metadata,
      }),
    ));
  const deleteMarkerLogicalVersion =
    (await findLogicalVersionByStorage({
      orgId: user.orgId,
      vaultId: vault.vaultId,
      storageBucket: S3_BUCKET,
      storageKey: key,
      storageVersionId: currentMarker.VersionId,
    })) ??
    (await putLogicalVersion(
      fileVersionFromStorageObservation({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        path: filePath,
        storageBucket: S3_BUCKET,
        storageKey: key,
        storageVersionId: currentMarker.VersionId,
        ciphertextBytes: 0,
        lastModified: currentMarker.LastModified?.toISOString(),
        state: 'tombstone',
        fallbackFileId: restoredLogicalVersion.fileId,
        parentFileVersionIds: [restoredLogicalVersion.fileVersionId],
      }),
    ));
  verifyStorageBinding(restoredLogicalVersion, {
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    storageBucket: S3_BUCKET,
    storageKey: key,
    storageVersionId: priorNonMarker.VersionId,
    storageEtag: priorObservation?.ETag,
    contentType: priorObservation?.ContentType,
    ciphertextBytes: priorObservation?.ContentLength ?? priorNonMarker.Size ?? 0,
    metadata: priorObservation?.Metadata,
  });
  verifyStorageBinding(deleteMarkerLogicalVersion, {
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    storageBucket: S3_BUCKET,
    storageKey: key,
    storageVersionId: currentMarker.VersionId,
    ciphertextBytes: 0,
    state: 'tombstone',
  });
  if (
    deleteMarkerLogicalVersion.fileId !== restoredLogicalVersion.fileId ||
    (!deleteMarkerLogicalVersion.fileVersionId.startsWith('fver_legacy_') &&
      deleteMarkerLogicalVersion.parentFileVersionIds[0] !==
        restoredLogicalVersion.fileVersionId)
  ) {
    throw new FileVersionIntegrityError(
      'Delete-marker lineage does not match the version being restored',
    );
  }

  const mutationIntent = await beginVaultMutationIntent({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'created',
    path: '/' + filePath,
    actorUserId: user.userId,
    verification: { kind: 'restored-version', versionId: priorNonMarker.VersionId },
  });

  // Remove the delete marker. S3 automatically promotes the most-recent
  // non-marker version as the new head.
  try {
    await s3Client.send(
      new DeleteObjectCommand({
        Bucket: S3_BUCKET,
        Key: key,
        VersionId: currentMarker.VersionId,
      })
    );
  } catch (error) {
    await abortMutationIntentAfterDefiniteFailure(mutationIntent);
    throw error;
  }

  await publishMutationIntentOrThrow(mutationIntent);

  // Removing the delete marker makes the prior object active again. Mirror the
  // normal write path so active-storage accounting and warm sync cursors notice
  // the restored file without waiting for a cold full scan.
  const restoredSizeBytes = priorNonMarker.Size ?? 0;
  if (restoredSizeBytes > 0) {
    const orgResult = await getActiveOrg(user.orgId);
    if (orgResult.org) {
      await updateOrgStorageUsage(orgResult.org.slug, restoredSizeBytes);
    }
  }

  // Phase 6 (Plan 06-02): chain-of-custody record of which DEK is active when
  // the file is re-promoted. Future Phase 7 cross-DEK restore reads this to
  // correlate restored versions to historical keys.
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.restore.softDelete',
    resourcePath: '/' + filePath,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      removedDeleteMarkerVersionId: currentMarker.VersionId,
      restoredVersionId: priorNonMarker.VersionId,
      restoredFileVersionId: restoredLogicalVersion.fileVersionId,
      removedTombstoneFileVersionId: deleteMarkerLogicalVersion.fileVersionId,
      restoredSizeBytes,
      ...(activeKeyId ? { keyId: activeKeyId } : {}),
    },
  }, event);

  return formatSuccess(
    200,
    {
      path: filePath,
      versionId: priorNonMarker.VersionId,
      restoredFrom: currentMarker.VersionId,
      fileId: restoredLogicalVersion.fileId,
      fileVersionId: restoredLogicalVersion.fileVersionId,
      restoredFromFileVersionId: deleteMarkerLogicalVersion.fileVersionId,
    },
    requestId
  );
  } finally {
    await releaseVaultMutationPermit(mutationPermit);
  }
}

// ─── POST /vaults/{vaultId}/files/{path+}/restore ───────────────────────────

/**
 * Synthesize an event whose `filePath` + `path` end in `/restore-delete` so
 * `handleRestoreDelete`'s path-suffix check succeeds when we delegate to it
 * from `handleRestoreVersion`. The original `/restore`-shaped event would
 * fail the `endsWith('/restore-delete')` guard inside that handler.
 *
 * We deliberately copy-then-overwrite (rather than mutate the caller's event)
 * so the audit emission's `event` reference still reflects the original API
 * Gateway path the user actually invoked.
 */
function deleteMarkerEvent(event: APIGatewayProxyEvent, filePath: string): APIGatewayProxyEvent {
  const restoreDeleteSuffix = `${filePath}/restore-delete`;
  const newPath = `/vaults/${event.pathParameters?.vaultId ?? ''}/files/${restoreDeleteSuffix}`;
  return {
    ...event,
    path: newPath,
    pathParameters: {
      ...(event.pathParameters ?? {}),
      filePath: restoreDeleteSuffix,
      path: restoreDeleteSuffix,
    },
  };
}

/**
 * Cross-DEK version restore — Phase 7, Plan 07-01.
 *
 * Restores a noncurrent S3 versionId as the new head. The historical version
 * may have been encrypted with a DEK that's no longer active (after one or more
 * rotations), so this handler runs the 13-step cross-DEK crypto flow locked in
 * `.planning/phases/07-cross-dek-version-restore-admin-ui/07-CONTEXT.md`:
 *
 *   1. GetObjectCommand({ VersionId }) — fetch the historical ciphertext.
 *   2. Read `Metadata['vaultguard-key-id']`. Missing or 'legacy' → 410 Gone.
 *   3. Query `user_keys` via `keyId-index` GSI for the source keyId.
 *      Retry up to 2× with 200ms backoff (DDB GSI eventual consistency).
 *   4. KMS Decrypt with `scopeKmsContext(orgId, scope, vaultId)` — KMS refuses
 *      with InvalidCiphertextException if the context doesn't match what was
 *      used at GenerateDataKey time (T-07-02). Authoritative.
 *   5. AES-decrypt the historical ciphertext with the unwrapped DEK.
 *   6. Fetch the current ACTIVE DEK via `getActiveScopeDataKey('/**')`.
 *   7. AES-encrypt the plaintext with the current DEK.
 *   8. `plaintext.fill(0)` — best-effort wipe.
 *   9. PutObjectCommand with new Metadata including 'vaultguard-key-id' (new),
 *      'restored-from-version', 'modified-by', 'modified-at'.
 *  10. Audit `files.restore.version` with sourceVersionId, sourceKeyId,
 *      targetVersionId, targetKeyId.
 *  11. Response: { versionId, restoredFrom: { versionId, keyId }, targetKeyId }
 *      — pure metadata, no plaintext (T-07-07 mitigation).
 *
 * Routing rules:
 *  - If the source versionId is a delete marker (S3 returns 405 MethodNotAllowed
 *    for GET on a delete-marker version), route to `handleRestoreDelete` so the
 *    client has a single affordance for both restore types.
 *  - Source not found → 404. Bad body → 400. Permission denied → 403/404 +
 *    `files.restore.version.denied` audit.
 *
 * Permission gate identical to `handleRestoreDelete` (UND-02 / T-07-01):
 *   requireVaultMember(user, vaultId, 'admin')
 *   → evaluatePermission('write', '/' + relPath, ...)
 *
 * 410 Gone messages are uniformly generic (T-07-03): missing keyId metadata,
 * 'legacy' sentinel, and empty GSI after retries all return the same string so
 * callers can't probe for which DEK existed when.
 */
async function handleRestoreVersion(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // The greedy `{filePath+}` path parameter ends in `/restore` — strip the
  // suffix to recover the actual file path.
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  if (!rawPath.endsWith('/restore')) {
    return formatError(404, 'Invalid restore path', requestId);
  }
  const filePath = sanitizeFilePath(rawPath.slice(0, -'/restore'.length));
  if (!filePath) {
    return formatError(400, 'Missing file path', requestId);
  }
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(404, `File not found: ${filePath}`, requestId);
  }

  // Body validation (before permission gate is fine — the permission gate is
  // free of side effects until requireVaultMember runs, and getting a 400 for
  // a malformed body before the role check matches the rest of this handler).
  const body = parseBody(event);
  const requestedSourceVersionId = body?.versionId;
  const requestedSourceFileVersionId =
    typeof body?.fileVersionId === 'string'
      ? readBoundedLogicalVersionId(body.fileVersionId, 'fileVersionId')
      : undefined;
  if (
    (requestedSourceVersionId === undefined && !requestedSourceFileVersionId) ||
    (requestedSourceVersionId !== undefined && requestedSourceFileVersionId) ||
    (requestedSourceVersionId !== undefined &&
      (typeof requestedSourceVersionId !== 'string' ||
        requestedSourceVersionId.length === 0 ||
        requestedSourceVersionId.length > 1024 ||
        /[\r\n]/.test(requestedSourceVersionId)))
  ) {
    return formatError(
      400,
      'Provide exactly one valid body field: versionId or fileVersionId',
      requestId,
    );
  }
  const expectedCurrentVersionId = body?.expectedCurrentVersionId;
  if (
    !expectedCurrentVersionId ||
    typeof expectedCurrentVersionId !== 'string' ||
    expectedCurrentVersionId.length > 1024 ||
    /[\r\n]/.test(expectedCurrentVersionId)
  ) {
    return formatError(400, 'Missing or invalid body field: expectedCurrentVersionId', requestId);
  }

  // Upgrade the dispatcher's viewer-level membership to 'admin' for this
  // destructive recovery operation. Org admins bypass the role check inside
  // requireVaultMember. On failure we emit a `.denied` audit row before
  // propagating the typed error to the top-level dispatcher (T-07-01, T-07-05).
  try {
    await requireVaultMember(user, vault.vaultId, 'admin');
  } catch (err: unknown) {
    await logAudit(
      {
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'files.restore.version.denied',
        resourcePath: '/' + filePath,
        outcome: 'denied',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: { reason: 'role_check_failed' },
      },
      event
    );
    throw err;
  }

  // Per-path ACL check — write action, since restore re-promotes content at
  // the path. A denied 'write' rule should block restore the same way it
  // blocks an overwrite. LF1: evaluate on the vault-membership role, not user.roles.
  const permRoles = await resolveFileOpRoles(user, vault);
  const permResult = await evaluatePermission(
    user.userId,
    permRoles,
    'write',
    '/' + filePath,
    user.orgId,
    vault.vaultId,
    await fileOpPermissionOptions(user, vault)
  );
  if (!permResult.allowed) {
    await logAudit(
      {
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'files.restore.version.denied',
        resourcePath: '/' + filePath,
        outcome: 'denied',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: { matchedRule: permResult.matchedRule?.id },
      },
      event
    );
    return formatError(403, 'Access denied: insufficient permissions to restore this file', requestId);
  }
  const authorizationBinding = await bindFileAuthorizationGenerations(user, vault);

  const requestedLogicalVersion = requestedSourceFileVersionId
    ? await requireLogicalVersionStore().require(
        user.orgId,
        vault.vaultId,
        requestedSourceFileVersionId,
      )
    : null;
  if (
    requestedLogicalVersion &&
    (requestedLogicalVersion.path !== filePath || requestedLogicalVersion.state !== 'content')
  ) {
    throw new FileVersionNotFoundError();
  }
  const sourceVersionId =
    requestedLogicalVersion?.storageVersionId ?? String(requestedSourceVersionId);

  const bucket = S3_BUCKET;
  const key = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;

  // Bind the restore to the exact head the caller inspected. The ETag is then
  // carried into the conditional PUT below, closing the HEAD -> PUT race.
  const currentHead = await headObjectOrNull({ Key: key });
  // The outgoing head's size is needed later to account for the active-byte
  // delta this restore causes, so it is part of what binding the head means.
  const previousHeadSizeBytes = currentHead?.ContentLength;
  if (
    !currentHead?.VersionId ||
    currentHead.VersionId !== expectedCurrentVersionId ||
    !currentHead.ETag ||
    typeof previousHeadSizeBytes !== 'number'
  ) {
    await logAudit(
      {
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'files.restore.version.conflict',
        resourcePath: '/' + filePath,
        outcome: 'denied',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: {
          sourceVersionId,
          expectedCurrentVersionId,
          observedCurrentVersionId: currentHead?.VersionId ?? null,
          reason:
            currentHead?.VersionId && currentHead.VersionId !== expectedCurrentVersionId
              ? 'version_mismatch'
              : 'current_head_unavailable',
        },
      },
      event
    );
    return formatError(409, 'Conflict: the current file version changed before restore', requestId);
  }
  const currentLogicalVersion = await observeFileVersion(
    user,
    vault,
    filePath,
    currentHead,
  );

  // STEP 1 — GET the historical ciphertext by VersionId.
  type S3GetResp = {
    Metadata?: Record<string, string>;
    ContentType?: string;
    ContentLength?: number;
    ETag?: string;
    LastModified?: Date;
    VersionId?: string;
    Body?: { transformToByteArray: () => Promise<Uint8Array> };
    DeleteMarker?: boolean;
  };
  let getResp: S3GetResp;
  try {
    getResp = (await s3Client.send(
      new GetObjectCommand({ Bucket: bucket, Key: key, VersionId: sourceVersionId })
    )) as unknown as S3GetResp;
  } catch (err: unknown) {
    const e = err as { name?: string; Code?: string; $metadata?: { httpStatusCode?: number }; DeleteMarker?: boolean };
    const code = e?.name || e?.Code || '';
    const status = e?.$metadata?.httpStatusCode;
    // STEP 1b — delete-marker source: S3 returns 405 MethodNotAllowed for GET
    // on a delete-marker versionId. Route to handleRestoreDelete — single
    // client affordance covers both flavours of restore.
    if (code === 'MethodNotAllowed' || status === 405 || e?.DeleteMarker === true) {
      return await handleRestoreDelete(deleteMarkerEvent(event, filePath), user, vault, requestId);
    }
    if (code === 'NoSuchVersion' || code === 'NoSuchKey' || code === 'NotFound' || status === 404) {
      return formatError(404, 'Source version not found', requestId);
    }
    throw err;
  }

  // Some S3 responses to a delete-marker GET don't throw — they return with
  // `DeleteMarker: true`. Route the same way as the 405 branch.
  if ((getResp as { DeleteMarker?: boolean })?.DeleteMarker === true) {
    return await handleRestoreDelete(deleteMarkerEvent(event, filePath), user, vault, requestId);
  }

  // STEP 2 — read keyId Metadata (SDK lowercases all metadata keys).
  const sourceKeyId = getResp.Metadata?.['vaultguard-key-id'];
  if (!sourceKeyId) {
    return formatError(410, 'Historical key material is no longer available', requestId);
  }

  // STEP 3 — 'legacy' sentinel → 410.
  if (sourceKeyId === 'legacy') {
    return formatError(410, 'Historical key material is no longer available', requestId);
  }

  const mutationPermit = await acquireVaultMutationPermit({
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  try {
  // STEPS 4–7 — resolve the exact version's tenant-bound DEK, reconstruct
  // the original KMS EncryptionContext, unwrap, decrypt, and wipe key material
  // inside the shared crypto service.
  const ciphertextBody = await getResp.Body!.transformToByteArray();
  const ciphertext = Buffer.from(ciphertextBody);
  const sourceLogicalVersion = await observeFileVersion(user, vault, filePath, {
    ...getResp,
    VersionId: getResp.VersionId ?? sourceVersionId,
    ContentLength: getResp.ContentLength ?? ciphertext.byteLength,
  });
  if (sourceLogicalVersion) {
    assertRequestedLogicalVersion(requestedLogicalVersion, sourceLogicalVersion);
    verifyCiphertextIntegrity(sourceLogicalVersion, ciphertext, getResp.Metadata);
  }
  const { plaintext } = await decryptExactVaultVersion(
    ciphertext,
    getResp.Metadata,
    { orgId: user.orgId, vaultId: vault.vaultId },
  );

  try {
    if (sourceLogicalVersion) verifyPlaintextIntegrity(sourceLogicalVersion, plaintext);
  } catch (error) {
    plaintext.fill(0);
    throw error;
  }

  // STEPS 8–10 — re-encrypt under the current vault DEK, then zero both the
  // active key and plaintext on every success/error path.
  const {
    newCiphertext,
    plaintextSize,
    plaintextSha256,
    encryptedSha256,
    currentKeyId,
  } = await encryptPlaintextWithActiveVaultKey(plaintext, {
    orgId: user.orgId,
    vaultId: vault.vaultId,
  });
  // Read the length now: the buffer is zeroed on every path below, and a
  // zeroed buffer still reports its byteLength but the value is only correct
  // to use before the PUT has consumed it.
  const newCiphertextSizeBytes = newCiphertext.byteLength;
  const createdAt = new Date().toISOString();
  const restoredLogicalDraft = createFileVersionDraft({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    path: filePath,
    fileId:
      currentLogicalVersion?.fileId ??
      sourceLogicalVersion?.fileId ??
      legacyFileId(user.orgId, vault.vaultId, filePath),
    fileVersionId: makeFileVersionId(generateId()),
    parentFileVersionIds: currentLogicalVersion
      ? [currentLogicalVersion.fileVersionId]
      : [],
    contentType: getResp.ContentType || 'application/octet-stream',
    plaintextBytes: plaintextSize,
    ciphertextBytes: newCiphertext.byteLength,
    plaintextSha256,
    ciphertextSha256: encryptedSha256,
    cloudKeyId: currentKeyId,
    createdAt,
    actorIdentityId: user.userId,
    agentSessionId: user.sessionId,
    restoredFromFileVersionId: sourceLogicalVersion?.fileVersionId ?? null,
  });

  try {
    await revalidateFileAuthorization(
      authorizationBinding,
      user,
      vault.vaultId,
      filePath,
      'write',
      'admin',
      403,
      'Access denied: insufficient permissions to restore this file',
      event,
    );
  } catch (error) {
    newCiphertext.fill(0);
    throw error;
  }

  let mutationIntent: VaultMutationIntent;
  try {
    mutationIntent = await beginVaultMutationIntent({
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'modified',
      path: '/' + filePath,
      actorUserId: user.userId,
      verification: { kind: 'object-metadata' },
    });
  } catch (error) {
    newCiphertext.fill(0);
    throw error;
  }

  // STEP 11 — PUT as the new head with audit-tagged Metadata.
  let putResp;
  try {
    putResp = await s3Client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: newCiphertext,
        ChecksumSHA256: checksumBase64FromHex(encryptedSha256),
        ContentType: getResp.ContentType || 'application/octet-stream',
        IfMatch: currentHead.ETag,
        Metadata: logicalVersionMetadata(restoredLogicalDraft, {
          'modified-by': user.userId,
          'modified-at': createdAt,
          'vaultguard-key-id': currentKeyId,
          'vaultguard-plaintext-sha256': plaintextSha256,
          'vaultguard-plaintext-size': String(plaintextSize),
          'vaultguard-encrypted-sha256': encryptedSha256,
          'vaultguard-mutation-id': mutationIntent.intentId,
          'restored-from-version': sourceVersionId,
          'restore-expected-version': expectedCurrentVersionId,
        }),
      })
    );
  } catch (error: unknown) {
    newCiphertext.fill(0);
    await abortMutationIntentAfterDefiniteFailure(mutationIntent);
    const name = error && typeof error === 'object' && 'name' in error
      ? String((error as { name: unknown }).name)
      : '';
    const status = error && typeof error === 'object' && '$metadata' in error
      ? (error as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode
      : undefined;
    if (
      name === 'PreconditionFailed' ||
      name === 'ConditionalRequestConflict' ||
      name === 'NotFound' ||
      name === 'NoSuchKey' ||
      status === 404 ||
      status === 409 ||
      status === 412
    ) {
      await logAudit(
        {
          userId: user.userId,
          userEmail: user.email,
          orgId: user.orgId,
          vaultId: vault.vaultId,
          action: 'files.restore.version.conflict',
          resourcePath: '/' + filePath,
          outcome: 'denied',
          ipAddress: getClientIp(event),
          userAgent: getUserAgent(event),
          metadata: {
            sourceVersionId,
            expectedCurrentVersionId,
            observedCurrentVersionId: currentHead.VersionId,
            reason: 'conditional_write_failed',
            errorName: name || null,
            httpStatusCode: status ?? null,
          },
        },
        event
      );
      return formatError(409, 'Conflict: the current file version changed during restore', requestId);
    }
    throw error;
  }
  newCiphertext.fill(0);

  const targetLogicalVersion = await persistBoundFileVersion(restoredLogicalDraft, {
    storageKey: key,
    storageVersionId: (putResp as { VersionId?: string }).VersionId,
    storageEtag: (putResp as { ETag?: string }).ETag,
  });

  await publishMutationIntentOrThrow(mutationIntent);

  // A restore swaps one active ciphertext head for another, so only the
  // active-byte delta is billable. The noncurrent versions this leaves behind
  // are governed by the bucket's retention contract and are not part of org
  // active-storage use. Both sizes are already in hand, so this adds no S3
  // read. Every sibling write path in this handler accounts for its bytes;
  // restore was the one that did not, which let org usage drift on each call.
  const storageDeltaBytes = newCiphertextSizeBytes - previousHeadSizeBytes;
  if (storageDeltaBytes !== 0) {
    const orgResult = await getActiveOrg(user.orgId);
    if (orgResult.org) {
      await updateOrgStorageUsage(orgResult.org.slug, storageDeltaBytes);
    }
  }

  // STEP 12 — capture the new head versionId.
  const targetVersionId = (putResp as { VersionId?: string }).VersionId || '';

  // STEP 13 — emit the success audit row (T-07-05 chain-of-custody).
  await logAudit(
    {
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'files.restore.version',
      resourcePath: '/' + filePath,
      outcome: 'success',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        sourceVersionId,
        sourceFileVersionId: sourceLogicalVersion?.fileVersionId,
        parentFileVersionId: currentLogicalVersion?.fileVersionId,
        expectedCurrentVersionId,
        sourceKeyId,
        targetVersionId,
        targetFileVersionId: targetLogicalVersion.fileVersionId,
        targetKeyId: currentKeyId,
      },
    },
    event
  );

  // Response is pure metadata — never include plaintext (T-07-07).
  return formatSuccess(
    200,
    {
      versionId: targetVersionId,
      fileId: targetLogicalVersion.fileId,
      fileVersionId: targetLogicalVersion.fileVersionId,
      restoredFrom: {
        versionId: sourceVersionId,
        fileVersionId: sourceLogicalVersion?.fileVersionId,
        keyId: sourceKeyId,
      },
      targetKeyId: currentKeyId,
    },
    requestId
  );
  } finally {
    await releaseVaultMutationPermit(mutationPermit);
  }
}

// ─── GET /vaults/{vaultId}/files/deleted ────────────────────────────────────

/**
 * Lists files whose current S3 head is a delete marker (i.e. soft-deleted).
 *
 * Per-row permission filtering mirrors handleListFiles: the caller only
 * sees deleted paths they can `read`. Returns path + delete-marker
 * versionId + ISO-formatted deletion timestamp. `previousSize` is
 * intentionally omitted from the v1 response (would require N extra S3
 * calls per file — PATTERNS open Q6).
 */
async function handleListDeleted(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Upgrade to admin — the deleted-files affordance is admin-only so it
  // matches the restore endpoint's permission gate. Non-admins should not
  // even learn that soft-deleted files exist.
  await requireVaultMember(user, vault.vaultId, 'admin');

  // LF1: role-scoped rules bind on the vault-membership role, not user.roles.
  // Org admins pass through unchanged; a vault-admin-not-org-admin gets their
  // 'admin' vault role so a role-scoped read-deny on `admin` is honored here.
  const permRoles = await resolveFileOpRoles(user, vault);
  const prefix = vaultS3Prefix(user.orgId, vault.vaultId);

  interface DeletedFileEntry {
    path: string;
    deleteMarkerVersionId: string;
    fileId: string;
    fileVersionId: string;
    deletedAt: string;
  }

  const limit = parseRecoveryLimit(event.queryStringParameters?.limit);
  const cursor = decodeOpaqueCursor(event.queryStringParameters?.cursor);
  const vaultDigest = sha256Hex(`${user.orgId}:${vault.vaultId}`);
  if (
    Object.keys(cursor).length > 0 &&
    (cursor.kind !== 'deleted' || cursor.vault !== vaultDigest)
  ) {
    return formatError(400, 'Pagination cursor does not belong to this vault', requestId);
  }
  const res = await s3Client.send(
    new ListObjectVersionsCommand({
      Bucket: S3_BUCKET,
      Prefix: prefix,
      MaxKeys: limit,
      KeyMarker: cursor.keyMarker,
      VersionIdMarker: cursor.versionIdMarker,
    })
  );
  const files: DeletedFileEntry[] = [];
  const permissionOptions = await fileOpPermissionOptions(user, vault);

  for (const marker of res.DeleteMarkers ?? []) {
    if (marker.IsLatest !== true || !marker.Key || !marker.VersionId || !marker.LastModified) continue;
    const relPath = marker.Key.slice(prefix.length);
    if (!relPath) continue;
    if (isClientLocalOnlyPath(relPath)) continue;
    if (isFolderMarkerPath(relPath)) continue;

    // Per-row permission filter — only include paths the caller can read.
    const perm = await evaluatePermission(
      user.userId,
      permRoles,
      'read',
      '/' + relPath,
      user.orgId,
      vault.vaultId,
      permissionOptions
    );
    if (!perm.allowed) continue;

    const deletedAt =
      marker.LastModified instanceof Date
        ? marker.LastModified.toISOString()
        : String(marker.LastModified);
    const logicalVersion =
      (await findLogicalVersionByStorage({
        orgId: user.orgId,
        vaultId: vault.vaultId,
        storageBucket: S3_BUCKET,
        storageKey: marker.Key,
        storageVersionId: marker.VersionId,
      })) ??
      (await putLogicalVersion(
        fileVersionFromStorageObservation({
          orgId: user.orgId,
          vaultId: vault.vaultId,
          path: relPath,
          storageBucket: S3_BUCKET,
          storageKey: marker.Key,
          storageVersionId: marker.VersionId,
          ciphertextBytes: 0,
          lastModified: deletedAt,
          state: 'tombstone',
        }),
      ));

    files.push({
      path: relPath,
      deleteMarkerVersionId: marker.VersionId,
      fileId: logicalVersion.fileId,
      fileVersionId: logicalVersion.fileVersionId,
      deletedAt,
    });
  }

  const nextCursor =
    res.IsTruncated && res.NextKeyMarker
      ? encodeOpaqueCursor({
          kind: 'deleted',
          vault: vaultDigest,
          keyMarker: res.NextKeyMarker,
          versionIdMarker: res.NextVersionIdMarker,
        })
      : null;

  return formatSuccess(
    200,
    {
      files,
      items: files,
      cursor: nextCursor,
      hasMore: nextCursor !== null,
      partial: false,
    },
    requestId
  );
}

// ─── POST /vaults/{vaultId}/files/sync ──────────────────────────────────────

/** Maximum age of `lastSyncTimestamp` for the activity-log fast path to be
 *  trusted. Set 1 day below the activity-log TTL so we never query against a
 *  partially-pruned log. Older clients fall back to the full S3 listing. */
const ACTIVITY_LOG_VALID_WINDOW_MS = 13 * 24 * 60 * 60 * 1000;

/**
 * Result of consulting the activity log. Either we have a fully-formed
 * warm-path delta set, or we have a reason we need to fall back to the
 * cold path (with `permissionsChanged` propagated up so the client can
 * invalidate its local permission cache).
 */
type ActivityLogResult =
  | { kind: 'warm'; deltas: SyncDelta[] }
  | { kind: 'fallback'; reason: 'epoch' | 'stale-cursor' | 'permission-changed' | 'activity-overflow'; permissionsChanged: boolean };

/**
 * Maximum number of activity-log events the warm path will deliver in one
 * response. If more than this changed since the client's cursor, we cannot
 * return the full delta set without silently truncating (queryVaultActivity
 * returns the OLDEST N and drops the newest), so we fall back to the cold
 * full-S3 scan instead. LF4.
 */
const ACTIVITY_LOG_SYNC_CAP = 1000;

/**
 * Pulls the changed-paths set from the vault activity log, dedupes by path
 * (last-action wins), and runs each path through the permission engine. The
 * resulting deltas are dressed up with the current S3 metadata so the client
 * sees the same shape it would from the full-scan path.
 *
 * Returns a `fallback` result when the activity log can't be trusted for
 * this client's cursor (too old, never synced, or a permission rule
 * changed since lastSync) so the caller can run the full listing scan.
 */
async function buildSyncDeltasFromActivityLog(
  user: UserContext,
  vault: VaultRecord,
  lastSyncMs: number
): Promise<ActivityLogResult> {
  if (lastSyncMs <= 0) {
    return { kind: 'fallback', reason: 'epoch', permissionsChanged: false };
  }
  if (Date.now() - lastSyncMs > ACTIVITY_LOG_VALID_WINDOW_MS) {
    return { kind: 'fallback', reason: 'stale-cursor', permissionsChanged: false };
  }

  // Request one more than the cap so we can distinguish "exactly at the cap"
  // from "overflowed". If we overflowed, the oldest-N truncation would silently
  // drop the newest changes — fall back to the cold scan instead (LF4).
  const events = await queryVaultActivity(vault.vaultId, lastSyncMs, ACTIVITY_LOG_SYNC_CAP + 1);
  if (events.length > ACTIVITY_LOG_SYNC_CAP) {
    return { kind: 'fallback', reason: 'activity-overflow', permissionsChanged: false };
  }

  // Permission rule changes can flip every file's accessibility at once.
  // The activity log doesn't enumerate which files are affected — we'd
  // need a per-file scan with re-evaluation to know. Force the caller to
  // fall back to the cold path (full S3 listing + per-file
  // evaluatePermission) which already does that work, and surface a flag
  // so the client knows to invalidate its local permission cache.
  const hasPermissionChange = events.some((e) => e.action === 'permission_changed');
  if (hasPermissionChange) {
    return { kind: 'fallback', reason: 'permission-changed', permissionsChanged: true };
  }

  // Dedupe by path so a file written 50 times appears once. ASC ordering of
  // the Query means the last entry written to the map is the most recent.
  const latestByPath = new Map<string, VaultActivityRecord>();
  for (const event of events) {
    if (event.action === 'permission_changed') continue;
    latestByPath.set(event.path, event);
  }

  const deltas: SyncDelta[] = [];
  const permRoles = await resolveFileOpRoles(user, vault);

  for (const event of latestByPath.values()) {
    const path = event.path;
    if (isClientLocalOnlyPath(path)) continue;
    const isMarker = isFolderMarkerPath(path.replace(/^\/+/, ''));

    if (event.action === 'deleted') {
      if (isMarker) {
        // Markers carry no content but their path still leaks the folder name
        // and structure. Gate on the parent folder's read permission.
        if (!(await canSeeFolderMarker(user, vault, path))) continue;
      } else {
        const perm = await evaluatePermission(user.userId, permRoles, 'read', path, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
        if (!perm.allowed) continue;
      }
      deltas.push({
        path,
        action: 'deleted',
        lastModified: event.changedAt,
        checksum: '',
        size: 0,
      });
      continue;
    }

    // Created or modified — gate on read permission, then HEAD the current
    // object to fill in size/checksum/lastModified. If the HEAD fails (e.g.
    // the object was deleted again after the activity-log entry was
    // written), drop this delta — a later sync will pick up the deletion.
    if (isMarker) {
      if (!(await canSeeFolderMarker(user, vault, path))) continue;
    } else {
      const perm = await evaluatePermission(user.userId, permRoles, 'read', path, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
      if (!perm.allowed) continue;
    }

    const s3Key = vaultS3Prefix(user.orgId, vault.vaultId) + path.replace(/^\/+/, '');
    try {
      const head = await s3Client.send(
        new HeadObjectCommand({ Bucket: S3_BUCKET, Key: s3Key })
      );
      deltas.push({
        path,
        action: event.action === 'permission_changed' ? 'modified' : event.action,
        lastModified: head.LastModified?.toISOString() ?? event.changedAt,
        checksum: head.ETag ?? '',
        size: head.ContentLength ?? 0,
        // BIN-A / D-04: the HeadObject already carries ContentType — attach it at
        // zero extra AWS cost so the pull side can pre-sort binary vs text.
        contentType: head.ContentType,
      });
    } catch (err: unknown) {
      const isMissing = err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NotFound';
      if (!isMissing) throw err;
      // Object was deleted after the create/modify event was logged. Skip
      // this delta — the next activity-log sweep will pick up the deletion.
    }
  }

  return { kind: 'warm', deltas };
}

/**
 * Delta sync endpoint for efficient client synchronization.
 *
 * Two execution paths:
 * 1. **Warm path** — when the client provides a `lastSyncTimestamp` newer
 *    than the activity-log retention window, query the log and return only
 *    paths that actually changed. No full S3 scan, no big permission sweep.
 * 2. **Cold path** — first sync (epoch) or stale cursor: fall back to a
 *    full paginated S3 listing and diff against the client's manifest. This
 *    is the deletion-detection path that the manifest is designed for.
 *
 * Request body:
 * - lastSyncTimestamp: ISO timestamp of last successful sync (required)
 * - fileChecksums: presence-only map of path -> "" (used by cold path for
 *   deletion detection; ignored on the warm path)
 * - prefix: optional vault-relative prefix to scope the response
 */
async function handleSync(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['lastSyncTimestamp']);

  const lastSyncTimestamp = body.lastSyncTimestamp as string;
  const clientChecksums = (body.fileChecksums as Record<string, string>) || {};
  const prefix = (body.prefix as string) || '';

  const lastSyncDate = new Date(lastSyncTimestamp);

  if (isNaN(lastSyncDate.getTime())) {
    return formatError(400, 'Invalid lastSyncTimestamp format', requestId);
  }

  const pendingMutationIntents = await reconcilePendingMutationIntents(user, vault);
  const reconciliationRequired = pendingMutationIntents.length > 0;

  // LF5: snapshot the high-water mark (timestamp + revision) BEFORE reading any
  // deltas. Returning a cursor captured at handler END would permanently skip a
  // write that lands mid-handler (after the activity/S3 read but before the
  // response): the client persists a cursor newer than that write and never
  // re-queries it. Capturing before the read gives at-least-once delivery — a
  // boundary write is simply re-included next sync (idempotent; a delta is just
  // "download this path"). Both return paths use these snapshots.
  const syncStartedAt = new Date().toISOString();
  const cursorSnapshot = await getVaultCursor(user.orgId, vault.vaultId);

  // ── Warm path: activity-log-driven incremental sync ───────────────────────
  // Only attempted when the client has a recent enough cursor for the log
  // to cover the gap. The result tells us whether the warm path was
  // applicable; when it wasn't, we propagate `permissionsChanged` into
  // the cold-path response so the client can invalidate its local
  // permission cache.
  let permissionsChanged = false;
  if (!prefix && !reconciliationRequired) {
    const warm = await buildSyncDeltasFromActivityLog(user, vault, lastSyncDate.getTime());
    if (warm.kind === 'warm') {
      const cursor = cursorSnapshot;
      await logAudit({
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'files.sync',
        resourcePath: '/',
        outcome: 'success',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: {
          mode: 'activity-log',
          deltaCount: warm.deltas.length,
          lastSyncTimestamp,
          revision: cursor.revision,
        },
      });
      return formatSuccess(
        200,
        {
          deltas: warm.deltas,
          count: warm.deltas.length,
          syncTimestamp: syncStartedAt,
          revision: cursor.revision,
          mode: 'activity-log',
          permissionsChanged: false,
          reconciliationRequired: false,
          isTruncated: false,
        },
        requestId
      );
    }
    permissionsChanged = warm.permissionsChanged;
  }

  // ── Cold path: full S3 listing scan ───────────────────────────────────────
  // List every file under this vault prefix, paginating through S3 so vaults
  // with more than 1000 objects still produce a complete delta set.
  const deltas: SyncDelta[] = [];
  const permRoles = await resolveFileOpRoles(user, vault);
  const serverPaths = new Set<string>();
  let continuationToken: string | undefined;

  do {
    const s3Response = await s3Client.send(
      new ListObjectsV2Command({
        Bucket: S3_BUCKET,
        Prefix: vaultS3Prefix(user.orgId, vault.vaultId) + prefix,
        ContinuationToken: continuationToken,
      })
    );

    for (const obj of s3Response.Contents || []) {
      const relativePath = '/' + obj.Key!.replace(vaultS3Prefix(user.orgId, vault.vaultId), '');
      if (isClientLocalOnlyPath(relativePath)) continue;
      serverPaths.add(relativePath);

      // Folder markers are returned in sync deltas (so the plugin can mirror
      // empty folders), but their path itself leaks the folder name and
      // structure to anyone who can sync. Gate marker exposure on the same
      // read permission the parent folder would require — without this, a
      // deny on `/secret/**` still ships `/secret/.vaultguard-folder` and
      // tells the user the folder exists.
      if (isFolderMarkerPath(relativePath)) {
        if (!(await canSeeFolderMarker(user, vault, relativePath))) continue;
        const objModified = obj.LastModified || new Date(0);
        if (objModified > lastSyncDate || !clientChecksums[relativePath]) {
          deltas.push({
            path: relativePath,
            action: clientChecksums[relativePath] ? 'modified' : 'created',
            lastModified: objModified.toISOString(),
            checksum: obj.ETag || '',
            size: 0,
          });
        }
        continue;
      }

      // Check permission for each file
      const permResult = await evaluatePermission(user.userId, permRoles, 'read', relativePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
      if (!permResult.allowed) continue;

      const objModified = obj.LastModified || new Date(0);
      const objChecksum = obj.ETag || '';
      const clientChecksum = clientChecksums[relativePath];
      // A file the client has NO manifest entry for is absent locally and must
      // be delivered even when its S3 LastModified predates the client's cursor.
      // Without this, a file that was on the server before the cursor but was
      // never landed locally (e.g. a binary a pre-BIN-A client received, skipped
      // writing, yet still advanced its cursor past) is stranded forever: the
      // `objModified > lastSyncDate` gate below never fires and the checksum
      // `else if` requires a client entry. STRICT `=== undefined` is mandatory:
      // buildLocalSyncManifest stores every locally-present file as "" (a
      // presence-only marker), so a falsy `!clientChecksum` would re-download
      // every present file on every cold sync. Mirrors the folder-marker branch
      // above, which already uses the same absent-locally rule.
      const absentLocally = clientChecksum === undefined;

      if (absentLocally || objModified > lastSyncDate) {
        // Absent locally → created; present-but-stale-cursor → modified.
        const action: SyncDelta['action'] = clientChecksum ? 'modified' : 'created';

        // BIN-A / D-04 + L9: cold-path deltas deliberately DO NOT carry contentType.
        // ListObjectsV2 Contents entries have no ContentType, and a per-object
        // HeadObject would explode cold-scan cost (see the list route's hardcoded
        // 'application/octet-stream' at :833). Clients fall back to the authoritative
        // GET-response contentType, which is always present.
        deltas.push({
          path: relativePath,
          action,
          lastModified: objModified.toISOString(),
          checksum: objChecksum,
          size: obj.Size || 0,
        });
      } else if (clientChecksum && clientChecksum !== objChecksum) {
        // Checksum mismatch — file content differs. Empty-string client
        // checksums are presence-only markers (the plugin uses them so the
        // server can detect deletions without computing real ETags) and
        // never trigger this branch.
        deltas.push({
          path: relativePath,
          action: 'modified',
          lastModified: objModified.toISOString(),
          checksum: objChecksum,
          size: obj.Size || 0,
        });
      }
    }

    continuationToken = s3Response.IsTruncated ? s3Response.NextContinuationToken || undefined : undefined;
  } while (continuationToken);

  // Detect deletions: files in client manifest that no longer exist on server
  for (const clientPath of Object.keys(clientChecksums)) {
    if (isClientLocalOnlyPath(clientPath)) continue;
    if (!serverPaths.has(clientPath)) {
      // Folder marker deletions still need the parent-folder read gate —
      // mirrors the creation branch above so denied-folder structure can
      // never round-trip out via a delete delta.
      if (isFolderMarkerPath(clientPath)) {
        if (!(await canSeeFolderMarker(user, vault, clientPath))) continue;
        deltas.push({
          path: clientPath,
          action: 'deleted',
          lastModified: new Date().toISOString(),
          checksum: '',
          size: 0,
        });
        continue;
      }

      // Verify user had permission to see this file
      const permResult = await evaluatePermission(user.userId, permRoles, 'read', clientPath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
      if (permResult.allowed) {
        deltas.push({
          path: clientPath,
          action: 'deleted',
          lastModified: new Date().toISOString(),
          checksum: '',
          size: 0,
        });
      }
    }
  }

  const cursor = cursorSnapshot;

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'files.sync',
    resourcePath: prefix ? `/${prefix}` : '/',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      mode: 'full-scan',
      deltaCount: deltas.length,
      lastSyncTimestamp,
      created: deltas.filter((d) => d.action === 'created').length,
      modified: deltas.filter((d) => d.action === 'modified').length,
      deleted: deltas.filter((d) => d.action === 'deleted').length,
      revision: cursor.revision,
      permissionsChanged,
    },
  });

  return formatSuccess(
    200,
    {
      deltas,
      count: deltas.length,
      syncTimestamp: syncStartedAt,
      revision: cursor.revision,
      mode: 'full-scan',
      permissionsChanged,
      reconciliationRequired,
      isTruncated: false,
    },
    requestId
  );
}

// ─── GET /vaults/{vaultId}/sync-cursor ──────────────────────────────────────

/**
 * Cheap cursor endpoint clients call before the heavyweight sync. Returns
 * the vault's current revision counter and the timestamp of its most recent
 * change. When the client's last-seen revision matches, it can skip the
 * full sync entirely — no S3, no permissions, no payload.
 *
 * One DynamoDB GetItem per call, plus the route-level vault membership
 * check that already ran in the dispatcher.
 */
async function handleSyncCursorGet(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const pendingMutationIntents = await reconcilePendingMutationIntents(user, vault);
  const cursor = await getVaultCursor(user.orgId, vault.vaultId);
  return formatSuccess(
    200,
    {
      revision: cursor.revision,
      lastChangedAt: cursor.lastChangedAt,
      reconciliationRequired: pendingMutationIntents.length > 0,
      serverTime: new Date().toISOString(),
    },
    requestId
  );
}
