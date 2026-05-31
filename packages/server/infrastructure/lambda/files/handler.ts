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
  GetObjectCommand,
  PutObjectCommand,
  ListObjectsV2Command,
  DeleteObjectCommand,
  ListObjectVersionsCommand,
  HeadObjectCommand,
} from '@aws-sdk/client-s3';
import { KMSClient, DecryptCommand } from '@aws-sdk/client-kms';
import {
  aesDecrypt,
  aesEncrypt,
  getActiveScopeDataKey,
  scopeKmsContext,
} from '../reencryption/handler';
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
  getVaultMembership,
  isAdmin,
  vaultRoleMeetsRequirement,
  sanitizeFilePath,
  recordVaultActivity,
  getVaultCursor,
  queryVaultActivity,
  UserContext,
  PermissionAction,
  VaultRecord,
  VaultActivityRecord,
  AuthError,
  GetCommand,
  PutCommand,
  QueryCommand,
} from '../shared/utils';

// ─── Configuration ───────────────────────────────────────────────────────────

const S3_BUCKET = process.env.VAULT_BUCKET || process.env.VAULT_S3_BUCKET!;
const S3_PREFIX_BASE = process.env.VAULT_S3_PREFIX || 'vault/';
const REGION = process.env.AWS_REGION || 'eu-west-1';
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || '10485760', 10); // 10MB default
const DEFAULT_OVERVIEW_LIMIT = 5000;
const MAX_OVERVIEW_LIMIT = 10000;

// Phase 6 (Plan 06-02): the `user_keys` table holds per-`(orgId, scope, vaultId)`
// DEK metadata. This handler does NOT decrypt DEKs (that's the reencryption Lambda's
// job) — it only reads the `keyId` attribute to annotate S3 objects + audit rows so
// Phase 7's cross-DEK restore endpoint can match noncurrent versions to their DEKs.
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE || 'UserKeysTable';

// ─── Active DEK keyId lookup (Plan 06-02) ────────────────────────────────────
//
// These three helpers mirror the equivalent definitions in
// `infrastructure/lambda/reencryption/handler.ts` (the canonical home of
// `scopeKeyPk` / `encodedScope`). They're inline-copied here to avoid pulling
// reencryption-specific symbols into the files handler. If a third caller
// appears (Phase 7 restore endpoint is a likely candidate), extract into
// `shared/utils.ts` instead.

function encodedScope(scope: string): string {
  return Buffer.from(scope, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function scopeKeyPk(orgId: string, scope: string, vaultId?: string): string {
  const scopePart = encodedScope(scope);
  if (vaultId) {
    return `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${scopePart}`;
  }
  return `ORG#${orgId}#SCOPE#${scopePart}`;
}

/**
 * Returns the active DEK's `keyId` for a vault, or `null` if no active row
 * exists yet (pre-backfill / first-ever write).
 *
 * Pre-backfill rows that exist but lack the `keyId` attribute return the
 * `'legacy'` sentinel — matching the same fallback semantics used by
 * `getActiveScopeDataKey` in the reencryption handler. Phase 7's restore
 * endpoint treats `'legacy'` as a "fall back to current-ACTIVE DEK + emit
 * warning audit" signal.
 *
 * Implementation note: this is a single DDB Get on `user_keys` with NO KMS
 * Decrypt call — we only need the metadata id here, not the plaintext key
 * material. The reencryption handler's `getActiveScopeDataKey` does the
 * heavier round-trip when actual decryption is required.
 *
 * Defensive try/catch: T-06-02-05 mitigation — a DDB hiccup must not block
 * the user-visible write. On any failure we log and return null so the write
 * proceeds without keyId tagging.
 */
async function getActiveKeyIdForVault(
  orgId: string,
  vaultId: string
): Promise<string | null> {
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: USER_KEYS_TABLE,
        Key: { pk: scopeKeyPk(orgId, '/**', vaultId), sk: 'ACTIVE' },
      })
    );
    const item = result.Item as { keyId?: string; status?: string } | undefined;
    if (!item || item.status !== 'active') return null;
    if (typeof item.keyId === 'string' && item.keyId.length > 0) {
      return item.keyId;
    }
    // Row exists but is pre-backfill — surface the 'legacy' sentinel so
    // downstream metadata writers know there's no canonical keyId.
    return 'legacy';
  } catch (err) {
    console.error('[VaultGuard] getActiveKeyIdForVault failed:', err);
    return null;
  }
}

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

function permissionEvaluationOptions(user: UserContext): { userAliases: string[] } {
  return { userAliases: user.email ? [user.email] : [] };
}

/**
 * Async variant of {@link permissionEvaluationOptions} that ALSO carries
 * the per-org `respectAdminBypass` flag. File operations call this so
 * that when `allowAdminPerFileRestrictions` is on, per-file deny rules
 * actually take effect on admins' reads/writes/deletes/lists — without
 * this flag the bypass in `evaluatePermission` would short-circuit
 * `allowed=true` for admins and the toggle would only affect what the UI
 * displays, not what the API enforces.
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
  const perm = await evaluatePermission(
    user.userId,
    user.roles,
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

async function decryptCurrentVaultBlobForRead(
  ciphertext: Buffer,
  user: UserContext,
  vault: VaultRecord
): Promise<{ plaintext: Buffer; keyId: string }> {
  const active = await getActiveScopeDataKey(user.orgId, vault.vaultId, '/**');
  if (!active) {
    throw new AuthError('Vault key unavailable for server-side decrypt.', 409);
  }

  try {
    return { plaintext: aesDecrypt(ciphertext, active.key), keyId: active.keyId };
  } finally {
    active.key.fill(0);
  }
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

const s3Client = new S3Client({ region: REGION });

// Phase 7 (Plan 07-01): KMS client for cross-DEK restore. The restore endpoint
// reaches into the keyId-index GSI for a historical user_keys row, then asks
// KMS to unwrap that row's envelope with the row's EncryptionContext (orgId +
// scope + vaultId). Mirroring the s3Client singleton pattern keeps the cold
// start fast and avoids per-request client construction.
const kmsClient = new KMSClient({ region: REGION });

// ─── Types ───────────────────────────────────────────────────────────────────

/** File metadata returned in listings (never includes content). */
interface FileMetadata {
  path: string;
  size: number;
  lastModified: string;
  contentType: string;
  versionId: string;
  checksum: string;
}

/** A version history entry for a file. */
interface FileVersion {
  versionId: string;
  lastModified: string;
  size: number;
  isLatest: boolean;
  isDeleteMarker: boolean;
  modifiedBy?: string;
}

/** Delta sync response item. */
interface SyncDelta {
  path: string;
  action: 'created' | 'modified' | 'deleted';
  lastModified: string;
  checksum: string;
  size: number;
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
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
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
    const isHistoryResource = isFilePathResource && actualPath.endsWith('/history');
    const isOverviewResource = resource === '/vaults/{vaultId}/overview' || actualPath.endsWith('/overview');
    // The greedy `{filePath+}` resource also matches the `/restore-delete` suffix.
    // The dispatch order below ensures the restore arm wins over the generic
    // read/write/delete arms for the same resource string. Donor: isHistoryResource.
    const isRestoreDeleteResource = isFilePathResource && actualPath.endsWith('/restore-delete');
    // Phase 7 (Plan 07-01): cross-DEK version restore. The regex anchor `$`
    // matches `/restore` but NOT `/restore-delete` (which doesn't end at
    // `/restore`); the dispatch order below places this arm BEFORE the generic
    // file-path arms but AFTER `isRestoreDeleteResource` for belt-and-suspenders
    // mutual exclusivity.
    const isRestoreVersionResource = isFilePathResource && /\/restore$/.test(actualPath);
    // Static sibling of `{filePath+}` — `GET /vaults/{vaultId}/files/deleted`
    // is its own API Gateway resource, but older/dev API Gateway deployments may
    // still hand it through the greedy filePath route. Treat the concrete URL as
    // authoritative so the Lambda remains compatible with either resource shape.
    const isDeletedListResource =
      resource === '/vaults/{vaultId}/files/deleted' ||
      actualPath.replace(/\/+$/, '').endsWith('/files/deleted');

    switch (true) {
      case method === 'GET' && resource === '/vaults/{vaultId}/files':
        return await handleListFiles(event, user, vault, requestId);

      case method === 'GET' && isOverviewResource:
        return await handleVaultOverview(event, user, vault, requestId);

      case method === 'GET' && isDeletedListResource:
        return await handleListDeleted(event, user, vault, requestId);

      case method === 'POST' && isRestoreDeleteResource:
        return await handleRestoreDelete(event, user, vault, requestId);

      case method === 'POST' && isRestoreVersionResource:
        return await handleRestoreVersion(event, user, vault, requestId);

      case method === 'GET' && isHistoryResource:
        return await handleGetHistory(event, user, vault, requestId);

      case method === 'GET' && isReadDecryptedResource(resource):
        return await handleReadDecrypted(event, user, vault, requestId);

      case method === 'GET' && isFilePathResource:
        return await handleReadFile(event, user, vault, requestId);

      case method === 'PUT' && isFilePathResource:
        return await handleWriteFile(event, user, vault, requestId);

      case method === 'DELETE' && isFilePathResource:
        return await handleDeleteFile(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/files/sync':
        return await handleSync(event, user, vault, requestId);

      case method === 'GET' && resource === '/vaults/{vaultId}/sync-cursor':
        return await handleSyncCursorGet(event, user, vault, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
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
        ensureOverviewFolder(root, folderPath, lastModified);
        latestModified = maxIsoTimestamp(latestModified, lastModified);
        const folderDepth = folderPath.split('/').filter(Boolean).length;
        maxDepth = Math.max(maxDepth, folderDepth);
        continue;
      }

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

function parseOverviewLimit(rawLimit: string | undefined): number {
  if (!rawLimit) return DEFAULT_OVERVIEW_LIMIT;
  const parsed = Number.parseInt(rawLimit, 10);
  if (!Number.isInteger(parsed) || parsed < 1) return DEFAULT_OVERVIEW_LIMIT;
  return Math.min(parsed, MAX_OVERVIEW_LIMIT);
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
  requestId: string
): Promise<APIGatewayProxyResult> {
  const prefix = event.queryStringParameters?.prefix || '';
  const limit = Math.min(parseInt(event.queryStringParameters?.limit || '100', 10), 1000);
  const continuationToken = event.queryStringParameters?.continuationToken;

  // List objects from S3
  const s3Response = await s3Client.send(
    new ListObjectsV2Command({
      Bucket: S3_BUCKET,
      Prefix: vaultS3Prefix(user.orgId, vault.vaultId) + prefix,
      MaxKeys: limit * 2, // Fetch extra since we'll filter by permissions
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
    const permResult = await evaluatePermission(user.userId, user.roles, 'list', '/' + relativePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

    if (permResult.allowed) {
      files.push({
        path: '/' + relativePath,
        size: obj.Size || 0,
        lastModified: obj.LastModified?.toISOString() || '',
        contentType: 'application/octet-stream', // Would need HeadObject for actual type
        versionId: '', // Would need ListObjectVersions for this
        checksum: obj.ETag || '',
      });
    }

    if (files.length >= limit) break;
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
    metadata: { resultCount: files.length, prefix },
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
  requestId: string
): Promise<APIGatewayProxyResult> {
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  if (isClientLocalOnlyPath(filePath)) {
    return formatError(404, `File not found: ${filePath}`, requestId);
  }

  // Permission check
  const permResult = await evaluatePermission(user.userId, user.roles, 'read', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

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

  // Fetch from S3
  try {
    const s3Response = await s3Client.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      })
    );

    const bodyBytes = await s3Response.Body?.transformToByteArray();
    const encryptedBody = bodyBytes ? Buffer.from(bodyBytes) : Buffer.alloc(0);
    const responseBody = encryptedBody;

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
      },
    });

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
      },
      requestId
    );
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NoSuchKey') {
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
  requestId: string
): Promise<APIGatewayProxyResult> {
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);
  if (!filePath || isClientLocalOnlyPath(filePath)) {
    // 404 (not 403/400) — see D-02. Plugin-internal paths must never be served
    // through this endpoint.
    return formatError(404, 'File not found', requestId);
  }

  // Per-file permission gate — 404 on deny (D-02). Audit BEFORE returning per T-08-05.
  const permResult = await evaluatePermission(
    user.userId,
    user.roles,
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

  // Fetch ciphertext from S3.
  let s3Response;
  try {
    s3Response = await s3Client.send(
      new GetObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      })
    );
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NoSuchKey') {
      // Indistinguishable from permission deny per D-02.
      return formatError(404, 'File not found', requestId);
    }
    throw err;
  }

  const bodyBytes = await s3Response.Body?.transformToByteArray();
  const ciphertext = bodyBytes ? Buffer.from(bodyBytes) : Buffer.alloc(0);

  // Reuse the existing scope-DEK unwrap helper (Phase 6/7 plumbing) — KMS Decrypt
  // with EncryptionContext is the tampering defense (T-08-03). Helper zeros the
  // DEK in its own finally; we zero the plaintext buffer below (T-08-06).
  const { plaintext, keyId } = await decryptCurrentVaultBlobForRead(ciphertext, user, vault);

  let content: string;
  try {
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
      keyId,
    },
  });

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
    },
    requestId
  );
}

// ─── PUT /vaults/{vaultId}/files/{path} ─────────────────────────────────────

/**
 * Writes (creates or updates) a file in S3 after verifying 'write' permission.
 * S3 versioning preserves previous versions automatically.
 *
 * Request body:
 * - content: Base64-encoded file content
 * - contentType: MIME type (optional, defaults to 'text/markdown')
 * - expectedVersionId: For optimistic locking (optional)
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
  const expectedVersionId = body.expectedVersionId as string | undefined;

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
  const permResult = await evaluatePermission(user.userId, user.roles, 'write', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

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

  // Optimistic locking: check current version if expectedVersionId is provided
  if (expectedVersionId) {
    try {
      const headResponse = await s3Client.send(
        new HeadObjectCommand({
          Bucket: S3_BUCKET,
          Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
        })
      );

      if (headResponse.VersionId && headResponse.VersionId !== expectedVersionId) {
        return formatError(
          409,
          'Conflict: file has been modified since your last read. ' +
            `Expected version ${expectedVersionId}, current version ${headResponse.VersionId}`,
          requestId
        );
      }
    } catch (err: unknown) {
      // File doesn't exist yet — that's fine for creation
      if (!(err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NotFound')) {
        throw err;
      }
    }
  }

  // Phase 6 (Plan 06-02): annotate the object with the DEK keyId so Phase 7's
  // cross-DEK restore endpoint can match noncurrent versions back to their DEK.
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);

  // Write to S3
  const putResponse = await s3Client.send(
    new PutObjectCommand({
      Bucket: S3_BUCKET,
      Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      Body: contentBuffer,
      ContentType: contentType,
      Metadata: {
        'modified-by': user.userId,
        'modified-at': new Date().toISOString(),
        ...(activeKeyId ? { 'vaultguard-key-id': activeKeyId } : {}),
      },
    })
  );

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
  await recordVaultActivity({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: expectedVersionId ? 'modified' : 'created',
    path: '/' + filePath,
    actorUserId: user.userId,
  });

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
      lastModified: new Date().toISOString(),
      checksum: putResponse.ETag,
    },
    requestId
  );
}

// ─── DELETE /vaults/{vaultId}/files/{path} ──────────────────────────────────

/**
 * Soft-deletes a file by placing an S3 delete marker.
 * The file remains recoverable through version history.
 * Only users with 'delete' permission on the path can perform this operation.
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
  const rawPath = decodeURIComponent((event.pathParameters?.filePath ?? event.pathParameters?.path) || '');
  const filePath = sanitizeFilePath(rawPath);

  // Permission check
  const permResult = await evaluatePermission(user.userId, user.roles, 'delete', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

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

  // Verify file exists and capture size for storage tracking
  let fileSize = 0;
  try {
    const headResult = await s3Client.send(
      new HeadObjectCommand({
        Bucket: S3_BUCKET,
        Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      })
    );
    fileSize = headResult.ContentLength || 0;
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'name' in err && (err as { name: string }).name === 'NotFound') {
      return formatError(404, `File not found: ${filePath}`, requestId);
    }
    throw err;
  }

  // Phase 6 (Plan 06-02): record the keyId active at delete time so the audit
  // log has chain-of-custody for which DEK protected the now-hidden version.
  const activeKeyId = await getActiveKeyIdForVault(user.orgId, vault.vaultId);

  // Soft delete (S3 versioning creates a delete marker)
  const deleteResponse = await s3Client.send(
    new DeleteObjectCommand({
      Bucket: S3_BUCKET,
      Key: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
    })
  );

  // Decrement storage usage
  if (fileSize > 0) {
    const orgResult = await getActiveOrg(user.orgId);
    if (orgResult.org) {
      await updateOrgStorageUsage(orgResult.org.slug, -fileSize);
    }
  }

  // Record on the activity log so peers learn about the deletion without
  // having to diff their full manifest against an S3 listing.
  await recordVaultActivity({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'deleted',
    path: '/' + filePath,
    actorUserId: user.userId,
  });

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
      recoverable: true,
      message: 'File soft-deleted. Previous versions remain accessible via history.',
    },
    requestId
  );
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
  const permResult = await evaluatePermission(user.userId, user.roles, 'read', '/' + filePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));

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

  // Fetch version history from S3
  const versionsResponse = await s3Client.send(
    new ListObjectVersionsCommand({
      Bucket: S3_BUCKET,
      Prefix: vaultS3Prefix(user.orgId, vault.vaultId) + filePath,
      MaxKeys: 50,
    })
  );

  const versions: FileVersion[] = [];

  // Process object versions
  for (const version of versionsResponse.Versions || []) {
    if (version.Key === vaultS3Prefix(user.orgId, vault.vaultId) + filePath) {
      versions.push({
        versionId: version.VersionId || '',
        lastModified: version.LastModified?.toISOString() || '',
        size: version.Size || 0,
        isLatest: version.IsLatest || false,
        isDeleteMarker: false,
      });
    }
  }

  // Process delete markers
  for (const marker of versionsResponse.DeleteMarkers || []) {
    if (marker.Key === vaultS3Prefix(user.orgId, vault.vaultId) + filePath) {
      versions.push({
        versionId: marker.VersionId || '',
        lastModified: marker.LastModified?.toISOString() || '',
        size: 0,
        isLatest: marker.IsLatest || false,
        isDeleteMarker: true,
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
    metadata: { versionCount: versions.length },
  });

  return formatSuccess(
    200,
    {
      path: '/' + filePath,
      versions,
      count: versions.length,
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
  // blocks an overwrite.
  const permResult = await evaluatePermission(
    user.userId,
    user.roles,
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

  // Remove the delete marker. S3 automatically promotes the most-recent
  // non-marker version as the new head.
  await s3Client.send(
    new DeleteObjectCommand({
      Bucket: S3_BUCKET,
      Key: key,
      VersionId: currentMarker.VersionId,
    })
  );

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

  await recordVaultActivity({
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'created',
    path: '/' + filePath,
    actorUserId: user.userId,
  });

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
    },
    requestId
  );
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
  const sourceVersionId = body?.versionId;
  if (!sourceVersionId || typeof sourceVersionId !== 'string') {
    return formatError(400, 'Missing or invalid body field: versionId', requestId);
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
  // blocks an overwrite.
  const permResult = await evaluatePermission(
    user.userId,
    user.roles,
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

  const bucket = S3_BUCKET;
  const key = vaultS3Prefix(user.orgId, vault.vaultId) + filePath;

  // STEP 1 — GET the historical ciphertext by VersionId.
  type S3GetResp = {
    Metadata?: Record<string, string>;
    ContentType?: string;
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

  // STEP 4 — Query `keyId-index` GSI with retry/backoff for DDB GSI eventual
  // consistency (T-07-04 mitigation). 3 total attempts × 200ms backoff bounds
  // worst-case latency at ~600ms added.
  type DekItem = {
    orgId?: string;
    vaultId?: string;
    scope?: string;
    encryptedDataKey?: string;
  };
  let dekItem: DekItem | null = null;
  const ATTEMPTS = 3;
  const BACKOFF_MS = 200;
  for (let i = 0; i < ATTEMPTS; i++) {
    const q = await docClient.send(
      new QueryCommand({
        TableName: USER_KEYS_TABLE,
        IndexName: 'keyId-index',
        KeyConditionExpression: 'keyId = :kid',
        ExpressionAttributeValues: { ':kid': sourceKeyId },
        Limit: 1,
      })
    );
    if (q.Items && q.Items.length > 0) {
      dekItem = q.Items[0] as DekItem;
      break;
    }
    if (i < ATTEMPTS - 1) {
      await new Promise((r) => setTimeout(r, BACKOFF_MS));
    }
  }

  // STEP 5 — still empty after retries → 410. Same generic message as the
  // missing-metadata and 'legacy' branches above (T-07-03 mitigation).
  if (!dekItem || !dekItem.encryptedDataKey) {
    return formatError(410, 'Historical key material is no longer available', requestId);
  }

  // STEP 6 — KMS Decrypt the historical envelope. The EncryptionContext is
  // reconstructed from the GSI row's (orgId, scope, vaultId) — KMS refuses
  // with InvalidCiphertextException BEFORE producing plaintext if these don't
  // match what was used at GenerateDataKey time (T-07-02 mitigation).
  const decryptResp = await kmsClient.send(
    new DecryptCommand({
      CiphertextBlob: Buffer.from(dekItem.encryptedDataKey, 'base64'),
      EncryptionContext: scopeKmsContext(
        dekItem.orgId || user.orgId,
        dekItem.scope || '/**',
        dekItem.vaultId || vault.vaultId
      ),
    })
  );
  if (!decryptResp.Plaintext) {
    throw new Error('KMS Decrypt returned no plaintext for historical DEK');
  }
  const oldDek = Buffer.from(decryptResp.Plaintext);

  // STEP 7 — AES-decrypt the historical ciphertext.
  const ciphertextBody = await getResp.Body!.transformToByteArray();
  const plaintext = aesDecrypt(Buffer.from(ciphertextBody), oldDek);

  // STEP 8 — fetch the current ACTIVE DEK for the vault.
  const active = await getActiveScopeDataKey(user.orgId, vault.vaultId, '/**');
  if (!active) {
    throw new Error('No active DEK for vault — cannot complete restore');
  }
  const { key: currentDek, keyId: currentKeyId } = active;

  // STEP 9 — AES-encrypt with the current DEK.
  const newCiphertext = aesEncrypt(plaintext, currentDek);

  // STEP 10 — best-effort plaintext wipe. Matches `reEncryptFile`'s pattern.
  plaintext.fill(0);

  // STEP 11 — PUT as the new head with audit-tagged Metadata.
  const putResp = await s3Client.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: newCiphertext,
      ContentType: getResp.ContentType || 'application/octet-stream',
      Metadata: {
        'modified-by': user.userId,
        'modified-at': new Date().toISOString(),
        'vaultguard-key-id': currentKeyId,
        'restored-from-version': sourceVersionId,
      },
    })
  );

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
        sourceKeyId,
        targetVersionId,
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
      restoredFrom: { versionId: sourceVersionId, keyId: sourceKeyId },
      targetKeyId: currentKeyId,
    },
    requestId
  );
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

  const prefix = vaultS3Prefix(user.orgId, vault.vaultId);

  interface DeletedFileEntry {
    path: string;
    deleteMarkerVersionId: string;
    deletedAt: string;
  }

  const files: DeletedFileEntry[] = [];
  let keyMarker: string | undefined;
  let versionIdMarker: string | undefined;
  let safetyIterations = 0;

  do {
    const res = await s3Client.send(
      new ListObjectVersionsCommand({
        Bucket: S3_BUCKET,
        Prefix: prefix,
        MaxKeys: 1000,
        KeyMarker: keyMarker,
        VersionIdMarker: versionIdMarker,
      })
    );

    for (const marker of res.DeleteMarkers ?? []) {
      if (marker.IsLatest !== true || !marker.Key || !marker.VersionId || !marker.LastModified) continue;
      const relPath = marker.Key.slice(prefix.length);
      if (!relPath) continue;
      if (isClientLocalOnlyPath(relPath)) continue;
      if (isFolderMarkerPath(relPath)) continue;

      // Per-row permission filter — only include paths the caller can read.
      const perm = await evaluatePermission(
        user.userId,
        user.roles,
        'read',
        '/' + relPath,
        user.orgId,
        vault.vaultId,
        await fileOpPermissionOptions(user, vault)
      );
      if (!perm.allowed) continue;

      const deletedAt =
        marker.LastModified instanceof Date
          ? marker.LastModified.toISOString()
          : String(marker.LastModified);

      files.push({
        path: relPath,
        deleteMarkerVersionId: marker.VersionId,
        deletedAt,
      });
    }

    keyMarker = res.IsTruncated ? res.NextKeyMarker : undefined;
    versionIdMarker = res.IsTruncated ? res.NextVersionIdMarker : undefined;

    safetyIterations += 1;
    if (safetyIterations > 100) {
      // Defensive — a vault with > 100,000 versions returned per call is
      // pathological; bail out rather than spin indefinitely.
      break;
    }
  } while (keyMarker);

  return formatSuccess(
    200,
    { files },
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
  | { kind: 'fallback'; reason: 'epoch' | 'stale-cursor' | 'permission-changed'; permissionsChanged: boolean };

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

  const events = await queryVaultActivity(vault.vaultId, lastSyncMs);

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
        const perm = await evaluatePermission(user.userId, user.roles, 'read', path, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
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
      const perm = await evaluatePermission(user.userId, user.roles, 'read', path, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
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

  // ── Warm path: activity-log-driven incremental sync ───────────────────────
  // Only attempted when the client has a recent enough cursor for the log
  // to cover the gap. The result tells us whether the warm path was
  // applicable; when it wasn't, we propagate `permissionsChanged` into
  // the cold-path response so the client can invalidate its local
  // permission cache.
  let permissionsChanged = false;
  if (!prefix) {
    const warm = await buildSyncDeltasFromActivityLog(user, vault, lastSyncDate.getTime());
    if (warm.kind === 'warm') {
      const cursor = await getVaultCursor(user.orgId, vault.vaultId);
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
          syncTimestamp: new Date().toISOString(),
          revision: cursor.revision,
          mode: 'activity-log',
          permissionsChanged: false,
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
      const permResult = await evaluatePermission(user.userId, user.roles, 'read', relativePath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
      if (!permResult.allowed) continue;

      const objModified = obj.LastModified || new Date(0);
      const objChecksum = obj.ETag || '';
      const clientChecksum = clientChecksums[relativePath];

      if (objModified > lastSyncDate) {
        // File was modified since last sync
        const action: SyncDelta['action'] = clientChecksum ? 'modified' : 'created';

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
      const permResult = await evaluatePermission(user.userId, user.roles, 'read', clientPath, user.orgId, vault.vaultId, await fileOpPermissionOptions(user, vault));
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

  const cursor = await getVaultCursor(user.orgId, vault.vaultId);

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
      syncTimestamp: new Date().toISOString(),
      revision: cursor.revision,
      mode: 'full-scan',
      permissionsChanged,
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
  const cursor = await getVaultCursor(user.orgId, vault.vaultId);
  return formatSuccess(
    200,
    {
      revision: cursor.revision,
      lastChangedAt: cursor.lastChangedAt,
      serverTime: new Date().toISOString(),
    },
    requestId
  );
}
