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
import {
  docClient,
  verifyActiveUser,
  evaluatePermission,
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
    vault.vaultId
  );
  return perm.allowed;
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

    switch (true) {
      case method === 'GET' && resource === '/vaults/{vaultId}/files':
        return await handleListFiles(event, user, vault, requestId);

      case method === 'GET' && isOverviewResource:
        return await handleVaultOverview(event, user, vault, requestId);

      case method === 'GET' && isHistoryResource:
        return await handleGetHistory(event, user, vault, requestId);

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
      const typed = err as { statusCode: number; message: string };
      return formatError(typed.statusCode, typed.message, requestId);
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
    const permResult = await evaluatePermission(user.userId, user.roles, 'list', '/' + relativePath, user.orgId, vault.vaultId);

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
  const permResult = await evaluatePermission(user.userId, user.roles, 'read', '/' + filePath, user.orgId, vault.vaultId);

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
    const content = bodyBytes ? Buffer.from(bodyBytes).toString('base64') : '';

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
  const permResult = await evaluatePermission(user.userId, user.roles, 'write', '/' + filePath, user.orgId, vault.vaultId);

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
  const permResult = await evaluatePermission(user.userId, user.roles, 'delete', '/' + filePath, user.orgId, vault.vaultId);

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
  const permResult = await evaluatePermission(user.userId, user.roles, 'read', '/' + filePath, user.orgId, vault.vaultId);

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
        const perm = await evaluatePermission(user.userId, user.roles, 'read', path, user.orgId, vault.vaultId);
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
      const perm = await evaluatePermission(user.userId, user.roles, 'read', path, user.orgId, vault.vaultId);
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
      const permResult = await evaluatePermission(user.userId, user.roles, 'read', relativePath, user.orgId, vault.vaultId);
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
      const permResult = await evaluatePermission(user.userId, user.roles, 'read', clientPath, user.orgId, vault.vaultId);
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
