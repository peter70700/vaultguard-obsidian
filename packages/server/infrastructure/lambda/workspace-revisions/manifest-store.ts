import { createHash } from 'node:crypto';
import { GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { isTransientStorageFailure } from '../shared/transient-storage';

import {
  type CommittedWorkspaceManifest,
  type PreparedWorkspaceManifest,
  WORKSPACE_MANIFEST_SCHEMA_VERSION,
  type WorkspaceManifest,
  type WorkspaceManifestEntry,
  type WorkspaceManifestPointer,
  type WorkspaceManifestEncryption,
  type WorkspaceScope,
  type WorkspaceManifestStore,
} from './types';

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MAX_MANIFEST_ENTRIES = 100_000;
const MAX_MANIFEST_BYTES = 64 * 1024 * 1024;

export class WorkspaceRevisionValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WorkspaceRevisionValidationError';
  }
}

export class WorkspaceManifestIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WorkspaceManifestIntegrityError';
  }
}

function requireId(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new WorkspaceRevisionValidationError(`${field} must be a safe non-empty identifier`);
  }
}

function requireSha256(value: unknown, field: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new WorkspaceRevisionValidationError(`${field} must be a lowercase SHA-256 digest`);
  }
}

function requireNullableSha256(value: unknown, field: string): asserts value is string | null {
  if (value !== null) requireSha256(value, field);
}

function requireIsoTimestamp(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value) ||
    !Number.isFinite(Date.parse(value))
  ) {
    throw new WorkspaceRevisionValidationError(`${field} must be an ISO-8601 UTC timestamp`);
  }
}

function requireCanonicalPath(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 4096 ||
    value.startsWith('/') ||
    value.includes('\\') ||
    value.includes('\0') ||
    // A manifest is the trusted inventory that read views and the connector
    // serve from. Every consumer today compares entries against an already
    // sanitised request path, but a future consumer that derives a storage key
    // or filesystem path from `canonicalPath` must never inherit a traversal
    // vector, so reject empty, `.` and `..` segments at the trust boundary.
    value.split('/').some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new WorkspaceRevisionValidationError(`${field} must be a canonical vault-relative path`);
  }
}

function requireName(value: unknown, field: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 255 ||
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    value.includes('\0')
  ) {
    throw new WorkspaceRevisionValidationError(`${field} must be a safe path segment`);
  }
}

function assertManifestEntry(entry: WorkspaceManifestEntry, index: number): void {
  const prefix = `entries[${index}]`;
  if (!entry || typeof entry !== 'object') {
    throw new WorkspaceRevisionValidationError(`${prefix} must be an object`);
  }
  if (entry.kind !== 'file' && entry.kind !== 'folder') {
    throw new WorkspaceRevisionValidationError(`${prefix}.kind is unsupported`);
  }
  requireCanonicalPath(entry.canonicalPath, `${prefix}.canonicalPath`);
  requireSha256(entry.canonicalPathHash, `${prefix}.canonicalPathHash`);
  requireName(entry.name, `${prefix}.name`);
  if (entry.parentFolderId !== null) requireId(entry.parentFolderId, `${prefix}.parentFolderId`);
  if (entry.state !== 'active' && entry.state !== 'tombstone') {
    throw new WorkspaceRevisionValidationError(`${prefix}.state is unsupported`);
  }
  if (entry.kind === 'folder') {
    requireId(entry.folderId, `${prefix}.folderId`);
    return;
  }
  requireId(entry.fileId, `${prefix}.fileId`);
  requireId(entry.fileVersionId, `${prefix}.fileVersionId`);
  if (entry.fileVersionState !== 'content' && entry.fileVersionState !== 'tombstone') {
    throw new WorkspaceRevisionValidationError(`${prefix}.fileVersionState is unsupported`);
  }
  requireNullableSha256(entry.plaintextSha256, `${prefix}.plaintextSha256`);
  requireNullableSha256(entry.ciphertextSha256, `${prefix}.ciphertextSha256`);
  if (
    entry.fileVersionState === 'tombstone' &&
    (entry.state !== 'tombstone' ||
      entry.plaintextSha256 !== null ||
      entry.ciphertextSha256 !== null)
  ) {
    throw new WorkspaceRevisionValidationError(
      `${prefix} tombstone must have tombstoned location and no content hashes`,
    );
  }
  if (entry.fileVersionState === 'content' && entry.state !== 'active') {
    throw new WorkspaceRevisionValidationError(
      `${prefix} content version must have an active location`,
    );
  }
}

export function assertWorkspaceManifest(manifest: WorkspaceManifest): void {
  if (!manifest || typeof manifest !== 'object') {
    throw new WorkspaceRevisionValidationError('manifest must be an object');
  }
  if (manifest.schemaVersion !== WORKSPACE_MANIFEST_SCHEMA_VERSION) {
    throw new WorkspaceRevisionValidationError('manifest schemaVersion is unsupported');
  }
  if (manifest.state !== 'prepared' && manifest.state !== 'committed') {
    throw new WorkspaceRevisionValidationError('manifest state is unsupported');
  }
  requireId(manifest.orgId, 'orgId');
  requireId(manifest.vaultId, 'vaultId');
  requireId(manifest.workspaceRevisionId, 'workspaceRevisionId');
  if (manifest.expectedWorkspaceRevisionId !== null) {
    requireId(manifest.expectedWorkspaceRevisionId, 'expectedWorkspaceRevisionId');
  }
  requireId(manifest.changeSetId, 'changeSetId');
  requireId(manifest.actorIdentityId, 'actorIdentityId');
  requireIsoTimestamp(manifest.createdAt, 'createdAt');
  if (!Array.isArray(manifest.parentRevisionIds) || manifest.parentRevisionIds.length > 2) {
    throw new WorkspaceRevisionValidationError('parentRevisionIds must contain zero to two revisions');
  }
  for (const [index, parentRevisionId] of manifest.parentRevisionIds.entries()) {
    requireId(parentRevisionId, `parentRevisionIds[${index}]`);
  }
  if (new Set(manifest.parentRevisionIds).size !== manifest.parentRevisionIds.length) {
    throw new WorkspaceRevisionValidationError('parentRevisionIds cannot contain duplicates');
  }
  if (manifest.parentRevisionIds.includes(manifest.workspaceRevisionId)) {
    throw new WorkspaceRevisionValidationError('a workspace revision cannot be its own parent');
  }
  if (manifest.expectedWorkspaceRevisionId === null && manifest.parentRevisionIds.length !== 0) {
    throw new WorkspaceRevisionValidationError('a genesis manifest cannot declare a parent');
  }
  if (
    manifest.expectedWorkspaceRevisionId !== null &&
    manifest.parentRevisionIds[0] !== manifest.expectedWorkspaceRevisionId
  ) {
    throw new WorkspaceRevisionValidationError('the first parent must be the expected workspace head');
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length > MAX_MANIFEST_ENTRIES) {
    throw new WorkspaceRevisionValidationError(`entries exceeds the ${MAX_MANIFEST_ENTRIES} entry limit`);
  }

  const paths = new Set<string>();
  const fileIds = new Set<string>();
  const folderIds = new Set<string>();
  const folders = new Map<string, Extract<WorkspaceManifestEntry, { kind: 'folder' }>>();
  for (const [index, entry] of manifest.entries.entries()) {
    assertManifestEntry(entry, index);
    if (entry.state === 'active' && paths.has(entry.canonicalPath)) {
      throw new WorkspaceRevisionValidationError(`duplicate canonical path: ${entry.canonicalPath}`);
    }
    // Tombstones retain identity/lineage when a new file reuses the same path.
    if (entry.state === 'active') paths.add(entry.canonicalPath);
    if (entry.kind === 'file') {
      if (fileIds.has(entry.fileId)) {
        throw new WorkspaceRevisionValidationError(`fileId appears more than once: ${entry.fileId}`);
      }
      fileIds.add(entry.fileId);
    } else {
      if (folderIds.has(entry.folderId)) {
        throw new WorkspaceRevisionValidationError(`folderId appears more than once: ${entry.folderId}`);
      }
      folderIds.add(entry.folderId);
      folders.set(entry.folderId, entry);
    }
  }

  for (const entry of manifest.entries) {
    if (entry.parentFolderId === null) continue;
    const parent = folders.get(entry.parentFolderId);
    if (!parent || (entry.state === 'active' && parent.state !== 'active')) {
      throw new WorkspaceRevisionValidationError(
        `entry ${entry.canonicalPath} references an unavailable parent folder`,
      );
    }
  }
  for (const folder of folders.values()) {
    const visited = new Set([folder.folderId]);
    let parentFolderId = folder.parentFolderId;
    while (parentFolderId !== null) {
      if (visited.has(parentFolderId)) {
        throw new WorkspaceRevisionValidationError(`folder cycle includes ${folder.folderId}`);
      }
      visited.add(parentFolderId);
      parentFolderId = folders.get(parentFolderId)?.parentFolderId ?? null;
    }
  }

  const orderedPaths = manifest.entries.map((entry) => entry.canonicalPath);
  const sortedPaths = [...orderedPaths].sort((left, right) =>
    left < right ? -1 : left > right ? 1 : 0,
  );
  if (orderedPaths.some((path, index) => path !== sortedPaths[index])) {
    throw new WorkspaceRevisionValidationError('entries must be sorted by canonicalPath');
  }

  if (manifest.state === 'committed') {
    const committed = manifest as CommittedWorkspaceManifest;
    requireSha256(committed.preparedManifestSha256, 'preparedManifestSha256');
    requireIsoTimestamp(committed.committedAt, 'committedAt');
    if (Date.parse(committed.committedAt) < Date.parse(committed.createdAt)) {
      throw new WorkspaceRevisionValidationError('committedAt cannot precede createdAt');
    }
    if (!Number.isSafeInteger(committed.sequence) || committed.sequence < 1) {
      throw new WorkspaceRevisionValidationError('sequence must be a positive safe integer');
    }
  }
}

function canonicalValue(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new WorkspaceRevisionValidationError('manifest numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalValue).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalValue(record[key])}`).join(',')}}`;
  }
  throw new WorkspaceRevisionValidationError('manifest contains an unsupported value');
}

export function canonicalWorkspaceManifestBytes(manifest: WorkspaceManifest): Uint8Array {
  assertWorkspaceManifest(manifest);
  const bytes = Buffer.from(canonicalValue(manifest), 'utf8');
  if (bytes.byteLength > MAX_MANIFEST_BYTES) {
    throw new WorkspaceRevisionValidationError(`manifest exceeds ${MAX_MANIFEST_BYTES} bytes`);
  }
  return bytes;
}

export function workspaceManifestSha256(manifest: WorkspaceManifest): string {
  return createHash('sha256').update(canonicalWorkspaceManifestBytes(manifest)).digest('hex');
}

function encodedSegment(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

export function workspaceManifestObjectKey(
  manifest: WorkspaceManifest,
  sha256: string,
  prefix = '_vaultguard-workspace-revisions',
): string {
  return [
    prefix.replace(/^\/+|\/+$/gu, ''),
    encodedSegment(manifest.orgId),
    encodedSegment(manifest.vaultId),
    encodedSegment(manifest.workspaceRevisionId),
    `${manifest.state}-${sha256}.json`,
  ].join('/');
}

function isPreconditionFailure(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { name?: unknown; $metadata?: { httpStatusCode?: unknown } };
  return candidate.name === 'PreconditionFailed' || candidate.$metadata?.httpStatusCode === 412;
}

async function bodyBytes(body: unknown): Promise<Uint8Array> {
  const limit = MAX_MANIFEST_BYTES + 4096;
  if (body instanceof Uint8Array) { if (body.byteLength > limit) throw new WorkspaceManifestIntegrityError('manifest is too large'); return body; }
  if (typeof body === 'string') return bodyBytes(Buffer.from(body, 'utf8'));
  if (
    body &&
    typeof body === 'object' &&
    'transformToByteArray' in body &&
    typeof (body as { transformToByteArray?: unknown }).transformToByteArray === 'function'
  ) {
    return bodyBytes(await (body as { transformToByteArray: () => Promise<Uint8Array> }).transformToByteArray());
  }
  if (body && typeof body === 'object' && Symbol.asyncIterator in body) {
    const chunks: Uint8Array[] = []; let size = 0;
    for await (const chunk of body as AsyncIterable<Uint8Array | string>) {
      size += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.byteLength;
      if (size > limit) { chunks.forEach(b => b.fill(0)); throw new WorkspaceManifestIntegrityError('manifest is too large'); }
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
    }
    return Buffer.concat(chunks);
  }
  throw new WorkspaceManifestIntegrityError('manifest object body is unavailable');
}

function parseManifest(bytes: Uint8Array): WorkspaceManifest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(bytes).toString('utf8'));
  } catch {
    throw new WorkspaceManifestIntegrityError('manifest object is not valid JSON');
  }
  try {
    assertWorkspaceManifest(parsed as WorkspaceManifest);
  } catch (error) {
    throw new WorkspaceManifestIntegrityError(
      error instanceof Error ? error.message : 'manifest validation failed',
    );
  }
  return deepFreeze(parsed as WorkspaceManifest);
}

export function deepFreeze<T>(value: T): T {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  return Object.freeze(value);
}

export interface WorkspaceManifestCrypto {
  encrypt(bytes: Buffer, scope: WorkspaceScope): Promise<{ ciphertext: Buffer; keyId: string }>;
  decrypt(bytes: Buffer, keyId: string, scope: WorkspaceScope): Promise<Buffer>;
}
const canonicalManifestCrypto: WorkspaceManifestCrypto = {
  async encrypt(bytes, scope) {
    const owner = await import('../shared/vault-crypto');
    const result = await owner.encryptPlaintextWithActiveVaultKey(bytes, scope);
    return { ciphertext: result.newCiphertext, keyId: result.currentKeyId };
  },
  async decrypt(bytes, keyId, scope) {
    const owner = await import('../shared/vault-crypto');
    return (await owner.decryptExactVaultVersion(bytes, { 'vaultguard-key-id': keyId }, scope)).plaintext;
  },
};
export interface S3WorkspaceManifestStoreDependencies {
  /** New atomic publication always selects encryption; historical writers remain compatible. */
  readonly encryptWrites?: boolean;
  readonly crypto?: WorkspaceManifestCrypto;
  readonly send: (command: unknown) => Promise<unknown>;
  readonly bucket: string;
  readonly prefix?: string;
}

/** Content-addressed, write-once workspace manifest storage on the vault bucket. */
export class S3WorkspaceManifestStore implements WorkspaceManifestStore {
  private readonly prefix: string;

  constructor(private readonly dependencies: S3WorkspaceManifestStoreDependencies) {
    if (!dependencies.bucket) throw new WorkspaceRevisionValidationError('manifest bucket is required');
    this.prefix = (dependencies.prefix ?? '_vaultguard-workspace-revisions').replace(
      /^\/+|\/+$/gu,
      '',
    );
    if (!this.prefix || this.prefix.split('/').some((segment) => segment === '.' || segment === '..')) {
      throw new WorkspaceRevisionValidationError('manifest prefix is invalid');
    }
  }

  async put(manifest: WorkspaceManifest): Promise<WorkspaceManifestPointer> {
    const bytes = Buffer.from(canonicalWorkspaceManifestBytes(manifest));
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    const objectKey = workspaceManifestObjectKey(manifest, sha256, this.prefix);
    const scope = { orgId: manifest.orgId, vaultId: manifest.vaultId };
    let ciphertext: Buffer | undefined, envelope: Buffer | undefined;
    let encryption: WorkspaceManifestEncryption | undefined;
    try {
      if (this.dependencies.encryptWrites) {
        envelope = Buffer.from(canonicalValue({ format: 'vault-aead-v1', kind: 'workspace-manifest', ...scope, sha256, manifest }));
        if (envelope.length > MAX_MANIFEST_BYTES + 1024) throw new WorkspaceManifestIntegrityError('manifest envelope is too large');
        const encrypted = await (this.dependencies.crypto ?? canonicalManifestCrypto).encrypt(envelope, scope);
        ciphertext = encrypted.ciphertext;
        if (!encrypted.keyId || ciphertext.length > MAX_MANIFEST_BYTES + 4096 || ciphertext.length < 28)
          throw new WorkspaceManifestIntegrityError('manifest encryption failed');
        encryption = { format: 'vault-aead-v1', cloudKeyId: encrypted.keyId,
          ciphertextSha256: createHash('sha256').update(ciphertext).digest('hex'), ciphertextBytes: ciphertext.length };
      }
      try {
        const response = await this.dependencies.send(new PutObjectCommand({
          Bucket: this.dependencies.bucket, Key: objectKey, Body: ciphertext ?? bytes,
          ContentType: encryption ? 'application/octet-stream' : 'application/vnd.vaultguard.workspace-manifest+json',
          ChecksumSHA256: Buffer.from(encryption?.ciphertextSha256 ?? sha256, 'hex').toString('base64'),
          IfNoneMatch: '*', Metadata: { 'workspace-revision-id': manifest.workspaceRevisionId,
            'manifest-state': manifest.state, 'manifest-sha256': sha256,
            ...(encryption ? { 'manifest-format': encryption.format, 'vaultguard-key-id': encryption.cloudKeyId } : {}) },
        })) as { VersionId?: string };
        if (!response.VersionId || response.VersionId === 'null') throw new WorkspaceManifestIntegrityError('exact manifest storage version is required');
        return deepFreeze({ objectKey, storageVersionId: response.VersionId, sha256, byteLength: bytes.length, ...(encryption ? { encryption } : {}) });
      } catch (error) {
        if (!encryption && !isPreconditionFailure(error)) throw error;
        // Recover an immutable object after collision or lost acknowledgement, never overwrite it.
        // A missing or unreadable object decides nothing. A collision or integrity failure
        // found by the read is its own answer, and so is a transient read failure: an object
        // that already exists (412) behind a throttled read stays retryable. Otherwise the
        // put's own failure is the answer, so a transient put failure stays recognisable too
        // (P4-010).
        const existing = await this.readObject({ objectKey, sha256, byteLength: bytes.length }).catch((readError: unknown) => {
          throw readError instanceof WorkspaceManifestIntegrityError || isTransientStorageFailure(readError) ? readError : error;
        });
        if (!!existing.encryption !== !!encryption || !Buffer.from(canonicalWorkspaceManifestBytes(existing.manifest)).equals(bytes))
          throw new WorkspaceManifestIntegrityError('immutable manifest collision');
        return deepFreeze({ objectKey, storageVersionId: existing.storageVersionId, sha256, byteLength: bytes.length,
          ...(existing.encryption ? { encryption: existing.encryption } : {}) });
      }
    } finally { bytes.fill(0); ciphertext?.fill(0); envelope?.fill(0); }
  }

  async get(pointer: WorkspaceManifestPointer): Promise<WorkspaceManifest> {
    return (await this.readObject(pointer, pointer.storageVersionId)).manifest;
  }

  private async readObject(
    pointer: Omit<WorkspaceManifestPointer, 'storageVersionId'>,
    storageVersionId?: string,
  ): Promise<{ manifest: WorkspaceManifest; storageVersionId: string; encryption?: WorkspaceManifestEncryption }> {
    requireSha256(pointer.sha256, 'manifest pointer sha256');
    if (!pointer.objectKey.startsWith(`${this.prefix}/`) || (storageVersionId !== undefined && (!storageVersionId || storageVersionId === 'null')) ||
      !Number.isSafeInteger(pointer.byteLength) || pointer.byteLength < 1 || pointer.byteLength > MAX_MANIFEST_BYTES)
      throw new WorkspaceManifestIntegrityError('manifest pointer is invalid');
    const response = await this.dependencies.send(new GetObjectCommand({ Bucket: this.dependencies.bucket, Key: pointer.objectKey,
      ...(storageVersionId ? { VersionId: storageVersionId } : {}), Range: `bytes=0-${MAX_MANIFEST_BYTES + 4096}`,
    })) as { Body?: unknown; VersionId?: string; Metadata?: Record<string, string> };
    if (!response.VersionId || response.VersionId === 'null' || (storageVersionId && response.VersionId !== storageVersionId))
      throw new WorkspaceManifestIntegrityError('manifest storage version mismatch');
    const bytes = Buffer.from(await bodyBytes(response.Body));
    let plaintext: Buffer | undefined, encryption: WorkspaceManifestEncryption | undefined;
    try {
      if (response.Metadata?.['manifest-format'] || pointer.encryption) {
        const segments = pointer.objectKey.slice(this.prefix.length + 1).split('/');
        if (segments.length !== 4) throw new WorkspaceManifestIntegrityError('invalid manifest key');
        const scope = { orgId: Buffer.from(segments[0], 'base64url').toString(), vaultId: Buffer.from(segments[1], 'base64url').toString() };
        requireId(scope.orgId, 'orgId'); requireId(scope.vaultId, 'vaultId');
        const keyId = response.Metadata?.['vaultguard-key-id'];
        if (response.Metadata?.['manifest-format'] !== 'vault-aead-v1' || !keyId)
          throw new WorkspaceManifestIntegrityError('manifest encryption metadata mismatch');
        // Same field order as the write path: a pointer recovered after an immutable
        // collision must be indistinguishable from the one the writer first returned,
        // including for consumers that compare the stored value literally.
        encryption = { format: 'vault-aead-v1', cloudKeyId: keyId,
          ciphertextSha256: createHash('sha256').update(bytes).digest('hex'), ciphertextBytes: bytes.length };
        if (storageVersionId && (!pointer.encryption || canonicalValue(pointer.encryption) !== canonicalValue(encryption)))
          throw new WorkspaceManifestIntegrityError('manifest ciphertext pointer mismatch');
        try { plaintext = await (this.dependencies.crypto ?? canonicalManifestCrypto).decrypt(bytes, keyId, scope); }
        catch (error) {
          // An unavailable key service is not an authentication failure of the manifest.
          if (isTransientStorageFailure(error)) throw error;
          throw new WorkspaceManifestIntegrityError('manifest authentication failed');
        }
        if (plaintext.length > MAX_MANIFEST_BYTES + 1024) throw new WorkspaceManifestIntegrityError('manifest envelope is too large');
        let envelope: any;
        try { envelope = JSON.parse(plaintext.toString()); } catch { throw new WorkspaceManifestIntegrityError('invalid manifest envelope'); }
        if (envelope.format !== 'vault-aead-v1' || envelope.kind !== 'workspace-manifest' || envelope.orgId !== scope.orgId || envelope.vaultId !== scope.vaultId || envelope.sha256 !== pointer.sha256)
          throw new WorkspaceManifestIntegrityError('manifest envelope binding mismatch');
        const manifest = parseManifest(canonicalWorkspaceManifestBytes(envelope.manifest));
        const canonical = canonicalWorkspaceManifestBytes(manifest);
        if (canonical.length !== pointer.byteLength || workspaceManifestSha256(manifest) !== pointer.sha256 || workspaceManifestObjectKey(manifest, pointer.sha256, this.prefix) !== pointer.objectKey)
          throw new WorkspaceManifestIntegrityError('manifest does not match its pointer');
        return { manifest, storageVersionId: response.VersionId, encryption };
      }
      if (bytes.length !== pointer.byteLength || createHash('sha256').update(bytes).digest('hex') !== pointer.sha256)
        throw new WorkspaceManifestIntegrityError('manifest object does not match its immutable pointer');
      const manifest = parseManifest(bytes);
      if (workspaceManifestObjectKey(manifest, pointer.sha256, this.prefix) !== pointer.objectKey)
        throw new WorkspaceManifestIntegrityError('manifest key does not match its content');
      return { manifest, storageVersionId: response.VersionId };
    } finally { bytes.fill(0); plaintext?.fill(0); }
  }
}

export function committedManifestFromPrepared(
  prepared: PreparedWorkspaceManifest,
  preparedManifestSha256: string,
  sequence: number,
  committedAt: string,
): CommittedWorkspaceManifest {
  const committed: CommittedWorkspaceManifest = {
    ...prepared,
    state: 'committed',
    preparedManifestSha256,
    sequence,
    committedAt,
  };
  assertWorkspaceManifest(committed);
  return deepFreeze(committed);
}
