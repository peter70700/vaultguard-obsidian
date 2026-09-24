import { createHash } from 'node:crypto';
import { workspaceCandidateKey } from '../shared/workspace-candidate-key';
import {
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
} from '@aws-sdk/lib-dynamodb';

export const FILE_VERSION_SCHEMA_VERSION = 1 as const;
/** GSI over (fileScopeId, createdAtVersionId); see terraform/modules/dynamodb. */
export const FILE_HISTORY_INDEX = 'file-history-index';
export const FILE_VERSION_METADATA = {
  fileId: 'vaultguard-file-id',
  fileVersionId: 'vaultguard-file-version-id',
  parentFileVersionId: 'vaultguard-parent-file-version-id',
  plaintextSha256: 'vaultguard-plaintext-sha256',
  plaintextBytes: 'vaultguard-plaintext-size',
  ciphertextSha256: 'vaultguard-encrypted-sha256',
  ciphertextBytes: 'vaultguard-encrypted-size',
  cloudKeyId: 'vaultguard-key-id',
} as const;

const LOGICAL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export type FileVersionState = 'content' | 'tombstone';
export type FileVersionIntegrity =
  | 'verified'
  | 'ciphertext-only'
  | 'legacy-unverified'
  | 'tombstone';

export interface FileVersionRecord {
  readonly schemaVersion: typeof FILE_VERSION_SCHEMA_VERSION;
  readonly recordType: 'file-version';
  readonly orgId: string;
  readonly vaultId: string;
  readonly fileId: string;
  readonly fileVersionId: string;
  readonly path: string;
  readonly parentFileVersionIds: readonly string[];
  readonly state: FileVersionState;
  readonly contentType: string | null;
  readonly plaintextBytes: number | null;
  readonly ciphertextBytes: number;
  readonly plaintextSha256: string | null;
  readonly ciphertextSha256: string | null;
  readonly cloudKeyId: string | null;
  readonly storageBucket: string;
  readonly storageKey: string;
  readonly storageVersionId: string;
  readonly storageEtag: string | null;
  readonly createdAt: string;
  readonly actorIdentityId: string;
  readonly agentSessionId: string | null;
  readonly changeSetId: string | null;
  readonly parserVersion: string | null;
  readonly metadataSnapshotId: string | null;
  readonly restoredFromFileVersionId: string | null;
  readonly integrity: FileVersionIntegrity;
}

export interface FileVersionDraft
  extends Omit<
    FileVersionRecord,
    'storageVersionId' | 'storageEtag' | 'storageBucket' | 'storageKey'
  > {
  readonly storageBucket?: never;
  readonly storageKey?: never;
  readonly storageVersionId?: never;
  readonly storageEtag?: never;
}

export interface StorageObservation {
  readonly orgId: string;
  readonly vaultId: string;
  readonly path: string;
  readonly storageBucket: string;
  readonly storageKey: string;
  readonly storageVersionId: string;
  readonly storageEtag?: string | null;
  readonly contentType?: string | null;
  readonly ciphertextBytes: number;
  readonly lastModified?: string | null;
  readonly metadata?: Record<string, string>;
  readonly state?: FileVersionState;
  readonly actorIdentityId?: string;
  readonly fallbackFileId?: string;
  readonly fallbackFileVersionId?: string;
  readonly parentFileVersionIds?: readonly string[];
}

export interface NewFileVersionInput {
  readonly orgId: string;
  readonly vaultId: string;
  readonly path: string;
  readonly fileId: string;
  readonly fileVersionId: string;
  readonly parentFileVersionIds?: readonly string[];
  readonly state?: FileVersionState;
  readonly contentType?: string | null;
  readonly plaintextBytes?: number | null;
  readonly ciphertextBytes?: number;
  readonly plaintextSha256?: string | null;
  readonly ciphertextSha256?: string | null;
  readonly cloudKeyId?: string | null;
  readonly createdAt: string;
  readonly actorIdentityId: string;
  readonly agentSessionId?: string | null;
  readonly changeSetId?: string | null;
  readonly parserVersion?: string | null;
  readonly metadataSnapshotId?: string | null;
  readonly restoredFromFileVersionId?: string | null;
}

export class FileVersionIntegrityError extends Error {
  readonly statusCode = 409;
  readonly code = 'FILE_VERSION_INTEGRITY_FAILED';

  constructor(message = 'Stored file version failed integrity validation') {
    super(message);
    this.name = 'FileVersionIntegrityError';
  }
}

export class FileVersionNotFoundError extends Error {
  readonly statusCode = 404;
  readonly code = 'FILE_VERSION_NOT_FOUND';

  constructor() {
    super('File version not found');
    this.name = 'FileVersionNotFoundError';
  }
}

export interface FileVersionDocumentClient {
  send(command: unknown): Promise<unknown>;
}

interface FileVersionItem extends FileVersionRecord {
  readonly vaultKey: string;
  readonly fileScopeId: string;
  readonly createdAtVersionId: string;
}

interface StorageBindingItem {
  readonly vaultKey: string;
  readonly fileVersionId: string;
  readonly recordType: 'file-version-storage-binding';
  readonly targetFileVersionId: string;
  readonly storageBucket: string;
  readonly storageKey: string;
  readonly storageVersionId: string;
}

function sha256(value: string | Buffer | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function assertLogicalId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !LOGICAL_ID_PATTERN.test(value)) {
    throw new FileVersionIntegrityError(`${field} is not a valid logical identifier`);
  }
  return value;
}

function assertLogicalIdKind(value: unknown, field: string, prefix: string): string {
  const id = assertLogicalId(value, field);
  if (!id.startsWith(`${prefix}_`) || id.includes('..')) {
    throw new FileVersionIntegrityError(`${field} is not a valid ${prefix} identifier`);
  }
  return id;
}

function boundedString(value: unknown, field: string, maximum: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new FileVersionIntegrityError(`${field} is invalid`);
  }
  return value;
}

function nullableBoundedString(
  value: unknown,
  field: string,
  maximum: number,
): string | null {
  if (value === undefined || value === null) return null;
  return boundedString(value, field, maximum);
}

function nullableSha256(value: unknown, field: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new FileVersionIntegrityError(`${field} is not a valid SHA-256 digest`);
  }
  return value;
}

function nullableBoundedInteger(
  value: unknown,
  field: string,
): number | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new FileVersionIntegrityError(`${field} is not a non-negative safe integer`);
  }
  return value;
}

function metadataInteger(
  metadata: Record<string, string> | undefined,
  field: string,
): number | null {
  const raw = metadata?.[field];
  if (raw === undefined || raw === '') return null;
  const parsed = Number(raw);
  return nullableBoundedInteger(parsed, field);
}

function normalizedParents(values: unknown): readonly string[] {
  const parents = values ?? [];
  if (!Array.isArray(parents)) {
    throw new FileVersionIntegrityError('parentFileVersionIds must be an array');
  }
  if (parents.length > 2) {
    throw new FileVersionIntegrityError('A file version cannot have more than two parents');
  }
  const normalized = parents.map((value) =>
    assertLogicalIdKind(value, 'parentFileVersionId', 'fver'),
  );
  if (new Set(normalized).size !== normalized.length) {
    throw new FileVersionIntegrityError('A file version cannot repeat a parent');
  }
  return Object.freeze([...normalized]);
}

function vaultKey(orgId: string, vaultId: string): string {
  return `ORG#${orgId}#VAULT#${vaultId}`;
}

function storageLocator(
  storageBucket: string,
  storageKey: string,
  storageVersionId: string,
): string {
  return sha256(`${storageBucket}\u0000${storageKey}\u0000${storageVersionId}`);
}

function storageBindingKey(
  storageBucket: string,
  storageKey: string,
  storageVersionId: string,
): string {
  return `STORAGE#${storageLocator(storageBucket, storageKey, storageVersionId)}`;
}

function fileScopeId(orgId: string, vaultId: string, fileId: string): string {
  return `${vaultKey(orgId, vaultId)}#FILE#${fileId}`;
}

function itemFor(record: FileVersionRecord): FileVersionItem {
  return {
    ...record,
    vaultKey: vaultKey(record.orgId, record.vaultId),
    fileScopeId: fileScopeId(record.orgId, record.vaultId, record.fileId),
    createdAtVersionId: `${record.createdAt}#${record.fileVersionId}`,
  };
}

function storageBindingFor(record: FileVersionRecord): StorageBindingItem {
  return {
    vaultKey: vaultKey(record.orgId, record.vaultId),
    fileVersionId: storageBindingKey(
      record.storageBucket,
      record.storageKey,
      record.storageVersionId,
    ),
    recordType: 'file-version-storage-binding',
    targetFileVersionId: record.fileVersionId,
    storageBucket: record.storageBucket,
    storageKey: record.storageKey,
    storageVersionId: record.storageVersionId,
  };
}

function validatedFileVersionRecord(
  candidate: Partial<FileVersionRecord>,
): FileVersionRecord {
  return bindStorageVersion(
    createFileVersionDraft({
      orgId: candidate.orgId as string,
      vaultId: candidate.vaultId as string,
      fileId: candidate.fileId as string,
      fileVersionId: candidate.fileVersionId as string,
      path: candidate.path as string,
      parentFileVersionIds: candidate.parentFileVersionIds as readonly string[],
      state: candidate.state,
      contentType: candidate.contentType,
      plaintextBytes: candidate.plaintextBytes,
      ciphertextBytes: candidate.ciphertextBytes,
      plaintextSha256: candidate.plaintextSha256,
      ciphertextSha256: candidate.ciphertextSha256,
      cloudKeyId: candidate.cloudKeyId,
      createdAt: candidate.createdAt as string,
      actorIdentityId: candidate.actorIdentityId as string,
      agentSessionId: candidate.agentSessionId,
      changeSetId: candidate.changeSetId,
      parserVersion: candidate.parserVersion,
      metadataSnapshotId: candidate.metadataSnapshotId,
      restoredFromFileVersionId: candidate.restoredFromFileVersionId,
    }),
    {
      storageBucket: candidate.storageBucket as string,
      storageKey: candidate.storageKey as string,
      storageVersionId: candidate.storageVersionId as string,
      storageEtag: candidate.storageEtag,
    },
  );
}

function recordFromItem(item: unknown): FileVersionRecord | null {
  if (!item || typeof item !== 'object') return null;
  const candidate = item as Partial<FileVersionItem>;
  if (candidate.recordType !== 'file-version' || candidate.schemaVersion !== 1) {
    throw new FileVersionIntegrityError('Stored logical file-version record is corrupt');
  }
  const {
    vaultKey: _vaultKey,
    fileScopeId: _fileScopeId,
    createdAtVersionId: _createdAtVersionId,
    ...record
  } = candidate;
  const normalized = validatedFileVersionRecord(candidate);
  const expectedItem = itemFor(normalized);
  if (
    immutableProjection(normalized) !== immutableProjection(record as FileVersionRecord) ||
    candidate.vaultKey !== expectedItem.vaultKey ||
    candidate.fileScopeId !== expectedItem.fileScopeId ||
    candidate.createdAtVersionId !== expectedItem.createdAtVersionId
  ) {
    throw new FileVersionIntegrityError('Stored logical file-version record is corrupt');
  }
  return normalized;
}

function immutableProjection(record: FileVersionRecord): string {
  return JSON.stringify({
    schemaVersion: record.schemaVersion,
    recordType: record.recordType,
    orgId: record.orgId,
    vaultId: record.vaultId,
    fileId: record.fileId,
    fileVersionId: record.fileVersionId,
    path: record.path,
    parentFileVersionIds: [...record.parentFileVersionIds],
    state: record.state,
    contentType: record.contentType,
    plaintextBytes: record.plaintextBytes,
    ciphertextBytes: record.ciphertextBytes,
    plaintextSha256: record.plaintextSha256,
    ciphertextSha256: record.ciphertextSha256,
    cloudKeyId: record.cloudKeyId,
    storageBucket: record.storageBucket,
    storageKey: record.storageKey,
    storageVersionId: record.storageVersionId,
    storageEtag: record.storageEtag,
    createdAt: record.createdAt,
    actorIdentityId: record.actorIdentityId,
    agentSessionId: record.agentSessionId,
    changeSetId: record.changeSetId,
    parserVersion: record.parserVersion,
    metadataSnapshotId: record.metadataSnapshotId,
    restoredFromFileVersionId: record.restoredFromFileVersionId,
    integrity: record.integrity,
  });
}

function isConditionalConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === 'object' &&
    'name' in error &&
    ['ConditionalCheckFailedException', 'TransactionCanceledException'].includes(
      String((error as { name?: unknown }).name),
    )
  );
}

/** Resolve only a committed logical row's exact locator, never a caller-supplied key. */
export function exactFileVersionStorageKey(record: FileVersionRecord, scope: { orgId: string; vaultId: string }, bucket: string, path: string): string {
  if (record.orgId !== scope.orgId || record.vaultId !== scope.vaultId || record.storageBucket !== bucket || record.path !== path || record.state !== 'content' ||
    !record.storageVersionId || record.storageVersionId === 'null' ||
    (record.storageKey !== `vault/${scope.orgId}/${scope.vaultId}/${path}` &&
      (!record.changeSetId || record.storageKey !== workspaceCandidateKey(scope, record.changeSetId, record.fileVersionId))))
    throw new FileVersionIntegrityError('Logical version locator is not bound to this vault path');
  if (record.storageKey !== `vault/${scope.orgId}/${scope.vaultId}/${path}` &&
    (record.integrity !== 'verified' || !record.cloudKeyId || !record.plaintextSha256 || !record.ciphertextSha256 || record.plaintextBytes === null))
    throw new FileVersionIntegrityError('Candidate content requires verified integrity metadata');
  return record.storageKey;
}

export function makeFileId(randomId: string): string {
  return assertLogicalIdKind(`fil_${randomId}`, 'fileId', 'fil');
}

export function makeFileVersionId(randomId: string): string {
  return assertLogicalIdKind(`fver_${randomId}`, 'fileVersionId', 'fver');
}

export function legacyFileId(orgId: string, vaultId: string, path: string): string {
  return `fil_legacy_${sha256(`${orgId}\u0000${vaultId}\u0000${path}`).slice(0, 32)}`;
}

export function legacyFileVersionId(
  orgId: string,
  vaultId: string,
  path: string,
  storageVersionId: string,
): string {
  return `fver_legacy_${sha256(
    `${orgId}\u0000${vaultId}\u0000${path}\u0000${storageVersionId}`,
  ).slice(0, 32)}`;
}

export function createFileVersionDraft(input: NewFileVersionInput): FileVersionDraft {
  const state = input.state ?? 'content';
  if (state !== 'content' && state !== 'tombstone') {
    throw new FileVersionIntegrityError('state is invalid');
  }
  const orgId = boundedString(input.orgId, 'orgId', 256);
  const vaultId = boundedString(input.vaultId, 'vaultId', 256);
  const path = boundedString(input.path, 'path', 1024);
  if (
    path.startsWith('/') ||
    path.includes('\\') ||
    [...path].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f;
    }) ||
    path.split('/').some((segment) => segment === '.' || segment === '..' || segment === '')
  ) {
    throw new FileVersionIntegrityError('path is not a canonical vault-relative path');
  }
  const createdAt = boundedString(input.createdAt, 'createdAt', 64);
  const createdAtDate = new Date(createdAt);
  if (Number.isNaN(createdAtDate.getTime()) || createdAtDate.toISOString() !== createdAt) {
    throw new FileVersionIntegrityError('createdAt is invalid');
  }
  const plaintextSha256 = nullableSha256(input.plaintextSha256, 'plaintextSha256');
  const ciphertextSha256 = nullableSha256(input.ciphertextSha256, 'ciphertextSha256');
  const plaintextBytes = nullableBoundedInteger(input.plaintextBytes, 'plaintextBytes');
  const ciphertextBytes = nullableBoundedInteger(
    input.ciphertextBytes === undefined ? 0 : input.ciphertextBytes,
    'ciphertextBytes',
  );
  if (ciphertextBytes === null) {
    throw new FileVersionIntegrityError('ciphertextBytes is required');
  }
  if (state === 'tombstone' && (ciphertextBytes !== 0 || ciphertextSha256 !== null)) {
    throw new FileVersionIntegrityError('A tombstone cannot describe content bytes');
  }
  return {
    schemaVersion: FILE_VERSION_SCHEMA_VERSION,
    recordType: 'file-version',
    orgId,
    vaultId,
    fileId: assertLogicalIdKind(input.fileId, 'fileId', 'fil'),
    fileVersionId: assertLogicalIdKind(input.fileVersionId, 'fileVersionId', 'fver'),
    path,
    parentFileVersionIds: normalizedParents(input.parentFileVersionIds),
    state,
    contentType:
      state === 'tombstone'
        ? null
        : nullableBoundedString(input.contentType, 'contentType', 256),
    plaintextBytes: state === 'tombstone' ? null : plaintextBytes,
    ciphertextBytes: state === 'tombstone' ? 0 : ciphertextBytes,
    plaintextSha256: state === 'tombstone' ? null : plaintextSha256,
    ciphertextSha256: state === 'tombstone' ? null : ciphertextSha256,
    cloudKeyId:
      state === 'tombstone'
        ? null
        : nullableBoundedString(input.cloudKeyId, 'cloudKeyId', 512),
    createdAt,
    actorIdentityId: boundedString(input.actorIdentityId, 'actorIdentityId', 512),
    agentSessionId: nullableBoundedString(input.agentSessionId, 'agentSessionId', 512),
    changeSetId: nullableBoundedString(input.changeSetId, 'changeSetId', 512),
    parserVersion: nullableBoundedString(input.parserVersion, 'parserVersion', 256),
    metadataSnapshotId: nullableBoundedString(
      input.metadataSnapshotId,
      'metadataSnapshotId',
      512,
    ),
    restoredFromFileVersionId:
      input.restoredFromFileVersionId === undefined ||
      input.restoredFromFileVersionId === null
        ? null
        : assertLogicalIdKind(
            input.restoredFromFileVersionId,
            'restoredFromFileVersionId',
            'fver',
          ),
    integrity:
      state === 'tombstone'
        ? 'tombstone'
        : plaintextSha256 && ciphertextSha256
          ? 'verified'
          : ciphertextSha256
            ? 'ciphertext-only'
            : 'legacy-unverified',
  };
}

export function bindStorageVersion(
  draft: FileVersionDraft,
  storage: {
    storageBucket: string;
    storageKey: string;
    storageVersionId: string;
    storageEtag?: string | null;
  },
): FileVersionRecord {
  if (!storage.storageVersionId) {
    throw new FileVersionIntegrityError('S3 did not return an exact storage version');
  }
  return Object.freeze({
    ...draft,
    storageBucket: boundedString(storage.storageBucket, 'storageBucket', 255),
    storageKey: boundedString(storage.storageKey, 'storageKey', 2048),
    storageVersionId: boundedString(storage.storageVersionId, 'storageVersionId', 1024),
    storageEtag: nullableBoundedString(storage.storageEtag, 'storageEtag', 512),
  });
}

export function metadataForFileVersion(
  draft: Pick<
    FileVersionRecord,
    | 'fileId'
    | 'fileVersionId'
    | 'parentFileVersionIds'
    | 'plaintextSha256'
    | 'plaintextBytes'
    | 'ciphertextSha256'
    | 'ciphertextBytes'
    | 'cloudKeyId'
  >,
): Record<string, string> {
  const metadata: Record<string, string> = {
    [FILE_VERSION_METADATA.fileId]: draft.fileId,
    [FILE_VERSION_METADATA.fileVersionId]: draft.fileVersionId,
    [FILE_VERSION_METADATA.ciphertextBytes]: String(draft.ciphertextBytes),
  };
  if (draft.parentFileVersionIds[0]) {
    metadata[FILE_VERSION_METADATA.parentFileVersionId] = draft.parentFileVersionIds[0];
  }
  if (draft.plaintextSha256) {
    metadata[FILE_VERSION_METADATA.plaintextSha256] = draft.plaintextSha256;
  }
  if (draft.plaintextBytes !== null) {
    metadata[FILE_VERSION_METADATA.plaintextBytes] = String(draft.plaintextBytes);
  }
  if (draft.ciphertextSha256) {
    metadata[FILE_VERSION_METADATA.ciphertextSha256] = draft.ciphertextSha256;
  }
  if (draft.cloudKeyId) {
    metadata[FILE_VERSION_METADATA.cloudKeyId] = draft.cloudKeyId;
  }
  return metadata;
}

export function fileVersionFromStorageObservation(
  observation: StorageObservation,
): FileVersionRecord {
  const metadata = observation.metadata;
  const state = observation.state ?? 'content';
  const metadataFileId = metadata?.[FILE_VERSION_METADATA.fileId];
  const metadataVersionId = metadata?.[FILE_VERSION_METADATA.fileVersionId];
  const fileId =
    metadataFileId ??
    observation.fallbackFileId ??
    legacyFileId(observation.orgId, observation.vaultId, observation.path);
  const fileVersionId =
    metadataVersionId ??
    observation.fallbackFileVersionId ??
    legacyFileVersionId(
      observation.orgId,
      observation.vaultId,
      observation.path,
      observation.storageVersionId,
    );
  const parent = metadata?.[FILE_VERSION_METADATA.parentFileVersionId];
  const metadataCiphertextBytes = metadataInteger(
    metadata,
    FILE_VERSION_METADATA.ciphertextBytes,
  );
  if (
    state === 'content' &&
    metadataCiphertextBytes !== null &&
    metadataCiphertextBytes !== observation.ciphertextBytes
  ) {
    throw new FileVersionIntegrityError('Stored ciphertext size metadata does not match S3');
  }
  const draft = createFileVersionDraft({
    orgId: observation.orgId,
    vaultId: observation.vaultId,
    path: observation.path,
    fileId,
    fileVersionId,
    parentFileVersionIds:
      observation.parentFileVersionIds ?? (parent ? [parent] : []),
    state,
    contentType: observation.contentType ?? null,
    plaintextBytes: metadataInteger(metadata, FILE_VERSION_METADATA.plaintextBytes),
    ciphertextBytes: state === 'tombstone' ? 0 : observation.ciphertextBytes,
    plaintextSha256: metadata?.[FILE_VERSION_METADATA.plaintextSha256] ?? null,
    ciphertextSha256: metadata?.[FILE_VERSION_METADATA.ciphertextSha256] ?? null,
    cloudKeyId: metadata?.[FILE_VERSION_METADATA.cloudKeyId] ?? null,
    createdAt: observation.lastModified ?? new Date(0).toISOString(),
    actorIdentityId:
      observation.actorIdentityId ?? metadata?.['modified-by'] ?? 'legacy-import',
  });
  return bindStorageVersion(draft, observation);
}

export function verifyStorageBinding(
  record: FileVersionRecord,
  observation: StorageObservation,
): void {
  if (
    record.orgId !== observation.orgId ||
    record.vaultId !== observation.vaultId ||
    record.path !== observation.path ||
    record.storageBucket !== observation.storageBucket ||
    record.storageKey !== observation.storageKey ||
    record.storageVersionId !== observation.storageVersionId ||
    record.state !== (observation.state ?? 'content') ||
    record.ciphertextBytes !== observation.ciphertextBytes ||
    (observation.contentType !== undefined &&
      record.contentType !== observation.contentType) ||
    (record.storageEtag && observation.storageEtag &&
      record.storageEtag !== observation.storageEtag)
  ) {
    throw new FileVersionIntegrityError('Logical version record does not match its S3 locator');
  }
  const metadata = observation.metadata;
  const expectedParent = record.parentFileVersionIds[0];
  const expectedPlaintextBytes =
    record.plaintextBytes === null ? undefined : String(record.plaintextBytes);
  const expectedCiphertextBytes = String(record.ciphertextBytes);
  if (
    record.state === 'content' &&
    record.ciphertextSha256 &&
    (!metadata ||
      metadata[FILE_VERSION_METADATA.fileId] === undefined ||
      metadata[FILE_VERSION_METADATA.fileVersionId] === undefined ||
      metadata[FILE_VERSION_METADATA.ciphertextSha256] === undefined ||
      metadata[FILE_VERSION_METADATA.ciphertextBytes] === undefined ||
      (record.plaintextSha256 !== null &&
        metadata[FILE_VERSION_METADATA.plaintextSha256] === undefined) ||
      (record.plaintextBytes !== null &&
        metadata[FILE_VERSION_METADATA.plaintextBytes] === undefined))
  ) {
    throw new FileVersionIntegrityError(
      'Committed S3 integrity metadata is missing from the logical version',
    );
  }
  if (
    (metadata?.[FILE_VERSION_METADATA.fileId] !== undefined &&
      metadata[FILE_VERSION_METADATA.fileId] !== record.fileId) ||
    (metadata?.[FILE_VERSION_METADATA.fileVersionId] !== undefined &&
      metadata[FILE_VERSION_METADATA.fileVersionId] !== record.fileVersionId) ||
    (metadata?.[FILE_VERSION_METADATA.parentFileVersionId] !== undefined &&
      metadata[FILE_VERSION_METADATA.parentFileVersionId] !== expectedParent) ||
    (metadata?.[FILE_VERSION_METADATA.plaintextSha256] !== undefined &&
      metadata[FILE_VERSION_METADATA.plaintextSha256] !== record.plaintextSha256) ||
    (metadata?.[FILE_VERSION_METADATA.plaintextBytes] !== undefined &&
      metadata[FILE_VERSION_METADATA.plaintextBytes] !== expectedPlaintextBytes) ||
    (metadata?.[FILE_VERSION_METADATA.ciphertextSha256] !== undefined &&
      metadata[FILE_VERSION_METADATA.ciphertextSha256] !== record.ciphertextSha256) ||
    (metadata?.[FILE_VERSION_METADATA.ciphertextBytes] !== undefined &&
      metadata[FILE_VERSION_METADATA.ciphertextBytes] !== expectedCiphertextBytes) ||
    (metadata?.[FILE_VERSION_METADATA.cloudKeyId] !== undefined &&
      metadata[FILE_VERSION_METADATA.cloudKeyId] !== record.cloudKeyId)
  ) {
    throw new FileVersionIntegrityError('S3 metadata does not match the logical version record');
  }
}

export function verifyCiphertextIntegrity(
  record: FileVersionRecord,
  ciphertext: Buffer | Uint8Array,
  metadata?: Record<string, string>,
): boolean {
  if (record.state !== 'content') {
    throw new FileVersionIntegrityError('A tombstone cannot be read as content');
  }
  const metadataHash = nullableSha256(
    metadata?.[FILE_VERSION_METADATA.ciphertextSha256],
    'S3 ciphertextSha256',
  );
  if (record.ciphertextSha256 && metadataHash && record.ciphertextSha256 !== metadataHash) {
    throw new FileVersionIntegrityError('Ciphertext hashes disagree across storage boundaries');
  }
  const expectedHash = record.ciphertextSha256 ?? metadataHash;
  if (record.ciphertextBytes !== ciphertext.byteLength) {
    throw new FileVersionIntegrityError('Ciphertext byte count does not match the version record');
  }
  if (!expectedHash) return false;
  if (sha256(ciphertext) !== expectedHash) {
    throw new FileVersionIntegrityError('Ciphertext SHA-256 validation failed');
  }
  return true;
}

export function verifyPlaintextIntegrity(
  record: FileVersionRecord,
  plaintext: Buffer | Uint8Array,
): boolean {
  if (record.state !== 'content') {
    throw new FileVersionIntegrityError('A tombstone cannot have plaintext');
  }
  if (record.plaintextBytes !== null && record.plaintextBytes !== plaintext.byteLength) {
    throw new FileVersionIntegrityError('Plaintext byte count does not match the version record');
  }
  if (!record.plaintextSha256) return false;
  if (sha256(plaintext) !== record.plaintextSha256) {
    throw new FileVersionIntegrityError('Plaintext SHA-256 validation failed');
  }
  return true;
}

export class DynamoFileVersionStore {
  constructor(
    private readonly client: FileVersionDocumentClient,
    private readonly tableName: string,
  ) {}

  async get(
    orgId: string,
    vaultId: string,
    fileVersionId: string,
  ): Promise<FileVersionRecord | null> {
    assertLogicalIdKind(fileVersionId, 'fileVersionId', 'fver');
    const result = (await this.client.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { vaultKey: vaultKey(orgId, vaultId), fileVersionId },
        ConsistentRead: true,
      }),
    )) as { Item?: unknown };
    const record = recordFromItem(result.Item);
    if (record && (record.orgId !== orgId || record.vaultId !== vaultId)) {
      throw new FileVersionIntegrityError('Logical version escaped its vault scope');
    }
    return record;
  }

  async require(
    orgId: string,
    vaultId: string,
    fileVersionId: string,
  ): Promise<FileVersionRecord> {
    const record = await this.get(orgId, vaultId, fileVersionId);
    if (!record) throw new FileVersionNotFoundError();
    return record;
  }

  /**
   * One logical file's immutable versions, newest first, through the
   * `file-history-index` GSI (fileScopeId, createdAtVersionId).
   *
   * The index is eventually consistent, so a version written moments ago can
   * be missing from a page. Every returned row is still an exact immutable
   * record, re-validated here exactly as a strong `get` validates it; a caller
   * that needs completeness up to a known version checks that version is
   * present. `upTo` bounds the listing at a version's `createdAtVersionId`,
   * which makes the set immutable for a fixed upper bound.
   */
  async listHistory(
    orgId: string,
    vaultId: string,
    fileId: string,
    options: { upTo?: { createdAt: string; fileVersionId: string }; maxRecords: number },
  ): Promise<{ records: FileVersionRecord[]; exhausted: boolean }> {
    assertLogicalIdKind(fileId, 'fileId', 'fil');
    if (!Number.isSafeInteger(options.maxRecords) || options.maxRecords < 1 || options.maxRecords > 5000) {
      throw new FileVersionIntegrityError('History scan bound is invalid');
    }
    const scope = fileScopeId(orgId, vaultId, fileId);
    const upTo = options.upTo ? `${options.upTo.createdAt}#${options.upTo.fileVersionId}` : null;
    const records: FileVersionRecord[] = [];
    const seen = new Set<string>();
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const result = (await this.client.send(
        new QueryCommand({
          TableName: this.tableName,
          IndexName: FILE_HISTORY_INDEX,
          KeyConditionExpression: upTo
            ? 'fileScopeId = :scope AND createdAtVersionId <= :upTo'
            : 'fileScopeId = :scope',
          ExpressionAttributeValues: upTo ? { ':scope': scope, ':upTo': upTo } : { ':scope': scope },
          ScanIndexForward: false,
          Limit: Math.min(100, options.maxRecords + 1 - records.length),
          ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {}),
        }),
      )) as { Items?: unknown[]; LastEvaluatedKey?: Record<string, unknown> };
      for (const item of result.Items ?? []) {
        const record = recordFromItem(item);
        if (!record || record.orgId !== orgId || record.vaultId !== vaultId || record.fileId !== fileId) {
          throw new FileVersionIntegrityError('History index returned a record from another scope');
        }
        if (seen.has(record.fileVersionId)) continue;
        seen.add(record.fileVersionId);
        if (records.length === options.maxRecords) return { records, exhausted: false };
        records.push(record);
      }
      exclusiveStartKey = result.LastEvaluatedKey;
    } while (exclusiveStartKey);
    return { records, exhausted: true };
  }

  async findByStorageVersion(input: {
    orgId: string;
    vaultId: string;
    storageBucket: string;
    storageKey: string;
    storageVersionId: string;
  }): Promise<FileVersionRecord | null> {
    const expectedVaultKey = vaultKey(input.orgId, input.vaultId);
    const result = (await this.client.send(
      new GetCommand({
        TableName: this.tableName,
        Key: {
          vaultKey: expectedVaultKey,
          fileVersionId: storageBindingKey(
            input.storageBucket,
            input.storageKey,
            input.storageVersionId,
          ),
        },
        ConsistentRead: true,
      }),
    )) as { Item?: unknown };
    if (!result.Item) return null;
    const binding = result.Item as Partial<StorageBindingItem>;
    if (
      binding.recordType !== 'file-version-storage-binding' ||
      binding.vaultKey !== expectedVaultKey ||
      binding.fileVersionId !==
        storageBindingKey(input.storageBucket, input.storageKey, input.storageVersionId) ||
      binding.storageBucket !== input.storageBucket ||
      binding.storageKey !== input.storageKey ||
      binding.storageVersionId !== input.storageVersionId ||
      typeof binding.targetFileVersionId !== 'string'
    ) {
      throw new FileVersionIntegrityError('Storage-version binding is corrupt');
    }
    const record = await this.get(input.orgId, input.vaultId, binding.targetFileVersionId);
    if (
      !record ||
      record.orgId !== input.orgId ||
        record.vaultId !== input.vaultId ||
        record.storageBucket !== input.storageBucket ||
        record.storageKey !== input.storageKey ||
        record.storageVersionId !== input.storageVersionId
    ) {
      throw new FileVersionIntegrityError('Storage-version binding returned a mismatched record');
    }
    return record;
  }

  /** Exact logical version + storage binding, unpublished until its owner's transaction. */
  publicationItems(record: FileVersionRecord) {
    const normalized = validatedFileVersionRecord(record);
    if (immutableProjection(normalized) !== immutableProjection(record)) {
      throw new FileVersionIntegrityError('Logical file-version record is invalid');
    }
    const item = itemFor(normalized);
    const binding = storageBindingFor(normalized);
    return { normalized, items: [
            {
              Put: {
                TableName: this.tableName,
                Item: item,
                ConditionExpression:
                  'attribute_not_exists(vaultKey) AND attribute_not_exists(fileVersionId)',
              },
            },
            {
              Put: {
                TableName: this.tableName,
                Item: binding,
                ConditionExpression:
                  'attribute_not_exists(vaultKey) AND attribute_not_exists(fileVersionId)',
              },
            },
          ] };
  }

  async putImmutable(record: FileVersionRecord): Promise<FileVersionRecord> {
    const { normalized, items } = this.publicationItems(record);
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: items,
        }),
      );
      return normalized;
    } catch (error) {
      if (!isConditionalConflict(error)) throw error;
      const existing = await this.get(
        normalized.orgId,
        normalized.vaultId,
        normalized.fileVersionId,
      );
      const existingBinding = await this.findByStorageVersion({
        orgId: normalized.orgId,
        vaultId: normalized.vaultId,
        storageBucket: normalized.storageBucket,
        storageKey: normalized.storageKey,
        storageVersionId: normalized.storageVersionId,
      });
      if (!existing && !existingBinding) throw error;
      if (
        !existing ||
        !existingBinding ||
        existingBinding.fileVersionId !== normalized.fileVersionId ||
        immutableProjection(existing) !== immutableProjection(normalized)
      ) {
        throw new FileVersionIntegrityError(
          'An immutable fileVersionId or S3 version binding was reused',
        );
      }
      return existing;
    }
  }
}
