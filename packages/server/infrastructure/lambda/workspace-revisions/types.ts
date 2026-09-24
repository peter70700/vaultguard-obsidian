export const WORKSPACE_MANIFEST_SCHEMA_VERSION = 1 as const;

/** Structurally matches P1-003's immutable logical file-version states. */
export type WorkspaceManifestFileVersionState = 'content' | 'tombstone';

export interface WorkspaceScope {
  readonly orgId: string;
  readonly vaultId: string;
}

export interface WorkspaceManifestEncryption {
  readonly format: 'vault-aead-v1';
  readonly cloudKeyId: string;
  readonly ciphertextSha256: string;
  readonly ciphertextBytes: number;
}
export interface WorkspaceManifestPointer {
  /** Absent only for exact historical plaintext manifests. */
  readonly encryption?: WorkspaceManifestEncryption;
  readonly objectKey: string;
  readonly storageVersionId: string;
  readonly sha256: string;
  readonly byteLength: number;
}

interface WorkspaceManifestEntryBase {
  readonly canonicalPath: string;
  readonly canonicalPathHash: string;
  readonly name: string;
  readonly parentFolderId: string | null;
  readonly state: 'active' | 'tombstone';
}

export interface WorkspaceFileManifestEntry extends WorkspaceManifestEntryBase {
  readonly kind: 'file';
  readonly fileId: string;
  readonly fileVersionId: string;
  /** Mirrors the exact logical version state defined by P1-003. */
  readonly fileVersionState: WorkspaceManifestFileVersionState;
  readonly plaintextSha256: string | null;
  readonly ciphertextSha256: string | null;
}

export interface WorkspaceFolderManifestEntry extends WorkspaceManifestEntryBase {
  readonly kind: 'folder';
  readonly folderId: string;
}

export type WorkspaceManifestEntry =
  | WorkspaceFileManifestEntry
  | WorkspaceFolderManifestEntry;

interface WorkspaceManifestBase extends WorkspaceScope {
  readonly schemaVersion: typeof WORKSPACE_MANIFEST_SCHEMA_VERSION;
  readonly workspaceRevisionId: string;
  readonly expectedWorkspaceRevisionId: string | null;
  readonly parentRevisionIds: readonly string[];
  readonly changeSetId: string;
  readonly createdAt: string;
  readonly actorIdentityId: string;
  readonly entries: readonly WorkspaceManifestEntry[];
}

/**
 * A complete candidate view. It is durable but never reachable by ordinary
 * readers until a committed companion manifest is published through head CAS.
 */
export interface PreparedWorkspaceManifest extends WorkspaceManifestBase {
  readonly state: 'prepared';
}

/**
 * The immutable manifest addressed by a published workspace head. Its digest
 * binds it to the exact prepared candidate and the sequence won by the CAS.
 */
export interface CommittedWorkspaceManifest extends WorkspaceManifestBase {
  readonly state: 'committed';
  readonly preparedManifestSha256: string;
  readonly sequence: number;
  readonly committedAt: string;
}

export type WorkspaceManifest = PreparedWorkspaceManifest | CommittedWorkspaceManifest;

export interface PreparedWorkspaceRevisionRecord extends WorkspaceScope {
  readonly recordType: 'workspace-revision';
  readonly state: 'prepared';
  readonly workspaceRevisionId: string;
  readonly expectedWorkspaceRevisionId: string | null;
  readonly preparedManifest: WorkspaceManifestPointer;
  readonly createdAt: string;
}

export interface CommittedWorkspaceRevisionRecord extends WorkspaceScope {
  readonly recordType: 'workspace-revision';
  readonly state: 'committed';
  readonly workspaceRevisionId: string;
  readonly expectedWorkspaceRevisionId: string | null;
  readonly preparedManifestSha256: string;
  readonly committedManifest: WorkspaceManifestPointer;
  readonly sequence: number;
  readonly committedAt: string;
}

export interface VaultWorkspaceHead extends WorkspaceScope {
  readonly recordType: 'workspace-head';
  readonly workspaceRevisionId: string;
  readonly sequence: number;
  readonly preparedManifestSha256: string;
  readonly committedManifest: WorkspaceManifestPointer;
  readonly publishedAt: string;
}

export interface PreparedWorkspaceRevision {
  readonly manifest: PreparedWorkspaceManifest;
  readonly record: PreparedWorkspaceRevisionRecord;
  readonly disposition: 'created' | 'already-prepared';
}

export interface CommittedWorkspaceRevision {
  readonly head: VaultWorkspaceHead;
  readonly manifest: CommittedWorkspaceManifest;
  readonly record: CommittedWorkspaceRevisionRecord;
}

export interface PublishWorkspaceRevisionResult extends CommittedWorkspaceRevision {
  readonly disposition: 'published' | 'already-published' | 'reconciled-after-ambiguous-result';
}

export interface WorkspaceManifestStore {
  put(manifest: WorkspaceManifest): Promise<WorkspaceManifestPointer>;
  get(pointer: WorkspaceManifestPointer): Promise<WorkspaceManifest>;
}

export interface WorkspaceRevisionRepository {
  /** Implementations must issue a strongly consistent head read. */
  getHead(scope: WorkspaceScope): Promise<VaultWorkspaceHead | null>;
  putPrepared(
    record: PreparedWorkspaceRevisionRecord,
  ): Promise<'created' | 'already-prepared'>;
  getPrepared(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
  ): Promise<PreparedWorkspaceRevisionRecord | null>;
  getCommitted(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
  ): Promise<CommittedWorkspaceRevisionRecord | null>;
  /**
   * Atomically writes the committed record and performs exactly one
   * conditional workspace-head update. It must never retry unconditionally.
   */
  publish(
    expectedHead: VaultWorkspaceHead | null,
    prepared: PreparedWorkspaceRevisionRecord,
    committed: CommittedWorkspaceRevisionRecord,
  ): Promise<void>;
}
