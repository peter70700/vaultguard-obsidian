import { createHash } from 'node:crypto';
import type { CommittedWorkspaceRevision, WorkspaceFileManifestEntry, WorkspaceScope } from '../workspace-revisions/types';
import { assertWorkspaceManifest, workspaceManifestSha256 } from '../workspace-revisions/manifest-store';
import { FileVersionIntegrityError, FileVersionNotFoundError, exactFileVersionStorageKey, type FileVersionRecord } from './file-version-service';

/** A request-local, immutable current-file view. Authorization stays in the
 * existing file handlers. This view never reads a mutable S3 head or falls back
 * from a missing logical version. It is not a migration completeness certificate. */
export class RevisionFileReadView {
  readonly scope: WorkspaceScope;
  readonly workspaceRevisionId: string;
  private readonly entries: readonly WorkspaceFileManifestEntry[];
  private readonly records = new Map<string, Promise<FileVersionRecord>>();
  private readonly digest: string;
  private readonly bucket: string;
  private readonly requireVersion: (orgId: string, vaultId: string, id: string) => Promise<FileVersionRecord>;

  constructor(options: {
    scope: WorkspaceScope;
    bucket: string;
    revision: CommittedWorkspaceRevision;
    requireVersion(orgId: string, vaultId: string, id: string): Promise<FileVersionRecord>;
  }) {
    const { revision, scope } = options;
    try { assertWorkspaceManifest(revision.manifest); } catch { throw new FileVersionIntegrityError(); }
    const { manifest, head, record } = revision;
    const digest = workspaceManifestSha256(manifest);
    if (!options.bucket || manifest.state !== 'committed' ||
      [manifest, head, record].some(row => row.orgId !== scope.orgId || row.vaultId !== scope.vaultId || row.workspaceRevisionId !== manifest.workspaceRevisionId) ||
      head.recordType !== 'workspace-head' || record.recordType !== 'workspace-revision' || record.state !== 'committed' ||
      head.sequence !== manifest.sequence || record.sequence !== manifest.sequence ||
      head.committedManifest.sha256 !== digest || record.committedManifest.sha256 !== digest ||
      head.preparedManifestSha256 !== manifest.preparedManifestSha256 || record.preparedManifestSha256 !== manifest.preparedManifestSha256) {
      throw new FileVersionIntegrityError();
    }
    this.scope = Object.freeze({ orgId: scope.orgId, vaultId: scope.vaultId });
    this.workspaceRevisionId = manifest.workspaceRevisionId;
    this.digest = digest;
    this.bucket = options.bucket;
    this.requireVersion = options.requireVersion;
    this.entries = Object.freeze(manifest.entries.filter((entry): entry is WorkspaceFileManifestEntry => entry.kind === 'file' && entry.state === 'active')
      .map(entry => Object.freeze({ ...entry })).sort((a, b) => Buffer.compare(Buffer.from(a.canonicalPath), Buffer.from(b.canonicalPath))));
  }

  assertScope(scope: WorkspaceScope, bucket: string): void {
    if (scope.orgId !== this.scope.orgId || scope.vaultId !== this.scope.vaultId || bucket !== this.bucket) throw new FileVersionIntegrityError();
  }

  async current(path: string): Promise<FileVersionRecord> {
    const entry = this.entries.find(row => row.canonicalPath === path);
    if (!entry) throw new FileVersionNotFoundError();
    let pending = this.records.get(path);
    if (!pending) {
      pending = this.requireVersion(this.scope.orgId, this.scope.vaultId, entry.fileVersionId).then(record => {
        if (record.schemaVersion !== 1 || record.recordType !== 'file-version' || record.orgId !== this.scope.orgId || record.vaultId !== this.scope.vaultId ||
          record.path !== path || record.fileId !== entry.fileId || record.fileVersionId !== entry.fileVersionId || record.state !== 'content' ||
          record.plaintextSha256 !== entry.plaintextSha256 || record.ciphertextSha256 !== entry.ciphertextSha256 ||
          record.storageBucket !== this.bucket ||
          typeof record.storageVersionId !== 'string' || !record.storageVersionId || record.storageVersionId === 'null' ||
          !Number.isSafeInteger(record.ciphertextBytes) || record.ciphertextBytes < 0 || !Number.isFinite(Date.parse(record.createdAt))) {
          throw new FileVersionIntegrityError();
        }
        exactFileVersionStorageKey(record, this.scope, this.bucket, path);
        return Object.freeze({ ...record, parentFileVersionIds: Object.freeze([...record.parentFileVersionIds]) });
      });
      this.records.set(path, pending);
    }
    return pending;
  }

  /** Cursor selects positions, never authority. Scope, revision digest and prefix
   * are bound; every resulting path still goes through current per-file ACLs.
   * A path-era cursor or changed HEAD requires the caller to start a new listing. */
  page(prefix: string, limit: number, continuationToken?: string): {
    paths: string[]; nextContinuationToken: string | null; isTruncated: boolean;
  } {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new RevisionReadCursorError();
    const binding = createHash('sha256').update(JSON.stringify([this.scope, this.digest, prefix])).digest('hex');
    let offset = 0;
    if (continuationToken) {
      try {
        if (!/^wrp1\.[A-Za-z0-9_-]{1,256}$/.test(continuationToken)) throw new Error();
        const encoded = continuationToken.slice(5);
        const bytes = Buffer.from(encoded, 'base64url');
        if (bytes.toString('base64url') !== encoded) throw new Error();
        const parsed = JSON.parse(bytes.toString('utf8'));
        if (!Array.isArray(parsed) || parsed.length !== 2 || parsed[0] !== binding || !Number.isSafeInteger(parsed[1]) || parsed[1] < 1) throw new Error();
        offset = parsed[1];
      } catch { throw new RevisionReadCursorError(); }
    }
    const selected = this.entries.filter(entry => entry.canonicalPath.startsWith(prefix));
    if (offset > selected.length) throw new RevisionReadCursorError();
    const paths = selected.slice(offset, offset + limit).map(entry => entry.canonicalPath);
    const next = offset + paths.length;
    return {
      paths,
      isTruncated: next < selected.length,
      nextContinuationToken: next < selected.length ? `wrp1.${Buffer.from(JSON.stringify([binding, next])).toString('base64url')}` : null,
    };
  }
}

export class RevisionReadCursorError extends Error {
  readonly statusCode = 409;
  readonly code = 'WORKSPACE_LIST_RESTART_REQUIRED';
  constructor() { super('Restart the file listing without a continuation token'); }
}
