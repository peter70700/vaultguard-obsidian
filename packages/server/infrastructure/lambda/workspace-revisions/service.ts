import { requireWorkspaceCapability, type WorkspaceCapabilityGate } from '../shared/workspace-capabilities';
import {
  assertWorkspaceManifest,
  committedManifestFromPrepared,
  deepFreeze,
} from './manifest-store';
import {
  WorkspaceHeadCasError,
  WorkspaceRevisionImmutabilityError,
} from './head-store';
import type {
  CommittedWorkspaceManifest,
  CommittedWorkspaceRevision,
  CommittedWorkspaceRevisionRecord,
  PreparedWorkspaceManifest,
  PreparedWorkspaceRevision,
  PreparedWorkspaceRevisionRecord,
  PublishWorkspaceRevisionResult,
  VaultWorkspaceHead,
  WorkspaceManifestStore,
  WorkspaceManifest,
  WorkspaceManifestPointer,
  WorkspaceRevisionRepository,
  WorkspaceScope,
} from './types';

export class WorkspaceRevisionNotFoundError extends Error {
  constructor(workspaceRevisionId: string) {
    super(`committed workspace revision not found: ${workspaceRevisionId}`);
    this.name = 'WorkspaceRevisionNotFoundError';
  }
}

export class WorkspaceHeadConflictError extends Error {
  readonly currentWorkspaceRevisionId: string | null;

  constructor(expectedWorkspaceRevisionId: string | null, current: VaultWorkspaceHead | null) {
    super(
      `workspace head conflict: expected ${expectedWorkspaceRevisionId ?? '<empty>'}, observed ${current?.workspaceRevisionId ?? '<empty>'}`,
    );
    this.name = 'WorkspaceHeadConflictError';
    this.currentWorkspaceRevisionId = current?.workspaceRevisionId ?? null;
  }
}

export class WorkspacePublicationOutcomeUnknownError extends Error {
  readonly observedWorkspaceRevisionId: string | null;
  readonly cause: unknown;

  constructor(observed: VaultWorkspaceHead | null, cause: unknown) {
    super('workspace publication outcome is unknown; the service did not retry the head update');
    this.name = 'WorkspacePublicationOutcomeUnknownError';
    this.observedWorkspaceRevisionId = observed?.workspaceRevisionId ?? null;
    this.cause = cause;
  }
}

function sameScope(left: WorkspaceScope, right: WorkspaceScope): boolean {
  return left.orgId === right.orgId && left.vaultId === right.vaultId;
}

function samePointer(
  left: CommittedWorkspaceRevisionRecord['committedManifest'],
  right: CommittedWorkspaceRevisionRecord['committedManifest'],
): boolean {
  return (
    left.objectKey === right.objectKey &&
    left.storageVersionId === right.storageVersionId &&
    left.sha256 === right.sha256 &&
    left.byteLength === right.byteLength &&
    left.encryption?.format === right.encryption?.format &&
    left.encryption?.cloudKeyId === right.encryption?.cloudKeyId &&
    left.encryption?.ciphertextSha256 === right.encryption?.ciphertextSha256 &&
    left.encryption?.ciphertextBytes === right.encryption?.ciphertextBytes
  );
}

function preparedRecordFromManifest(
  manifest: PreparedWorkspaceManifest,
  preparedManifest: PreparedWorkspaceRevisionRecord['preparedManifest'],
): PreparedWorkspaceRevisionRecord {
  return deepFreeze({
    recordType: 'workspace-revision',
    state: 'prepared',
    orgId: manifest.orgId,
    vaultId: manifest.vaultId,
    workspaceRevisionId: manifest.workspaceRevisionId,
    expectedWorkspaceRevisionId: manifest.expectedWorkspaceRevisionId,
    preparedManifest,
    createdAt: manifest.createdAt,
  });
}

function committedRecordFromManifest(
  manifest: CommittedWorkspaceManifest,
  committedManifest: CommittedWorkspaceRevisionRecord['committedManifest'],
): CommittedWorkspaceRevisionRecord {
  return deepFreeze({
    recordType: 'workspace-revision',
    state: 'committed',
    orgId: manifest.orgId,
    vaultId: manifest.vaultId,
    workspaceRevisionId: manifest.workspaceRevisionId,
    expectedWorkspaceRevisionId: manifest.expectedWorkspaceRevisionId,
    preparedManifestSha256: manifest.preparedManifestSha256,
    committedManifest,
    sequence: manifest.sequence,
    committedAt: manifest.committedAt,
  });
}

export class WorkspaceRevisionService {
  private readonly committedManifestCache = new Map<string, { value: Promise<WorkspaceManifest>;
    bytes: number; expiresAt: number }>();
  private committedManifestCacheBytes = 0;
  private committedManifestCacheHits = 0;
  private committedManifestCacheMisses = 0;
  constructor(
    private readonly manifests: WorkspaceManifestStore,
    private readonly repository: WorkspaceRevisionRepository,
    private readonly gate: WorkspaceCapabilityGate = requireWorkspaceCapability,
  ) {}

  /** Internal diagnostics only; caller access and HEAD are still read afresh. */
  manifestCacheSnapshot() { return { entries: this.committedManifestCache.size,
    declaredBytes: this.committedManifestCacheBytes, hits: this.committedManifestCacheHits,
    misses: this.committedManifestCacheMisses }; }

  private async exactCommittedManifest(scope: WorkspaceScope, pointer: WorkspaceManifestPointer): Promise<WorkspaceManifest> {
    if (pointer.byteLength > 16 * 1024 * 1024) return this.manifests.get(pointer);
    const key = JSON.stringify([scope.orgId, scope.vaultId, pointer]);
    const existing = this.committedManifestCache.get(key);
    if (existing) {
      this.committedManifestCache.delete(key);
      this.committedManifestCacheBytes -= existing.bytes;
      if (existing.expiresAt > Date.now()) {
        existing.expiresAt = Date.now() + 30_000;
        this.committedManifestCache.set(key, existing);
        this.committedManifestCacheBytes += existing.bytes;
        this.committedManifestCacheHits++;
        return existing.value;
      }
    }
    this.committedManifestCacheMisses++;
    const entry = { value: this.manifests.get(pointer), bytes: pointer.byteLength,
      expiresAt: Date.now() + 30_000 };
    this.committedManifestCache.set(key, entry);
    this.committedManifestCacheBytes += entry.bytes;
    while (this.committedManifestCache.size > 2 || this.committedManifestCacheBytes > 16 * 1024 * 1024) {
      const oldest = this.committedManifestCache.keys().next().value;
      if (!oldest) break;
      this.committedManifestCacheBytes -= this.committedManifestCache.get(oldest)!.bytes;
      this.committedManifestCache.delete(oldest);
    }
    try { return await entry.value; }
    catch (error) {
      if (this.committedManifestCache.get(key) === entry) {
        this.committedManifestCache.delete(key);
        this.committedManifestCacheBytes -= entry.bytes;
      }
      throw error;
    }
  }

  /** Stages an immutable candidate. This operation never changes the head. */
  async prepare(manifest: PreparedWorkspaceManifest): Promise<PreparedWorkspaceRevision> {
    await this.gate('revision_writes');
    assertWorkspaceManifest(manifest);
    const frozenManifest = deepFreeze(structuredClone(manifest));
    const pointer = await this.manifests.put(frozenManifest);
    const record = preparedRecordFromManifest(frozenManifest, pointer);
    await this.gate('revision_writes');
    const disposition = await this.repository.putPrepared(record);
    await this.gate('revision_writes');
    return deepFreeze({ manifest: frozenManifest, record, disposition });
  }

  /**
   * Publishes a prepared revision with one conditional head transaction. Any
   * ambiguous result is reconciled by read only; this method never retries CAS.
   */
  async publish(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
    committedAt = new Date().toISOString(),
  ): Promise<PublishWorkspaceRevisionResult> {
    await this.gate('revision_writes');
    const prepared = await this.repository.getPrepared(scope, workspaceRevisionId);
    if (!prepared) throw new WorkspaceRevisionNotFoundError(workspaceRevisionId);
    if (!sameScope(scope, prepared)) {
      throw new WorkspaceRevisionImmutabilityError('prepared revision belongs to another workspace');
    }

    const alreadyCommitted = await this.repository.getCommitted(scope, workspaceRevisionId);
    if (alreadyCommitted) {
      this.assertPreparedBinding(prepared, alreadyCommitted);
      const exact = await this.resolveCommitted(scope, workspaceRevisionId);
      await this.gate('revision_writes');
      return deepFreeze({ ...exact, disposition: 'already-published' });
    }

    const expectedHead = await this.repository.getHead(scope);
    if (expectedHead?.workspaceRevisionId !== prepared.expectedWorkspaceRevisionId) {
      if (!(expectedHead === null && prepared.expectedWorkspaceRevisionId === null)) {
        throw new WorkspaceHeadConflictError(prepared.expectedWorkspaceRevisionId, expectedHead);
      }
    }

    const preparedManifest = await this.manifests.get(prepared.preparedManifest);
    if (
      preparedManifest.state !== 'prepared' ||
      preparedManifest.workspaceRevisionId !== workspaceRevisionId ||
      !sameScope(scope, preparedManifest)
    ) {
      throw new WorkspaceRevisionImmutabilityError('prepared manifest does not match its registry record');
    }
    const sequence = (expectedHead?.sequence ?? 0) + 1;
    await this.gate('revision_writes');
    const committedManifest = committedManifestFromPrepared(
      preparedManifest,
      prepared.preparedManifest.sha256,
      sequence,
      committedAt,
    );
    const committedPointer = await this.manifests.put(committedManifest);
    const committedRecord = committedRecordFromManifest(committedManifest, committedPointer);

    await this.gate('revision_writes');
    try {
      await this.repository.publish(expectedHead, prepared, committedRecord);
    } catch (error) {
      let committedAfterError: CommittedWorkspaceRevisionRecord | null;
      try {
        committedAfterError = await this.repository.getCommitted(scope, workspaceRevisionId);
      } catch (recoveryError) {
        throw new WorkspacePublicationOutcomeUnknownError(null, recoveryError);
      }
      if (committedAfterError) {
        this.assertPreparedBinding(prepared, committedAfterError);
        const reconciled = await this.resolveCommitted(scope, workspaceRevisionId);
        return deepFreeze({
          ...reconciled,
          disposition: 'reconciled-after-ambiguous-result',
        });
      }
      let observed: VaultWorkspaceHead | null;
      try {
        observed = await this.repository.getHead(scope);
      } catch (recoveryError) {
        throw new WorkspacePublicationOutcomeUnknownError(null, recoveryError);
      }
      const observedBase = observed?.workspaceRevisionId ?? null;
      if (
        error instanceof WorkspaceHeadCasError ||
        observedBase !== prepared.expectedWorkspaceRevisionId
      ) {
        throw new WorkspaceHeadConflictError(prepared.expectedWorkspaceRevisionId, observed);
      }
      throw new WorkspacePublicationOutcomeUnknownError(observed, error);
    }

    const exact = await this.resolveCommitted(scope, workspaceRevisionId);
    return deepFreeze({ ...exact, disposition: 'published' });
  }

  /** Strongly resolves the current head to one complete committed manifest. */
  async readCurrent(scope: WorkspaceScope): Promise<CommittedWorkspaceRevision | null> {
    await this.gate('revision_reads');
    const head = await this.repository.getHead(scope);
    const result = head ? await this.resolveCommitted(scope, head.workspaceRevisionId, head) : null;
    await this.gate('revision_reads');
    return result;
  }

  /** Prepared-only revisions deliberately return not found here. */
  async readCommitted(scope: WorkspaceScope, workspaceRevisionId: string): Promise<CommittedWorkspaceRevision> {
    await this.gate('revision_reads');
    const result = await this.resolveCommitted(scope, workspaceRevisionId);
    await this.gate('revision_reads');
    return result;
  }

  private async resolveCommitted(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
    observedHead?: VaultWorkspaceHead,
  ): Promise<CommittedWorkspaceRevision> {
    const record = await this.repository.getCommitted(scope, workspaceRevisionId);
    if (!record) throw new WorkspaceRevisionNotFoundError(workspaceRevisionId);
    if (!sameScope(scope, record) || record.workspaceRevisionId !== workspaceRevisionId) {
      throw new WorkspaceRevisionImmutabilityError('committed revision registry record is cross-scoped');
    }
    const manifest = await this.exactCommittedManifest(scope, record.committedManifest);
    if (
      manifest.state !== 'committed' ||
      manifest.workspaceRevisionId !== workspaceRevisionId ||
      !sameScope(scope, manifest) ||
      manifest.preparedManifestSha256 !== record.preparedManifestSha256 ||
      manifest.sequence !== record.sequence
    ) {
      throw new WorkspaceRevisionImmutabilityError('committed manifest does not match its registry record');
    }
    const head = observedHead ?? (await this.repository.getHead(scope));
    if (!head || head.workspaceRevisionId !== workspaceRevisionId) {
      return deepFreeze({
        head: {
          recordType: 'workspace-head',
          orgId: scope.orgId,
          vaultId: scope.vaultId,
          workspaceRevisionId,
          sequence: record.sequence,
          preparedManifestSha256: record.preparedManifestSha256,
          committedManifest: record.committedManifest,
          publishedAt: record.committedAt,
        },
        manifest,
        record,
      });
    }
    if (
      head.sequence !== record.sequence ||
      head.preparedManifestSha256 !== record.preparedManifestSha256 ||
      !samePointer(head.committedManifest, record.committedManifest)
    ) {
      throw new WorkspaceRevisionImmutabilityError('workspace head does not match its committed revision');
    }
    return deepFreeze({ head, manifest, record });
  }

  private assertPreparedBinding(
    prepared: PreparedWorkspaceRevisionRecord,
    committed: CommittedWorkspaceRevisionRecord,
  ): void {
    if (
      prepared.preparedManifest.sha256 !== committed.preparedManifestSha256 ||
      prepared.expectedWorkspaceRevisionId !== committed.expectedWorkspaceRevisionId ||
      !sameScope(prepared, committed)
    ) {
      throw new WorkspaceRevisionImmutabilityError(
        'committed revision is not bound to the requested prepared manifest',
      );
    }
  }
}
