import type { VaultPathPolicy } from "./path-policy.js";
import {
  type LegacyIdentityAssignment,
  type LegacyWorkspaceEntry,
  type WorkspaceIdentityIdFactory,
  type WorkspaceIdentityMutation,
  type WorkspaceIdentityProvenance,
  type WorkspaceIdentityState,
  type WorkspaceFileKind,
  type WorkspacePathClaim,
  WorkspaceIdentityError,
  WorkspaceIdentityLedger,
} from "./workspace-identity.js";

/**
 * Persistence seam for the current identity snapshot. Implementations must make
 * compareAndSwap one durable conditional write; they must never emulate it with
 * an unconditional read followed by a write.
 */
export interface WorkspaceIdentityRepository {
  load(vaultId: string): Promise<WorkspaceIdentityState | null>;
  compareAndSwap(input: {
    readonly vaultId: string;
    readonly expectedRevision: number;
    readonly nextState: WorkspaceIdentityState;
  }): Promise<boolean>;
}

export interface WorkspaceFileIdentityServiceDependencies {
  readonly repository: WorkspaceIdentityRepository;
  readonly ids: WorkspaceIdentityIdFactory;
}

/**
 * Focused file-service boundary for stable identity and conditional path claims.
 * Content/object publication remains separate and must join the same transaction
 * boundary when immutable workspace revisions are introduced.
 */
export class WorkspaceFileIdentityService {
  private readonly repository: WorkspaceIdentityRepository;
  private readonly ids: WorkspaceIdentityIdFactory;

  constructor(dependencies: WorkspaceFileIdentityServiceDependencies) {
    this.repository = dependencies.repository;
    this.ids = dependencies.ids;
  }

  async createFile(input: {
    readonly vaultId: string;
    readonly path: string;
    readonly fileKind: WorkspaceFileKind;
    readonly fileVersionId: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly fileId: string; readonly claim: WorkspacePathClaim; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.createFile(input),
      input.path,
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async createFolder(input: {
    readonly vaultId: string;
    readonly path: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly folderId: string; readonly claim: WorkspacePathClaim; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.createFolder(input),
      input.path,
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async moveFile(input: {
    readonly vaultId: string;
    readonly fileId: string;
    readonly fromPath: string;
    readonly toPath: string;
    readonly expectedFileVersionId: string;
    readonly destinationMustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly fileId: string; readonly claim: WorkspacePathClaim; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.moveFile(input),
      input.toPath,
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async moveFolder(input: {
    readonly vaultId: string;
    readonly folderId: string;
    readonly fromPath: string;
    readonly toPath: string;
    readonly destinationMustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly folderId: string; readonly movedEntityIds: readonly string[]; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.moveFolder(input),
      input.toPath,
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async deleteFile(input: {
    readonly vaultId: string;
    readonly fileId: string;
    readonly path: string;
    readonly expectedFileVersionId: string;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly fileId: string; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.deleteFile(input),
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async deleteFolder(input: {
    readonly vaultId: string;
    readonly folderId: string;
    readonly path: string;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly folderId: string; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.deleteFolder(input),
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async restoreFile(input: {
    readonly vaultId: string;
    readonly fileId: string;
    readonly path: string;
    readonly fileVersionId: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly fileId: string; readonly claim: WorkspacePathClaim; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.restoreFile(input),
      input.path,
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async backfillLegacySnapshot(input: {
    readonly vaultId: string;
    readonly entries: readonly LegacyWorkspaceEntry[];
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly assignments: readonly LegacyIdentityAssignment[]; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.backfillLegacySnapshot(input),
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  async migratePathPolicy(input: {
    readonly vaultId: string;
    readonly nextPolicy: VaultPathPolicy;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): Promise<{ readonly policyVersion: number; readonly revision: number }> {
    return this.commit(
      input.vaultId,
      input.expectedRevision,
      (ledger) => ledger.migratePathPolicy(input),
    ).then(({ value, state }) => Object.freeze({ ...value, revision: state.revision }));
  }

  private async commit<T>(
    vaultId: string,
    expectedRevision: number,
    mutate: (ledger: WorkspaceIdentityLedger) => WorkspaceIdentityMutation<T>,
    collisionPath?: string,
  ): Promise<WorkspaceIdentityMutation<T>> {
    const current = await this.repository.load(vaultId);
    if (!current) throw new WorkspaceIdentityError("IDENTITY_NOT_FOUND", "Workspace identity state does not exist.");
    if (current.vaultId !== vaultId) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity repository returned a cross-vault state.");
    }
    if (current.revision !== expectedRevision) {
      throw new WorkspaceIdentityError(
        "STALE_WORKSPACE_REVISION",
        "Workspace identity state advanced before the operation began.",
        { expectedRevision, currentRevision: current.revision },
      );
    }
    const ledger = new WorkspaceIdentityLedger(current, this.ids);
    const mutation = mutate(ledger);
    const committed = await this.repository.compareAndSwap({
      vaultId,
      expectedRevision,
      nextState: mutation.state,
    });
    if (committed) return mutation;

    if (collisionPath) {
      const latest = await this.repository.load(vaultId);
      if (latest) {
        const resolution = new WorkspaceIdentityLedger(latest, this.ids).resolvePath({ path: collisionPath });
        if (resolution.status === "resolved") {
          throw new WorkspaceIdentityError(
            "PATH_CLAIM_CONFLICT",
            "Conditional path claim lost to another writer.",
            { path: collisionPath, currentEntityId: resolution.entityId },
          );
        }
      }
    }
    throw new WorkspaceIdentityError(
      "STALE_WORKSPACE_REVISION",
      "Conditional workspace identity publication lost to another writer.",
      { expectedRevision },
    );
  }
}
