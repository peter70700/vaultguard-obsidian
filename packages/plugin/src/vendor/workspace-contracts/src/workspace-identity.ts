import {
  type NormalizedWorkspacePath,
  type PathCollision,
  type PathCollisionInput,
  type VaultPathPolicy,
  WorkspacePathError,
  createVaultPathPolicy,
  detectWorkspacePathCollisions,
  normalizeWorkspacePath,
  planWorkspacePathPolicyMigration,
} from "./path-policy.js";
import { isAnyStableId, isStableId } from "./ids.js";

export const WORKSPACE_IDENTITY_SCHEMA_VERSION = "1.0.0" as const;
export const ROOT_FOLDER_ID = "fld_root" as const;

export type WorkspaceEntityKind = "file" | "folder";
export type WorkspaceFileKind = "markdown" | "canvas" | "text" | "binary";
export type WorkspaceIdentityOrigin = "web" | "mcp" | "obsidian-sync" | "import" | "system";
export type PathClaimReleaseReason = "rename" | "move" | "delete" | "policy-migration" | "version";

export interface WorkspaceIdentityProvenance {
  readonly at: string;
  readonly actorId: string;
  readonly origin: WorkspaceIdentityOrigin;
}

export interface FileIdentity {
  readonly entityKind: "file";
  readonly fileId: string;
  readonly fileKind: WorkspaceFileKind;
  readonly createdAt: string;
  readonly createdBy: string;
  readonly origin: WorkspaceIdentityOrigin;
  readonly tombstonedAt?: string;
  readonly tombstonedBy?: string;
  readonly tombstonedRevision?: number;
}

export interface FolderIdentity {
  readonly entityKind: "folder";
  readonly folderId: string;
  readonly createdAt: string;
  readonly createdBy: string;
  readonly origin: WorkspaceIdentityOrigin;
  readonly tombstonedAt?: string;
  readonly tombstonedBy?: string;
  readonly tombstonedRevision?: number;
}

export type WorkspaceIdentity = FileIdentity | FolderIdentity;

export interface WorkspacePathClaim {
  readonly claimId: string;
  readonly entityKind: WorkspaceEntityKind;
  readonly entityId: string;
  readonly displayPath: string;
  readonly canonicalPath: string;
  readonly canonicalPathHash: string;
  readonly parentFolderId: string;
  readonly name: string;
  readonly fileVersionId?: string;
  readonly policyVersion: number;
  readonly validFromRevision: number;
  readonly validThroughRevision?: number;
  readonly releasedReason?: PathClaimReleaseReason;
}

export interface HistoricalPathAlias {
  readonly aliasId: string;
  readonly entityKind: WorkspaceEntityKind;
  readonly entityId: string;
  readonly oldDisplayPath: string;
  readonly oldCanonicalPath: string;
  readonly oldCanonicalPathHash: string;
  readonly policyVersion: number;
  readonly validFromRevision: number;
  readonly validThroughRevision: number;
  readonly releasedReason: PathClaimReleaseReason;
  readonly supersededAtRevision?: number;
  readonly supersededByEntityId?: string;
  readonly supersededByFileId?: string;
  readonly supersededByFolderId?: string;
}

export interface VaultPathPolicyActivation {
  readonly policy: VaultPathPolicy;
  readonly validFromRevision: number;
  readonly validThroughRevision?: number;
}

export interface WorkspaceIdentityState {
  readonly schemaVersion: typeof WORKSPACE_IDENTITY_SCHEMA_VERSION;
  readonly vaultId: string;
  readonly revision: number;
  readonly pathPolicy: VaultPathPolicy;
  readonly pathPolicyHistory: readonly VaultPathPolicyActivation[];
  readonly identities: readonly WorkspaceIdentity[];
  readonly pathClaims: readonly WorkspacePathClaim[];
  readonly aliases: readonly HistoricalPathAlias[];
}

export interface WorkspaceIdentityIdFactory {
  nextId(kind: "file" | "folder" | "claim" | "alias"): string;
}

export function createWorkspaceIdentityIdFactory(nextRandomSuffix: () => string): WorkspaceIdentityIdFactory {
  if (typeof nextRandomSuffix !== "function") {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity factory requires a random suffix source.");
  }
  const prefixes = Object.freeze({ file: "fil", folder: "fld", claim: "pclaim", alias: "palias" });
  return Object.freeze({
    nextId(kind: "file" | "folder" | "claim" | "alias"): string {
      const suffix = nextRandomSuffix();
      if (
        typeof suffix !== "string" ||
        suffix.length === 0 ||
        suffix.length > 118 ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(suffix) ||
        suffix.includes("..")
      ) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity suffix source returned an unsafe value.");
      }
      return `${prefixes[kind]}_${suffix}`;
    },
  });
}

export type WorkspaceIdentityErrorCode =
  | "IDENTITY_INVALID"
  | "IDENTITY_NOT_FOUND"
  | "IDENTITY_TOMBSTONED"
  | "FOLDER_NOT_EMPTY"
  | "PATH_CLAIM_CONFLICT"
  | "PATH_IDENTITY_MISMATCH"
  | "PATH_RESOLUTION_AMBIGUOUS"
  | "STALE_FILE_VERSION"
  | "STALE_WORKSPACE_REVISION";

export class WorkspaceIdentityError extends Error {
  readonly code: WorkspaceIdentityErrorCode;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: WorkspaceIdentityErrorCode,
    message: string,
    details?: Readonly<Record<string, unknown>>,
  ) {
    super(message);
    this.name = "WorkspaceIdentityError";
    this.code = code;
    this.details = details;
  }
}

export type WorkspacePathResolution =
  | { readonly status: "missing"; readonly normalized: NormalizedWorkspacePath }
  | {
      readonly status: "resolved";
      readonly source: "active" | "historical";
      readonly normalized: NormalizedWorkspacePath;
      readonly entityKind: WorkspaceEntityKind;
      readonly entityId: string;
      readonly claim?: WorkspacePathClaim;
      readonly alias?: HistoricalPathAlias;
    }
  | {
      readonly status: "ambiguous";
      readonly normalized: NormalizedWorkspacePath;
      readonly candidates: readonly (
        | {
            readonly source: "active";
            readonly entityKind: WorkspaceEntityKind;
            readonly entityId: string;
            readonly claimId: string;
          }
        | {
            readonly source: "historical";
            readonly entityKind: WorkspaceEntityKind;
            readonly entityId: string;
            readonly aliasId: string;
          }
      )[];
    };

export interface LegacyWorkspaceEntry {
  readonly path: string;
  readonly kind: WorkspaceEntityKind;
  readonly fileKind?: WorkspaceFileKind;
  readonly fileVersionId?: string;
  readonly sourceKey?: string;
}

export interface LegacyIdentityAssignment {
  readonly path: string;
  readonly entityKind: WorkspaceEntityKind;
  readonly entityId: string;
  readonly status: "created" | "preserved";
}

export interface WorkspaceIdentityMutation<T> {
  readonly state: WorkspaceIdentityState;
  readonly value: T;
}

export function createWorkspaceIdentityState(input: {
  readonly vaultId: string;
  readonly pathPolicy: VaultPathPolicy;
  readonly provenance: WorkspaceIdentityProvenance;
}): WorkspaceIdentityState {
  if (input.pathPolicy.vaultId !== input.vaultId) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path policy belongs to another vault.");
  }
  assertProvenance(input.provenance);
  const pathPolicy = copyPathPolicy(input.pathPolicy);
  const root: FolderIdentity = Object.freeze({
    entityKind: "folder",
    folderId: ROOT_FOLDER_ID,
    createdAt: input.provenance.at,
    createdBy: input.provenance.actorId,
    origin: input.provenance.origin,
  });
  return freezeState({
    schemaVersion: WORKSPACE_IDENTITY_SCHEMA_VERSION,
    vaultId: input.vaultId,
    revision: 0,
    pathPolicy,
    pathPolicyHistory: [Object.freeze({ policy: pathPolicy, validFromRevision: 0 })],
    identities: [root],
    pathClaims: [],
    aliases: [],
  });
}

export class WorkspaceIdentityLedger {
  private stateValue: WorkspaceIdentityState;
  private readonly ids: WorkspaceIdentityIdFactory;
  private readonly allocatedIds: Set<string>;

  constructor(state: WorkspaceIdentityState, ids: WorkspaceIdentityIdFactory) {
    assertState(state);
    this.stateValue = cloneState(state);
    this.ids = ids;
    this.allocatedIds = new Set([
      ...state.identities.map(identityId),
      ...state.pathClaims.map((claim) => claim.claimId),
      ...state.aliases.map((alias) => alias.aliasId),
    ]);
  }

  get state(): WorkspaceIdentityState {
    assertState(this.stateValue);
    return cloneState(this.stateValue);
  }

  resolvePath(input: {
    readonly path: string;
    readonly atRevision?: number;
    readonly includeHistoricalAliases?: boolean;
  }): WorkspacePathResolution {
    const revision = input.atRevision ?? this.stateValue.revision;
    assertRevisionInRange(revision, this.stateValue.revision);
    const resolutionPolicy = policyAtRevision(this.stateValue, revision);
    const normalized = normalizeWorkspacePath(input.path, resolutionPolicy, { allowExcluded: true });
    const claims = this.stateValue.pathClaims.filter(
      (claim) => claim.canonicalPath === normalized.canonicalPath && isClaimActiveAt(claim, revision),
    );
    if (claims.length > 1) {
      throw new WorkspaceIdentityError(
        "PATH_RESOLUTION_AMBIGUOUS",
        "Persisted identity state contains multiple active claims for one canonical path.",
        { canonicalPath: normalized.canonicalPath },
      );
    }
    if (claims.length === 1 && input.includeHistoricalAliases !== true) {
      const claim = claims[0];
      return Object.freeze({
        status: "resolved",
        source: "active",
        normalized,
        entityKind: claim.entityKind,
        entityId: claim.entityId,
        claim,
      });
    }
    if (input.includeHistoricalAliases !== true) return Object.freeze({ status: "missing", normalized });

    const aliases = this.stateValue.aliases
      .filter((alias) => {
        if (revision <= alias.validThroughRevision) return false;
        const currentCanonical = normalizeWorkspacePath(alias.oldDisplayPath, resolutionPolicy, {
          kind: alias.entityKind,
          allowExcluded: true,
        }).canonicalPath;
        return currentCanonical === normalized.canonicalPath;
      })
      .sort(compareAliases);
    const candidates = uniqueResolutionCandidates(claims, aliases);
    if (candidates.length === 0) return Object.freeze({ status: "missing", normalized });
    if (candidates.length > 1) {
      return Object.freeze({ status: "ambiguous", normalized, candidates: Object.freeze(candidates) });
    }
    if (claims.length === 1) {
      const claim = claims[0];
      return Object.freeze({
        status: "resolved",
        source: "active",
        normalized,
        entityKind: claim.entityKind,
        entityId: claim.entityId,
        claim,
      });
    }
    const alias = aliases.find((candidate) => candidate.entityId === candidates[0].entityId)!;
    return Object.freeze({
      status: "resolved",
      source: "historical",
      normalized,
      entityKind: alias.entityKind,
      entityId: alias.entityId,
      alias,
    });
  }

  createFile(input: {
    readonly path: string;
    readonly fileKind: WorkspaceFileKind;
    readonly fileVersionId: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly fileId: string; readonly claim: WorkspacePathClaim }> {
    this.assertMutationPreconditions(input);
    if (input.mustBeAbsent !== true) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "File creation requires mustBeAbsent: true.");
    }
    assertStableIdKind("fileVersion", input.fileVersionId, "fileVersionId");
    if (!["markdown", "canvas", "text", "binary"].includes(input.fileKind)) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Unsupported file kind.");
    }
    const normalized = normalizeWorkspacePath(input.path, this.stateValue.pathPolicy, { kind: "file" });
    this.assertPathAbsent(normalized);
    const parentFolderId = this.requireParentFolder(normalized);
    const revision = this.stateValue.revision + 1;
    const fileId = this.nextUniqueId("file");
    const identity: FileIdentity = Object.freeze({
      entityKind: "file",
      fileId,
      fileKind: input.fileKind,
      createdAt: input.provenance.at,
      createdBy: input.provenance.actorId,
      origin: input.provenance.origin,
    });
    const claim = this.makeClaim({
      entityKind: "file",
      entityId: fileId,
      normalized,
      parentFolderId,
      fileVersionId: input.fileVersionId,
      revision,
    });
    this.supersedeAliases(normalized.canonicalPath, fileId, "file", revision);
    this.replaceState({
      revision,
      identities: [...this.stateValue.identities, identity],
      pathClaims: [...this.stateValue.pathClaims, claim],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ fileId, claim }) });
  }

  createFolder(input: {
    readonly path: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly folderId: string; readonly claim: WorkspacePathClaim }> {
    this.assertMutationPreconditions(input);
    if (input.mustBeAbsent !== true) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Folder creation requires mustBeAbsent: true.");
    }
    const normalized = normalizeWorkspacePath(input.path, this.stateValue.pathPolicy, { kind: "folder" });
    this.assertPathAbsent(normalized);
    const parentFolderId = this.requireParentFolder(normalized);
    const revision = this.stateValue.revision + 1;
    const folderId = this.nextUniqueId("folder");
    const identity: FolderIdentity = Object.freeze({
      entityKind: "folder",
      folderId,
      createdAt: input.provenance.at,
      createdBy: input.provenance.actorId,
      origin: input.provenance.origin,
    });
    const claim = this.makeClaim({
      entityKind: "folder",
      entityId: folderId,
      normalized,
      parentFolderId,
      revision,
    });
    this.supersedeAliases(normalized.canonicalPath, folderId, "folder", revision);
    this.replaceState({
      revision,
      identities: [...this.stateValue.identities, identity],
      pathClaims: [...this.stateValue.pathClaims, claim],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ folderId, claim }) });
  }

  moveFile(input: {
    readonly fileId: string;
    readonly fromPath: string;
    readonly toPath: string;
    readonly expectedFileVersionId: string;
    readonly destinationMustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly fileId: string; readonly claim: WorkspacePathClaim }> {
    this.assertMutationPreconditions(input);
    if (input.destinationMustBeAbsent !== true) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "File move requires destinationMustBeAbsent: true.");
    }
    const identity = this.requireActiveIdentity("file", input.fileId) as FileIdentity;
    const source = this.requireActiveClaim(input.fromPath, "file", identity.fileId);
    if (source.fileVersionId !== input.expectedFileVersionId) {
      throw new WorkspaceIdentityError(
        "STALE_FILE_VERSION",
        "File move source version no longer matches the expected version.",
        { expectedFileVersionId: input.expectedFileVersionId, currentFileVersionId: source.fileVersionId },
      );
    }
    const destination = normalizeWorkspacePath(input.toPath, this.stateValue.pathPolicy, { kind: "file" });
    if (
      destination.canonicalPath === source.canonicalPath &&
      destination.displayPath === source.displayPath
    ) {
      throw new WorkspaceIdentityError(
        "PATH_CLAIM_CONFLICT",
        "A file cannot be renamed to its current path.",
        { canonicalPath: destination.canonicalPath },
      );
    }
    if (destination.canonicalPath !== source.canonicalPath) this.assertPathAbsent(destination);
    const parentFolderId = this.requireParentFolder(destination);
    const revision = this.stateValue.revision + 1;
    const released = releaseClaim(source, revision, source.parentFolderId === parentFolderId ? "rename" : "move");
    const alias = this.makeAlias(released);
    const claim = this.makeClaim({
      entityKind: "file",
      entityId: identity.fileId,
      normalized: destination,
      parentFolderId,
      fileVersionId: source.fileVersionId,
      revision,
    });
    this.supersedeAliases(destination.canonicalPath, identity.fileId, "file", revision);
    this.replaceState({
      revision,
      pathClaims: replaceClaim(this.stateValue.pathClaims, released).concat(claim),
      aliases: [...this.stateValue.aliases, alias],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ fileId: identity.fileId, claim }) });
  }

  moveFolder(input: {
    readonly folderId: string;
    readonly fromPath: string;
    readonly toPath: string;
    readonly destinationMustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{
    readonly folderId: string;
    readonly movedEntityIds: readonly string[];
  }> {
    this.assertMutationPreconditions(input);
    if (input.destinationMustBeAbsent !== true) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Folder move requires destinationMustBeAbsent: true.");
    }
    if (input.folderId === ROOT_FOLDER_ID) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "The root folder cannot be moved.");
    }
    this.requireActiveIdentity("folder", input.folderId);
    const source = this.requireActiveClaim(input.fromPath, "folder", input.folderId);
    const destination = normalizeWorkspacePath(input.toPath, this.stateValue.pathPolicy, { kind: "folder" });
    if (destination.displayPath === source.displayPath) {
      throw new WorkspaceIdentityError("PATH_CLAIM_CONFLICT", "A folder cannot be renamed to its current path.");
    }
    if (destination.canonicalPath.startsWith(`${source.canonicalPath}/`)) {
      throw new WorkspaceIdentityError("PATH_CLAIM_CONFLICT", "A folder cannot move onto or inside itself.");
    }
    if (destination.canonicalPath !== source.canonicalPath) this.assertPathAbsent(destination);
    const destinationParentId = this.requireParentFolder(destination);
    const activeClaims = this.activeClaims();
    const movedClaims = activeClaims
      .filter(
        (claim) =>
          claim.canonicalPath === source.canonicalPath ||
          claim.canonicalPath.startsWith(`${source.canonicalPath}/`),
      )
      .sort(compareClaims);
    const movedIds = new Set(movedClaims.map((claim) => claim.entityId));
    const projected = movedClaims.map((claim) => {
      const suffix = claim.displayPath === source.displayPath
        ? ""
        : claim.displayPath.slice(source.displayPath.length + 1);
      return {
        claim,
        normalized: normalizeWorkspacePath(
          suffix ? `${destination.displayPath}/${suffix}` : destination.displayPath,
          this.stateValue.pathPolicy,
          { kind: claim.entityKind },
        ),
      };
    });
    const collisions = detectWorkspacePathCollisions(
      [
        ...activeClaims
          .filter((claim) => !movedIds.has(claim.entityId))
          .map((claim) => ({ path: claim.displayPath, kind: claim.entityKind, sourceKey: claim.entityId })),
        ...projected.map(({ claim, normalized }) => ({
          path: normalized.displayPath,
          kind: claim.entityKind,
          sourceKey: claim.entityId,
        })),
      ],
      this.stateValue.pathPolicy,
    );
    if (collisions.length > 0) throw collisionError(collisions);

    const revision = this.stateValue.revision + 1;
    const releasedReason: PathClaimReleaseReason = source.parentFolderId === destinationParentId ? "rename" : "move";
    const released = projected.map(({ claim }) => releaseClaim(claim, revision, releasedReason));
    const nextClaims = projected.map(({ claim, normalized }) => this.makeClaim({
      entityKind: claim.entityKind,
      entityId: claim.entityId,
      normalized,
      parentFolderId: claim.entityId === input.folderId
        ? destinationParentId
        : this.parentFolderIdForProjectedPath(normalized, projected),
      fileVersionId: claim.fileVersionId,
      revision,
    }));
    const aliases = released.map((claim) => this.makeAlias(claim));
    for (const claim of nextClaims) {
      this.supersedeAliases(claim.canonicalPath, claim.entityId, claim.entityKind, revision);
    }
    const releasedById = new Map(released.map((claim) => [claim.claimId, claim]));
    this.replaceState({
      revision,
      pathClaims: this.stateValue.pathClaims
        .map((claim) => releasedById.get(claim.claimId) ?? claim)
        .concat(nextClaims),
      aliases: [...this.stateValue.aliases, ...aliases],
    });
    return Object.freeze({
      state: this.state,
      value: Object.freeze({ folderId: input.folderId, movedEntityIds: Object.freeze([...movedIds].sort(compareStrings)) }),
    });
  }

  deleteFile(input: {
    readonly fileId: string;
    readonly path: string;
    readonly expectedFileVersionId: string;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly fileId: string }> {
    this.assertMutationPreconditions(input);
    const identity = this.requireActiveIdentity("file", input.fileId) as FileIdentity;
    const claim = this.requireActiveClaim(input.path, "file", identity.fileId);
    if (claim.fileVersionId !== input.expectedFileVersionId) {
      throw new WorkspaceIdentityError("STALE_FILE_VERSION", "File delete source version no longer matches.");
    }
    const revision = this.stateValue.revision + 1;
    const released = releaseClaim(claim, revision, "delete");
    const tombstone: FileIdentity = Object.freeze({
      ...identity,
      tombstonedAt: input.provenance.at,
      tombstonedBy: input.provenance.actorId,
      tombstonedRevision: revision,
    });
    this.replaceState({
      revision,
      identities: replaceIdentity(this.stateValue.identities, tombstone),
      pathClaims: replaceClaim(this.stateValue.pathClaims, released),
      aliases: [...this.stateValue.aliases, this.makeAlias(released)],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ fileId: identity.fileId }) });
  }

  deleteFolder(input: {
    readonly folderId: string;
    readonly path: string;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly folderId: string }> {
    this.assertMutationPreconditions(input);
    if (input.folderId === ROOT_FOLDER_ID) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "The root folder cannot be deleted.");
    }
    const identity = this.requireActiveIdentity("folder", input.folderId) as FolderIdentity;
    const claim = this.requireActiveClaim(input.path, "folder", input.folderId);
    if (this.activeClaims().some((candidate) => candidate.parentFolderId === input.folderId)) {
      throw new WorkspaceIdentityError("FOLDER_NOT_EMPTY", "Folder deletion requires an empty folder.");
    }
    const revision = this.stateValue.revision + 1;
    const released = releaseClaim(claim, revision, "delete");
    const tombstone: FolderIdentity = Object.freeze({
      ...identity,
      tombstonedAt: input.provenance.at,
      tombstonedBy: input.provenance.actorId,
      tombstonedRevision: revision,
    });
    this.replaceState({
      revision,
      identities: replaceIdentity(this.stateValue.identities, tombstone),
      pathClaims: replaceClaim(this.stateValue.pathClaims, released),
      aliases: [...this.stateValue.aliases, this.makeAlias(released)],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ folderId: identity.folderId }) });
  }

  restoreFile(input: {
    readonly fileId: string;
    readonly path: string;
    readonly fileVersionId: string;
    readonly mustBeAbsent: true;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly fileId: string; readonly claim: WorkspacePathClaim }> {
    this.assertMutationPreconditions(input);
    if (input.mustBeAbsent !== true) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "File restoration requires mustBeAbsent: true.");
    }
    assertStableIdKind("fileVersion", input.fileVersionId, "fileVersionId");
    const identity = this.requireIdentity("file", input.fileId) as FileIdentity;
    if (identity.tombstonedRevision === undefined) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Only a tombstoned file identity can be restored.");
    }
    const normalized = normalizeWorkspacePath(input.path, this.stateValue.pathPolicy, { kind: "file" });
    this.assertPathAbsent(normalized);
    const revision = this.stateValue.revision + 1;
    const restored: FileIdentity = Object.freeze({
      entityKind: "file",
      fileId: identity.fileId,
      fileKind: identity.fileKind,
      createdAt: identity.createdAt,
      createdBy: identity.createdBy,
      origin: identity.origin,
    });
    const claim = this.makeClaim({
      entityKind: "file",
      entityId: identity.fileId,
      normalized,
      parentFolderId: this.requireParentFolder(normalized),
      fileVersionId: input.fileVersionId,
      revision,
    });
    this.supersedeAliases(normalized.canonicalPath, identity.fileId, "file", revision);
    this.replaceState({
      revision,
      identities: replaceIdentity(this.stateValue.identities, restored),
      pathClaims: [...this.stateValue.pathClaims, claim],
    });
    return Object.freeze({ state: this.state, value: Object.freeze({ fileId: identity.fileId, claim }) });
  }

  /** Apply a complete, exact-base inventory as ONE identity revision. Intermediate
   * rename cycles and subtree edits are never published. Historical claims and
   * aliases remain immutable; explicit restore reuses only a tombstoned file ID. */
  publishSnapshot(input: {
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
    readonly restoredFileIds: readonly string[];
    readonly entries: readonly {
      readonly entityKind: WorkspaceEntityKind;
      readonly entityId: string;
      readonly path: string;
      readonly fileVersionId?: string;
      readonly fileKind?: WorkspaceFileKind;
    }[];
  }): WorkspaceIdentityState {
    this.assertMutationPreconditions(input);
    const revision = this.stateValue.revision + 1;
    const projected = input.entries.map((entry) => ({
      entry, normalized: normalizeWorkspacePath(entry.path, this.stateValue.pathPolicy, { kind: entry.entityKind }),
    }));
    const collisions = detectWorkspacePathCollisions(input.entries.map(e => ({ path: e.path, kind: e.entityKind })), this.stateValue.pathPolicy);
    if (collisions.length) throw collisionError(collisions);
    const nextIds = new Set(input.entries.map(e => e.entityId));
    if (nextIds.size !== projected.length || nextIds.has(ROOT_FOLDER_ID))
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Publication inventory repeats an identity.");
    const restores = new Set(input.restoredFileIds);
    if (restores.size !== input.restoredFileIds.length)
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Publication repeats a restore.");
    const oldClaims = new Map(this.activeClaims().map(c => [c.entityId, c]));
    const identities = [...this.stateValue.identities];
    const claims = [...this.stateValue.pathClaims];
    let aliases = [...this.stateValue.aliases];
    for (const { entry, normalized } of projected) {
      assertStableIdKind(entry.entityKind, entry.entityId, "entityId");
      if (entry.entityKind === "file") assertStableIdKind("fileVersion", entry.fileVersionId, "fileVersionId");
      else if (entry.fileVersionId !== undefined) throw new WorkspaceIdentityError("IDENTITY_INVALID", "Folder cannot hold a file version.");
      const index = identities.findIndex(i => identityId(i) === entry.entityId), previous = identities[index];
      if (previous && previous.entityKind !== entry.entityKind)
        throw new WorkspaceIdentityError("PATH_IDENTITY_MISMATCH", "Publication changed an identity kind.");
      if (previous?.tombstonedRevision !== undefined) {
        if (entry.entityKind !== "file" || !restores.delete(entry.entityId))
          throw new WorkspaceIdentityError("IDENTITY_TOMBSTONED", "Publication requires explicit file restore.");
        const { tombstonedAt: _at, tombstonedBy: _by, tombstonedRevision: _rev, ...restored } = previous;
        identities[index] = restored;
      } else if (restores.has(entry.entityId)) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Restore requires a tombstoned identity.");
      } else if (!previous) {
        if (this.allocatedIds.has(entry.entityId)) throw new WorkspaceIdentityError("IDENTITY_INVALID", "Publication recycled an allocated ID.");
        if (entry.entityKind === "file" && !["markdown", "canvas", "text", "binary"].includes(entry.fileKind!))
          throw new WorkspaceIdentityError("IDENTITY_INVALID", "New file requires its kind.");
        this.allocatedIds.add(entry.entityId);
        const common = { createdAt: input.provenance.at, createdBy: input.provenance.actorId, origin: input.provenance.origin };
        identities.push(entry.entityKind === "file"
          ? { ...common, entityKind: "file", fileId: entry.entityId, fileKind: entry.fileKind! }
          : { ...common, entityKind: "folder", folderId: entry.entityId });
      }
      const parent = normalized.parentPath ? projected.find(p => p.entry.entityKind === "folder" && p.normalized.canonicalPath === normalizeWorkspacePath(normalized.parentPath, this.stateValue.pathPolicy, { kind: "folder" }).canonicalPath) : null;
      if (normalized.parentPath && !parent) throw new WorkspaceIdentityError("IDENTITY_NOT_FOUND", "Publication requires every parent folder.");
      const parentFolderId = parent?.entry.entityId ?? ROOT_FOLDER_ID, old = oldClaims.get(entry.entityId);
      if (old && old.displayPath === normalized.displayPath && old.parentFolderId === parentFolderId && old.fileVersionId === entry.fileVersionId) continue;
      if (old) {
        const reason = old.displayPath === normalized.displayPath ? "version" : old.parentFolderId === parentFolderId ? "rename" : "move";
        const released = releaseClaim(old, revision, reason);
        claims[claims.findIndex(c => c.claimId === old.claimId)] = released;
        if (reason !== "version") aliases.push(this.makeAlias(released));
      }
      claims.push(this.makeClaim({ entityKind: entry.entityKind, entityId: entry.entityId, normalized, parentFolderId, fileVersionId: entry.fileVersionId, revision }));
    }
    if (restores.size) throw new WorkspaceIdentityError("IDENTITY_INVALID", "Restore is absent from final inventory.");
    for (const [entityId, old] of oldClaims) {
      if (nextIds.has(entityId)) continue;
      const released = releaseClaim(old, revision, "delete");
      claims[claims.findIndex(c => c.claimId === old.claimId)] = released;
      aliases.push(this.makeAlias(released));
      const index = identities.findIndex(i => identityId(i) === entityId);
      identities[index] = { ...identities[index], tombstonedAt: input.provenance.at, tombstonedBy: input.provenance.actorId, tombstonedRevision: revision };
    }
    aliases = aliases.map(alias => {
      if (alias.supersededAtRevision !== undefined) return alias;
      const replacement = projected.find(p => p.normalized.canonicalPath === normalizeWorkspacePath(alias.oldDisplayPath, this.stateValue.pathPolicy, { kind: alias.entityKind, allowExcluded: true }).canonicalPath);
      return replacement ? { ...alias, supersededAtRevision: revision, supersededByEntityId: replacement.entry.entityId,
        ...(replacement.entry.entityKind === "file" ? { supersededByFileId: replacement.entry.entityId } : { supersededByFolderId: replacement.entry.entityId }) } : alias;
    });
    const next = freezeState({ ...this.stateValue, revision, identities, pathClaims: claims, aliases });
    assertState(next);
    this.stateValue = next;
    return this.state;
  }

  backfillLegacySnapshot(input: {
    readonly entries: readonly LegacyWorkspaceEntry[];
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly assignments: readonly LegacyIdentityAssignment[] }> {
    this.assertMutationPreconditions(input);
    const collisionInputs: PathCollisionInput[] = input.entries.map((entry) => ({
      path: entry.path,
      kind: entry.kind,
      sourceKey: entry.sourceKey,
    }));
    const collisions = detectWorkspacePathCollisions(collisionInputs, this.stateValue.pathPolicy);
    if (collisions.length > 0) throw collisionError(collisions);

    const normalizedEntries = input.entries.map((entry) => ({
      entry,
      normalized: normalizeWorkspacePath(entry.path, this.stateValue.pathPolicy, { kind: entry.kind }),
    })).sort((left, right) => compareStrings(left.normalized.canonicalPath, right.normalized.canonicalPath));

    const prospectiveKinds = new Map(
      this.activeClaims().map((claim) => [claim.canonicalPath, claim.entityKind] as const),
    );
    for (const { entry, normalized } of normalizedEntries) {
      prospectiveKinds.set(normalized.canonicalPath, entry.kind);
    }

    for (const { entry, normalized } of normalizedEntries) {
      const active = this.activeClaimAt(normalized.canonicalPath);
      if (active && active.entityKind !== entry.kind) {
        throw new WorkspaceIdentityError("PATH_CLAIM_CONFLICT", "Legacy path conflicts with an active identity.");
      }
      if (normalized.parentPath) {
        const parent = normalizeWorkspacePath(normalized.parentPath, this.stateValue.pathPolicy, {
          kind: "folder",
          allowExcluded: true,
        });
        if (prospectiveKinds.get(parent.canonicalPath) !== "folder") {
          throw new WorkspaceIdentityError(
            "IDENTITY_NOT_FOUND",
            "Legacy snapshot must contain each missing parent folder explicitly.",
            { parentPath: normalized.parentPath },
          );
        }
      }
      if (entry.kind === "file") {
        if (!entry.fileKind || !entry.fileVersionId) {
          throw new WorkspaceIdentityError(
            "IDENTITY_INVALID",
            "Legacy file entries require fileKind and fileVersionId.",
          );
        }
        assertStableIdKind("fileVersion", entry.fileVersionId, "fileVersionId");
      }
    }

    const missing = normalizedEntries.filter(({ normalized }) => !this.activeClaimAt(normalized.canonicalPath));
    if (missing.length === 0) {
      const assignments = normalizedEntries.map(({ entry, normalized }) => {
        const claim = this.activeClaimAt(normalized.canonicalPath)!;
        return Object.freeze({
          path: entry.path,
          entityKind: entry.kind,
          entityId: claim.entityId,
          status: "preserved" as const,
        });
      });
      return Object.freeze({ state: this.state, value: Object.freeze({ assignments: Object.freeze(assignments) }) });
    }

    const revision = this.stateValue.revision + 1;
    const identities = [...this.stateValue.identities];
    const pathClaims = [...this.stateValue.pathClaims];
    const assignments: LegacyIdentityAssignment[] = [];
    for (const { entry, normalized } of normalizedEntries) {
      const existing = this.activeClaimAt(normalized.canonicalPath);
      if (existing) {
        assignments.push(Object.freeze({
          path: entry.path,
          entityKind: entry.kind,
          entityId: existing.entityId,
          status: "preserved",
        }));
        continue;
      }
      const entityId = this.nextUniqueId(entry.kind);
      const identity: WorkspaceIdentity = entry.kind === "file"
        ? Object.freeze({
            entityKind: "file",
            fileId: entityId,
            fileKind: entry.fileKind!,
            createdAt: input.provenance.at,
            createdBy: input.provenance.actorId,
            origin: input.provenance.origin,
          })
        : Object.freeze({
            entityKind: "folder",
            folderId: entityId,
            createdAt: input.provenance.at,
            createdBy: input.provenance.actorId,
            origin: input.provenance.origin,
          });
      identities.push(identity);
      pathClaims.push(this.makeClaim({
        entityKind: entry.kind,
        entityId,
        normalized,
        parentFolderId: this.requireParentFolderFromClaims(normalized, pathClaims),
        fileVersionId: entry.fileVersionId,
        revision,
      }));
      assignments.push(Object.freeze({ path: entry.path, entityKind: entry.kind, entityId, status: "created" }));
    }
    for (const assignment of assignments) {
      if (assignment.status !== "created") continue;
      const normalized = normalizeWorkspacePath(assignment.path, this.stateValue.pathPolicy, {
        kind: assignment.entityKind,
      });
      this.supersedeAliases(
        normalized.canonicalPath,
        assignment.entityId,
        assignment.entityKind,
        revision,
      );
    }
    this.replaceState({ revision, identities, pathClaims });
    return Object.freeze({ state: this.state, value: Object.freeze({ assignments: Object.freeze(assignments) }) });
  }

  migratePathPolicy(input: {
    readonly nextPolicy: VaultPathPolicy;
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): WorkspaceIdentityMutation<{ readonly policyVersion: number }> {
    this.assertMutationPreconditions(input);
    const nextPolicy = copyPathPolicy(input.nextPolicy);
    const activeClaims = this.activeClaims();
    const plan = planWorkspacePathPolicyMigration({
      fromPolicy: this.stateValue.pathPolicy,
      toPolicy: nextPolicy,
      paths: activeClaims.map((claim) => ({ path: claim.displayPath, kind: claim.entityKind, sourceKey: claim.entityId })),
    });
    if (plan.status === "blocked") {
      if (plan.collisions.length > 0) throw collisionError(plan.collisions);
      throw new WorkspaceIdentityError(
        "PATH_CLAIM_CONFLICT",
        "Path policy migration would make active paths invalid or excluded.",
        { invalid: plan.invalid },
      );
    }
    const revision = this.stateValue.revision + 1;
    const released = activeClaims.map((claim) => releaseClaim(claim, revision, "policy-migration"));
    const replacements = activeClaims.map((claim) => {
      const normalized = normalizeWorkspacePath(claim.displayPath, nextPolicy, {
        kind: claim.entityKind,
      });
      return this.makeClaim({
        entityKind: claim.entityKind,
        entityId: claim.entityId,
        normalized,
        parentFolderId: claim.parentFolderId,
        fileVersionId: claim.fileVersionId,
        revision,
      });
    });
    const releasedById = new Map(released.map((claim) => [claim.claimId, claim]));
    const pathPolicyHistory = this.stateValue.pathPolicyHistory.map((activation) =>
      activation.validThroughRevision === undefined
        ? Object.freeze({ ...activation, validThroughRevision: revision - 1 })
        : activation,
    ).concat(Object.freeze({ policy: nextPolicy, validFromRevision: revision }));
    this.replaceState({
      revision,
      pathPolicy: nextPolicy,
      pathPolicyHistory,
      pathClaims: this.stateValue.pathClaims
        .map((claim) => releasedById.get(claim.claimId) ?? claim)
        .concat(replacements),
    });
    return Object.freeze({
      state: this.state,
      value: Object.freeze({ policyVersion: nextPolicy.policyVersion }),
    });
  }

  private assertMutationPreconditions(input: {
    readonly expectedRevision: number;
    readonly expectedPolicyVersion: number;
    readonly provenance: WorkspaceIdentityProvenance;
  }): void {
    assertProvenance(input.provenance);
    if (input.expectedRevision !== this.stateValue.revision) {
      throw new WorkspaceIdentityError(
        "STALE_WORKSPACE_REVISION",
        "Workspace revision no longer matches the caller's expected revision.",
        { expectedRevision: input.expectedRevision, currentRevision: this.stateValue.revision },
      );
    }
    if (input.expectedPolicyVersion !== this.stateValue.pathPolicy.policyVersion) {
      throw new WorkspaceIdentityError(
        "STALE_WORKSPACE_REVISION",
        "Path policy version no longer matches the caller's expected version.",
        {
          expectedPolicyVersion: input.expectedPolicyVersion,
          currentPolicyVersion: this.stateValue.pathPolicy.policyVersion,
        },
      );
    }
  }

  private assertPathAbsent(path: NormalizedWorkspacePath): void {
    const current = this.activeClaimAt(path.canonicalPath);
    if (current) {
      throw new WorkspaceIdentityError(
        "PATH_CLAIM_CONFLICT",
        "Canonical path is already claimed.",
        {
          requestedPath: path.displayPath,
          canonicalPath: path.canonicalPath,
          currentEntityKind: current.entityKind,
          currentEntityId: current.entityId,
        },
      );
    }
  }

  private requireParentFolder(path: NormalizedWorkspacePath): string {
    return this.requireParentFolderFromClaims(path, this.activeClaims());
  }

  private requireParentFolderFromClaims(
    path: NormalizedWorkspacePath,
    claims: readonly WorkspacePathClaim[],
  ): string {
    if (!path.parentPath) return ROOT_FOLDER_ID;
    const normalizedParent = normalizeWorkspacePath(path.parentPath, this.stateValue.pathPolicy, {
      kind: "folder",
      allowExcluded: true,
    });
    const parent = claims.find(
      (claim) =>
        claim.validThroughRevision === undefined &&
        claim.canonicalPath === normalizedParent.canonicalPath,
    );
    if (!parent || parent.entityKind !== "folder") {
      throw new WorkspaceIdentityError(
        "IDENTITY_NOT_FOUND",
        "Parent folder must have an active stable identity before claiming a child path.",
        { parentPath: path.parentPath },
      );
    }
    return parent.entityId;
  }

  private requireActiveClaim(path: string, kind: WorkspaceEntityKind, entityId: string): WorkspacePathClaim {
    const normalized = normalizeWorkspacePath(path, this.stateValue.pathPolicy, { kind, allowExcluded: true });
    const claim = this.activeClaimAt(normalized.canonicalPath);
    if (!claim) throw new WorkspaceIdentityError("IDENTITY_NOT_FOUND", "No active identity claims the source path.");
    if (claim.entityKind !== kind || claim.entityId !== entityId) {
      throw new WorkspaceIdentityError(
        "PATH_IDENTITY_MISMATCH",
        "Source path resolves to a different stable identity.",
        { expectedEntityId: entityId, actualEntityId: claim.entityId },
      );
    }
    return claim;
  }

  private requireIdentity(kind: WorkspaceEntityKind, entityId: string): WorkspaceIdentity {
    const identity = this.stateValue.identities.find(
      (candidate) => candidate.entityKind === kind && identityId(candidate) === entityId,
    );
    if (!identity) throw new WorkspaceIdentityError("IDENTITY_NOT_FOUND", `${kind} identity does not exist.`);
    return identity;
  }

  private requireActiveIdentity(kind: WorkspaceEntityKind, entityId: string): WorkspaceIdentity {
    const identity = this.requireIdentity(kind, entityId);
    if (identity.tombstonedRevision !== undefined) {
      throw new WorkspaceIdentityError("IDENTITY_TOMBSTONED", `${kind} identity is tombstoned.`);
    }
    return identity;
  }

  private activeClaimAt(canonicalPath: string): WorkspacePathClaim | undefined {
    return this.stateValue.pathClaims.find(
      (claim) => claim.canonicalPath === canonicalPath && claim.validThroughRevision === undefined,
    );
  }

  private activeClaims(): WorkspacePathClaim[] {
    return this.stateValue.pathClaims.filter((claim) => claim.validThroughRevision === undefined);
  }

  private makeClaim(input: {
    readonly entityKind: WorkspaceEntityKind;
    readonly entityId: string;
    readonly normalized: NormalizedWorkspacePath;
    readonly parentFolderId: string;
    readonly fileVersionId?: string;
    readonly revision: number;
  }): WorkspacePathClaim {
    return Object.freeze({
      claimId: this.nextUniqueId("claim"),
      entityKind: input.entityKind,
      entityId: input.entityId,
      displayPath: input.normalized.displayPath,
      canonicalPath: input.normalized.canonicalPath,
      canonicalPathHash: input.normalized.canonicalPathHash,
      parentFolderId: input.parentFolderId,
      name: input.normalized.basename,
      ...(input.fileVersionId ? { fileVersionId: input.fileVersionId } : {}),
      policyVersion: input.normalized.policyVersion,
      validFromRevision: input.revision,
    });
  }

  private makeAlias(claim: WorkspacePathClaim): HistoricalPathAlias {
    if (claim.validThroughRevision === undefined || claim.releasedReason === undefined) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Only a released path claim can become an alias.");
    }
    return Object.freeze({
      aliasId: this.nextUniqueId("alias"),
      entityKind: claim.entityKind,
      entityId: claim.entityId,
      oldDisplayPath: claim.displayPath,
      oldCanonicalPath: claim.canonicalPath,
      oldCanonicalPathHash: claim.canonicalPathHash,
      policyVersion: claim.policyVersion,
      validFromRevision: claim.validFromRevision,
      validThroughRevision: claim.validThroughRevision,
      releasedReason: claim.releasedReason,
    });
  }

  private supersedeAliases(
    canonicalPath: string,
    entityId: string,
    entityKind: WorkspaceEntityKind,
    revision: number,
  ): void {
    const aliases = this.stateValue.aliases.map((alias) =>
      normalizeWorkspacePath(alias.oldDisplayPath, this.stateValue.pathPolicy, {
        kind: alias.entityKind,
        allowExcluded: true,
      }).canonicalPath === canonicalPath && alias.supersededAtRevision === undefined
        ? Object.freeze({
            ...alias,
            supersededAtRevision: revision,
            supersededByEntityId: entityId,
            ...(entityKind === "file"
              ? { supersededByFileId: entityId }
              : { supersededByFolderId: entityId }),
          })
        : alias,
    );
    this.replaceState({ aliases });
  }

  private parentFolderIdForProjectedPath(
    path: NormalizedWorkspacePath,
    projected: readonly { readonly claim: WorkspacePathClaim; readonly normalized: NormalizedWorkspacePath }[],
  ): string {
    if (!path.parentPath) return ROOT_FOLDER_ID;
    const parent = projected.find(
      (candidate) => candidate.claim.entityKind === "folder" && candidate.normalized.displayPath === path.parentPath,
    );
    if (parent) return parent.claim.entityId;
    return this.requireParentFolder(path);
  }

  private nextUniqueId(kind: "file" | "folder" | "claim" | "alias"): string {
    const id = this.ids.nextId(kind);
    if (kind === "file" || kind === "folder") assertStableIdKind(kind, id, `${kind}Id`);
    else assertSafeId(id, `${kind}Id`);
    if (this.allocatedIds.has(id)) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", `Identity factory reused ${kind} ID ${id}.`);
    }
    this.allocatedIds.add(id);
    return id;
  }

  private replaceState(patch: Partial<WorkspaceIdentityState>): void {
    this.stateValue = freezeState({ ...this.stateValue, ...patch });
  }
}

function releaseClaim(
  claim: WorkspacePathClaim,
  revision: number,
  releasedReason: PathClaimReleaseReason,
): WorkspacePathClaim {
  return Object.freeze({
    ...claim,
    validThroughRevision: revision - 1,
    releasedReason,
  });
}

function replaceClaim(
  claims: readonly WorkspacePathClaim[],
  replacement: WorkspacePathClaim,
): WorkspacePathClaim[] {
  return claims.map((claim) => claim.claimId === replacement.claimId ? replacement : claim);
}

function replaceIdentity(
  identities: readonly WorkspaceIdentity[],
  replacement: WorkspaceIdentity,
): WorkspaceIdentity[] {
  return identities.map((identity) => identityId(identity) === identityId(replacement) ? replacement : identity);
}

function identityId(identity: WorkspaceIdentity): string {
  return identity.entityKind === "file" ? identity.fileId : identity.folderId;
}

function isClaimActiveAt(claim: WorkspacePathClaim, revision: number): boolean {
  return claim.validFromRevision <= revision &&
    (claim.validThroughRevision === undefined || revision <= claim.validThroughRevision);
}

function uniqueResolutionCandidates(
  claims: readonly WorkspacePathClaim[],
  aliases: readonly HistoricalPathAlias[],
): (
  | {
      source: "active";
      entityKind: WorkspaceEntityKind;
      entityId: string;
      claimId: string;
    }
  | {
      source: "historical";
      entityKind: WorkspaceEntityKind;
      entityId: string;
      aliasId: string;
    }
)[] {
  const byEntity = new Map<string, ReturnType<typeof resolutionCandidate>>();
  for (const claim of claims) {
    const key = `${claim.entityKind}:${claim.entityId}`;
    byEntity.set(key, resolutionCandidate(claim));
  }
  for (const alias of aliases) {
    const key = `${alias.entityKind}:${alias.entityId}`;
    if (!byEntity.has(key)) byEntity.set(key, resolutionCandidate(alias));
  }
  return [...byEntity.values()].sort(
    (left, right) =>
      compareStrings(left.entityKind, right.entityKind) ||
      compareStrings(left.entityId, right.entityId),
  );
}

function resolutionCandidate(
  value: WorkspacePathClaim | HistoricalPathAlias,
):
  | {
      source: "active";
      entityKind: WorkspaceEntityKind;
      entityId: string;
      claimId: string;
    }
  | {
      source: "historical";
      entityKind: WorkspaceEntityKind;
      entityId: string;
      aliasId: string;
    } {
  return "claimId" in value
    ? {
        source: "active",
        entityKind: value.entityKind,
        entityId: value.entityId,
        claimId: value.claimId,
      }
    : {
        source: "historical",
        entityKind: value.entityKind,
        entityId: value.entityId,
        aliasId: value.aliasId,
      };
}

function collisionError(collisions: readonly PathCollision[]): WorkspaceIdentityError {
  return new WorkspaceIdentityError(
    "PATH_CLAIM_CONFLICT",
    "Canonical path collision prevents the operation.",
    { collisions },
  );
}

function assertState(state: WorkspaceIdentityState): void {
  if (
    !state ||
    !state.pathPolicy ||
    !Array.isArray(state.pathPolicyHistory) ||
    !Array.isArray(state.identities) ||
    !Array.isArray(state.pathClaims) ||
    !Array.isArray(state.aliases) ||
    state.schemaVersion !== WORKSPACE_IDENTITY_SCHEMA_VERSION ||
    state.vaultId !== state.pathPolicy.vaultId ||
    !Number.isInteger(state.revision) ||
    state.revision < 0
  ) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Invalid workspace identity state.");
  }
  if (state.pathPolicyHistory.length === 0) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Workspace identity state requires path policy history.");
  }
  let expectedFromRevision = 0;
  let previousPolicyVersion = 0;
  const policyVersions = new Set<number>();
  for (let index = 0; index < state.pathPolicyHistory.length; index += 1) {
    const activation = state.pathPolicyHistory[index];
    const rebuilt = createVaultPathPolicy({
      vaultId: activation.policy.vaultId,
      policyVersion: activation.policy.policyVersion,
      caseMode: activation.policy.caseMode,
      unicodeMode: activation.policy.unicodeMode,
      maxDepth: activation.policy.maxDepth,
      maxPathBytes: activation.policy.maxPathBytes,
      maxSegmentBytes: activation.policy.maxSegmentBytes,
      exclusions: activation.policy.exclusions,
    });
    if (
      activation.policy.vaultId !== state.vaultId ||
      activation.validFromRevision !== expectedFromRevision ||
      policyVersions.has(activation.policy.policyVersion) ||
      activation.policy.policyVersion <= previousPolicyVersion ||
      policyFingerprint(rebuilt) !== policyFingerprint(activation.policy)
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path policy history is invalid or non-contiguous.");
    }
    policyVersions.add(activation.policy.policyVersion);
    previousPolicyVersion = activation.policy.policyVersion;
    const isCurrent = index === state.pathPolicyHistory.length - 1;
    if (isCurrent) {
      if (
        activation.validThroughRevision !== undefined ||
        policyFingerprint(activation.policy) !== policyFingerprint(state.pathPolicy) ||
        activation.validFromRevision > state.revision
      ) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Current path policy activation is inconsistent.");
      }
    } else {
      if (
        !Number.isInteger(activation.validThroughRevision) ||
        activation.validThroughRevision! < activation.validFromRevision ||
        activation.validThroughRevision! >= state.revision
      ) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Historical path policy interval is invalid.");
      }
      expectedFromRevision = activation.validThroughRevision! + 1;
    }
  }
  const root = state.identities.filter(
    (identity) => identity.entityKind === "folder" && identity.folderId === ROOT_FOLDER_ID,
  );
  if (root.length !== 1 || root[0].tombstonedRevision !== undefined) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Workspace identity state requires one active root folder.");
  }
  const ids = state.identities.map(identityId);
  if (new Set(ids).size !== ids.length) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Workspace identity IDs must be unique.");
  }
  for (const identity of state.identities) {
    assertStableIdKind(identity.entityKind, identityId(identity), `${identity.entityKind}Id`);
    if (!isIsoDateTime(identity.createdAt)) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity creation timestamp is invalid.");
    }
    assertKnownStableId(identity.createdBy, "createdBy");
    const hasTombstone = identity.tombstonedRevision !== undefined;
    if (
      hasTombstone !== (identity.tombstonedAt !== undefined) ||
      hasTombstone !== (identity.tombstonedBy !== undefined) ||
      (hasTombstone && (
        !Number.isInteger(identity.tombstonedRevision) ||
        identity.tombstonedRevision! < 1 ||
        identity.tombstonedRevision! > state.revision ||
        !isIsoDateTime(identity.tombstonedAt)
      ))
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity tombstone fields are inconsistent.");
    }
  }

  const claimIds = state.pathClaims.map((claim) => claim.claimId);
  const aliasIds = state.aliases.map((alias) => alias.aliasId);
  const allRecordIds = [...ids, ...claimIds, ...aliasIds];
  if (new Set(allRecordIds).size !== allRecordIds.length) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity, claim, and alias IDs must be globally unique.");
  }
  for (const claim of state.pathClaims) {
    assertSafeId(claim.claimId, "claimId");
    assertStableIdKind(claim.entityKind, claim.entityId, `${claim.entityKind}Id`);
    assertStableIdKind("folder", claim.parentFolderId, "parentFolderId");
    if (claim.fileVersionId !== undefined) {
      assertStableIdKind("fileVersion", claim.fileVersionId, "fileVersionId");
    }
    const identity = state.identities.find((candidate) => identityId(candidate) === claim.entityId);
    if (!identity || identity.entityKind !== claim.entityKind) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path claim references a missing or mismatched identity.");
    }
    if ((claim.entityKind === "file") !== (claim.fileVersionId !== undefined)) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Only file path claims carry a fileVersionId.");
    }
    if (
      !Number.isInteger(claim.validFromRevision) ||
      claim.validFromRevision < 1 ||
      claim.validFromRevision > state.revision ||
      (claim.validThroughRevision !== undefined && (
        !Number.isInteger(claim.validThroughRevision) ||
        claim.validThroughRevision < claim.validFromRevision ||
        claim.validThroughRevision > state.revision
      )) ||
      (claim.validThroughRevision === undefined) !== (claim.releasedReason === undefined)
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path claim lifecycle fields are inconsistent.");
    }
    const claimPolicy = state.pathPolicyHistory.find(
      (activation) => activation.policy.policyVersion === claim.policyVersion,
    )?.policy;
    if (!claimPolicy) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path claim references an unknown policy version.");
    }
    const activation = state.pathPolicyHistory.find(
      (candidate) => candidate.policy.policyVersion === claim.policyVersion,
    )!;
    if (
      claim.validFromRevision < activation.validFromRevision ||
      (activation.validThroughRevision !== undefined && (
        claim.validThroughRevision === undefined ||
        claim.validThroughRevision > activation.validThroughRevision
      ))
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path claim extends outside its policy activation.");
    }
    const normalized = normalizeWorkspacePath(claim.displayPath, claimPolicy, {
      kind: claim.entityKind,
      allowExcluded: claim.validThroughRevision !== undefined,
    });
    if (
      normalized.canonicalPath !== claim.canonicalPath ||
      normalized.canonicalPathHash !== claim.canonicalPathHash ||
      normalized.basename !== claim.name
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Path claim does not match its versioned path policy.");
    }
  }
  for (const alias of state.aliases) {
    assertSafeId(alias.aliasId, "aliasId");
    const identity = state.identities.find((candidate) => identityId(candidate) === alias.entityId);
    if (!identity || identity.entityKind !== alias.entityKind) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Historical alias references a missing identity.");
    }
    if (
      !Number.isInteger(alias.validFromRevision) ||
      !Number.isInteger(alias.validThroughRevision) ||
      alias.validFromRevision < 1 ||
      alias.validThroughRevision < alias.validFromRevision ||
      alias.validThroughRevision > state.revision ||
      (alias.supersededAtRevision !== undefined && (
        !Number.isInteger(alias.supersededAtRevision) ||
        alias.supersededAtRevision <= alias.validThroughRevision ||
        alias.supersededAtRevision > state.revision ||
        alias.supersededByEntityId === undefined
      ))
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Historical alias lifecycle fields are inconsistent.");
    }
    const supersededFields = [alias.supersededByFileId, alias.supersededByFolderId]
      .filter((value): value is string => value !== undefined);
    if (alias.supersededAtRevision === undefined) {
      if (alias.supersededByEntityId !== undefined || supersededFields.length > 0) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Unsuperseded alias carries a replacement identity.");
      }
    } else {
      if (
        alias.supersededByEntityId === undefined ||
        supersededFields.length !== 1 ||
        supersededFields[0] !== alias.supersededByEntityId ||
        (alias.supersededByFileId !== undefined && !isStableId("file", alias.supersededByFileId)) ||
        (alias.supersededByFolderId !== undefined && !isStableId("folder", alias.supersededByFolderId))
      ) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Superseded alias replacement fields are inconsistent.");
      }
      if (!state.identities.some((candidate) => identityId(candidate) === alias.supersededByEntityId)) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Superseded alias references a missing replacement.");
      }
    }
    const aliasPolicy = state.pathPolicyHistory.find(
      (activation) => activation.policy.policyVersion === alias.policyVersion,
    )?.policy;
    if (!aliasPolicy) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Historical alias references an unknown policy version.");
    }
    const normalized = normalizeWorkspacePath(alias.oldDisplayPath, aliasPolicy, {
      kind: alias.entityKind,
      allowExcluded: true,
    });
    if (
      normalized.canonicalPath !== alias.oldCanonicalPath ||
      normalized.canonicalPathHash !== alias.oldCanonicalPathHash
    ) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Historical alias does not match the path policy.");
    }
  }
  const activeClaims = state.pathClaims.filter((claim) => claim.validThroughRevision === undefined);
  if (activeClaims.some((claim) => claim.policyVersion !== state.pathPolicy.policyVersion)) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Active claims must use the current path policy.");
  }
  const collisions = detectWorkspacePathCollisions(
    activeClaims.map((claim) => ({ path: claim.displayPath, kind: claim.entityKind, sourceKey: claim.entityId })),
    state.pathPolicy,
  );
  if (collisions.length > 0) throw collisionError(collisions);
  if (new Set(activeClaims.map((claim) => claim.entityId)).size !== activeClaims.length) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "An active identity cannot claim multiple paths.");
  }
  const activeEntityIds = new Set(activeClaims.map((claim) => claim.entityId));
  for (const identity of state.identities) {
    const id = identityId(identity);
    if (id === ROOT_FOLDER_ID) continue;
    if ((identity.tombstonedRevision === undefined) !== activeEntityIds.has(id)) {
      throw new WorkspaceIdentityError(
        "IDENTITY_INVALID",
        "Each active non-root identity must have exactly one active path claim.",
      );
    }
  }
  for (const claim of activeClaims) {
    const parentIdentity = state.identities.find(
      (identity) => identity.entityKind === "folder" && identity.folderId === claim.parentFolderId,
    );
    if (!parentIdentity || parentIdentity.tombstonedRevision !== undefined) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Active path claim has no active parent folder.");
    }
    const segments = claim.displayPath.split("/");
    if (segments.length === 1) {
      if (claim.parentFolderId !== ROOT_FOLDER_ID) {
        throw new WorkspaceIdentityError("IDENTITY_INVALID", "Top-level path must belong to the root folder.");
      }
      continue;
    }
    const parentPath = segments.slice(0, -1).join("/");
    const normalizedParent = normalizeWorkspacePath(parentPath, state.pathPolicy, {
      kind: "folder",
      allowExcluded: true,
    });
    const parentClaim = activeClaims.find(
      (candidate) =>
        candidate.entityKind === "folder" &&
        candidate.entityId === claim.parentFolderId &&
        candidate.canonicalPath === normalizedParent.canonicalPath,
    );
    if (!parentClaim) {
      throw new WorkspaceIdentityError("IDENTITY_INVALID", "Active path claim parent relation does not match its path.");
    }
  }
}

function policyAtRevision(state: WorkspaceIdentityState, revision: number): VaultPathPolicy {
  const activation = state.pathPolicyHistory.find(
    (candidate) =>
      candidate.validFromRevision <= revision &&
      (candidate.validThroughRevision === undefined || revision <= candidate.validThroughRevision),
  );
  if (!activation) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "No path policy is active at the requested revision.");
  }
  return activation.policy;
}

function policyFingerprint(policy: VaultPathPolicy): string {
  return JSON.stringify({
    schemaVersion: policy.schemaVersion,
    vaultId: policy.vaultId,
    policyVersion: policy.policyVersion,
    caseMode: policy.caseMode,
    unicodeMode: policy.unicodeMode,
    maxDepth: policy.maxDepth,
    maxPathBytes: policy.maxPathBytes,
    maxSegmentBytes: policy.maxSegmentBytes,
    exclusions: policy.exclusions,
  });
}

function cloneState(state: WorkspaceIdentityState): WorkspaceIdentityState {
  return freezeState({
    ...state,
    pathPolicy: copyPathPolicy(state.pathPolicy),
    pathPolicyHistory: state.pathPolicyHistory.map((activation) => Object.freeze({
      ...activation,
      policy: copyPathPolicy(activation.policy),
    })),
    identities: state.identities.map((identity) => Object.freeze({ ...identity })),
    pathClaims: state.pathClaims.map((claim) => Object.freeze({ ...claim })),
    aliases: state.aliases.map((alias) => Object.freeze({ ...alias })),
  });
}

function copyPathPolicy(policy: VaultPathPolicy): VaultPathPolicy {
  return createVaultPathPolicy({
    vaultId: policy.vaultId,
    policyVersion: policy.policyVersion,
    caseMode: policy.caseMode,
    unicodeMode: policy.unicodeMode,
    maxDepth: policy.maxDepth,
    maxPathBytes: policy.maxPathBytes,
    maxSegmentBytes: policy.maxSegmentBytes,
    exclusions: policy.exclusions,
  });
}

function freezeState(state: WorkspaceIdentityState): WorkspaceIdentityState {
  return Object.freeze({
    ...state,
    identities: Object.freeze([...state.identities]),
    pathPolicyHistory: Object.freeze([...state.pathPolicyHistory]),
    pathClaims: Object.freeze([...state.pathClaims]),
    aliases: Object.freeze([...state.aliases]),
  });
}

function assertProvenance(value: WorkspaceIdentityProvenance): void {
  if (!value || !isIsoDateTime(value.at)) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity provenance requires an ISO UTC timestamp.");
  }
  assertKnownStableId(value.actorId, "actorId");
  if (!["web", "mcp", "obsidian-sync", "import", "system"].includes(value.origin)) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Identity provenance has an unsupported origin.");
  }
}

function assertSafeId(value: unknown, name: string): asserts value is string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) ||
    value.includes("..")
  ) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", `${name} must be a safe stable ID.`);
  }
}

function assertKnownStableId(value: unknown, name: string): asserts value is string {
  if (!isAnyStableId(value)) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", `${name} must be a recognized stable ID.`);
  }
}

function assertStableIdKind(
  kind: "file" | "fileVersion" | "folder",
  value: unknown,
  name: string,
): asserts value is string {
  if (!isStableId(kind, value)) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", `${name} must be a ${kind} stable ID.`);
  }
}

function assertRevisionInRange(revision: number, currentRevision: number): void {
  if (!Number.isInteger(revision) || revision < 0 || revision > currentRevision) {
    throw new WorkspaceIdentityError("IDENTITY_INVALID", "Requested revision is outside the known workspace history.");
  }
}

function isIsoDateTime(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u.test(value)) {
    return false;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed);
}

function compareClaims(left: WorkspacePathClaim, right: WorkspacePathClaim): number {
  return compareStrings(left.canonicalPath, right.canonicalPath) || compareStrings(left.entityId, right.entityId);
}

function compareAliases(left: HistoricalPathAlias, right: HistoricalPathAlias): number {
  return compareStrings(left.entityId, right.entityId) || compareStrings(left.aliasId, right.aliasId);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function isWorkspacePathError(error: unknown): error is WorkspacePathError {
  return error instanceof WorkspacePathError;
}
