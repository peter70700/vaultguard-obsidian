declare const stableIdBrand: unique symbol;
declare const sha256Brand: unique symbol;

export const STABLE_ID_KINDS = Object.freeze([
  "agentIdentity",
  "agentSession",
  "approval",
  "artifact",
  "auditEvent",
  "changeSet",
  "conflict",
  "contextPack",
  "contextPackVersion",
  "feature",
  "file",
  "fileVersion",
  "folder",
  "graphRevision",
  "handoff",
  "idempotencyRecord",
  "membership",
  "oauthClient",
  "oauthGrant",
  "operation",
  "organization",
  "permissionRevision",
  "policyRevision",
  "projectionRevision",
  "proposal",
  "receipt",
  "request",
  "reservation",
  "schemaDocument",
  "share",
  "subject",
  "vault",
  "workIntent",
  "workspaceRevision",
] as const);

export type StableIdKind = (typeof STABLE_ID_KINDS)[number];
export type StableId<K extends StableIdKind> = string & {
  readonly [stableIdBrand]: K;
};
export type AnyStableId = {
  readonly [K in StableIdKind]: StableId<K>;
}[StableIdKind];

export type AgentIdentityId = StableId<"agentIdentity">;
export type AgentSessionId = StableId<"agentSession">;
export type ApprovalId = StableId<"approval">;
export type ArtifactId = StableId<"artifact">;
export type AuditEventId = StableId<"auditEvent">;
export type ChangeSetId = StableId<"changeSet">;
export type ConflictId = StableId<"conflict">;
export type ContextPackId = StableId<"contextPack">;
export type ContextPackVersionId = StableId<"contextPackVersion">;
export type FeatureId = StableId<"feature">;
export type FileId = StableId<"file">;
export type FileVersionId = StableId<"fileVersion">;
export type FolderId = StableId<"folder">;
export type GraphRevisionId = StableId<"graphRevision">;
export type HandoffId = StableId<"handoff">;
export type IdempotencyRecordId = StableId<"idempotencyRecord">;
export type MembershipId = StableId<"membership">;
export type OAuthClientId = StableId<"oauthClient">;
export type OAuthGrantId = StableId<"oauthGrant">;
export type OperationId = StableId<"operation">;
export type OrganizationId = StableId<"organization">;
export type PermissionRevisionId = StableId<"permissionRevision">;
export type PolicyRevisionId = StableId<"policyRevision">;
export type ProjectionRevisionId = StableId<"projectionRevision">;
export type ProposalId = StableId<"proposal">;
export type ReceiptId = StableId<"receipt">;
export type RequestId = StableId<"request">;
export type ReservationId = StableId<"reservation">;
export type SchemaDocumentId = StableId<"schemaDocument">;
export type ShareId = StableId<"share">;
export type SubjectId = StableId<"subject">;
export type VaultId = StableId<"vault">;
export type WorkIntentId = StableId<"workIntent">;
export type WorkspaceRevisionId = StableId<"workspaceRevision">;
export type SafeId = AnyStableId;
export type Sha256 = string & { readonly [sha256Brand]: "sha256" };

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

export class StableIdError extends TypeError {
  readonly kind: StableIdKind;

  constructor(kind: StableIdKind, _value: unknown) {
    super(`Expected a safe opaque ${kind} ID between 1 and 128 characters.`);
    this.name = "StableIdError";
    this.kind = kind;
  }
}

export function isStableId<K extends StableIdKind>(
  _kind: K,
  value: unknown,
): value is StableId<K> {
  return typeof value === "string" && !value.includes("..") && SAFE_ID.test(value);
}

export function parseStableId<K extends StableIdKind>(kind: K, value: unknown): StableId<K> {
  if (!isStableId(kind, value)) throw new StableIdError(kind, value);
  return value;
}

export function isAnyStableId(value: unknown): value is AnyStableId {
  return typeof value === "string" && !value.includes("..") && SAFE_ID.test(value);
}

export function parseAnyStableId(value: unknown): AnyStableId {
  if (isAnyStableId(value)) return value;
  throw new TypeError("Expected a safe opaque VaultGuard stable ID.");
}

export function isSha256(value: unknown): value is Sha256 {
  return typeof value === "string" && SHA256.test(value);
}

export function parseSha256(value: unknown): Sha256 {
  if (!isSha256(value)) throw new TypeError("Expected a lowercase SHA-256 digest.");
  return value;
}
