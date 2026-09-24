/** Durable internal records, not public mutation requests. Bodies are encrypted
 * by the collaboration repository; only its allowlisted index/audit is plaintext. */
export const COLLABORATION_KINDS = [
  "agent-identity",
  "agent-session",
  "work-item",
  "work-claim",
  "work-intent",
  "reservation",
  "proposal",
  "approval",
  "first-party-intent",
  "handoff",
  "change-set",
  "conflict",
  "receipt",
] as const;
export type CollaborationKind = (typeof COLLABORATION_KINDS)[number];
export interface CollaborationScope {
  readonly orgId: string;
  readonly vaultId: string;
}
export interface DelegatedCollaborationActor {
  readonly kind: "delegated-agent";
  readonly userId: string;
  readonly clientId: string;
  readonly grantId: string;
  readonly connectorSessionId: string;
  readonly agentIdentityId: string;
  readonly agentSessionId: string;
  readonly hostKind: "chatgpt" | "claude" | "custom-mcp";
}
/** A real authenticated human session, never a synthetic OAuth agent grant. */
export interface HumanCollaborationActor {
  readonly kind: "human";
  readonly userId: string;
  readonly userSessionId: string;
  readonly channel: "vaultguard-web" | "obsidian" | "admin-workflow" | "signed-host";
}
export type CollaborationActor = DelegatedCollaborationActor | HumanCollaborationActor;
/** Paths and semantic identifiers are sensitive. These are encrypted, never index fields. */
export type CollaborationTarget =
  | { readonly kind: "file"; readonly fileId: string; readonly fileVersionId: string; readonly path: string }
  | { readonly kind: "folder"; readonly folderId: string; readonly path: string }
  | { readonly kind: "path"; readonly path: string; readonly mustBeAbsent: true }
  | { readonly kind: "vault-metadata" };
export interface CollaborationArtifact extends CollaborationScope {
  readonly kind: string;
  readonly objectKey: string;
  readonly storageVersionId: string;
  readonly sha256: string;
  readonly ciphertextSha256: string;
  readonly byteLength: number;
  readonly ciphertextBytes: number;
  readonly cloudKeyId: string;
}
export interface CollaborationPayloads {
  "agent-identity": { readonly trustClass: "delegated-agent"; readonly agentName: string; readonly modelLabel: string };
  "agent-session": {
    readonly permissionRevision: number;
    readonly policyRevision: number;
    readonly bindingFingerprint: string;
  };
  /**
   * A shared unit of delegated work (COLLAB-003). Its `targets` carry the
   * allowed resources, its `goal` is encrypted with the rest of the body, and
   * `claimGeneration` is the monotonic fencing generation: it increases on every
   * claim AND on every release or reclamation, so a token minted for an earlier
   * holder can never be replayed. A work item is coordination only — holding a
   * claim grants no read, write or approval authority anywhere.
   */
  "work-item": {
    readonly goal: string;
    readonly riskClass: "low" | "medium" | "high";
    readonly dependencies: readonly string[];
    /** Monotonic per item; the fencing token of a claim binds to this value. */
    readonly claimGeneration: number;
    /** The claim record currently holding the item, or null when it is free. */
    readonly claimId: string | null;
  };
  /**
   * One advisory claim on one work item. `fencingToken` is derived from the
   * item, the generation and the holder, so it identifies a claim without
   * carrying the holder's identity, and it is never an authorization token.
   */
  "work-claim": {
    readonly workItemId: string;
    readonly generation: number;
    readonly fencingToken: string;
    readonly advisory: true;
  };
  "work-intent": {
    readonly purpose: string;
    readonly riskClass: "low" | "medium" | "high";
    readonly dependencies: readonly string[];
    readonly supersedes: string | null;
    /** The work item this intent plans against, when the caller named one. */
    readonly workItemId?: string;
  };
  reservation: {
    readonly workIntentId: string;
    readonly mode: "observe" | "shared-read" | "intent-to-write";
    readonly advisory: true;
    readonly fencingGeneration: number;
  };
  proposal: {
    readonly proposalRevision: number;
    readonly operations: CollaborationArtifact;
    readonly operationsHash: string;
    readonly preview: CollaborationArtifact;
    readonly previewHash: string;
    readonly riskClass: "low" | "medium" | "high";
    readonly requiredApprovalPolicyId: string;
    readonly permissionRevision: number;
    readonly policyRevision: number;
    readonly validationRevision: string;
  };
  approval: {
    /** Encrypted human decision evidence for independent apply-time revalidation. */
    readonly reviewerProof?: CollaborationArtifact;
    readonly handoffId?: string;
    readonly proposalId: string;
    readonly proposalRevision: number;
    readonly operationsHash: string;
    readonly previewHash: string;
    readonly decidedByUserId: string;
    readonly decision: "approve" | "reject";
    readonly channel: "vaultguard-web" | "signed-host" | "admin-workflow";
    readonly permissionRevision: number;
    readonly policyRevision: number;
    readonly bindingFingerprint: string;
  };
  "first-party-intent": {
    readonly proposalId: string;
    readonly proposalRevision: number;
    readonly operationsHash: string;
    readonly previewHash: string;
    readonly requestHash: string;
    readonly contractVersion: string;
    readonly permissionRevision: number;
    readonly membershipRevision: number;
    readonly policyRevision: number;
  };
  handoff: {
    readonly proposalId: string;
    readonly proposalRevision: number;
    readonly binding: CollaborationArtifact;
    readonly requestHash: string;
    readonly decisionRequestHash: string | null;
    readonly approvalId: string | null;
  };
  "change-set": {
    readonly proposalId: string;
    readonly proposalRevision: number;
    readonly approvalId: string | null;
    readonly firstPartyIntentId?: string;
    readonly idempotencyRecordId: string;
    readonly preparedRevisionId: string | null;
    readonly outcome: { readonly kind: "receipt" | "conflict" | "failure"; readonly id: string } | null;
  };
  conflict: {
    readonly proposalId: string;
    readonly changeSetId: string | null;
    readonly conflictKind:
      | "same-file"
      | "delete-update"
      | "rename-rename"
      | "path-claim"
      | "permission-changed"
      | "approval-stale"
      | "graph-base-stale"
      | "ambiguous-merge";
    readonly currentWorkspaceRevisionId: string;
    readonly resolutionOptions: readonly (
      | "refresh"
      | "rebase-disjoint"
      | "three-way-review"
      | "choose-current"
      | "new-path"
      | "abort"
    )[];
    readonly details: CollaborationArtifact | null;
    /** Immutable resolution request and proposed subject; encrypted before claiming resolution. */
    readonly resolution?: CollaborationArtifact;
    readonly resolvedBy: string | null;
  };
  receipt: {
    readonly changeSetId: string;
    readonly workspaceRevisionId: string;
    readonly approvalId: string | null;
    readonly firstPartyIntentId?: string;
    readonly beforeVersionIds: readonly string[];
    readonly afterVersionIds: readonly string[];
    readonly beforeHashes: readonly string[];
    readonly afterHashes: readonly string[];
    readonly permissionRevision: number;
    readonly policyRevision: number;
    readonly committedAt: number;
    readonly verifiedAt: number;
  };
}
export interface CollaborationStates {
  "agent-identity": "active" | "revoked";
  "agent-session": "active" | "ended" | "revoked" | "expired";
  "work-item": "open" | "claimed" | "completed" | "cancelled" | "expired";
  "work-claim": "active" | "released" | "expired";
  "work-intent": "open" | "active" | "proposed" | "completed" | "abandoned" | "expired";
  reservation: "active" | "released" | "expired";
  proposal: "draft" | "validated" | "awaiting-approval" | "sync-ready" | "approved" | "applied" | "rejected" | "superseded" | "expired";
  approval: "active" | "consumed" | "invalidated" | "expired";
  "first-party-intent": "active" | "consumed" | "invalidated" | "expired";
  handoff: "pending" | "deciding" | "completed" | "declined" | "revoked" | "expired";
  "change-set":
    | "draft"
    | "validating"
    | "validated"
    | "awaiting-approval"
    | "approved"
    | "preparing"
    | "prepared"
    | "committing"
    | "applied"
    | "conflict"
    | "rejected"
    | "aborted"
    | "expired"
    | "failed-recoverable";
  conflict:
    | "open"
    | "resolving"
    | "rebased"
    | "proposal-revalidated"
    | "resolved-current"
    | "resolved-proposed"
    | "resolved-manual"
    | "abandoned"
    | "expired";
  receipt: "verified";
}
export type CollaborationRecord<K extends CollaborationKind = CollaborationKind> = K extends CollaborationKind
  ? CollaborationScope & {
      readonly schemaVersion: 1;
      readonly kind: K;
      readonly id: string;
      readonly version: number;
      readonly actor: CollaborationActor;
      readonly baseWorkspaceRevisionId: string;
      readonly targets: readonly CollaborationTarget[];
      readonly state: CollaborationStates[K];
      readonly data: CollaborationPayloads[K];
      readonly createdAt: number;
      readonly updatedAt: number;
      readonly expiresAt: number | null;
      /** Cleanup eligibility only; no automatic table TTL. Reconciliation owns active change sets. */
      readonly cleanupAt: number | null;
    }
  : never;
/**
 * Content-free workflow references of the record an audit event describes
 * (VAULTGUARD-113): the proposal, approval, handoff, change-set, receipt,
 * conflict, idempotency and coordination identifiers its own payload names.
 * Server identifiers only; never a path, operation, body or label.
 */
export interface CollaborationAuditReferences {
  readonly proposalId?: string;
  readonly proposalRevision?: number;
  readonly approvalId?: string;
  readonly firstPartyIntentId?: string;
  readonly handoffId?: string;
  readonly changeSetId?: string;
  readonly receiptId?: string;
  readonly conflictId?: string;
  readonly idempotencyRecordId?: string;
  readonly workItemId?: string;
  readonly workIntentId?: string;
  readonly workspaceRevisionId?: string;
}
export interface CollaborationAudit extends CollaborationScope {
  /** `comment` records that a proposal discussion entry was added: identifiers and the
   * proposal record digest only, never the comment body (P5-005). */
  readonly action?: "review" | "status" | "publication-admission" | "comment";
  readonly schemaVersion: 1;
  readonly eventId: string;
  readonly requestId: string;
  readonly actor: CollaborationActor;
  readonly entityKind: CollaborationKind;
  readonly entityId: string;
  readonly entityVersion: number;
  readonly state: string;
  readonly timestamp: number;
  readonly recordDigest: string;
  /** Present on events written since VAULTGUARD-113; older retained events carry none. */
  readonly references?: CollaborationAuditReferences;
}
export const COLLABORATION_LIFETIMES = Object.freeze({
  // D-034: maximum record bound; fresh consent defaults to 30 days and can be 1–90.
  // Creation always takes the minimum of this and the actual live grant/session.
  session: 90 * 86_400_000,
  intent: 2 * 60 * 60_000,
  /**
   * A work intent MUST receive a heartbeat within fifteen minutes
   * (`contracts/collaboration-security.md`, Retention and Expiry). This is a
   * liveness limit per issuance and per renewal, enforced INDEPENDENTLY of the
   * two-hour renewable maximum above: an intent issued for two hours still
   * stops being usable fifteen minutes after its last authorized heartbeat.
   */
  intentHeartbeat: 15 * 60_000,
  /** Default and maximum lifetime of one advisory work-item claim issuance. */
  claim: 5 * 60_000,
  claimMaximum: 30 * 60_000,
  /** A shared work item outlives the sessions that claim it, but not forever. */
  workItem: 7 * 86_400_000,
  reservation: 5 * 60_000,
  reservationMaximum: 30 * 60_000,
  proposal: 90 * 86_400_000,
  terminal: 7 * 86_400_000,
  conflict: 30 * 86_400_000,
});
