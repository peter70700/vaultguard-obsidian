import type { CollaborationRecord } from "./collaboration.js";
import type {
  AgentIdentityId,
  AgentSessionId,
  ApprovalId,
  ArtifactId,
  ChangeSetId,
  ConflictId,
  ContextPackVersionId,
  FileId,
  FileVersionId,
  FolderId,
  IdempotencyRecordId,
  OperationId,
  OrganizationId,
  PermissionRevisionId,
  PolicyRevisionId,
  ProposalId,
  ReceiptId,
  Sha256,
  SubjectId,
  VaultId,
  WorkIntentId,
  WorkspaceRevisionId,
} from "./ids.js";
import type { ErrorCode, RiskClass } from "./types.js";
import type { JsonValue } from "./validator.js";

export type FileSelector =
  | { readonly fileId: FileId; readonly path?: never }
  | { readonly path: string; readonly fileId?: never };

export interface CallContext {
  readonly vaultId: VaultId;
  readonly workIntentId?: WorkIntentId;
}

export interface SemanticAnchor {
  readonly kind: "heading" | "block" | "task" | "byte_range";
  readonly idOrHash: string;
  readonly expectedSourceHash: Sha256;
}

interface ProposalOperationBase {
  readonly operationId: OperationId;
}

export interface ProposalByteEdit {
  readonly startByte: number;
  readonly endByte: number;
  readonly expectedSourceHash: Sha256;
  readonly replacement: string;
}

export type ProposalOperation =
  | (ProposalOperationBase & {
      readonly op: "create_text";
      readonly path: string;
      readonly mustBeAbsent: true;
      readonly content: string;
    })
  | (ProposalOperationBase & {
      readonly op: "patch_text";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly expectedHash: Sha256;
      readonly diff: string;
    })
  | (ProposalOperationBase & {
      readonly op: "insert_text";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly anchor: SemanticAnchor;
      readonly position: "append" | "prepend";
      readonly text: string;
    })
  | (ProposalOperationBase & {
      readonly op: "set_property";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly key: string;
      readonly value: JsonValue;
    })
  | (ProposalOperationBase & {
      readonly op: "remove_property";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly key: string;
    })
  | (ProposalOperationBase & {
      readonly op: "create_task";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly text: string;
    })
  | (ProposalOperationBase & {
      readonly op: "update_task";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly taskRef: SemanticAnchor;
      readonly text: string;
    })
  | (ProposalOperationBase & {
      readonly op: "toggle_task";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly taskRef: SemanticAnchor;
      readonly status: string;
    })
  | (ProposalOperationBase & {
      readonly op: "create_from_template";
      readonly template: FileSelector;
      readonly templateVersionId: FileVersionId;
      readonly path: string;
      readonly mustBeAbsent: true;
      readonly variables: Readonly<Record<string, string>>;
    })
  | (ProposalOperationBase & {
      readonly op: "rename" | "move";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly newPath: string;
      readonly destinationMustBeAbsent: true;
      readonly referencePolicy: "path_only" | "update_references";
    })
  | (ProposalOperationBase & {
      readonly op: "delete";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
    })
  | (ProposalOperationBase & {
      readonly op: "replace_binary";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly uploadArtifactId: ArtifactId;
      readonly expectedSha256: Sha256;
    })
  | (ProposalOperationBase & {
      readonly op: "replace_text";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly expectedHash: Sha256;
      readonly content: string;
    })
  | (ProposalOperationBase & {
      readonly op: "restore";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly sourceWorkspaceRevisionId: WorkspaceRevisionId;
      readonly restoreVersionId: FileVersionId;
      /** Optional explicit destination for a retained deleted identity; absence is still required. */
      readonly targetPath?: string;
    })
  | (ProposalOperationBase & {
      readonly op: "create_folder";
      readonly path: string;
      readonly mustBeAbsent: true;
    })
  | (ProposalOperationBase & {
      readonly op: "move_folder";
      readonly folderId: FolderId;
      readonly path: string;
      readonly newPath: string;
      readonly destinationMustBeAbsent: true;
      readonly referencePolicy: "path_only" | "update_references";
    })
  | (ProposalOperationBase & {
      readonly op: "delete_folder";
      readonly folderId: FolderId;
      readonly path: string;
      readonly recursive: boolean;
    })
  | (ProposalOperationBase & {
      readonly op: "create_uploaded_text";
      readonly path: string;
      readonly mustBeAbsent: true;
      readonly uploadArtifactId: ArtifactId;
      readonly expectedSha256: Sha256;
    })
  | (ProposalOperationBase & {
      readonly op: "replace_uploaded_text";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly expectedHash: Sha256;
      readonly uploadArtifactId: ArtifactId;
      readonly expectedSha256: Sha256;
    })
  | (ProposalOperationBase & {
      readonly op: "create_binary";
      readonly path: string;
      readonly mustBeAbsent: true;
      readonly uploadArtifactId: ArtifactId;
      readonly expectedSha256: Sha256;
    })
  | (ProposalOperationBase & {
      readonly op: "edit_canvas" | "edit_base_source";
      readonly file: FileSelector;
      readonly expectedVersionId: FileVersionId;
      readonly expectedHash: Sha256;
      readonly edits: readonly ProposalByteEdit[];
    });

export interface CreateProposalInput extends CallContext {
  readonly baseWorkspaceRevisionId: WorkspaceRevisionId;
  readonly contextPackVersionIds?: readonly ContextPackVersionId[];
  readonly operations: readonly ProposalOperation[];
  readonly rationale?: string;
  readonly idempotencyKey: string;
}

export interface ChangeProposal {
  readonly schemaVersion: string;
  readonly proposalId: ProposalId;
  readonly proposalRevision: number;
  readonly previousProposalRevision?: number;
  readonly orgId: OrganizationId;
  readonly vaultId: VaultId;
  readonly creator: {
    readonly subjectId: SubjectId;
    readonly agentIdentityId?: AgentIdentityId;
    readonly agentSessionId?: AgentSessionId;
  };
  readonly baseWorkspaceRevisionId: WorkspaceRevisionId;
  readonly operationsHash: Sha256;
  readonly previewHash: Sha256;
  readonly affectedFileIds: readonly FileId[];
  readonly affectedPathHashes: readonly Sha256[];
  readonly affectedPolicyDomains: readonly (
    | "content"
    | "folders"
    | "context"
    | "permissions"
    | "membership"
    | "shares"
  )[];
  readonly riskClass: Exclude<RiskClass, "read" | "ceremony">;
  readonly requiredApprovalPolicyId: PolicyRevisionId;
  readonly status:
    | "draft"
    | "validated"
    | "awaiting_approval"
    | "approved"
    | "rejected"
    | "superseded"
    | "expired";
  readonly validation: {
    readonly workspaceRevisionId: WorkspaceRevisionId;
    readonly permissionRevisionId: PermissionRevisionId;
    readonly policyRevisionId: PolicyRevisionId;
    readonly validatedAt: string;
  };
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface ApprovalDecision {
  readonly schemaVersion: string;
  readonly approvalId: ApprovalId;
  readonly proposalId: ProposalId;
  readonly proposalRevision: number;
  readonly decidedBySubjectId: SubjectId;
  readonly decidedAt: string;
  readonly decision: "approve" | "reject";
  readonly approvedOperationsHash: Sha256;
  readonly previewHash: Sha256;
  readonly policyRevisionId: PolicyRevisionId;
  readonly permissionRevisionId: PermissionRevisionId;
  readonly expiresAt: string;
  readonly channel: "vaultguard_web" | "signed_host" | "admin_workflow";
}

export type ChangeSetStatus =
  | "draft"
  | "validating"
  | "validated"
  | "awaiting_approval"
  | "approved"
  | "preparing"
  | "prepared"
  | "committing"
  | "applied"
  | "conflict"
  | "rejected"
  | "aborted"
  | "expired"
  | "failed_recoverable";

export type ChangeSetOutcome =
  | { readonly kind: "receipt"; readonly receiptId: ReceiptId }
  | { readonly kind: "conflict"; readonly conflictId: ConflictId }
  | { readonly kind: "failure"; readonly errorCode: ErrorCode };

export interface MultiFileChangeSet {
  readonly schemaVersion: string;
  readonly changeSetId: ChangeSetId;
  readonly proposalId: ProposalId;
  readonly proposalRevision: number;
  readonly baseWorkspaceRevisionId: WorkspaceRevisionId;
  readonly rebasedFromRevisionId?: WorkspaceRevisionId;
  readonly preparedRevisionId?: WorkspaceRevisionId;
  readonly status: ChangeSetStatus;
  readonly actor: {
    readonly subjectId: SubjectId;
    readonly agentIdentityId?: AgentIdentityId;
    readonly agentSessionId?: AgentSessionId;
  };
  readonly approvalId?: ApprovalId;
  readonly idempotencyRecordId: IdempotencyRecordId;
  readonly startedAt: string;
  readonly updatedAt: string;
  readonly outcome?: ChangeSetOutcome;
}

export interface ApplyProposalInput extends CallContext {
  readonly proposalId: ProposalId;
  readonly proposalRevision: number;
  readonly approvedOperationsHash: Sha256;
  readonly previewHash: Sha256;
  readonly approvalId: ApprovalId;
  readonly expectedBaseWorkspaceRevisionId: WorkspaceRevisionId;
  readonly reservationFencingTokens?: readonly string[];
  readonly idempotencyKey: string;
}

/** Content-free proposal directory row backing `list_change_sets` (contract §8.6).
 * It carries no path, body, label or preview text: a caller learns a path only by
 * reading the proposal itself, which reauthorizes every disclosed path. */
export interface ProposalDescriptor {
  proposalId: string;
  proposalRevision: number;
  state: CollaborationRecord<"proposal">["state"];
  /** The proposal impact class, not the tool risk class. */
  riskClass: CollaborationRecord<"proposal">["data"]["riskClass"];
  requiredApprovalPolicyId: string;
  baseWorkspaceRevisionId: string;
  currentWorkspaceRevisionId: string;
  /** The creator's trust class. Never a session, grant or agent identifier. */
  createdByKind: CollaborationRecord<"proposal">["actor"]["kind"];
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  operationsHash: string;
  previewHash: string;
  /** Impact size only. A hidden entry contributes nothing to any count. */
  fileCount: number;
  folderCount: number;
  linkCount: number;
  /** Present only on the web inbox's closed descriptors (VAULTGUARD-126): the owner's own
   * proposal that can no longer be reviewed or applied because its lifetime ended
   * (`expired`, and `state` is then `expired`) or because the agent session that created it
   * ended (`agent_session_ended`). It is still disclosed only under the same full path
   * authority as an open descriptor, and it never carries the preview. */
  closedReason?: ProposalClosedReason;
}
export type ProposalClosedReason = "expired" | "agent_session_ended";
export interface ProposalDirectoryPage {
  items: readonly ProposalDescriptor[];
  /** A sealed continuation, or null at the end of the authorized listing. */
  cursor: string | null;
}
export interface ProposalChangeSetReference {
  changeSetId: string;
  state: CollaborationRecord<"change-set">["state"];
  /** The publication-intent (idempotency record) this attempt claimed. */
  publicationIntentId: string;
  approvalId: string | null;
  outcome: CollaborationRecord<"change-set">["data"]["outcome"];
}
/** Proposal-to-workflow references behind `changes:read` and current path authority.
 * Identifiers only: resolving one still runs its own owner's authorization.
 *
 * A review handoff or approval whose own lifetime ended while it was still live is reported
 * as `expired`, exactly as the approvals owner reports it at read time (VAULTGUARD-126): the
 * stored record keeps its last written state because nothing rewrites an expired record, but
 * it can no longer open a review or authorize an apply. Terminal states (`declined`,
 * `revoked`, `consumed`, `invalidated`) are durable facts and are reported as written. */
export interface ProposalReferences {
  /** Opaque continuation for this caller, subject revision and authority generation. */
  cursor?: string | null;
  proposalId: string;
  proposalRevision: number;
  state: CollaborationRecord<"proposal">["state"];
  handoffs: readonly { handoffId: string; state: CollaborationRecord<"handoff">["state"]; approvalId: string | null }[];
  approvals: readonly {
    approvalId: string;
    state: CollaborationRecord<"approval">["state"];
    decision: "approve" | "reject";
    handoffId: string | null;
  }[];
  changeSets: readonly ProposalChangeSetReference[];
  conflicts: readonly { conflictId: string; state: CollaborationRecord<"conflict">["state"] }[];
  receipts: readonly { receiptId: string; changeSetId: string; workspaceRevisionId: string }[];
}
export interface CancelProposalInput {
  cursor?: string;
  proposalId: string;
  proposalRevision: number;
  idempotencyKey: string;
}
export interface CancelProposalResult {
  /** `cancelled` moved the subject; `already_cancelled` replays this exact key;
   * `no_op` reports a subject that was already unapplied and terminal. */
  outcome: "cancelled" | "already_cancelled" | "no_op" | "cancelling";
  /** Resume with the SAME idempotency key until null. Terminal state prevents publication during cleanup. */
  cursor?: string | null;
  proposalId: string;
  proposalRevision: number;
  state: CollaborationRecord<"proposal">["state"];
  invalidatedApprovalIds: readonly string[];
  revokedHandoffIds: readonly string[];
}
/** Bounds of the proposal discussion (P5-005). A comment is plain text: it is never
 * rendered as Markdown or HTML, and a body carrying control, bidirectional-override
 * or invisible formatting characters is refused rather than silently rewritten. */
export const PROPOSAL_COMMENT_LIMITS = Object.freeze({
  bodyCharacters: 2000,
  bodyBytes: 8192,
  perProposal: 100,
});
export interface CreateProposalCommentInput {
  proposalId: string;
  /** The revision the author reviewed. A comment on a superseded revision is refused. */
  proposalRevision: number;
  body: string;
  idempotencyKey: string;
}
/** Who wrote a comment, relative to the reader. Never a user, session, grant, client or
 * agent identifier: a reader learns only whether it was them, their own agent, another
 * person or another person's agent. */
export type ProposalCommentAuthor = "you" | "your_agent" | "another_person" | "another_persons_agent";
export interface ProposalComment {
  commentId: string;
  proposalId: string;
  proposalRevision: number;
  author: ProposalCommentAuthor;
  body: string;
  createdAt: number;
}
export interface ProposalCommentResult {
  /** `replayed` answers this exact key and request from the comment it already created. */
  outcome: "created" | "replayed";
  comment: ProposalComment;
}
/** The content-free applied receipt behind one change set: version identifiers and hashes,
 * never a path or body. A reader learns where each version landed by reading the vault. */
export interface ProposalReceiptDetail {
  receiptId: string;
  changeSetId: string;
  approvalId: string | null;
  firstPartyIntentId?: string;
  workspaceRevisionId: string;
  beforeVersionIds: readonly string[];
  afterVersionIds: readonly string[];
  beforeHashes: readonly string[];
  afterHashes: readonly string[];
  permissionRevision: number;
  policyRevision: number;
  committedAt: number;
  verifiedAt: number;
  /** The exact before/after version of each file, aligned per file (VAULTGUARD-126). The
   * receipt stores the before versions compacted (a created file has none), so pairing them by
   * array index is wrong for a mixed change set; these pairs are derived from the applied
   * proposal revision's own per-file identities. Each before version must be that file's base
   * version with its hash, and each after version must be the version the manifest committed at
   * `workspaceRevisionId` names for that file (a tombstone for a delete, active content with the
   * previewed hash otherwise), so a pairing never rests on the receipt's array order. `null` when
   * that verification does not hold: the flat lists above are then the only exact facts, and no
   * pairing is invented. */
  files: readonly ProposalReceiptFile[] | null;
}
export interface ProposalReceiptFile {
  fileId: string;
  /** Null for a file this change set created. */
  beforeVersionId: string | null;
  afterVersionId: string;
  beforeHash: string | null;
  afterHash: string;
}
/** Which agent and which run created a delegated proposal (WEB-005), disclosed only inside the
 * owner-only proposal review. Never a user, client, grant, connector-session, agent-identity or
 * agent-session identifier: `runReference` is a per-vault digest that tells two runs apart and
 * reverses to nothing. The name and model label are what the agent recorded when its session
 * opened, shown as plain text, and null when none was recorded. */
export interface ProposalAgentIdentity {
  hostKind: "chatgpt" | "claude" | "custom-mcp";
  agentName: string | null;
  modelLabel: string | null;
  runReference: string;
  runStartedAt: number;
}
/** Code points a comment may not carry: C0/C1 controls other than tab and line feed, line
 * and paragraph separators, bidirectional marks, overrides and isolates, zero-width space,
 * word joiners, the byte-order mark, interlinear annotation controls, tag characters and
 * unpaired surrogates. Refusing them keeps a comment from visually disguising its text. */
function refusedCommentCodePoint(codePoint: number): boolean {
  return (
    (codePoint < 0x20 && codePoint !== 0x09 && codePoint !== 0x0a) ||
    (codePoint >= 0x7f && codePoint <= 0x9f) ||
    codePoint === 0x061c ||
    codePoint === 0x200b ||
    codePoint === 0x200e ||
    codePoint === 0x200f ||
    (codePoint >= 0x2028 && codePoint <= 0x202e) ||
    (codePoint >= 0x2060 && codePoint <= 0x2069) ||
    codePoint === 0xfeff ||
    (codePoint >= 0xfff9 && codePoint <= 0xfffb) ||
    (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
    (codePoint >= 0xe0000 && codePoint <= 0xe007f)
  );
}
/** The first reason a comment body is refused, or null when it is acceptable. Shared by the
 * canonical owner, which decides, and the browser, which explains before sending. */
export function proposalCommentBodyProblem(body: unknown): null | "empty" | "too_long" | "unsupported_characters" {
  if (typeof body !== "string" || body.trim().length === 0) return "empty";
  let characters = 0,
    bytes = 0;
  for (const character of body) {
    const codePoint = character.codePointAt(0) as number;
    characters += 1;
    bytes += codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
    if (characters > PROPOSAL_COMMENT_LIMITS.bodyCharacters || bytes > PROPOSAL_COMMENT_LIMITS.bodyBytes)
      return "too_long";
    if (refusedCommentCodePoint(codePoint)) return "unsupported_characters";
  }
  return null;
}
