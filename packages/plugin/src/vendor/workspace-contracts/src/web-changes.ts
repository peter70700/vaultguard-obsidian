/** Browser DTOs of the proposal inbox and conflict center (P5-005). Every command is a
 * `POST /vaults/{vaultId}/workspace/changes` action served by the canonical proposal,
 * conflict, approval and publication owners; nothing here carries a storage locator,
 * cloud key, session, grant or agent identifier. */
import type { ConflictDescriptor, ConflictResult, ResolveConflictInput } from "./conflicts.js";
import type {
  CancelProposalInput,
  CreateProposalCommentInput,
  ProposalAgentIdentity,
  ProposalClosedReason,
  ProposalComment,
  ProposalCommentAuthor,
  ProposalDescriptor,
  ProposalReceiptDetail,
  ProposalReferences,
} from "./proposals.js";
import type { HistoryDiffText } from "./web-history.js";

/** The canonical owner's closed proposal lifecycle. */
export type ChangeProposalState = ProposalDescriptor["state"];

export type ChangeCenterCommand =
  | { action: "list"; input: { state?: ChangeProposalState; cursor?: string; limit?: number } }
  | { action: "inspect"; input: { proposalId: string; proposalRevision?: number; referenceCursor?: string } }
  /** The owner's own proposal that can no longer be reviewed because its lifetime or its
   * agent session ended: a content-free closed descriptor, never the preview. */
  | { action: "inspect_closed"; input: { proposalId: string } }
  | { action: "cancel"; input: CancelProposalInput }
  | { action: "comment"; input: CreateProposalCommentInput }
  | { action: "conflicts"; input: { state?: "open" | "resolved"; cursor?: string; limit?: number } }
  | { action: "conflict"; input: { conflictId: string } }
  /** Turns a proposal prepared on an earlier workspace revision into a durable conflict at the
   * current revision, so it can continue through rebase, duplicate, manual merge or cancel.
   * Keyed: the same key and request replay the same conflict. */
  | { action: "conflict_inspect"; input: ChangeConflictInspectInput }
  | {
      action: "conflict_copy";
      input: { conflictId: string; fileId: string; copy: "original" | "current" | "proposed"; offset: number; length: number };
    }
  | { action: "resolve"; input: ResolveConflictInput }
  | { action: "conflict_recover"; input: { conflictId: string } }
  | {
      action: "conflict_refresh";
      input: { conflictId: string; expectedCurrentWorkspaceRevisionId: string; idempotencyKey: string };
    }
  /** Advisory coordination on ONE open file (WEB-002): live agent intents and reservations
   * declared against its current version, under the reader's current read authority. */
  | { action: "activity"; input: { fileId: string; cursor?: string } };
export interface ChangeConflictInspectInput {
  proposalId: string;
  proposalRevision: number;
  expectedCurrentWorkspaceRevisionId: string;
  idempotencyKey: string;
}

/** The actions that change durable state and therefore need the `web_editing` capability. */
export const CHANGE_CENTER_WRITE_ACTIONS = Object.freeze([
  "cancel",
  "comment",
  "resolve",
  "conflict_refresh",
  "conflict_inspect",
] as const);
export const CHANGE_CENTER_ACTIONS = Object.freeze([
  "list",
  "inspect",
  "inspect_closed",
  "cancel",
  "comment",
  "conflicts",
  "conflict",
  "conflict_copy",
  "resolve",
  "conflict_recover",
  "conflict_refresh",
  "conflict_inspect",
  "activity",
] as const);
export type ChangeCenterAction = (typeof CHANGE_CENTER_ACTIONS)[number];

/** The rendered diff budget one inspection may return, across every file (contract §7.2). */
export const CHANGE_DIFF_LIMIT_BYTES = 256 * 1024;

export interface ChangeImage {
  path: string;
  sha256: string;
  byteLength: number;
  binary: boolean;
}
export interface ChangeFileImpact {
  fileId: string;
  change: "created" | "updated" | "deleted" | "renamed" | "restored";
  baseVersionId: string | null;
  restoredFromVersionId: string | null;
  operationIds: readonly string[];
  before: ChangeImage | null;
  after: ChangeImage | null;
  /** A bounded exact unified diff of two UTF-8 images, or null with the reason below. */
  diff: HistoryDiffText | null;
  /** Why no diff is shown. `budget` means the inspection's diff budget was spent on
   * earlier files; the exact images remain reviewable through the approval review. */
  diffOmitted: null | "binary" | "identical" | "budget";
}
/** Index follow-up for one committed revision, from the ready index heads only.
 * `later` means only a later revision is indexed, so search reflects that one. */
export type ChangeIndexState = "indexed" | "pending" | "later" | "unavailable";
export interface ChangeReceiptView extends ProposalReceiptDetail {
  fileCount: number;
  index: { graph: ChangeIndexState; search: ChangeIndexState };
  /** VaultGuard does not observe which Obsidian devices downloaded a revision, so the web
   * workspace never claims device synchronization; it states that it is unconfirmed. */
  deviceSync: "unconfirmed";
}
export interface ChangeProposalView {
  /** The requested revision. Its `state` is that revision's own record. */
  descriptor: ProposalDescriptor;
  /** The subject's newest revision and current lifecycle state. When they differ from the
   * descriptor, the viewed revision is historical and can no longer be approved or applied. */
  latestRevision: number;
  latestState: ChangeProposalState;
  creator: ProposalCommentAuthor;
  /** Which agent and run created a delegated proposal (WEB-005); null for a person's own
   * proposal. Disclosed only here, inside the owner-only review. */
  agent: ProposalAgentIdentity | null;
  validation: { workspaceRevisionId: string; permissionRevision: number; policyRevision: number };
  operations: readonly { operationId: string; op: string }[];
  /** Pinned pack versions verified under this reader's current access. */
  contextCitations?: readonly { contextPackId: string; contextPackVersionId: string }[];
  files: readonly ChangeFileImpact[];
  folders: readonly { folderId: string; beforePath: string | null; afterPath: string | null; operationIds: readonly string[] }[];
  links: ChangeLinkImpact;
  access: {
    /** The rights below are the READER's own current rights over the preview's paths, as the
     * approval review projects them; never the rights the creator held when preparing it. */
    scope: "current-reviewer";
    rights: readonly { path: string; actions: { read: boolean; write: boolean; delete: boolean; list: boolean } }[];
    affectedPaths: readonly string[];
    permissionRulesChanged: false;
    pathInheritanceMayChange: boolean;
  };
  diffLimitBytes: number;
  /** Every file in a content change set publishes in ONE workspace revision, so a
   * partially applied content change is impossible by construction. */
  atomic: true;
  references: ProposalReferences;
  receipts: readonly ChangeReceiptView[];
  comments: readonly ProposalComment[];
}
/** How one link occurrence's resolution changes if the proposal is applied. Exactly one per
 * occurrence, in this priority: a resolved link that stops resolving or becomes ambiguous, a
 * resolved link that now reaches a different file, an unresolved or ambiguous link that now
 * resolves, a new or removed occurrence, and otherwise the same target. `rewritten` is
 * reported separately: a rewrite normally keeps the target. */
export type ChangeLinkChange =
  | "becomes_unresolved"
  | "becomes_ambiguous"
  | "redirected"
  | "becomes_resolved"
  | "added"
  | "removed"
  | "same_target";
export const CHANGE_LINK_CHANGES: readonly ChangeLinkChange[] = Object.freeze([
  "becomes_unresolved",
  "becomes_ambiguous",
  "redirected",
  "becomes_resolved",
  "added",
  "removed",
  "same_target",
]);
/** The most link occurrences one inspection lists individually; the counts cover all. */
export const CHANGE_LINK_ITEM_LIMIT = 200;
export interface ChangeLinkImpact {
  total: number;
  rewritten: number;
  /** Every occurrence counted once by its change. */
  changes: Readonly<Record<ChangeLinkChange, number>>;
  /** The occurrences whose target changes or whose link text is rewritten, most consequential
   * first, bounded by `CHANGE_LINK_ITEM_LIMIT`. `sourcePath` is the file that contains the link, under the
   * same full path authority the review already required; null when that file is not in the
   * reviewed revisions' inventories. */
  items: readonly {
    sourceFileId: string;
    sourcePath: string | null;
    occurrenceId: string;
    change: ChangeLinkChange;
    rewritten: boolean;
  }[];
  /** Listed-kind occurrences past the item bound. Nothing is summarized away silently. */
  omitted: number;
}
/** The owner's closed proposal, without its preview: why it closed and its content-free
 * descriptor. Nothing about it can be reviewed, approved or applied. */
export interface ChangeClosedProposalView {
  descriptor: ProposalDescriptor & { closedReason: ProposalClosedReason };
}
/** Advisory coordination on one open file (WEB-002). Reservations never lock anything: a save
 * still proposes against the exact version, and a review and apply still check it. */
export interface ChangeFileActivity {
  proposals?: readonly ProposalDescriptor[];
  proposalCursor?: string | null;
  advisory: true;
  fileId: string;
  /** The version the answer is about: the file's version at `workspaceRevisionId`. Reservations
   * declared against an earlier version of the file are not included. */
  fileVersionId: string;
  workspaceRevisionId: string;
  reservations: readonly {
    mode: "observe" | "shared-read" | "intent-to-write";
    expiresAt: number;
    /** Content-free per-vault holder reference: tells two holders apart, identifies nobody. */
    holderReference: string;
  }[];
}
export interface ChangeConflictPage {
  items: readonly ConflictDescriptor[];
  cursor: string | null;
}
export type ChangeConflictView = ConflictResult;
export interface ChangeConflictCopyWindow {
  conflictId: string;
  fileId: string;
  copy: "original" | "current" | "proposed";
  sha256: string;
  byteLength: number;
  offset: number;
  nextOffset: number | null;
  encoding: "base64";
  bytes: string;
}
export interface ChangeConflictResolution {
  outcome: "proposal_created" | "kept_current" | "cancelled";
  conflict: ConflictDescriptor;
  /** A NEW review subject. It still needs its own approval; nothing was applied. */
  proposal: { proposalId: string; proposalRevision: number; state: ChangeProposalState } | null;
}
