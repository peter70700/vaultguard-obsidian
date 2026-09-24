/** Closed source contract consumed by MCP and the web conflict center. No runtime adapters. */
import type { CollaborationRecord } from "./collaboration.js";
import type { ProposalOperation } from "./proposals.js";
export const CONFLICT_CODES = [
  "WORKSPACE_BASE_STALE",
  "TEXT_OVERLAP",
  "AMBIGUOUS_MERGE",
  "SEMANTIC_TARGET_CHANGED",
  "PATH_CLAIM_CONFLICT",
  "FOLDER_RELATION_CHANGED",
  "RENAME_RACE",
  "DELETE_UPDATE",
  "RESTORE_DELETE",
  "BINARY_RACE",
  "RESOURCE_LIMIT",
] as const;
export type ConflictCode = (typeof CONFLICT_CODES)[number];
export type ConflictStrategy =
  | "keep_current"
  | "cancel"
  | "rebase"
  | "merge"
  | "manual"
  | "duplicate"
  | "rename";
export interface InspectConflictInput {
  proposalId: string;
  proposalRevision: number;
  expectedCurrentWorkspaceRevisionId: string;
  idempotencyKey: string;
  /** Re-evaluate a durable interrupted conflict under a fresh current actor. */
  recoveryConflictId?: string;
  /** Links the durable conflict to the publication attempt that observed the stale
   * base, so a refused apply and its conflict reference the same change set. */
  changeSetId?: string;
}
export interface ResolveConflictInput {
  conflictId: string;
  expectedCurrentWorkspaceRevisionId: string;
  strategy: ConflictStrategy;
  idempotencyKey: string;
  /** Required with duplicate/rename. One exact affected file only. No implicit unique suffix. */
  targetPath?: string;
  /** Exact current-base operations for explicit manual review. */
  operations?: readonly ProposalOperation[];
}
export interface ConflictImageMetadata {
  path: string;
  sha256: string;
  byteLength: number;
  encoding: "utf8" | "base64";
}
export interface ConflictDescriptor {
  conflictId: string;
  proposalId: string;
  proposalRevision: number;
  state: CollaborationRecord<"conflict">["state"];
  code: ConflictCode;
  baseWorkspaceRevisionId: string;
  observedWorkspaceRevisionId: string;
  currentWorkspaceRevisionId: string;
  choices: readonly (ConflictStrategy | "refresh")[];
  /** Identifies a NEW review subject, never proof of publication. */
  resolutionProposalId: string | null;
}
export interface ConflictResult extends ConflictDescriptor {
  /** Metadata only. Read exact bounded byte windows through readCopy. */
  copies: readonly ({
    fileId: string;
    baseVersionId: string | null;
    currentVersionId: string | null;
    currentFileId: string | null;
  } & {
    original: ConflictImageMetadata | null;
    current: ConflictImageMetadata | null;
    proposed: ConflictImageMetadata | null;
  })[];
}
