export const TRANSFER_LIMITS = { files: 20, fileBytes: 1048576, attachmentBytes: 8388608, totalBytes: 16777216, windowBytes: 65536, lifetimeMs: 3600000 } as const;
export interface TransferFile { path: string; sha256: string; sizeBytes: number; fileId?: string; fileVersionId?: string }
export type TransferCommand =
  | { action: 'prepare_import'; handoffNonce?: string; workspaceRevisionId: string; files: TransferFile[]; idempotencyKey: string }
  | { action: 'prepare_export'; format?: 'native_files' | 'zip' | 'manifest'; handoffNonce?: string; workspaceRevisionId: string; fileIds: string[]; idempotencyKey: string }
  | { action: 'upload'; transferId: string; index: number; base64: string }
  | { action: 'upload_chunk'; transferId: string; index: number; offset: number; base64: string }
  | { action: 'download'; transferId: string; index: number; offset: number }
  | { action: 'propose' | 'status' | 'cancel'; transferId: string };
export interface TransferView { format?: 'native_files' | 'zip' | 'manifest'; transferId: string; kind: 'import' | 'export'; state: 'pending' | 'validating' | 'ready' | 'review_required' | 'cancelled' | 'expired';
  workspaceRevisionId: string; files: TransferFile[]; uploaded: number[]; uploadedOffsets?: Record<string, number>; expiresAt: number; proposalId?: string; proposalRevision?: number;
  /**
   * VAULTGUARD-111. Present only on a `status` answer, and only once the transfer
   * has a terminal outcome read back from the canonical records rather than
   * asserted by the transfer itself: `completed` when an import's proposal was
   * published with a receipt or every file of an export had its final window
   * served; `failed` when an import's proposal was rejected, cancelled, expired
   * or conflicted, or the transfer was cancelled. `state` keeps its own lifecycle
   * meaning, so a client that ignores `outcome` behaves exactly as before.
   */
  outcome?: TransferOutcome;
  /** VAULTGUARD-111. Epoch milliseconds of the latest durable change, on a `status` answer. */
  updatedAt?: number }
export type TransferOutcome = 'completed' | 'failed';
/** How an MCP-originated import treats an occupied destination. Only `review` is
 * served: every imported file is created only where the path is still absent,
 * and an occupied path is a conflict the reviewing human sees. `unique_path` is
 * refused when the handoff is prepared (VAULTGUARD-111), never silently treated
 * as `review`. */
export type TransferConflictPolicy = 'review';
export interface TransferDownload { transferId: string; index: number; base64: string; offset: number; nextOffset: number | null; totalBytes: number; sha256: string; path: string }
export interface BrowserProposal { proposalId: string; proposalRevision: number; operationsHash: string; previewHash: string; baseWorkspaceRevisionId: string }
export interface BrowserPublicationInput { proposalId: string; proposalRevision: number; approvedOperationsHash: string; previewHash: string; approvalId: string; expectedBaseWorkspaceRevisionId: string; idempotencyKey: string }
/** Explicit browser publication outcome. `conflict` and `rebased` (VAULTGUARD-104) published
 * nothing: `conflict` names a durable conflict both copies are kept in, `rebased` a NEW
 * proposal that still needs its own review. `retryable` is true only when nothing was staged
 * or published and the SAME request may resume. */
export interface BrowserPublicationResult {
  state: 'applied' | 'pending' | 'failed' | 'conflict' | 'rebased';
  idempotencyRecordId: string; changeSetId?: string; receiptId?: string; workspaceRevisionId?: string; code?: string;
  retryable?: boolean; conflictId?: string; expectedBaseWorkspaceRevisionId?: string; observedWorkspaceRevisionId?: string;
  allowedNextActions?: readonly string[]; rebasedProposalId?: string | null;
}

/** Text/parser bounds remain separate from attachments. */
export function transferFileByteLimit(path: string): number {
  return /\.(md|canvas|base|txt|json|yaml|yml|csv|tsv)$/i.test(path) ? TRANSFER_LIMITS.fileBytes : TRANSFER_LIMITS.attachmentBytes;
}
