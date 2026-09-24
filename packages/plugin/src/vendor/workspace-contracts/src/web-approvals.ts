/** Explicit browser DTOs. No storage pointers, cloud key IDs or grant metadata. */
export type ApprovalCommand =
  | { action: "create"; proposalId: string; proposalRevision: number; idempotencyKey: string }
  | { action: "review" | "status" | "revoke"; handoffId: string }
  | {
      action: "decide";
      handoffId: string;
      reviewToken: string;
      decision: "approve" | "reject";
      idempotencyKey: string;
    };
export interface ApprovalStatus {
  handoffId: string;
  purpose: "approve_change_set";
  status: "pending" | "deciding" | "completed" | "declined" | "revoked" | "expired";
  proposalId: string;
  proposalRevision: number;
  expiresAt: string;
  approvalId?: string;
  reviewPath: string;
}
export interface ApprovalReview extends ApprovalStatus {
  reviewToken: string;
  operationsHash: string;
  previewHash: string;
  workspaceRevisionId: string;
  riskClass: "low" | "medium" | "high";
  policyRevision: number;
  permissionRevision: number;
  operations: { id: string; type: string }[];
  /** Pinned pack versions verified under this reader's current access. */
  contextCitations?: readonly { contextPackId: string; contextPackVersionId: string }[];
  files: { fileId: string; before: ApprovalFileImage | null; after: ApprovalFileImage | null }[];
  folders: { folderId: string; beforePath: string | null; afterPath: string | null }[];
  linkChangesOmitted?: number;
  linkChanges: { sourceFileId: string; occurrenceId: string; rewritten: boolean }[];
  access: {
    scope: "current-reviewer";
    rights: { path: string; actions: { read: boolean; write: boolean; delete: boolean; list: boolean } }[];
    pathInheritanceMayChange: boolean;
    permissionRulesChanged: false;
  };
}
export interface ApprovalFileImage {
  path: string;
  sha256: string;
  byteLength: number;
  text?: string;
  binary: boolean;
  requiresPreview?: boolean;
}
/** Authenticated human-only bounded view of one immutable proposal image. */
export interface ApprovalPreviewCommand { action: 'preview'; handoffId: string; fileId: string; side: 'before' | 'after'; offsetBytes: number }
export interface ApprovalPreviewWindow { handoffId: string; fileId: string; side: 'before' | 'after'; sha256: string; totalBytes: number; offsetBytes: number; nextOffsetBytes: number | null; base64: string }
