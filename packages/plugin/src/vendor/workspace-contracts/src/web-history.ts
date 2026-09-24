/** Browser history contains committed revision references, never storage locators. */
export interface HistoryVersion {
  fileId: string; fileVersionId: string; workspaceRevisionId: string;
  path: string; state: 'active' | 'tombstone'; contentHash: string | null; committedAt: string;
}
export type HistoryCommand =
  | { action: 'deleted' }
  | { action: 'list'; fileId: string; workspaceRevisionId: string; cursor?: string }
  | { action: 'read'; fileId: string; workspaceRevisionId: string; fileVersionId: string; offset: number }
  | { action: 'diff'; fileId: string; from: { workspaceRevisionId: string; fileVersionId: string }; to: { workspaceRevisionId: string; fileVersionId: string } };
export interface HistoryPage { versions: HistoryVersion[]; nextCursor: string | null; currentWorkspaceRevisionId: string }
export interface HistoryBytes { version: HistoryVersion; base64: string; offset: number; totalBytes: number; nextOffset: number | null }
/** One unified-diff hunk range. Line numbers are 1-based, as `@@` headers are. */
export interface HistoryDiffHunk { oldStart: number; oldLines: number; newStart: number; newLines: number }
/** A computed, bounded, deterministic line difference between two exact versions.
 * `truncated` / `omitted*` state what the bound left out; nothing is inferred. */
export interface HistoryDiffText {
  format: 'unified'; text: string; textBytes: number; hunks: HistoryDiffHunk[];
  stats: { addedLines: number; removedLines: number };
  /** False when the edit-distance ceiling forced one replacement hunk. */
  minimal: boolean; truncated: boolean; omittedHunks: number; omittedBytes: number;
  sanitization: { controlCharacters: number; bidiControls: number; invisibleFormatting: number; tagCharacters: number };
}
export interface HistoryDiff {
  from: HistoryVersion; to: HistoryVersion; identical: boolean; binary: boolean;
  fromBytes: number; toBytes: number;
  /** Null only when a side is not UTF-8 text; byte identity is still reported. */
  diff: HistoryDiffText | null;
}
