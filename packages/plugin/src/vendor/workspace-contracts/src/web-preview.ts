import type { WorkspaceNodeRead } from './web-navigation';
/** Exact, authenticated preview reads. No storage identities or bearer URLs. */
export interface WorkspacePreviewRequest { fileId: string; workspaceRevisionId: string }
export interface WorkspaceBaseRequest extends WorkspacePreviewRequest { viewName: string; limit?: number; cursor?: string }
export interface PreviewDiagnostic { code: string; severity: 'info' | 'warning' | 'error'; count: number }
export interface PreviewLink {
  label: string; embed: boolean;
  status: 'resolved' | 'unresolved' | 'ambiguous' | 'external' | 'target-tombstoned' | 'unavailable';
  fragment: 'none' | 'resolved' | 'unresolved' | 'ambiguous';
  targets: { fileId: string; fileVersionId: string; path: string }[];
}
/** Where a structural answer (link states, Base rows) came from, and how fresh it is.
 * `graph` is the prepared projection; `bounded-scan` is the raw-byte fallback,
 * which only answers within its own visible-file/byte budget. */
export interface PreviewStructure {
  source: 'graph' | 'bounded-scan' | 'unavailable';
  consistency: 'exact' | 'stale' | null;
  /** The revision the answering projection was built from, when `source` is `graph`. */
  sourceWorkspaceRevisionId: string | null;
  graphRevisionId: string | null;
  projectionLagRevisions: number | null;
}
export interface PreviewCanvasNode {
  id: string; kind: 'text' | 'file' | 'link' | 'group'; x: number; y: number; width: number; height: number;
  text: string; color: string | null; groups: readonly string[]; link?: PreviewLink;
}
export interface WorkspacePreviewRead extends WorkspaceNodeRead {
  kind: 'markdown' | 'text' | 'canvas' | 'base' | 'attachment';
  totalBytes: number; source: string | null; rendered: string | null;
  parseStatus: 'complete' | 'unsupported' | 'failed'; compatibilityProfile: string;
  diagnostics: PreviewDiagnostic[]; links: PreviewLink[]; views: { name: string; type: string | null }[];
  /** Which service resolved this document's link structure. Absent for a kind
   * that has none — text, `.base` and attachment previews — and for a response
   * produced before structural serving existed. */
  structure?: PreviewStructure;
  canvas: { nodes: PreviewCanvasNode[]; edges: { id: string; from: string; to: string; label: string; fromSide: string | null; toSide: string | null; fromEnd: string | null; toEnd: string | null; color: string | null }[] } | null;
}
export interface WorkspaceAssetRead extends WorkspaceNodeRead {
  encoding: 'base64'; bytes: string; totalBytes: number;
  mime: 'image/png' | 'image/jpeg' | 'image/gif' | 'image/webp' | 'application/octet-stream';
  disposition: 'image' | 'download';
}
export type PreviewValue = { kind: 'null' } | { kind: 'string' | 'date'; value: string } | { kind: 'number'; value: number } |
  { kind: 'boolean'; value: boolean } | { kind: 'list'; value: readonly PreviewValue[] } | { kind: 'unsupported'; reason: string; raw?: string };
export interface WorkspaceBaseRead extends WorkspaceNodeRead {
  /** Absent only for a response produced before structural serving existed. */
  structure?: PreviewStructure;
  view: {
    status: string; baseParseStatus: string; columns: readonly string[];
    citation: { baseFileId: string; baseFileVersionId: string; baseSourceHash: string; workspaceRevisionId: string; permissionRevisionId: string; viewName: string; viewType: string | null };
    rows: readonly { fileId: string; fileVersionId: string; path: string; rank: number; groupKey: string | null; cells: readonly { property: string; value: PreviewValue }[] }[];
    groups: readonly { key: string; value: PreviewValue; rowCount: number; firstRank: number; summaries: readonly { property: string; summaryName: string; value: PreviewValue }[] }[] | null;
    summaries: readonly { property: string; summaryName: string; value: PreviewValue }[];
    visibleRowCount: number; returnedRowCount: number; truncated: boolean; nextCursor: string | null;
    undecided: readonly { fileId: string; fileVersionId: string; path: string; stage: string; reason: string }[];
    unsupported: readonly { reason: string; stage: string }[];
  };
}
