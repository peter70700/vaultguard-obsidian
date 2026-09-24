/** Browser-safe read DTOs. Identities refer to committed canonical manifests. */
export interface WorkspaceNode {
  id: string;
  kind: 'file' | 'folder';
  name: string;
  path: string;
  parentFolderId: string | null;
  fileVersionId?: string;
  contentHash?: string | null;
}
export interface WorkspaceReadProvenance {
  workspaceRevisionId: string;
  currentWorkspaceRevisionId: string;
  consistency: 'exact' | 'stale';
}
export interface WorkspaceTreePage extends WorkspaceReadProvenance {
  folder: WorkspaceNode | null;
  breadcrumbs: WorkspaceNode[];
  entries: WorkspaceNode[];
  nextCursor: string | null;
}
export interface WorkspaceNodeRead extends WorkspaceReadProvenance {
  node: WorkspaceNode;
  breadcrumbs: WorkspaceNode[];
}
export interface WorkspaceTextRead extends WorkspaceNodeRead {
  content: string;
  totalBytes: number;
}
export interface WorkspaceTreeRequest {
  folderId?: string;
  workspaceRevisionId?: string;
  limit?: number;
  cursor?: string;
}
export interface WorkspaceNodeRequest {
  fileId?: string;
  folderId?: string;
  workspaceRevisionId?: string;
}
