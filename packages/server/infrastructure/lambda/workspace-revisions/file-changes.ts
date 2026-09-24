import type { CommittedWorkspaceManifest, WorkspaceFileManifestEntry } from './types';

export interface FileChange {
  readonly action: 'created' | 'modified' | 'renamed' | 'deleted';
  /** The entry the revision records; null when the file left the manifest entirely. */
  readonly after: WorkspaceFileManifestEntry | null;
  /** The entry the previous revision recorded; null for a creation. */
  readonly before: WorkspaceFileManifestEntry | null;
}

const liveFile = (entry: WorkspaceFileManifestEntry | undefined): entry is WorkspaceFileManifestEntry =>
  !!entry && entry.state === 'active' && entry.fileVersionState === 'content';

/**
 * The file changes one committed revision made over its parent, in a
 * deterministic order (path bytes, then file ID): a live version appearing is a
 * creation, disappearing (tombstoned or removed) a deletion, a different path a
 * rename and a different version at the same path a modification. Folder
 * entries carry no version and produce no activity.
 */
export function fileChanges(parent: CommittedWorkspaceManifest | null, manifest: CommittedWorkspaceManifest): FileChange[] {
  const files = (value: CommittedWorkspaceManifest | null) =>
    new Map((value?.entries ?? []).filter((entry): entry is WorkspaceFileManifestEntry => entry.kind === 'file').map((entry) => [entry.fileId, entry]));
  const before = files(parent);
  const after = files(manifest);
  const changes: FileChange[] = [];
  for (const [fileId, entry] of after) {
    const prior = before.get(fileId);
    const live = liveFile(entry);
    const wasLive = liveFile(prior);
    if (live && !wasLive) changes.push({ action: 'created', after: entry, before: prior ?? null });
    else if (!live && wasLive) changes.push({ action: 'deleted', after: entry, before: prior });
    else if (live && wasLive && prior.canonicalPath !== entry.canonicalPath) changes.push({ action: 'renamed', after: entry, before: prior });
    else if (live && wasLive && prior.fileVersionId !== entry.fileVersionId) changes.push({ action: 'modified', after: entry, before: prior });
  }
  for (const [fileId, prior] of before) {
    if (!after.has(fileId) && liveFile(prior)) changes.push({ action: 'deleted', after: null, before: prior });
  }
  const pathOf = (change: FileChange) => (change.after ?? change.before)?.canonicalPath ?? '';
  const idOf = (change: FileChange) => (change.after ?? change.before)?.fileId ?? '';
  return changes.sort((left, right) =>
    Buffer.compare(Buffer.from(pathOf(left)), Buffer.from(pathOf(right))) ||
    Buffer.compare(Buffer.from(idOf(left)), Buffer.from(idOf(right))));
}
