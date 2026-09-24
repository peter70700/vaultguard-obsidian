/** P6-001: negotiated replica protocol. A signal describes parsing ability, never authority. */
import type { CreateProposalInput } from './proposals.js';
import type { ChangeCenterCommand } from './web-changes.js';
import type { HistoryCommand } from './web-history.js';
import type { BrowserPublicationInput, BrowserPublicationResult, TransferCommand } from './web-transfers.js';

export const SYNC_CONTRACT_VERSION = 'vaultguard-sync-v2' as const;
export const SYNC_REQUIRED_CAPABILITIES = Object.freeze([
  'stable-identities', 'exact-base', 'recoverable-conflicts', 'revision-cursors', 'first-party-intent',
] as const);
export interface SyncClientSignal { contractVersion: string; capabilities: readonly string[] }
export interface SyncNegotiation {
  contractVersion: typeof SYNC_CONTRACT_VERSION;
  requiredCapabilities: readonly string[];
  mode: 'compatible' | 'read_only';
  reason: 'supported' | 'upgrade_required';
  /** Compatibility is not write authorization; each owner rechecks gates, role and approval. */
  writeModel: 'conditional_first_party' | 'reviewed_exact_base';
  workspaceRevisionId: string;
  limits: { pageEntries: number; fileBytes: number; attachmentBytes: number; windowBytes: number; activityRevisions: number };
}
export type SyncChangesCommand = ChangeCenterCommand
  | { action: 'propose'; input: CreateProposalInput }
  | { action: 'apply' | 'status' | 'recover'; input: BrowserPublicationInput };
export interface SyncPageInput { workspaceRevisionId: string; cursor?: string; limit?: number }
export type SyncCommand = { client?: SyncClientSignal } & (
  | { action: 'negotiate'; input?: never }
  | { action: 'inventory'; input: SyncPageInput }
  | { action: 'activity'; input: SyncPageInput & { sinceWorkspaceRevisionId: string } }
  | { action: 'index'; input: { workspaceRevisionId: string; cursor?: string } }
  | { action: 'history'; input: HistoryCommand }
  | { action: 'changes'; input: SyncChangesCommand }
  | { action: 'transfers'; input: TransferCommand }
  | { action: 'intent'; input: SyncIntentCommand }
);
/** Exact previously staged native proposal; the server derives every publication binding. */
export interface SyncIntentCommand { action: 'submit' | 'status'; proposalId: string; proposalRevision: number; idempotencyKey: string }
export type SyncIntentResult = { firstPartyIntentId: string; proposalId: string; proposalRevision: number } & (BrowserPublicationResult | { state: 'ready' | 'retired' });
export interface SyncEntry {
  kind: 'file' | 'folder'; id: string; path: string; parentFolderId: string | null;
  state: 'active' | 'tombstone';
  fileVersionId?: string; contentHash?: string | null;
  sizeBytes?: number | null; transferState?: 'supported' | 'unsupported_size' | 'unverified_size' | 'deleted';
}
export interface SyncInventoryPage {
  contractVersion: typeof SYNC_CONTRACT_VERSION; workspaceRevisionId: string;
  entries: SyncEntry[]; nextCursor: string | null;
  /** A missing row may be unreadable. Only an explicit authorized tombstone describes deletion. */
  absenceMeansDeletion: false;
}
export interface SyncActivityEntry {
  action: 'created' | 'modified' | 'renamed' | 'deleted';
  fileId: string; fileVersionId: string; path: string; contentHash: string | null;
  previousPath?: string; previousFileVersionId?: string;
  workspaceRevisionId: string; changeSetId: string;
}
export interface SyncActivityPage {
  contractVersion: typeof SYNC_CONTRACT_VERSION; workspaceRevisionId: string;
  items: SyncActivityEntry[]; nextCursor: string | null;
  /** Advance only after all pages; an incomplete revision never advances this checkpoint. */
  throughWorkspaceRevisionId: string;
}
export interface SyncIndexCheckpoint {
  contractVersion: typeof SYNC_CONTRACT_VERSION; workspaceRevisionId: string;
  graph: 'indexed' | 'later' | 'pending' | 'unavailable'; search: 'indexed' | 'later' | 'pending' | 'unavailable';
  cursor: string; changed: boolean;
  /** Cloud/index observations never attest that local replica bytes were accepted or written. */
  local: 'unconfirmed';
}
export function syncClientCompatible(signal: SyncClientSignal | undefined): boolean {
  return signal?.contractVersion === SYNC_CONTRACT_VERSION &&
    SYNC_REQUIRED_CAPABILITIES.every(capability => signal.capabilities.includes(capability));
}

/** Returned by the existing files sync-cursor route; missing discovery is unknown, never legacy. */
export interface SyncCompatibilityDiscovery {
  mode: 'legacy' | 'workspace' | 'paused'; contractVersion: typeof SYNC_CONTRACT_VERSION | null; endpoint: string | null;
}
