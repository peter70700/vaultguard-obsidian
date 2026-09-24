import type { VaultGuardApiClient } from '../api/client';
import {
  parseStableId, SYNC_CONTRACT_VERSION, SYNC_REQUIRED_CAPABILITIES, TRANSFER_LIMITS, transferFileByteLimit,
  type SyncEntry, type SyncNegotiation, type SyncIndexCheckpoint, type SyncInventoryPage, type SyncCommand,
  type SyncIntentResult, type SyncActivityPage, type TransferView, type BrowserProposal, type HistoryBytes,
  type ChangeProposalView, type ChangeClosedProposalView, type CreateProposalInput, type ProposalOperation,
} from '../vendor/workspace-contracts/src';

export type ReplicaOrigin = 'human' | 'local-agent' | 'unknown';
export interface ReplicaFile extends SyncEntry { localHash?: string; workspaceRevisionId: string }
export interface ReplicaPending {
  id: string; operation: 'write' | 'delete' | 'rename' | 'create_folder' | 'move_folder' | 'delete_folder';
  path: string; newPath?: string; origin: ReplicaOrigin; base: ReplicaFile | null; baseRevision: string | null;
  /** Plain bytes exist only inside the LAK-encrypted journal, never settings or diagnostics. */
  base64?: string; hash?: string; sizeBytes?: number;
  status: 'pending' | 'publishing' | 'review_required' | 'conflict' | 'held'; reason?: string;
  transferId?: string; proposalId?: string; proposalRevision?: number;
  /** Persisted before dispatch; never coalesce or replace an uncertain request. */
  submitted?: true; syncAttempted?: true; publication?: SyncIntentResult;
  batchLeaderId?: string;
}
export interface ReplicaSnapshot {
  schema: 1; binding: string; workspaceRevisionId: string | null; files: ReplicaFile[];
  pending: ReplicaPending[]; index?: SyncIndexCheckpoint; activityRevisionId?: string;
  observedFiles?: ReplicaFile[]; legacyImports?: string[];
  /** Content-free terminal settlement history; preserves the original request identity across reauthentication. */
  settledIntents?: { key: string; intentId: string; baseRevision: string; outcome: "retired" }[];
}
export interface ReplicaStatus {
  mode: 'unknown' | 'legacy' | 'workspace' | 'paused'; writeModel: 'conditional_first_party' | 'reviewed_exact_base' | 'unavailable';
  pending: number; conflicts: number; held: number; reviewRequired: number;
  cloudRevision: string | null; localRevision: string | null;
  graph: SyncIndexCheckpoint['graph']; search: SyncIndexCheckpoint['search'];
  limits: { textBytes: number; attachmentBytes: number; batchBytes: number }; lastError: string | null;
}
export interface ReplicaContext {
  api(): VaultGuardApiClient;
  binding(): string | null;
  vaultId(): string;
  generation(): number;
  ready(): boolean;
  online(): boolean;
  origin(): ReplicaOrigin;
  excluded(path: string): boolean;
  read(path: string): Promise<ArrayBuffer | null>;
  write(path: string, bytes: ArrayBuffer): Promise<void>;
  saveLocal(path: string, bytes: ArrayBuffer): Promise<void>;
  removeEmptyFolder(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  trash(path: string): Promise<boolean>;
  ensureFolder(path: string): Promise<void>;
  localFiles(): string[];
  persist(): Promise<void>;
  changed(status: ReplicaStatus): void;
}
const SIGNAL = Object.freeze({ contractVersion: SYNC_CONTRACT_VERSION, capabilities: SYNC_REQUIRED_CAPABILITIES });
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const validId = (value: unknown): value is string => typeof value === 'string' && ID.test(value);
const JOURNAL_ENCODED_BYTE_LIMIT = 96 * 1024 * 1024;
// Recovery storage is independent of the current publication/transfer limits.
// An image above this bound stays in its original encrypted legacy queue.
const JOURNAL_IMAGE_BYTE_LIMIT = 16 * 1024 * 1024;
export function replicaPath(path: string): string {
  if (typeof path !== 'string' || !path || path.length > 1024 || path.startsWith('/') || /[\\\u0000-\u001f\u007f]/.test(path) || /^[A-Za-z]:/.test(path) || path.split('/').some(p => !p || p === '.' || p === '..')) throw Error('Unsafe replica path');
  return path;
}
export function replicaBase64(bytes: Uint8Array): string {
  let value = '';
  for (let at = 0; at < bytes.length; at += 0x8000) value += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  return btoa(value);
}
const decode = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));
export async function replicaHash(bytes: ArrayBuffer | Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))))).map(n => n.toString(16).padStart(2, '0')).join('');
}
function fresh(binding: string): ReplicaSnapshot { return { schema: 1, binding, workspaceRevisionId: null, files: [], pending: [] }; }

/** A native replica owns local bytes and exact bases, never an OAuth grant or a human approval.
 * All local and network mutations are serialized; callbacks recheck the live session/LAK gate.
 * Missing inventory rows are never deletion evidence. Local observations never attest index readiness. */
export class WorkspaceSyncRuntime {
  private state: ReplicaSnapshot | null = null;
  private mode: ReplicaStatus['mode'] = 'unknown';
  private negotiation: SyncNegotiation | null = null;
  private tail: Promise<unknown> = Promise.resolve();
  private lastError: string | null = null;
  private folderCleanup = new Set<string>();
  private discoveryGeneration: number | null = null;
  constructor(private readonly ctx: ReplicaContext) {}

  snapshot(): ReplicaSnapshot | null { return this.state ? structuredClone(this.state) : null; }
  pending(): readonly ReplicaPending[] { return structuredClone(this.state?.pending ?? []); }
  status(): ReplicaStatus {
    const pending = this.state?.pending ?? [];
    return { mode: this.mode, writeModel: this.negotiation?.mode === 'compatible' && ['conditional_first_party', 'reviewed_exact_base'].includes(this.negotiation.writeModel) ? this.negotiation.writeModel : 'unavailable',
      pending: pending.length, conflicts: pending.filter(p => p.status === 'conflict').length,
      held: pending.filter(p => p.status === 'held').length, reviewRequired: pending.filter(p => p.status === 'review_required').length,
      cloudRevision: this.negotiation?.workspaceRevisionId ?? null,
      localRevision: pending.length ? null : this.state?.workspaceRevisionId ?? null,
      graph: this.state?.index?.graph ?? 'unavailable', search: this.state?.index?.search ?? 'unavailable',
      limits: { textBytes: TRANSFER_LIMITS.fileBytes, attachmentBytes: TRANSFER_LIMITS.attachmentBytes, batchBytes: TRANSFER_LIMITS.totalBytes }, lastError: this.lastError };
  }
  clear(): void { this.state = null; this.mode = 'unknown'; this.negotiation = null; this.lastError = null; this.discoveryGeneration = null; this.folderCleanup.clear(); }
  /** Fail closed on an invalid decrypted envelope; a bad journal must not become an empty journal. */
  restore(raw: unknown): void {
    if (raw === null || raw === undefined) return;
    const s = raw as ReplicaSnapshot;
    if (typeof s !== 'object' || !s || s.schema !== 1 || typeof s.binding !== 'string' || !Array.isArray(s.files) || !Array.isArray(s.pending) || s.files.length > 100000 || s.pending.length > 1000 || (s.workspaceRevisionId !== null && !validId(s.workspaceRevisionId))) throw Error('Invalid revision sync recovery journal');
    if (s.observedFiles !== undefined && (!Array.isArray(s.observedFiles) || s.observedFiles.length > 100000)) throw Error('Invalid observed inventory');
    for (const f of [...s.files, ...(s.observedFiles ?? [])]) {
      this.validateEntry(f);
      if (!validId(f.workspaceRevisionId) || (f.localHash !== undefined && !HASH.test(f.localHash))) throw Error('Invalid local checkpoint');
    }
    if (s.index && (typeof s.index.cursor !== 'string' || s.index.cursor.length > 2048 || !validId(s.index.workspaceRevisionId))) throw Error('Invalid index cursor');
    if (s.settledIntents && (!Array.isArray(s.settledIntents) || s.settledIntents.length > 1000 || s.settledIntents.some(i => !validId(i.key) || !validId(i.intentId) || !validId(i.baseRevision) || i.outcome !== 'retired'))) throw Error('Invalid settled intent history');
    const ids = new Set<string>();
    for (const p of s.pending) {
      replicaPath(p.path); if (p.newPath) replicaPath(p.newPath);
      if (!validId(p.id) || ids.has(p.id) || !['human', 'local-agent', 'unknown'].includes(p.origin) || !['write','delete','rename','create_folder','move_folder','delete_folder'].includes(p.operation) || !['pending','publishing','held','conflict','review_required'].includes(p.status)) throw Error('Invalid pending replica edit');
      ids.add(p.id);
      if ((p.submitted !== undefined && p.submitted !== true) || (p.syncAttempted !== undefined && p.syncAttempted !== true) || (p.batchLeaderId !== undefined && !validId(p.batchLeaderId))) throw Error('Invalid submission journal');
      if (p.publication && (!validId(p.publication.firstPartyIntentId) || p.publication.proposalId !== p.proposalId || p.publication.proposalRevision !== p.proposalRevision || !['ready','retired','applied','pending','failed','conflict','rebased'].includes(p.publication.state))) throw Error('Invalid publication outcome');
      if ((p.proposalId !== undefined && (!validId(p.proposalId) || !Number.isSafeInteger(p.proposalRevision) || p.proposalRevision! < 1)) || (p.transferId !== undefined && !validId(p.transferId))) throw Error('Invalid pending reference');
      if (p.base) this.validateEntry(p.base);
      if (p.baseRevision !== null && !validId(p.baseRevision)) throw Error('Invalid pending base');
      if (p.base64 !== undefined && (typeof p.base64 !== 'string' || p.base64.length > Math.ceil(JOURNAL_IMAGE_BYTE_LIMIT / 3) * 4 || !HASH.test(p.hash ?? '') || !Number.isSafeInteger(p.sizeBytes) || decode(p.base64).length !== p.sizeBytes)) throw Error('Invalid pending byte image');
    }
    if (s.pending.reduce((sum, pending) => sum + (pending.base64?.length ?? 0), 0) > JOURNAL_ENCODED_BYTE_LIMIT) throw Error('Revision recovery journal exceeds its memory bound');
    this.state = structuredClone(s); this.mode = 'unknown';
  }
  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const task = this.tail.then(fn); this.tail = task.catch(() => undefined); return task;
  }
  private live(): () => void {
    const binding = this.ctx.binding(), generation = this.ctx.generation();
    if (!binding || !this.ctx.ready()) throw Error('Revision sync is paused until the vault is authorized and unlocked');
    if (this.state && this.state.binding !== binding) throw Error('Revision recovery belongs to another account or vault');
    if (!this.state) this.state = fresh(binding);
    return () => { if (this.ctx.binding() !== binding || this.ctx.generation() !== generation || !this.ctx.ready()) throw Error('Revision sync session changed'); };
  }
  private async persist(check: () => void): Promise<void> {
    check();
    if (this.state!.pending.length > 1000 || this.state!.pending.reduce((sum, pending) => sum + (pending.base64?.length ?? 0), 0) > JOURNAL_ENCODED_BYTE_LIMIT) throw Error('Revision recovery journal is full; resolve pending changes before saving more');
    await this.ctx.persist(); check(); this.ctx.changed(this.status());
  }
  private async call<T>(command: SyncCommand, check: () => void): Promise<T> { check(); const value = await this.ctx.api().workspaceSync<T>({ ...command, client: SIGNAL }); check(); return value; }
  private async discover(check: () => void): Promise<boolean> {
    check();
    if (!this.ctx.online()) return this.mode !== 'legacy';
    const response = await this.ctx.api().getSyncCompatibility(); check();
    const discovery = response.syncCompatibility;
    if (!discovery || !['legacy','workspace','paused'].includes(discovery.mode)) { this.mode = 'unknown'; throw Error('Server sync compatibility is unknown; local edits are preserved'); }
    if (discovery.mode === 'legacy') {
      if (this.state!.workspaceRevisionId || this.state!.pending.length) throw Error('Revision recovery must be resolved before switching to legacy sync');
      this.mode = 'legacy'; this.discoveryGeneration = this.ctx.generation(); return false;
    }
    this.mode = discovery.mode;
    this.discoveryGeneration = this.ctx.generation();
    if (discovery.mode === 'paused') throw Error('Server workspace sync is paused');
    this.negotiation = await this.call<SyncNegotiation>({ action: 'negotiate' }, check);
    if (this.negotiation.contractVersion !== SYNC_CONTRACT_VERSION || !validId(this.negotiation.workspaceRevisionId)) throw Error('Unsupported sync response');
    return true;
  }
  /** Returns false ONLY after explicit legacy discovery. Discovery failure retains local work. */
  async route(refresh = false): Promise<boolean> {
    return this.serial(async () => { const check = this.live(); try { if (!refresh && this.discoveryGeneration === this.ctx.generation() && (this.mode === 'legacy' || this.mode === 'workspace')) return this.mode !== 'legacy'; return await this.discover(check); } catch (error) { this.lastError = error instanceof Error ? error.message : 'Sync unavailable'; this.ctx.changed(this.status()); return true; } });
  }
  private base(path: string): ReplicaFile | null { return this.state!.files.find(f => f.path === path && f.state === 'active') ?? null; }
  private touches(path: string, id?: string): boolean { return this.state!.pending.some(p => p.path === path || p.newPath === path || (id && p.base?.id === id) || (['move_folder','delete_folder'].includes(p.operation) && path.startsWith(p.path + '/'))); }
  private validateEntry(entry: SyncEntry): void {
    replicaPath(entry.path);
    if (!validId(entry.id) || !['file','folder'].includes(entry.kind) || !['active','tombstone'].includes(entry.state) || (entry.fileVersionId && !validId(entry.fileVersionId)) || (entry.contentHash && !HASH.test(entry.contentHash))) throw Error('Invalid replica identity');
  }
  async write(path: string, bytes: ArrayBuffer): Promise<void> {
    const origin = this.ctx.origin();
    return this.serial(async () => {
      const check = this.live(); replicaPath(path); if (this.ctx.excluded(path)) throw Error('Excluded replica path');
      const hash = await replicaHash(bytes); check();
      const previous = this.state!.pending.find(p => p.path === path && p.operation === 'write' && !p.submitted && !p.proposalId && !p.transferId);
      const base = previous ? previous.base : this.base(path);
      const pending: ReplicaPending = { id: crypto.randomUUID(), operation: 'write', path, origin: previous?.origin === 'local-agent' || origin === 'local-agent' ? 'local-agent' : previous?.origin === 'unknown' ? 'unknown' : origin, base: base ? structuredClone(base) : null,
        baseRevision: previous ? previous.baseRevision : base?.workspaceRevisionId ?? this.state!.workspaceRevisionId, hash, sizeBytes: bytes.byteLength, status: 'pending' };
      if (bytes.byteLength > transferFileByteLimit(path)) { pending.status = 'held'; pending.reason = 'unsupported_size'; }
      else pending.base64 = replicaBase64(new Uint8Array(bytes));
      if (pending.origin !== 'human') { pending.status = 'held'; pending.reason = 'delegated_actor_required'; }
      if (!pending.baseRevision) { pending.status = 'held'; pending.reason = 'base_unknown'; }
      if (this.state!.pending.some(p => p.path === path && p !== previous)) { pending.status = 'held'; pending.reason = 'earlier_change_pending'; }
      if (this.state!.pending.length >= 1000 && !previous) throw Error('Revision pending queue is full; sync or recover pending changes before editing');
      // Journal the attribution and bytes before the local write; a crash cannot relabel them human.
      if (previous) this.state!.pending.splice(this.state!.pending.indexOf(previous), 1);
      this.state!.pending.push(pending); await this.persist(check);
      await this.ctx.saveLocal(path, bytes); check();
    });
  }
  async mutation(operation: Exclude<ReplicaPending['operation'],'write'>, path: string, newPath?: string): Promise<void> {
    const origin = this.ctx.origin();
    return this.serial(async () => {
      const check = this.live(); replicaPath(path); if (newPath) replicaPath(newPath);
      if (this.ctx.excluded(path) || (newPath && this.ctx.excluded(newPath))) return;
      if (this.state!.pending.some(p => (p.operation === operation && p.path === path && p.newPath === newPath) ||
        (['move_folder','delete_folder'].includes(p.operation) && path.startsWith(p.path + '/')))) return;
      if (this.state!.pending.length >= 1000) throw Error('Revision pending queue is full');
      const base = this.base(path);
      const blocked = origin !== 'human' ? 'delegated_actor_required' : (this.touches(path) || (['move_folder','delete_folder'].includes(operation) && this.state!.pending.some(p => p.path.startsWith(path + '/')))) ? 'earlier_change_pending' : !this.state!.workspaceRevisionId || (!base && operation !== 'create_folder') ? 'base_unknown' : undefined;
      this.state!.pending.push({ id: crypto.randomUUID(), operation, path, ...(newPath ? { newPath } : {}), origin,
        base: base ? structuredClone(base) : null, baseRevision: base?.workspaceRevisionId ?? this.state!.workspaceRevisionId, status: blocked ? 'held' : 'pending', ...(blocked ? {reason: blocked} : {}) });
      await this.persist(check);
    });
  }
  /** A legacy queue has no exact workspace base or reliable actor provenance. Hold it,
   * including deletions, before the first revision inventory can touch those paths. */
  async importLegacy(operations: readonly { operation: 'write' | 'delete'; path: string; data?: string; encoding?: 'base64' }[], tombstones: readonly string[]): Promise<void> {
    return this.serial(async () => {
      const check = this.live();
      const imports: { key: string; operation: 'write' | 'delete'; path: string; bytes: Uint8Array | null; hash: string | null }[] = [];
      const imported = new Set(this.state!.legacyImports ?? []);
      let encodedBytes = this.state!.pending.reduce((sum, pending) => sum + (pending.base64?.length ?? 0), 0);
      for (const op of [...operations, ...tombstones.map(path => ({ operation: 'delete' as const, path }))]) {
        replicaPath(op.path);
        if (this.ctx.excluded(op.path)) continue;
        const data = 'data' in op ? op.data : undefined;
        const key = await replicaHash(new TextEncoder().encode(JSON.stringify([op.operation, op.path, data ?? null, 'encoding' in op ? op.encoding ?? null : null])));
        if (imported.has(key)) continue;
        if (this.state!.pending.length + imports.length >= 1000) throw Error('Revision recovery queue is full');
        const bytes = data === undefined ? null : ('encoding' in op && op.encoding === 'base64' ? decode(data) : new TextEncoder().encode(data));
        if (bytes && bytes.length > JOURNAL_IMAGE_BYTE_LIMIT) throw Error('Legacy image exceeds encrypted recovery bound; original queue retained');
        encodedBytes += bytes ? Math.ceil(bytes.length / 3) * 4 : 0;
        if (encodedBytes > JOURNAL_ENCODED_BYTE_LIMIT) throw Error('Revision recovery journal exceeds its memory bound; original queue retained');
        imports.push({ key, operation: op.operation, path: op.path, bytes, hash: bytes ? await replicaHash(bytes) : null });
        imported.add(key);
      }
      for (const item of imports) {
        const bytes = item.bytes;
        this.state!.pending.push({ id: crypto.randomUUID(), operation: item.operation, path: item.path, origin: 'unknown', base: null, baseRevision: null,
          ...(bytes ? { base64: replicaBase64(bytes), hash: item.hash!, sizeBytes: bytes.length } : {}), status: 'held', reason: 'legacy_base_unavailable' });
        this.state!.legacyImports = [...(this.state!.legacyImports ?? []), item.key];
      }
      await this.persist(check);
    });
  }

  /** Runs complete pinned inventories; an expired cursor restarts next pass without advancing state. */
  async sync(): Promise<boolean> {
    return this.serial(async () => {
      const check = this.live();
      try {
        if (!await this.discover(check)) return false;
        if (!this.ctx.online() || this.mode !== 'workspace' || !this.negotiation) return true;
        if (await this.recoverProposals(check)) {
          // Recovery may have committed the original intent. Do not reconcile
          // or checkpoint against the negotiation captured before that commit.
          await this.discover(check);
        }
        const revision = this.negotiation.workspaceRevisionId, entries: SyncEntry[] = [], seen = new Set<string>();
        let cursor: string | undefined, pages = 0;
        do {
          const page = await this.call<SyncInventoryPage>({ action: 'inventory', input: { workspaceRevisionId: revision, ...(cursor ? {cursor} : {}), limit: 100 } }, check);
          if (page.contractVersion !== SYNC_CONTRACT_VERSION || page.workspaceRevisionId !== revision || page.absenceMeansDeletion !== false || !Array.isArray(page.entries) || page.entries.length > 100 || entries.length + page.entries.length > 100000) throw Error('Invalid immutable inventory');
          for (const entry of page.entries) { this.validateEntry(entry); if (seen.has(entry.id)) throw Error('Duplicate stable identity'); seen.add(entry.id); entries.push(entry); }
          if (page.nextCursor === cursor || (page.nextCursor !== null && (typeof page.nextCursor !== 'string' || !page.nextCursor || page.nextCursor.length > 2048)) || ++pages > 10000) throw Error('Inventory cursor did not advance');
          cursor = page.nextCursor ?? undefined;
        } while (cursor);
        // A tombstone may sort after a replacement with a different stable ID.
        // Resolve path ownership from the complete pinned inventory before any
        // filesystem mutation, independently of row order.
        const activeFileOwners = new Map<string, string>();
        for (const entry of entries) {
          if (entry.kind !== 'file' || entry.state !== 'active') continue;
          const owner = activeFileOwners.get(entry.path);
          if (owner && owner !== entry.id) throw Error('Ambiguous active inventory path');
          activeFileOwners.set(entry.path, entry.id);
        }
        this.state!.observedFiles = entries.map(entry => ({ ...entry, workspaceRevisionId: revision }));
        // Activity is a separate complete-revision checkpoint, never an index or byte receipt.
        if (this.state!.workspaceRevisionId && this.state!.workspaceRevisionId !== revision) {
          let activityCursor: string | undefined, pages = 0;
          do {
            const activity = await this.call<SyncActivityPage>({ action: 'activity', input: {
              workspaceRevisionId: revision, sinceWorkspaceRevisionId: this.state!.workspaceRevisionId,
              ...(activityCursor ? { cursor: activityCursor } : {}), limit: 100,
            } }, check);
            if (activity.workspaceRevisionId !== revision || activity.nextCursor === activityCursor || ++pages > 10000) throw Error('Activity cursor mismatch');
            activityCursor = activity.nextCursor ?? undefined;
            if (!activityCursor) this.state!.activityRevisionId = activity.throughWorkspaceRevisionId;
          } while (activityCursor);
        }
        // No local mutation occurs until every inventory page is validated.
        for (const entry of entries) { check(); if (!this.ctx.excluded(entry.path)) await this.reconcile(entry, revision, activeFileOwners, check); }
        for (const path of this.folderCleanup) { check(); await this.ctx.removeEmptyFolder(path); }
        this.folderCleanup.clear();
        this.state!.workspaceRevisionId = revision;
        await this.captureUntracked(entries, check);
        await this.continueRetired(revision, check);
        await this.persist(check);
        let proposed = false;
        if (this.negotiation.mode === 'compatible' && ['conditional_first_party', 'reviewed_exact_base'].includes(this.negotiation.writeModel)) {
          for (const pending of this.state!.pending) {
            if (pending.status !== 'pending' || (pending.batchLeaderId && pending.batchLeaderId !== pending.id)) continue;
            if (pending.baseRevision !== revision && !pending.submitted) {
              pending.status = 'conflict'; pending.reason = 'stale_base'; await this.persist(check); continue;
            }
            try { await this.propose(pending, check); proposed = true; }
            catch (error) {
              check();
              const refusal = (error as { apiError?: { statusCode?: number; code?: string } })?.apiError;
              if (!pending.syncAttempted && refusal?.statusCode && refusal.statusCode >= 400 && refusal.statusCode < 500 && ![408, 429].includes(refusal.statusCode)) {
                pending.status = refusal.statusCode === 409 ? 'conflict' : 'held'; pending.reason = refusal.code ?? 'submission_refused';
              } else pending.reason = 'submission_ambiguous';
              this.lastError = 'A local change is retained; retry or open sync recovery'; await this.persist(check);
            }
          }
        }
        if (proposed && this.negotiation.writeModel === 'conditional_first_party') {
          const before = this.negotiation.workspaceRevisionId;
          await this.discover(check);
          if (this.negotiation!.workspaceRevisionId !== before) {
            // A publication advanced HEAD during this pass. The next pass will
            // inventory the new revision and settle its original receipt.
            await this.persist(check); return true;
          }
        }
        try {
          const cursor = this.state!.index?.workspaceRevisionId === revision ? this.state!.index.cursor : undefined;
          try {
            this.state!.index = await this.call<SyncIndexCheckpoint>({ action: 'index', input: { workspaceRevisionId: revision, ...(cursor ? { cursor } : {}) } }, check);
          } catch (error) {
            // A sealed marker also binds authorization generations. Permissions can
            // change without a content revision; refresh only the marker, never bytes.
            const code = (error as { apiError?: { code?: string }; code?: string } | null)?.apiError?.code
              ?? (error as { code?: string } | null)?.code;
            if (!cursor || code !== 'stale_cursor') throw error;
            delete this.state!.index;
            this.state!.index = await this.call<SyncIndexCheckpoint>({ action: 'index', input: { workspaceRevisionId: revision } }, check);
          }
        } catch (error) { delete this.state!.index; await this.persist(check); throw error; }
        if (this.state!.index.workspaceRevisionId !== revision || this.state!.index.local !== 'unconfirmed') throw Error('Invalid index checkpoint');
        this.lastError = null; await this.persist(check); return true;
      } catch (error) { this.lastError = error instanceof Error ? error.message : 'Revision sync unavailable'; this.ctx.changed(this.status()); throw error; }
    });
  }
  private async exactBytes(entry: SyncEntry, revision: string, check: () => void): Promise<ArrayBuffer> {
    if (!entry.fileVersionId || !entry.contentHash || entry.transferState !== 'supported' || !Number.isSafeInteger(entry.sizeBytes) || entry.sizeBytes! < 0 || entry.sizeBytes! > transferFileByteLimit(entry.path)) throw Error('File size or exact version is unsupported');
    const bytes = new Uint8Array(entry.sizeBytes!); let offset = 0;
    do {
      const window: HistoryBytes = await this.call<HistoryBytes>({ action: 'history', input: { action: 'read', fileId: entry.id, fileVersionId: entry.fileVersionId, workspaceRevisionId: revision, offset } }, check);
      const part = decode(window.base64), next = offset + part.length;
      if (window.version.fileId !== entry.id || window.version.fileVersionId !== entry.fileVersionId || window.version.workspaceRevisionId !== revision || window.version.contentHash !== entry.contentHash || window.offset !== offset || window.totalBytes !== bytes.length || part.length > TRANSFER_LIMITS.windowBytes || next > bytes.length || window.nextOffset !== (next < bytes.length ? next : null) || (next < bytes.length && !part.length)) throw Error('Exact history window mismatch');
      bytes.set(part, offset); offset = next;
    } while (offset < bytes.length);
    if (await replicaHash(bytes) !== entry.contentHash) throw Error('Exact history checksum mismatch'); check(); return bytes.buffer;
  }
  private async reconcile(entry: SyncEntry, revision: string, activeFileOwners: ReadonlyMap<string, string>, check: () => void): Promise<void> {
    const old = this.state!.files.find(f => f.id === entry.id);
    if (this.touches(entry.path, entry.id) || (old && this.touches(old.path, old.id))) return;
    if (entry.kind === 'folder') {
      if (entry.state === 'active') await this.ctx.ensureFolder(entry.path);
      if (old && (old.path !== entry.path || entry.state === 'tombstone')) this.folderCleanup.add(old.path);
      // Folder deletion never recursively removes local-only descendants.
      this.replaceFile({ ...entry, workspaceRevisionId: revision }); return;
    }
    if (entry.state === 'tombstone') {
      // The retired identity no longer owns this path. Its tombstone updates
      // identity history, but cannot remove a live replacement's local bytes.
      if (old && activeFileOwners.get(old.path) && activeFileOwners.get(old.path) !== entry.id) {
        this.replaceFile({ ...entry, workspaceRevisionId: revision }); return;
      }
      if (old?.state === 'active' && old.localHash) {
        const bytes = await this.ctx.read(old.path); check();
        if (bytes && await replicaHash(bytes) !== old.localHash) { await this.holdLocal(old.path, old, bytes, 'remote_deleted', check); return; }
        if (bytes && !await this.ctx.trash(old.path)) throw Error('Recoverable local trash unavailable');
      }
      this.replaceFile({ ...entry, workspaceRevisionId: revision }); return;
    }
    if (entry.transferState !== 'supported') {
      if (!this.touches(entry.path)) { this.state!.pending.push({ id: crypto.randomUUID(), operation: 'write', path: entry.path, origin: 'unknown', base: old ?? null, baseRevision: revision, status: 'held', reason: entry.transferState ?? 'unverified_size' }); await this.persist(check); }
      return;
    }
    const sourcePath = old?.path ?? entry.path, local = await this.ctx.read(sourcePath); check();
    const localHash = local ? await replicaHash(local) : null;
    if (local && localHash !== old?.localHash && localHash !== entry.contentHash) { await this.holdLocal(sourcePath, old ?? null, local, 'local_conflict', check); return; }
    if (old && old.path !== entry.path) {
      const destination = await this.ctx.read(entry.path); check();
      if (destination !== null) {
        if (!local && await replicaHash(destination) === entry.contentHash) {
          this.replaceFile({ ...entry, localHash: entry.contentHash ?? undefined, workspaceRevisionId: revision });
          await this.persist(check); return;
        }
        await this.holdLocal(local ? old.path : entry.path, old, local ?? destination, 'rename_destination_occupied', check); return;
      }
      if (local) { await this.ctx.rename(old.path, entry.path); check(); }
    }
    if (localHash !== entry.contentHash) {
      const bytes = await this.exactBytes(entry, revision, check);
      // Filesystem changes may bypass the serialized native adapter (for example
      // an external editor). Recheck after network waits before replacing bytes.
      const current = await this.ctx.read(entry.path); check();
      const currentHash = current === null ? null : await replicaHash(current); check();
      if (currentHash !== localHash) {
        if (current !== null) await this.holdLocal(entry.path, old ?? null, current, 'local_conflict', check);
        else {
          this.state!.pending.push({ id: crypto.randomUUID(), operation: 'delete', path: entry.path,
            origin: 'unknown', base: old ?? null, baseRevision: old?.workspaceRevisionId ?? null,
            status: 'held', reason: 'local_deleted_during_download' });
          await this.persist(check);
        }
        return;
      }
      await this.ctx.write(entry.path, bytes); check();
    }
    this.replaceFile({ ...entry, localHash: entry.contentHash ?? undefined, workspaceRevisionId: revision });
    await this.persist(check);
  }
  private replaceFile(file: ReplicaFile): void { this.state!.files = this.state!.files.filter(f => f.id !== file.id); this.state!.files.push(file); }
  private async holdLocal(path: string, base: ReplicaFile | null, bytes: ArrayBuffer, reason: string, check: () => void): Promise<void> {
    if (this.touches(path)) return;
    if (this.state!.pending.length >= 1000) throw Error('Revision recovery queue is full');
    this.state!.pending.push({ id: crypto.randomUUID(), operation: 'write', path, base, baseRevision: base?.workspaceRevisionId ?? null, origin: 'unknown', hash: await replicaHash(bytes), sizeBytes: bytes.byteLength,
      ...(bytes.byteLength <= transferFileByteLimit(path) ? {base64: replicaBase64(new Uint8Array(bytes))} : {}), status: 'conflict', reason });
    await this.persist(check);
  }
  private async captureUntracked(entries: SyncEntry[], check: () => void): Promise<void> {
    const known = new Set([...entries.map(f => f.path), ...this.state!.files.map(f => f.path)]);
    for (const path of this.ctx.localFiles()) {
      if (this.ctx.excluded(path) || known.has(path) || this.touches(path)) continue;
      const bytes = await this.ctx.read(path); check();
      if (bytes) await this.holdLocal(path, null, bytes, 'untracked_local', check);
    }
  }
  private async propose(pending: ReplicaPending, check: () => void): Promise<void> {
    if (pending.origin !== 'human' || !pending.baseRevision) return;
    if (pending.proposalId && this.negotiation?.writeModel === 'conditional_first_party') {
      const group = pending.batchLeaderId ? this.state!.pending.filter(p => p.batchLeaderId === pending.batchLeaderId) : [pending];
      await this.submitIntent(pending, group, check); return;
    }
    let batch = [pending];
    if (pending.operation === 'write') {
      if (pending.batchLeaderId) batch = this.state!.pending.filter(p => p.batchLeaderId === pending.batchLeaderId);
      else {
        let total = 0;
        batch = this.state!.pending.filter(p => {
          if (p.operation !== 'write' || p.origin !== 'human' || p.status !== 'pending' || p.submitted || p.baseRevision !== pending.baseRevision || p.base64 === undefined || p.sizeBytes === undefined || total + p.sizeBytes > TRANSFER_LIMITS.totalBytes) return false;
          total += p.sizeBytes; return true;
        }).slice(0, TRANSFER_LIMITS.files);
        if (!batch.includes(pending)) batch = [pending];
        for (const item of batch) { item.batchLeaderId = pending.id; item.submitted = true; }
        await this.persist(check);
      }
      const images = await Promise.all(batch.map(async item => {
        if (item.base64 === undefined || !item.hash || item.sizeBytes === undefined) throw Error('Pending byte image missing');
        const bytes = decode(item.base64);
        if (bytes.length !== item.sizeBytes || await replicaHash(bytes) !== item.hash) throw Error('Pending image checksum mismatch');
        return bytes;
      }));
      let transfer: TransferView;
      if (pending.transferId) transfer = await this.call({ action: 'transfers', input: { action: 'status', transferId: pending.transferId } }, check);
      else {
        transfer = await this.call({ action: 'transfers', input: { action: 'prepare_import', workspaceRevisionId: pending.baseRevision,
          files: batch.map((item, index) => ({ path: item.path, sha256: item.hash!, sizeBytes: images[index].length,
            ...(item.base?.fileVersionId ? { fileId: item.base.id, fileVersionId: item.base.fileVersionId } : {}) })), idempotencyKey: pending.batchLeaderId ?? pending.id } }, check);
        if (!validId(transfer.transferId)) throw Error('Invalid transfer identity');
        for (const item of batch) item.transferId = transfer.transferId;
        await this.persist(check);
      }
      if (transfer.transferId !== pending.transferId || transfer.workspaceRevisionId !== pending.baseRevision || transfer.files.length !== batch.length ||
        batch.some((item, index) => transfer.files[index]?.sha256 !== item.hash || transfer.files[index]?.path !== item.path || transfer.files[index]?.sizeBytes !== item.sizeBytes)) throw Error('Pending transfer identity mismatch');
      if (transfer.state === 'expired' || transfer.state === 'cancelled' || transfer.outcome === 'failed') {
        for (const item of batch) { item.status = 'conflict'; item.reason = 'transfer_closed'; } await this.persist(check); return;
      }
      for (const [index, bytes] of images.entries()) {
        let offset = transfer.uploaded.includes(index) ? bytes.length : transfer.uploadedOffsets?.[String(index)] ?? 0;
        if (!Number.isSafeInteger(offset) || offset < 0 || offset > bytes.length) throw Error('Invalid upload offset');
        if (!bytes.length && !transfer.uploaded.includes(index)) transfer = await this.call({ action: 'transfers', input: { action: 'upload', transferId: transfer.transferId, index, base64: '' } }, check);
        while (offset < bytes.length) {
          const next = Math.min(bytes.length, offset + TRANSFER_LIMITS.windowBytes);
          transfer = await this.call({ action: 'transfers', input: { action: 'upload_chunk', transferId: transfer.transferId, index, offset, base64: replicaBase64(bytes.subarray(offset, next)) } }, check);
          offset = next;
        }
      }
      const proposed = transfer.proposalId ? transfer : await this.call<BrowserProposal>({ action: 'transfers', input: { action: 'propose', transferId: transfer.transferId } }, check);
      if (!validId(proposed.proposalId ?? '') || !Number.isSafeInteger(proposed.proposalRevision) || proposed.proposalRevision! < 1) throw Error('Proposal reference missing');
      for (const item of batch) { item.proposalId = proposed.proposalId; item.proposalRevision = proposed.proposalRevision; }
    } else {
      pending.submitted = true; await this.persist(check);
      const operationId = parseStableId('operation', pending.id), base = pending.base;
      let operation: ProposalOperation;
      if (pending.operation === 'create_folder') operation = { operationId, op: 'create_folder', path: pending.path, mustBeAbsent: true };
      else if (pending.operation === 'move_folder' && base && pending.newPath) operation = { operationId, op: 'move_folder', folderId: parseStableId('folder', base.id), path: pending.path, newPath: pending.newPath, destinationMustBeAbsent: true, referencePolicy: 'path_only' };
      else if (pending.operation === 'delete_folder' && base) operation = { operationId, op: 'delete_folder', folderId: parseStableId('folder', base.id), path: pending.path, recursive: true };
      else if (base?.fileVersionId && pending.operation === 'delete') operation = { operationId, op: 'delete', file: { fileId: parseStableId('file', base.id) }, expectedVersionId: parseStableId('fileVersion', base.fileVersionId) };
      else if (base?.fileVersionId && pending.operation === 'rename' && pending.newPath) operation = { operationId, op: 'rename', file: { fileId: parseStableId('file', base.id) }, expectedVersionId: parseStableId('fileVersion', base.fileVersionId), newPath: pending.newPath, destinationMustBeAbsent: true, referencePolicy: 'path_only' };
      else throw Error('Exact mutation identity missing');
      const input: CreateProposalInput = { vaultId: parseStableId('vault', this.ctx.vaultId()), baseWorkspaceRevisionId: parseStableId('workspaceRevision', pending.baseRevision), operations: [operation], idempotencyKey: pending.id };
      const proposal = await this.call<BrowserProposal>({ action: 'changes', input: { action: 'propose', input } }, check);
      pending.proposalId = proposal.proposalId; pending.proposalRevision = proposal.proposalRevision;
    }
    for (const item of batch) { item.status = 'review_required'; delete item.reason; } await this.persist(check);
    if (this.negotiation?.writeModel === 'conditional_first_party') await this.submitIntent(pending, batch, check);
  }
  /** A fresh login may continue only after the original authority is durably retired.
   * Unchanged exact base can resume automatically; an intervening commit needs explicit conflict recovery. */
  private async continueRetired(revision: string, check: () => void): Promise<void> {
    for (const item of [...this.state!.pending]) {
      if (item.publication?.state !== 'retired') continue;
      if (item.baseRevision !== revision) { item.status = 'conflict'; item.reason = 'stale_base'; continue; }
      const observed = item.base ? this.state!.observedFiles?.find(file => file.id === item.base!.id) : null;
      if (item.base && (!observed || observed.path !== item.base.path || observed.fileVersionId !== item.base.fileVersionId)) { item.status = 'conflict'; item.reason = 'stale_base'; continue; }
      const history = this.state!.settledIntents ?? [];
      if (history.length >= 1000) { item.status = 'held'; item.reason = 'settlement_history_full'; continue; }
      const original = { key: item.batchLeaderId ?? item.id, intentId: item.publication.firstPartyIntentId, baseRevision: item.baseRevision!, outcome: 'retired' as const };
      if (!history.some(record => record.intentId === original.intentId)) history.push(original);
      this.state!.settledIntents = history;
      const next = { ...item, id: crypto.randomUUID(), status: 'pending' as const };
      delete next.submitted; delete next.syncAttempted; delete next.publication; delete next.batchLeaderId;
      delete next.transferId; delete next.proposalId; delete next.proposalRevision; delete next.reason;
      this.state!.pending[this.state!.pending.indexOf(item)] = next;
      await this.persist(check);
    }
  }
  private async submitIntent(pending: ReplicaPending, batch: ReplicaPending[], check: () => void): Promise<void> {
    if (!pending.proposalId || !pending.proposalRevision || pending.origin !== 'human') throw Error('Native proposal missing');
    for (const item of batch) { item.syncAttempted = true; item.status = 'publishing'; item.reason = 'outcome_unknown'; }
    await this.persist(check);
    const result = await this.call<SyncIntentResult>({ action: 'intent', input: { action: 'submit', proposalId: pending.proposalId,
      proposalRevision: pending.proposalRevision, idempotencyKey: pending.batchLeaderId ?? pending.id } }, check);
    await this.acceptIntent(pending, batch, result, check);
  }
  private async acceptIntent(pending: ReplicaPending, batch: ReplicaPending[], result: SyncIntentResult, check: () => void): Promise<void> {
    if (!validId(result.firstPartyIntentId) || result.proposalId !== pending.proposalId || result.proposalRevision !== pending.proposalRevision ||
      (result.state === 'applied' && (!validId(result.receiptId) || !validId(result.workspaceRevisionId)))) throw Error('Native publication outcome mismatch');
    for (const item of batch) {
      item.publication = structuredClone(result);
      if (result.state === 'retired') { item.status = 'held'; item.reason = 'previous_session_settled'; }
      else if (result.state === 'conflict' || result.state === 'rebased' || (result.state === 'failed' && !result.retryable)) {
        item.status = 'conflict'; item.reason = result.code ?? result.state;
      } else { item.status = 'publishing'; item.reason = result.state === 'applied' ? 'confirming_receipt_and_inventory' : 'outcome_unknown'; }
    }
    await this.persist(check);
  }
  private publicationApplied(pending: ReplicaPending): boolean {
    return pending.publication?.state === 'applied';
  }
  private async recoverProposals(check: () => void): Promise<boolean> {
    let publicationMayHaveAdvanced = false;
    for (const pending of [...this.state!.pending]) {
      if (!pending.proposalId) continue;
      if (pending.syncAttempted && !this.publicationApplied(pending)) {
        publicationMayHaveAdvanced = true;
        if (pending.batchLeaderId && pending.batchLeaderId !== pending.id) continue;
        const batch = pending.batchLeaderId ? this.state!.pending.filter(p => p.batchLeaderId === pending.batchLeaderId) : [pending];
        try {
          const result = await this.call<SyncIntentResult>({ action: 'intent', input: { action: 'status', proposalId: pending.proposalId,
            proposalRevision: pending.proposalRevision!, idempotencyKey: pending.batchLeaderId ?? pending.id } }, check);
          await this.acceptIntent(pending, batch, result, check);
          if (result.state === 'ready' || (result.state === 'failed' && result.retryable)) await this.submitIntent(pending, batch, check);
          if (!this.publicationApplied(pending)) continue;
        } catch (error) {
          check();
          if ((error as { apiError?: { statusCode?: number } })?.apiError?.statusCode === 404) {
            try { await this.submitIntent(pending, batch, check); } catch { check(); }
          }
          if (!this.publicationApplied(pending)) { pending.status = 'publishing'; pending.reason = 'outcome_unknown'; await this.persist(check); continue; }
        }
      }

      let view: ChangeProposalView;
      try {
        view = await this.call<ChangeProposalView>({ action: 'changes', input: { action: 'inspect', input: { proposalId: pending.proposalId, proposalRevision: pending.proposalRevision } } }, check);
      } catch {
        check();
        try {
          const closed = await this.call<ChangeClosedProposalView>({ action: 'changes', input: { action: 'inspect_closed', input: { proposalId: pending.proposalId } } }, check);
          if (closed.descriptor.proposalId !== pending.proposalId) throw Error('Closed proposal identity mismatch');
          pending.status = 'conflict'; pending.reason = closed.descriptor.state;
        } catch { check(); pending.status = 'held'; pending.reason = 'recovery_unavailable'; }
        await this.persist(check); continue;
      }
      if (view.descriptor.proposalId !== pending.proposalId) throw Error('Proposal identity changed');
      if (!pending.syncAttempted && pending.submitted && pending.origin === 'human' && pending.status === 'review_required' &&
        this.negotiation?.mode === 'compatible' && this.negotiation.writeModel === 'conditional_first_party' &&
        !['applied', 'rejected', 'superseded', 'expired'].includes(view.latestState)) {
        if (pending.batchLeaderId && pending.batchLeaderId !== pending.id) continue;
        const batch = pending.batchLeaderId ? this.state!.pending.filter(p => p.batchLeaderId === pending.batchLeaderId) : [pending];
        if (!batch.length || batch.some(p => p.proposalId !== pending.proposalId || p.proposalRevision !== pending.proposalRevision || p.origin !== 'human')) throw Error('Native batch recovery identity mismatch');
        // The proposal and original key were already persisted. The canonical
        // first-party intent owner must decide current authority and base.
        await this.submitIntent(pending, batch, check);
        publicationMayHaveAdvanced = true;
        continue;
      }
      if (view.latestState === 'applied' && view.receipts.length) {
        // Receipt + inventory confirm publication. A changed local copy remains a conflict.
        if (pending.operation === 'write' && pending.hash) {
          const old = this.base(pending.path); if (old) old.localHash = pending.hash;
          else {
            const impact = view.files.find(f => f.after?.path === pending.path);
            if (impact?.after) this.replaceFile({ kind: 'file', id: impact.fileId, path: pending.path, parentFolderId: null, state: 'active', localHash: pending.hash, workspaceRevisionId: pending.baseRevision! });
          }
        }
        if (pending.operation === 'rename' && pending.base && pending.newPath) this.replaceFile({ ...pending.base, path: pending.newPath });
        if (pending.operation === 'move_folder' && pending.newPath) {
          const target = pending.newPath;
          this.state!.files = this.state!.files.map(file => file.path === pending.path || file.path.startsWith(pending.path + '/')
            ? { ...file, path: target + file.path.slice(pending.path.length) } : file);
        }
        this.state!.pending = this.state!.pending.filter(p => p.id !== pending.id);
        await this.persist(check);
      } else if (view.references.conflicts.some(conflict => ['open','resolving','rebased','proposal-revalidated'].includes(conflict.state)) ||
        view.references.changeSets.some(change => change.state === 'conflict' || change.outcome?.kind === 'conflict')) {
        // A refused publication records its conflict separately while its source
        // proposal can remain approved. Its bytes still require conflict review.
        pending.status = 'conflict'; pending.reason = 'conflict'; await this.persist(check);
      } else if (['rejected','superseded','expired'].includes(view.latestState)) {
        pending.status = 'conflict'; pending.reason = view.latestState; await this.persist(check);
      } else { pending.status = 'review_required'; delete pending.reason; await this.persist(check); }
    }
    return publicationMayHaveAdvanced;
  }
  /** An explicit human recovery choice makes a NEW reviewed proposal on today's exact base.
   * A delegated edit can never be relabelled by this operation. No server version is overwritten. */
  async prepareRecovery(id: string, destination?: string): Promise<void> {
    return this.serial(async () => {
      const check = this.live(), item = this.state!.pending.find(p => p.id === id);
      if (!this.ctx.online() || this.negotiation?.mode !== 'compatible' || !['conditional_first_party', 'reviewed_exact_base'].includes(this.negotiation.writeModel)) throw Error('Refresh supported workspace compatibility before preparing review');
      if (item?.syncAttempted && (!item.publication || item.publication.state === 'ready' || item.publication.state === 'pending' || item.publication.state === 'applied' || (item.publication.state === 'failed' && item.publication.retryable))) throw Error('Reconcile the original publication before choosing a new base');
      if (!item || item.origin === 'local-agent' || (item.proposalId && !item.publication && !['rejected','cancelled','expired'].includes(item.reason ?? '')) || !this.state!.workspaceRevisionId) throw Error('Use the canonical proposal/conflict review for this change');
      const path = replicaPath(destination ?? item.path);
      const observed = this.state!.observedFiles?.find(file => file.state === 'active' && (item.base ? file.id === item.base.id : file.path === item.path)) ?? null;
      if (item.operation !== 'write' && destination) throw Error('Only a file byte image can be duplicated');
      if (['delete','delete_folder','rename','move_folder'].includes(item.operation) && !observed)
        throw Error('Exact current identity is unavailable; the local intent remains held');
      const copy: ReplicaPending = { ...item, id: crypto.randomUUID(), path: item.operation === 'write' ? path : observed?.path ?? path,
        origin: 'human', base: destination ? null : observed, baseRevision: this.state!.workspaceRevisionId, status: 'pending', reason: undefined };
      delete copy.transferId; delete copy.proposalId; delete copy.proposalRevision;
      delete copy.submitted; delete copy.syncAttempted; delete copy.publication; delete copy.batchLeaderId;
      if (item.operation === 'write') {
        const bytes = item.base64 !== undefined ? decode(item.base64).buffer : await this.ctx.read(item.path); check();
        if (!bytes || bytes.byteLength > transferFileByteLimit(path)) throw Error('Local file is unavailable or exceeds the contract limit');
        if (destination && (this.base(path) || await this.ctx.read(path))) throw Error('Recovery destination already exists');
        copy.base64 = replicaBase64(new Uint8Array(bytes)); copy.hash = await replicaHash(bytes); copy.sizeBytes = bytes.byteLength;
        // Duplicate recovery keeps the original path; rebase retains the exact journal bytes.
        if (destination) await this.ctx.write(path, bytes);
      }
      this.state!.pending = this.state!.pending.filter(p => p.id !== item.id); this.state!.pending.push(copy);
      await this.persist(check); await this.propose(copy, check);
    });
  }
}
