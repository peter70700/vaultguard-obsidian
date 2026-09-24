import { App, ButtonComponent, Modal, Notice, TextComponent } from 'obsidian';
import type { WorkspaceSyncRuntime } from './workspace-sync-runtime';

/** Local recovery UI never decides a server approval and never exposes journal bytes. */
export class WorkspaceSyncModal extends Modal {
  constructor(app: App, private readonly runtime: WorkspaceSyncRuntime, private readonly refresh: () => Promise<void>, private readonly openReview: (proposalId: string) => void) { super(app); }
  onOpen(): void { this.render(); }
  onClose(): void { this.contentEl.empty(); }
  private render(): void {
    const el = this.contentEl; el.empty();
    const status = this.runtime.status();
    el.createEl('h2', { text: 'Workspace sync and recovery' });
    el.createEl('p', { text: `Connection: ${status.mode}. ${status.pending} local changes pending; ${status.reviewRequired} awaiting review; ${status.conflicts} conflicts; ${status.held} held.` });
    el.createEl('p', { text: status.writeModel === 'conditional_first_party' ? 'Your authorized local changes sync automatically against their exact cloud base. Pending or uncertain changes remain recoverable on this device.' : status.writeModel === 'reviewed_exact_base' ? 'This server requires review in VaultGuard before local changes are published. Saving locally or preparing a proposal does not mean it is synced.' : 'Write compatibility is unavailable. Local work is retained.' });
    el.createEl('p', { text: 'Supported envelope: 1 MiB per text file, 8 MiB per attachment, 16 MiB per transfer batch. Larger or unknown files stay pending.' });
    el.createEl('p', { text: `Cloud index: graph ${status.graph}; search ${status.search}. Local replica: ${status.localRevision ? 'downloaded checkpoint available' : 'not confirmed current'}.` });
    if (status.lastError) el.createEl('p', { text: status.lastError, attr: { role: 'status' } });
    new ButtonComponent(el).setButtonText('Refresh and retry').onClick(() => this.run(this.refresh));
    for (const item of this.runtime.pending()) {
      const row = el.createDiv();
      row.createEl('h3', { text: item.newPath ? `${item.path} → ${item.newPath}` : item.path });
      row.createEl('p', { text: `${item.operation}: ${item.status}${item.reason ? ` (${item.reason})` : ''}` });
      if (item.origin === 'local-agent') row.createEl('p', { text: 'This edit came from a local agent. It is held for a verified delegated workflow and will never be submitted as a human edit.' });
      if (item.syncAttempted) row.createEl('p', { text: item.publication?.state === 'applied' ? 'Published; confirming the receipt and exact cloud inventory.' : 'The original request is retained. Refresh and retry reconciles its durable outcome without changing its base or key.' });
      if (item.proposalId) new ButtonComponent(row).setButtonText('Open review and conflict recovery').onClick(() => this.openReview(item.proposalId!));
      if (['conditional_first_party', 'reviewed_exact_base'].includes(status.writeModel) && (!item.proposalId || ['rejected','cancelled','expired'].includes(item.reason ?? '') || (item.publication && (item.publication.state === 'retired' || item.publication.state === 'conflict' || item.publication.state === 'rebased' || (item.publication.state === 'failed' && !item.publication.retryable)))) && item.origin !== 'local-agent' && (item.operation !== 'write' || item.base64 !== undefined)) {
        row.createEl('p', { text: status.writeModel === 'conditional_first_party' ? 'This explicit choice starts a new request for the retained local bytes against the current cloud revision. An uncertain original request must be reconciled first.' : 'Preparing review explicitly proposes your local bytes against the current cloud revision. Nothing publishes until the browser review is approved and applied.' });
        new ButtonComponent(row).setButtonText(status.writeModel === 'conditional_first_party' ? 'Sync retained change on current base' : 'Prepare this change for review').onClick(() => this.run(() => this.runtime.prepareRecovery(item.id)));
        if (item.operation !== 'write') continue;
        let destination = '';
        new TextComponent(row).setPlaceholder('New path for a recoverable copy').onChange(value => destination = value.trim());
        new ButtonComponent(row).setButtonText(status.writeModel === 'conditional_first_party' ? 'Keep and sync a separate copy' : 'Keep a copy and prepare review').onClick(() => this.run(async () => {
          if (!destination) throw Error('Enter a new vault-relative path.');
          await this.runtime.prepareRecovery(item.id, destination);
        }));
      }
    }
  }
  private async run(action: () => Promise<void>): Promise<void> {
    try { await action(); } catch (error) { new Notice(error instanceof Error ? error.message : 'Recovery remains pending.'); }
    this.render();
  }
}
