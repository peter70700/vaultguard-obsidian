import { App, Modal, Notice, setIcon } from "obsidian";
import type {
  DeletedFileRecord,
  FileVersionRecord,
  RecoveryPage,
  VaultGuardApiClient,
} from "../api/client";
import type { SyncConflict } from "../types";

export type RecoveryCenterTab = "history" | "deleted" | "conflicts";

export interface RecoveryCenterConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  initialPath?: string;
  initialTab?: RecoveryCenterTab;
  getConflicts: () => SyncConflict[];
  getConflictFiles: () => string[];
  onOpenPath: (path: string) => Promise<void> | void;
  onRestored?: () => Promise<void> | void;
}

class RecoveryConfirmationModal extends Modal {
  constructor(
    app: App,
    private readonly title: string,
    private readonly detail: string,
    private readonly resolve: (confirmed: boolean) => void,
  ) {
    super(app);
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-recovery-confirm-modal");
    this.contentEl.createEl("h2", { text: this.title });
    this.contentEl.createEl("p", { text: this.detail });
    this.contentEl.createEl("p", {
      cls: "vaultguard-recovery-confirm-note",
      text: "The current server version remains in version history.",
    });
    const actions = this.contentEl.createDiv({ cls: "vaultguard-recovery-confirm-actions" });
    const cancel = actions.createEl("button", { text: "Cancel" });
    cancel.addEventListener("click", () => {
      this.resolve(false);
      this.close();
    });
    const confirm = actions.createEl("button", {
      cls: "mod-cta",
      text: "Restore",
    });
    confirm.addEventListener("click", () => {
      this.resolve(true);
      this.close();
    });
    confirm.focus();
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

function confirmRecovery(app: App, title: string, detail: string): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (confirmed: boolean) => {
      if (settled) return;
      settled = true;
      resolve(confirmed);
    };
    const modal = new RecoveryConfirmationModal(app, title, detail, finish);
    const close = modal.close.bind(modal);
    modal.close = () => {
      finish(false);
      close();
    };
    modal.open();
  });
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "Unknown size";
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 ** 2).toFixed(1)} MiB`;
}

/** Reverse the exact suffix emitted by SyncRuntime.generateConflictPath(). */
export function likelyOriginalForConflictCopy(path: string): string | null {
  const match = path.match(/^(.*) \(conflict [^)]+\)(\.[^/]+)?$/i);
  if (!match) return null;
  const original = `${match[1]}${match[2] ?? ""}`;
  return original === path ? null : original;
}

export class RecoveryCenterModal extends Modal {
  private tab: RecoveryCenterTab;
  private path: string;
  private history: RecoveryPage<FileVersionRecord> = {
    items: [], cursor: null, hasMore: false,
  };
  private deleted: RecoveryPage<DeletedFileRecord> = {
    items: [], cursor: null, hasMore: false,
  };
  private loading = false;
  private error: string | null = null;
  private requestEpoch = 0;
  private closed = false;

  constructor(private readonly cfg: RecoveryCenterConfig) {
    super(cfg.app);
    this.tab = cfg.initialTab ?? "history";
    this.path = cfg.initialPath ?? "";
  }

  async onOpen(): Promise<void> {
    this.closed = false;
    this.modalEl.addClass("vaultguard-recovery-center-modal");
    this.contentEl.addClass("vaultguard-recovery-center");
    this.render();
    await this.loadCurrent(false);
  }

  onClose(): void {
    this.closed = true;
    this.requestEpoch += 1;
    this.contentEl.empty();
  }

  private render(): void {
    this.contentEl.empty();
    const header = this.contentEl.createDiv({ cls: "vaultguard-recovery-header" });
    const icon = header.createSpan({ cls: "vaultguard-recovery-title-icon" });
    setIcon(icon, "history");
    const title = header.createDiv();
    title.createEl("h2", { text: "Recovery Center" });
    title.createEl("p", {
      text: "Find previous versions, restore deleted files, and inspect conflicts.",
    });

    const tabs = this.contentEl.createDiv({
      cls: "vaultguard-recovery-tabs",
      attr: { role: "tablist", "aria-label": "Recovery sections" },
    });
    const labels: Array<[RecoveryCenterTab, string]> = [
      ["history", "History"],
      ["deleted", "Deleted files"],
      ["conflicts", "Conflicts"],
    ];
    for (const [tab, label] of labels) {
      const button = tabs.createEl("button", {
        cls: tab === this.tab ? "is-active" : "",
        text: label,
        attr: {
          role: "tab",
          "aria-selected": String(tab === this.tab),
          type: "button",
        },
      });
      button.addEventListener("click", () => {
        if (this.tab === tab) return;
        this.tab = tab;
        this.error = null;
        this.render();
        void this.loadCurrent(false);
      });
    }

    const body = this.contentEl.createDiv({ cls: "vaultguard-recovery-body" });
    if (this.tab === "history") this.renderHistory(body);
    if (this.tab === "deleted") this.renderDeleted(body);
    if (this.tab === "conflicts") this.renderConflicts(body);
  }

  private renderStatus(container: HTMLElement): boolean {
    if (this.error) {
      const error = container.createDiv({ cls: "vaultguard-recovery-error" });
      error.createEl("strong", { text: "Could not load this section" });
      error.createEl("p", { text: this.error });
      const retry = error.createEl("button", { text: "Retry", cls: "mod-cta" });
      retry.addEventListener("click", () => void this.loadCurrent(false));
      return true;
    }
    if (this.loading) {
      container.createDiv({
        cls: "vaultguard-recovery-loading",
        text: "Loading recovery information…",
      });
      return true;
    }
    return false;
  }

  private renderHistory(container: HTMLElement): void {
    const controls = container.createDiv({ cls: "vaultguard-recovery-path-controls" });
    const label = controls.createEl("label", { text: "File path" });
    const input = label.createEl("input", {
      value: this.path,
      attr: {
        type: "text",
        placeholder: "Choose an active file or enter a vault path",
      },
    });
    input.addEventListener("input", () => { this.path = input.value.trim(); });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") void this.loadCurrent(false);
    });
    const load = controls.createEl("button", { text: "Show history", cls: "mod-cta" });
    load.addEventListener("click", () => void this.loadCurrent(false));
    if (!this.path) {
      container.createEl("p", {
        cls: "vaultguard-recovery-empty",
        text: "Open a file first, or enter its vault-relative path.",
      });
      return;
    }
    if (this.renderStatus(container)) return;
    if (this.history.partial) {
      container.createEl("p", {
        cls: "vaultguard-recovery-warning",
        text: "Only the versions you are allowed to read are shown.",
      });
    }
    if (this.history.items.length === 0) {
      container.createEl("p", {
        cls: "vaultguard-recovery-empty",
        text: "No versions were returned for this file.",
      });
      return;
    }
    const list = container.createDiv({ cls: "vaultguard-recovery-list" });
    for (const version of this.history.items) {
      const row = list.createDiv({ cls: "vaultguard-recovery-row" });
      const detail = row.createDiv({ cls: "vaultguard-recovery-row-detail" });
      detail.createEl("strong", {
        text: version.isLatest ? "Current version" : formatDate(version.lastModified),
      });
      detail.createEl("span", {
        text: `${formatBytes(version.size)}${version.isDeleteMarker ? " · delete marker" : ""}`,
      });
      if (!version.isLatest && !version.isDeleteMarker) {
        const restore = row.createEl("button", { text: "Restore" });
        restore.addEventListener("click", () => void this.restoreVersion(version));
      }
    }
    this.renderLoadMore(container, this.history.hasMore, () => this.loadCurrent(true));
  }

  private renderDeleted(container: HTMLElement): void {
    if (this.renderStatus(container)) return;
    if (this.deleted.partial) {
      container.createEl("p", {
        cls: "vaultguard-recovery-warning",
        text: "This is a permission-filtered page; additional authorized files may be on later pages.",
      });
    }
    if (this.deleted.items.length === 0) {
      container.createEl("p", {
        cls: "vaultguard-recovery-empty",
        text: "No restorable deleted files were returned.",
      });
      return;
    }
    const list = container.createDiv({ cls: "vaultguard-recovery-list" });
    for (const file of this.deleted.items) {
      const row = list.createDiv({ cls: "vaultguard-recovery-row" });
      const detail = row.createDiv({ cls: "vaultguard-recovery-row-detail" });
      detail.createEl("strong", { text: file.path });
      detail.createEl("span", { text: `Deleted ${formatDate(file.deletedAt)}` });
      const restore = row.createEl("button", { text: "Restore" });
      restore.addEventListener("click", () => void this.restoreDeleted(file));
    }
    this.renderLoadMore(container, this.deleted.hasMore, () => this.loadCurrent(true));
  }

  private renderConflicts(container: HTMLElement): void {
    const unresolved = this.cfg.getConflicts().filter((conflict) => !conflict.resolution);
    const conflictFiles = this.cfg.getConflictFiles();
    if (unresolved.length === 0 && conflictFiles.length === 0) {
      container.createEl("p", {
        cls: "vaultguard-recovery-empty",
        text: "No unresolved conflicts or conflict-copy files were found.",
      });
      return;
    }
    const list = container.createDiv({ cls: "vaultguard-recovery-list" });
    for (const conflict of unresolved) {
      const row = list.createDiv({ cls: "vaultguard-recovery-row" });
      const detail = row.createDiv({ cls: "vaultguard-recovery-row-detail" });
      detail.createEl("strong", { text: conflict.path });
      detail.createEl("span", {
        text: `Detected ${formatDate(conflict.detectedAt)} · no copy was discarded`,
      });
      const open = row.createEl("button", { text: "Open original" });
      open.addEventListener("click", () => void this.cfg.onOpenPath(conflict.path));
    }
    for (const path of conflictFiles) {
      const row = list.createDiv({ cls: "vaultguard-recovery-row" });
      const detail = row.createDiv({ cls: "vaultguard-recovery-row-detail" });
      detail.createEl("strong", { text: path });
      detail.createEl("span", { text: "Conflict copy kept in this vault" });
      const actions = row.createDiv({ cls: "vaultguard-recovery-row-actions" });
      const open = actions.createEl("button", { text: "Open copy" });
      open.addEventListener("click", () => void this.cfg.onOpenPath(path));
      const likelyOriginal = likelyOriginalForConflictCopy(path);
      if (likelyOriginal) {
        const openOriginal = actions.createEl("button", { text: "Open likely original" });
        openOriginal.addEventListener("click", () => void this.cfg.onOpenPath(likelyOriginal));
      }
    }
  }

  private renderLoadMore(
    container: HTMLElement,
    hasMore: boolean,
    load: () => Promise<void>,
  ): void {
    if (!hasMore) return;
    const button = container.createEl("button", {
      cls: "vaultguard-recovery-load-more",
      text: "Load more",
    });
    button.addEventListener("click", () => void load());
  }

  private async loadCurrent(append: boolean): Promise<void> {
    if (this.tab === "conflicts") {
      this.loading = false;
      this.error = null;
      this.render();
      return;
    }
    if (this.tab === "history" && !this.path) {
      this.loading = false;
      this.error = null;
      this.history = { items: [], cursor: null, hasMore: false };
      this.render();
      return;
    }
    const epoch = ++this.requestEpoch;
    this.loading = true;
    this.error = null;
    this.render();
    try {
      if (this.tab === "history") {
        const page = await this.cfg.apiClient.getFileHistoryPage(this.path, {
          limit: 50,
          ...(append && this.history.cursor ? { cursor: this.history.cursor } : {}),
        });
        if (this.closed || epoch !== this.requestEpoch) return;
        this.history = append
          ? { ...page, items: [...this.history.items, ...page.items] }
          : page;
      } else {
        const page = await this.cfg.apiClient.getDeletedFilesPage({
          limit: 50,
          ...(append && this.deleted.cursor ? { cursor: this.deleted.cursor } : {}),
        });
        if (this.closed || epoch !== this.requestEpoch) return;
        this.deleted = append
          ? { ...page, items: [...this.deleted.items, ...page.items] }
          : page;
      }
    } catch (error) {
      if (this.closed || epoch !== this.requestEpoch) return;
      this.error = error instanceof Error ? error.message : "Unknown recovery error";
    } finally {
      if (!this.closed && epoch === this.requestEpoch) {
        this.loading = false;
        this.render();
      }
    }
  }

  private async restoreVersion(version: FileVersionRecord): Promise<void> {
    const confirmed = await confirmRecovery(
      this.app,
      "Restore this file version?",
      `Restore ${this.path} from ${formatDate(version.lastModified)}?`,
    );
    if (!confirmed) return;
    try {
      await this.cfg.apiClient.restoreFileVersion(this.path, version.versionId);
      await this.cfg.onRestored?.();
      new Notice(`VaultGuard: Restored a previous version of "${this.path}".`);
      await this.loadCurrent(false);
    } catch (error) {
      new Notice(`VaultGuard: Restore failed — ${error instanceof Error ? error.message : error}`);
    }
  }

  private async restoreDeleted(file: DeletedFileRecord): Promise<void> {
    const confirmed = await confirmRecovery(
      this.app,
      "Restore this deleted file?",
      `Restore ${file.path} to the server vault?`,
    );
    if (!confirmed) return;
    try {
      await this.cfg.apiClient.restoreDeletedFile(file.path);
      await this.cfg.onRestored?.();
      new Notice(`VaultGuard: Restored "${file.path}".`);
      await this.loadCurrent(false);
    } catch (error) {
      new Notice(`VaultGuard: Restore failed — ${error instanceof Error ? error.message : error}`);
    }
  }
}
