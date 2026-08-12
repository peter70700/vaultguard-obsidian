/**
 * ShareManagementModal — lists active share links for the bound vault and
 * lets the user revoke them.
 *
 * Share links are opaque pointers into the vault — they don't grant access
 * on their own (the resolve endpoint still requires team membership), but
 * a leaked link is annoying to chase down without a UI. This modal is the
 * canonical "see and shut down" surface.
 */

import { App, ButtonComponent, Modal, Notice } from "obsidian";
import type {
  ShareListPage,
  ShareRecord,
  VaultGuardApiClient,
} from "../api/client";
import { OperationOwner } from "../ui/operation-owner";

export class ShareManagementModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private shares: ShareRecord[] = [];
  private nextCursor: string | null = null;
  private readonly seenCursors = new Set<string>();
  private readonly lifecycleOwner = new OperationOwner();

  constructor(app: App, apiClient: VaultGuardApiClient) {
    super(app);
    this.apiClient = apiClient;
  }

  async onOpen(): Promise<void> {
    this.lifecycleOwner.activate();
    this.shares = [];
    this.nextCursor = null;
    this.seenCursors.clear();
    const operation = this.lifecycleOwner.begin();
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-share-modal");

    contentEl.createEl("h2", {
      text: "VaultGuard share links",
      cls: "vaultguard-modal-title",
    });
    contentEl.createEl("p", {
      text:
        "Share links route a teammate to a specific file in this vault. " +
        "They only work for vault members — non-members can't resolve them.",
      cls: "vaultguard-modal-description",
    });

    const listEl = contentEl.createDiv({ cls: "vaultguard-share-list" });
    listEl.createEl("p", { text: "Loading…", cls: "setting-item-description" });

    try {
      const page = await this.requestSharePage();
      if (!operation.isCurrent()) return;
      this.shares = page.shares;
      this.nextCursor = page.nextCursor;
    } catch (err) {
      if (!operation.isCurrent()) return;
      listEl.empty();
      const msg = err instanceof Error ? err.message : String(err);
      listEl.createEl("p", {
        text: `Failed to load share links: ${msg}`,
        cls: "setting-item-description",
      });
      return;
    }

    listEl.empty();
    this.renderShares(listEl);
  }

  private renderShares(parent: HTMLElement): void {
    parent.empty();
    if (this.shares.length === 0 && !this.nextCursor) {
      parent.createEl("p", {
        text: "No active share links. Right-click any file → \"VaultGuard: Copy share link\" to create one.",
        cls: "setting-item-description",
      });
      return;
    }

    if (this.shares.length === 0) {
      parent.createEl("p", {
        text: "No links on this page are visible to you. More results are available.",
        cls: "setting-item-description",
      });
    }

    for (const share of this.shares) {
      const row = parent.createDiv({ cls: "vaultguard-share-row" });

      const info = row.createDiv({ cls: "vaultguard-share-info" });
      info.createEl("div", { text: share.relPath, cls: "vaultguard-share-path" });

      const meta = info.createEl("div", { cls: "vaultguard-share-meta setting-item-description" });
      meta.appendText(`Created ${formatRelativeDate(share.createdAt)}`);
      if (share.expiresAt) {
        meta.appendText(` · expires ${formatRelativeDate(share.expiresAt)}`);
      }
      meta.appendText(` · `);
      const linkEl = meta.createEl("a", { text: share.url, href: share.url });
      linkEl.setAttr("target", "_blank");
      linkEl.setAttr("rel", "noreferrer noopener");

      const actions = row.createDiv({ cls: "vaultguard-share-actions" });

      new ButtonComponent(actions)
        .setButtonText("Copy")
        .onClick(async () => {
          try {
            await navigator.clipboard.writeText(share.url);
            if (this.lifecycleOwner.isClosed) return;
            new Notice("Link copied to clipboard.");
          } catch {
            if (this.lifecycleOwner.isClosed) return;
            new Notice(share.url, 12000);
          }
        });

      new ButtonComponent(actions)
        .setButtonText("Revoke")
        .setWarning()
        .onClick(async () => {
          try {
            await this.apiClient.revokeShare(share.shareId);
            if (this.lifecycleOwner.isClosed) return;
            this.shares = this.shares.filter((s) => s.shareId !== share.shareId);
            const parentEl = row.parentElement;
            if (parentEl) this.renderShares(parentEl);
            new Notice("Share link revoked.");
          } catch (err) {
            if (this.lifecycleOwner.isClosed) return;
            const msg = err instanceof Error ? err.message : String(err);
            new Notice(`Failed to revoke: ${msg}`, 6000);
          }
        });
    }

    if (this.nextCursor) {
      new ButtonComponent(parent)
        .setButtonText("Load more share links")
        .onClick(async () => this.loadMore(parent));
    }
  }

  private async requestSharePage(cursor?: string): Promise<ShareListPage> {
    // Compatibility with older client fakes/integrations during rolling
    // upgrades: they still provide the original first-page array method.
    const paginatedClient = this.apiClient as VaultGuardApiClient & {
      listSharesPage?: VaultGuardApiClient["listSharesPage"];
    };
    if (typeof paginatedClient.listSharesPage === "function") {
      return paginatedClient.listSharesPage({ limit: 50, ...(cursor ? { cursor } : {}) });
    }
    const shares = await this.apiClient.listShares();
    return { shares, count: shares.length, nextCursor: null, hasMore: false };
  }

  private async loadMore(parent: HTMLElement): Promise<void> {
    const cursor = this.nextCursor;
    if (!cursor || this.seenCursors.has(cursor)) {
      this.nextCursor = null;
      this.renderShares(parent);
      return;
    }
    this.seenCursors.add(cursor);
    const operation = this.lifecycleOwner.begin();
    try {
      const page = await this.requestSharePage(cursor);
      if (!operation.isCurrent()) return;
      const known = new Set(this.shares.map((share) => share.shareId));
      this.shares.push(...page.shares.filter((share) => !known.has(share.shareId)));
      this.nextCursor =
        page.nextCursor && !this.seenCursors.has(page.nextCursor) ? page.nextCursor : null;
      this.renderShares(parent);
    } catch (err) {
      if (!operation.isCurrent()) return;
      this.seenCursors.delete(cursor);
      const msg = err instanceof Error ? err.message : String(err);
      new Notice(`Failed to load more share links: ${msg}`, 6000);
    }
  }

  onClose(): void {
    this.lifecycleOwner.close();
    this.seenCursors.clear();
    this.contentEl.empty();
  }
}

/** Compact relative-date formatter for share row metadata. */
function formatRelativeDate(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const deltaSec = Math.round((then - Date.now()) / 1000);
  const past = deltaSec < 0;
  const abs = Math.abs(deltaSec);

  const units: [number, string][] = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [30, "day"],
    [12, "month"],
    [Number.POSITIVE_INFINITY, "year"],
  ];

  let value = abs;
  let label = "second";
  for (const [div, unitLabel] of units) {
    if (value < div) {
      label = unitLabel;
      break;
    }
    value = Math.floor(value / div);
    label = unitLabel;
  }

  const plural = value === 1 ? label : `${label}s`;
  return past ? `${value} ${plural} ago` : `in ${value} ${plural}`;
}
