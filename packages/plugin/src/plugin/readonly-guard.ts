/**
 * VaultGuard - Read-Only Editor Guard
 *
 * Locks the markdown editor for files the user lacks write access to,
 * so view-only users can't accumulate edits that fail at save time with
 * "Failed to save file..." once the adapter interceptor rejects the write.
 *
 * The lock is applied at the CodeMirror 6 layer via a Compartment that
 * toggles `EditorView.editable` and `EditorState.readOnly`. Re-applied on
 * file-open / active-leaf-change and re-evaluated on permission refresh.
 */

import { App, MarkdownView, Plugin } from "obsidian";
import {
  Compartment,
  EditorState,
  Extension,
  StateEffect,
  Transaction,
} from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { PermissionLevel } from "../types";

interface ReadOnlyGuardContext {
  app: App;
  plugin: Plugin;
  /**
   * Resolves the effective permission level for a vault-relative path.
   * The guard locks the editor whenever this is below WRITE.
   */
  getPermissionLevel: (path: string) => Promise<PermissionLevel>;
  /**
   * Whether a user session is currently active. When false, the guard
   * downgrades the no-access overlay to a read-only banner so the user
   * can still view their local files — `getPermissionLevel` returns NONE
   * post-logout, but the file is on disk in plaintext anyway, so hiding
   * it behind an overlay just degrades UX without adding security.
   */
  isLoggedIn: () => boolean;
}

const COMPARTMENT_KEY = "__vaultguardReadOnlyCompartment";
const BANNER_CLS = "vaultguard-readonly-banner";
const NOACCESS_OVERLAY_CLS = "vaultguard-noaccess-overlay";

export class ReadOnlyGuard {
  private ctx: ReadOnlyGuardContext;
  private started = false;

  constructor(ctx: ReadOnlyGuardContext) {
    this.ctx = ctx;
  }

  start(): void {
    if (this.started) return;
    this.started = true;

    this.ctx.plugin.registerEvent(
      this.ctx.app.workspace.on("file-open", () => {
        // Defer one tick — `file-open` fires before Obsidian finishes wiring
        // the CM6 instance for the new leaf, and our compartment dispatch
        // would land on a half-set-up editor. The setTimeout pushes us
        // after the editor is ready.
        setTimeout(() => void this.applyToActiveView(), 0);
      })
    );
    this.ctx.plugin.registerEvent(
      this.ctx.app.workspace.on("active-leaf-change", () => {
        setTimeout(() => void this.applyToActiveView(), 0);
      })
    );
    // Mode switches (source ↔ live-preview ↔ reading) trigger layout-change.
    // Re-apply so toggling modes can't unlock the editor.
    this.ctx.plugin.registerEvent(
      this.ctx.app.workspace.on("layout-change", () => {
        setTimeout(() => void this.applyToActiveView(), 0);
      })
    );

    void this.applyToActiveView();
  }

  /**
   * Re-evaluate every open markdown view. Call after a permission refresh
   * so a viewer whose access just changed gets the right editor state
   * without having to close and reopen the file.
   */
  refreshAll(): void {
    this.ctx.app.workspace.iterateAllLeaves((leaf) => {
      const view = leaf.view;
      if (view instanceof MarkdownView) {
        void this.applyToView(view);
      }
    });
  }

  destroy(): void {
    this.ctx.app.workspace.iterateAllLeaves((leaf) => {
      const view = leaf.view;
      if (view instanceof MarkdownView) {
        this.setEditable(view, true);
        this.removeBanner(view);
        this.removeNoAccessOverlay(view);
      }
    });
    this.started = false;
  }

  private async applyToActiveView(): Promise<void> {
    const view = this.ctx.app.workspace.getActiveViewOfType(MarkdownView);
    if (view) await this.applyToView(view);
  }

  private async applyToView(view: MarkdownView): Promise<void> {
    if (!view.file) return;
    const path = view.file.path;
    const level = await this.ctx.getPermissionLevel(path);
    const writable = level >= PermissionLevel.WRITE;
    const readable = level >= PermissionLevel.READ;

    // The view may have been swapped out while the permission check was in
    // flight (user clicked away). Bail to avoid locking the wrong file.
    const stillCurrent =
      view.file?.path === path && view.containerEl.isConnected;
    if (!stillCurrent) return;

    this.setEditable(view, writable);

    if (!readable) {
      // Logged-out distinction: when there's no session the permission
      // resolver fails closed to NONE, but the file is sitting in the
      // vault folder in plaintext. Surfacing the no-access overlay here
      // would be theatrical — show the read-only banner instead so the
      // user can still view their files until they log back in.
      if (!this.ctx.isLoggedIn()) {
        this.removeNoAccessOverlay(view);
        this.showBanner(view);
        return;
      }

      // No access at all: cover the editor with an opaque overlay so the
      // file's content is never visible. Editor stays locked too. The
      // banner is redundant under the overlay; remove it.
      this.removeBanner(view);
      this.showNoAccessOverlay(view);
      return;
    }

    this.removeNoAccessOverlay(view);
    if (writable) this.removeBanner(view);
    else this.showBanner(view);
  }

  private setEditable(view: MarkdownView, editable: boolean): void {
    const cm = this.getCodeMirror(view);
    if (!cm) return;

    const extension: Extension = editable
      ? []
      : this.buildLockExtension();

    const cmAny = cm as unknown as Record<string, unknown>;
    let compartment = cmAny[COMPARTMENT_KEY] as Compartment | undefined;

    if (!compartment) {
      // First time we touch this editor: register the compartment with the
      // desired extension in a single dispatch. Combining `appendConfig` and
      // `reconfigure` into two transactions has been flaky in practice —
      // Obsidian re-applies its own editor config around our dispatches and
      // the reconfigure effect lands on a state where the compartment isn't
      // resolved yet.
      compartment = new Compartment();
      cmAny[COMPARTMENT_KEY] = compartment;
      cm.dispatch({
        effects: StateEffect.appendConfig.of(compartment.of(extension)),
      });
    } else {
      cm.dispatch({ effects: compartment.reconfigure(extension) });
    }

    // Belt-and-suspenders: directly toggle contentEditable on the editor's
    // contentDOM. The `editable` facet eventually does this, but doing it
    // synchronously here guarantees the lock is visible immediately even if
    // Obsidian re-renders the editor before our dispatch settles.
    const contentDom = (cm as unknown as { contentDOM?: HTMLElement }).contentDOM;
    if (contentDom) {
      contentDom.contentEditable = editable ? "true" : "false";
    }
  }

  /**
   * Build the CM6 extension that locks the editor:
   *   - `EditorView.editable.of(false)` — disables contentEditable.
   *   - `EditorState.readOnly.of(true)` — refuses user-input transactions.
   *   - `transactionFilter` — rejects user-event transactions that would
   *     change the doc. The readOnly facet already does this, but Obsidian
   *     ships its own input commands that occasionally bypass it; the
   *     filter is the real backstop. Programmatic changes (sync pulls,
   *     remote writes) carry no userEvent annotation and pass through.
   */
  private buildLockExtension(): Extension {
    return [
      EditorView.editable.of(false),
      EditorState.readOnly.of(true),
      EditorState.transactionFilter.of((tr: Transaction) => {
        if (!tr.docChanged) return tr;
        const userEvent = tr.annotation(Transaction.userEvent);
        if (userEvent) return [];
        return tr;
      }),
    ];
  }

  private getCodeMirror(view: MarkdownView): EditorView | null {
    const cm = (view.editor as unknown as { cm?: EditorView }).cm;
    return cm ?? null;
  }

  private showBanner(view: MarkdownView): void {
    const viewContent = view.containerEl.querySelector(".view-content");
    if (!viewContent) return;
    if (viewContent.querySelector(`.${BANNER_CLS}`)) return;

    const banner = document.createElement("div");
    banner.className = BANNER_CLS;
    banner.textContent =
      "Read-only — your access to this file doesn't include editing.";

    // The file permission header also prepends to viewContent, and event
    // ordering between that header and this guard is non-deterministic.
    // Anchor below the header when present so the banner never lands above it.
    const header = viewContent.querySelector(".vaultguard-file-header");
    if (header) {
      header.insertAdjacentElement("afterend", banner);
    } else {
      viewContent.insertBefore(banner, viewContent.firstChild);
    }
  }

  private removeBanner(view: MarkdownView): void {
    const banner = view.containerEl.querySelector(`.${BANNER_CLS}`);
    banner?.remove();
  }

  /**
   * Cover the editor with an opaque overlay when the user has no access to
   * the open file. Hides the file content from view (the read-only banner
   * still leaves contents visible, which is wrong for NONE-level access).
   * The overlay is anchored to `.view-content` so it covers the editor and
   * the file-permission header alike, leaving the tab header reachable so
   * the user can close the leaf.
   */
  private showNoAccessOverlay(view: MarkdownView): void {
    const viewContent = view.containerEl.querySelector(".view-content");
    if (!(viewContent instanceof HTMLElement)) return;
    if (viewContent.querySelector(`.${NOACCESS_OVERLAY_CLS}`)) return;

    // The overlay is positioned absolute; ensure the parent establishes a
    // containing block. Obsidian's default `.view-content` is `position:
    // relative` already, but set it defensively for any custom themes.
    const computed = getComputedStyle(viewContent);
    if (computed.position === "static") {
      viewContent.style.position = "relative";
    }

    const overlay = document.createElement("div");
    overlay.className = NOACCESS_OVERLAY_CLS;

    const card = document.createElement("div");
    card.className = "vaultguard-noaccess-card";

    const title = document.createElement("div");
    title.className = "vaultguard-noaccess-title";
    title.textContent = "No access to this file";
    card.appendChild(title);

    const body = document.createElement("div");
    body.className = "vaultguard-noaccess-body";
    body.textContent =
      "You don't have permission to view this file. Contact a vault admin if you think this is a mistake.";
    card.appendChild(body);

    const closeBtn = document.createElement("button");
    closeBtn.className = "vaultguard-noaccess-close";
    closeBtn.type = "button";
    closeBtn.textContent = "Close tab";
    closeBtn.addEventListener("click", () => {
      view.leaf.detach();
    });
    card.appendChild(closeBtn);

    overlay.appendChild(card);
    viewContent.appendChild(overlay);
  }

  private removeNoAccessOverlay(view: MarkdownView): void {
    const overlay = view.containerEl.querySelector(`.${NOACCESS_OVERLAY_CLS}`);
    overlay?.remove();
  }
}
