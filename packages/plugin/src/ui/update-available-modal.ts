/**
 * UpdateAvailableModal — a richer in-plugin "new release" notification shown
 * when a newer plugin version exists. UpdateChecker owns the decision to open
 * it, in two cases:
 *   1. the user runs the "Check for plugin updates" command and a newer
 *      release is found (manual / force), and
 *   2. the FIRST time the 24h background check detects a given new version.
 * Later background sightings of that same version fall back to the quiet
 * `notifyNewVersion()` toast (dedupe via `updateCheckState.lastSeenVersion`).
 *
 * The modal itself makes ZERO network calls: the GitHub release html_url is
 * supplied as a runtime parameter and opened with `window.open()`. No `fetch`,
 * no `requestUrl`, and no markdown renderer — release notes render as PLAIN
 * text (CSS `white-space: pre-wrap` preserves line breaks).
 *
 * No URLs in the copy: the public-plugin export scrubber rewrites hosted
 * domains to placeholders (scripts/export-public-plugin-repo.mjs), so the
 * release URL must arrive at runtime rather than being hard-coded here — the
 * same rule ProUpsellModal follows.
 */

import { App, ButtonComponent, Modal } from "obsidian";

export interface UpdateAvailableModalData {
  /** The currently-installed plugin version (e.g. "1.1.0"). */
  current: string;
  /** The newer version available upstream (e.g. "1.2.0"). */
  latest: string;
  /** GitHub release html_url; opened in the browser via the action button. */
  releaseUrl: string;
  /** The release title/name, if the release provided one. May be empty. */
  releaseName: string;
  /** Raw release notes (GitHub release body). Rendered as plain text. May be empty. */
  notes: string;
  /**
   * Invoked by the primary "Update…" button to open Obsidian's native
   * Community-plugins updater (where each plugin's per-plugin Update button
   * lives). When absent, the primary button falls back to opening `releaseUrl`.
   * Optional so existing five-field construction sites stay valid.
   */
  onUpdate?: () => void;
}

export class UpdateAvailableModal extends Modal {
  private readonly data: UpdateAvailableModalData;

  constructor(app: App, data: UpdateAvailableModalData) {
    super(app);
    this.data = data;
  }

  onOpen(): void {
    // Optional width styling hook; all layout lives in styles.css.
    this.modalEl.addClass("vaultguard-update-modal");
    const { data } = this;
    const c = this.contentEl;
    c.empty();

    c.createEl("h2", { text: "VaultGuard update available" });

    // Build the version line in code — never hard-code version strings.
    c.createDiv({
      cls: "vaultguard-update-modal-versions",
      text: `You're on ${data.current} — ${data.latest} is available`,
    });

    if (typeof data.releaseName === "string" && data.releaseName.trim().length > 0) {
      c.createEl("h3", { text: data.releaseName });
    }

    // Release notes: guard for empty/missing, render as PLAIN text (no markdown).
    const notes = typeof data.notes === "string" ? data.notes : "";
    if (notes.trim().length > 0) {
      const notesEl = c.createEl("pre", { cls: "vaultguard-update-modal-notes" });
      notesEl.setText(notes);
    } else {
      c.createDiv({
        cls: "vaultguard-update-modal-notes-empty",
        text: "No release notes were provided.",
      });
    }

    const row = c.createDiv({ cls: "vaultguard-modal-actions" });
    // Primary CTA: route to Obsidian's own Community-plugins updater (its native
    // per-plugin Update button). The ellipsis signals it opens a screen, not an
    // instant self-update. Falls back to the release page if no callback wired.
    new ButtonComponent(row)
      .setButtonText("Update…")
      .setCta()
      .onClick(() => {
        if (data.onUpdate) {
          // onUpdate may now return a Promise (it awaits a bounded update-list
          // refresh before opening the Community plugins tab); void it and let
          // the refresh + navigation run on its own while we close the modal.
          void data.onUpdate();
        } else if (data.releaseUrl) {
          window.open(data.releaseUrl, "_blank");
        }
        this.close();
      });
    // Secondary: keep the old GitHub-release capability as "Release notes".
    new ButtonComponent(row)
      .setButtonText("Release notes")
      .onClick(() => {
        // Pure client-side navigation to the release page — no network call here.
        if (data.releaseUrl) window.open(data.releaseUrl, "_blank");
      });
    new ButtonComponent(row).setButtonText("Close").onClick(() => this.close());
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
