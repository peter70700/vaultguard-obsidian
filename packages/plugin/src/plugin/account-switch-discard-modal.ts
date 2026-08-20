/**
 * AccountSwitchDiscardModal — the DIRTY-only consent gate for every reset
 * that replaces this folder's local cache: the account takeover
 * (quick-260820-ki7) and, since quick-260820-mv4, the vault-to-vault switch.
 * `kind` selects the copy; the stakes, the gate and the fail-closed dismissal
 * semantics are identical. `bindingAlreadyApplied` (quick-260820-prn) selects
 * a second vault-lane variant for the blocked adopt path, where the binding
 * has already flipped and there is no switch left to cancel.
 *
 * Under "auto when clean, ask when dirty", a switch with nothing unsynced
 * runs without ceremony — this dialog exists solely when the reset would
 * destroy something real, and it must name its concrete victims. Two
 * separately labeled classes, honestly split:
 *
 *  - "unsynced change(s)": queued/tracked local work — offline-queued edits,
 *    pending large-file uploads, unconfirmed local deletes, conflicts, edits
 *    made while the folder was paused. Discarding permanently removes them
 *    from this device.
 *  - "could not be confirmed as synced": local files absent from the server
 *    vault's permission-filtered listing. The listing hides files this
 *    account is denied, so a miss is NOT provably an unsynced change — the
 *    copy must never call it one.
 *
 * The destructive reset never proceeds on an implied answer: every dismissal
 * path (Escape, title-bar X, no decision) resolves "keep", which lands the
 * loud paused local-only state at the caller.
 */

import { App, ButtonComponent, Modal } from "obsidian";

/** Longest path list either class renders before collapsing to "+N more". */
const MAX_LISTED_PATHS = 8;

export type AccountSwitchDiscardDecision = "keep" | "discard";

export interface AccountSwitchDiscardContext {
  /**
   * Which boundary is being crossed (quick-260820-mv4).
   *
   * - `"account"` — a different ACCOUNT takes over this folder's binding
   *   (the original ki7 takeover). Default, and its copy is unchanged.
   * - `"vault"` — the SAME account re-points this folder at a different
   *   server vault. Identical stakes (the local cache is wiped and re-pulled),
   *   but the copy must name the vaults rather than the accounts, or it
   *   describes a takeover that is not happening.
   */
  kind?: "account" | "vault";
  /** Email of the signed-in account taking over, when the session carries one. */
  currentAccountEmail?: string;
  /** Email of the account that protected this folder, if the capsule has it. */
  previousAccountEmail?: string;
  /** Display name of the bound server vault, for orientation. */
  vaultName?: string;
  /** `kind: "vault"` — display name of the vault this folder is leaving. */
  previousVaultName?: string;
  /**
   * `kind: "vault"` — the binding has ALREADY flipped (quick-260820-prn).
   *
   * mv4's vault-switch gate runs BEFORE any mutation, so declining there
   * cancels the switch outright and the copy can honestly offer "Cancel".
   * The blocked adopt lane is the opposite: `applyVaultBinding` delegates to
   * `adoptBindingForCurrentAccount` only after the settings were rewritten, so
   * the folder is already connected to the new vault while still holding the
   * previous vault's files. There is no switch left to cancel — the choice is
   * "replace the local files" vs "keep them and stay paused", and the copy has
   * to say so or it is describing a state that does not exist.
   */
  bindingAlreadyApplied?: boolean;
  /**
   * `bindingAlreadyApplied` only — the server-listing cross-check could not
   * read the vault being LEFT (quick-260820-prn). That is the normal case on
   * this lane: it is reachable only when the server denied this account on
   * that vault, so `listVaultFilesPage` 403s and nothing local can be proven
   * already-saved. Disclosed rather than hidden behind the generic
   * "could not be fully listed" line.
   */
  previousVaultUnverifiable?: boolean;
  /** Tracked unsynced local changes (queued edits, deletes, conflicts, ...). */
  items: string[];
  /** Local files the server-listing cross-check could not confirm as synced. */
  unconfirmed: string[];
  /** True when some unsynced work could not be fully enumerated. */
  indeterminate: boolean;
}

export class AccountSwitchDiscardModal extends Modal {
  private context: AccountSwitchDiscardContext;
  private resolveDecision: (decision: AccountSwitchDiscardDecision) => void;
  private decided = false;

  constructor(
    app: App,
    context: AccountSwitchDiscardContext,
    resolveDecision: (decision: AccountSwitchDiscardDecision) => void
  ) {
    super(app);
    this.context = context;
    this.resolveDecision = resolveDecision;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-account-switch-discard-modal");

    const current = this.context.currentAccountEmail?.trim();
    const previous = this.context.previousAccountEmail?.trim();
    const vault = this.context.vaultName?.trim();
    const previousVault = this.context.previousVaultName?.trim();
    const isVaultSwitch = this.context.kind === "vault";
    // quick-260820-prn: only meaningful on the vault lane, and it changes
    // five copy sites — never the account lane's, which is byte-identical.
    const alreadyApplied = isVaultSwitch && this.context.bindingAlreadyApplied === true;
    const nextLabel = vault ? `"${vault}"` : "the selected vault";
    const prevLabel = previousVault
      ? `"${previousVault}"`
      : "the vault it was connected to before";
    const items = this.context.items;
    const unconfirmed = this.context.unconfirmed;

    contentEl.createEl("h2", {
      text: alreadyApplied
        ? "Replace this folder's local files?"
        : isVaultSwitch
          ? "Discard local changes and switch vaults?"
          : "Discard local changes and switch accounts?",
      cls: "vaultguard-modal-title",
    });

    contentEl.createEl("p", {
      text: alreadyApplied
        ? `This folder is now connected to ${nextLabel}, but it still holds the local contents of ` +
          `${prevLabel}. Replacing them permanently discards the data listed below from this device; ` +
          `everything else is re-downloaded from ${nextLabel}. ${prevLabel} keeps its own copy on ` +
          "the server — nothing is deleted there."
        : isVaultSwitch
          ? `Connecting this folder to ${nextLabel} replaces its local ` +
            `contents${previousVault ? ` — it currently holds "${previousVault}"` : ""}. ` +
            "The data listed below is permanently discarded from this device; " +
            "everything else is re-downloaded from the vault you are connecting to."
          : `Switching this folder to ${current || "the signed-in account"} resets its local protection` +
            `${previous ? ` — it was protected by ${previous}` : ""}. ` +
            "The data listed below is permanently discarded from this device; " +
            `everything else is re-downloaded with this account's access${vault ? ` from "${vault}"` : ""}.`,
      cls: "vaultguard-modal-description",
    });

    if (items.length > 0) {
      contentEl.createEl("p", {
        text: `${items.length} unsynced change${items.length === 1 ? "" : "s"} on this device would be permanently discarded:`,
        cls: "setting-item-description mod-warning",
      });
      this.renderPathList(items);
    }

    if (unconfirmed.length > 0) {
      contentEl.createEl("p", {
        text:
          `${unconfirmed.length} file${unconfirmed.length === 1 ? "" : "s"} could not be confirmed as synced ` +
          `${isVaultSwitch ? "with the vault you are leaving" : "with this account"}:`,
        cls: "setting-item-description mod-warning",
      });
      this.renderPathList(unconfirmed);
      // Honesty split (quick-260820-ki7): the server listing is
      // permission-filtered, so absence is NOT proof the file never synced —
      // it may be synced but denied to this account. Never present these as
      // unsynced changes.
      contentEl.createEl("p", {
        text:
          "These may already be synced but hidden from this account's permissions — VaultGuard cannot tell from here. " +
          (isVaultSwitch
            ? "Discarding removes the local copies; the vault you are connecting to is downloaded in their place."
            : "Discarding removes the local copies; anything this account may read is re-downloaded."),
        cls: "setting-item-description",
      });
    }

    if (this.context.indeterminate || (items.length === 0 && unconfirmed.length === 0)) {
      contentEl.createEl("p", {
        text:
          alreadyApplied && this.context.previousVaultUnverifiable === true
            ? `This account can no longer read ${prevLabel}, so VaultGuard cannot confirm which of ` +
              "these files are already saved there."
            : "Some unsynced changes on this device could not be fully listed.",
        cls: "setting-item-description mod-warning",
      });
    }

    contentEl.createEl("p", {
      text: alreadyApplied
        ? "Keeping them leaves everything on this device untouched. This folder stays connected to " +
          `${nextLabel} and paused — nothing uploads or downloads until the files from ${prevLabel} ` +
          "are dealt with."
        : isVaultSwitch
          ? "Cancelling leaves everything on this device untouched — this folder stays connected to " +
            `${previousVault ? `"${previousVault}"` : "the vault it is already using"} and keeps syncing.`
          : "Choosing to keep working locally leaves everything on this device untouched — " +
            "notes and edits stay here and nothing syncs until you decide.",
      cls: "setting-item-description",
    });

    const buttonRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });

    new ButtonComponent(buttonRow)
      // A declined vault switch simply does not happen — the folder stays on
      // the vault it is already connected to, which is still perfectly usable.
      // A declined account takeover has no working binding to fall back on, so
      // it lands the paused local-only state instead. And when the binding has
      // ALREADY flipped (quick-260820-prn) there is no switch to cancel: the
      // decline lands the same paused local-only state as a takeover.
      .setButtonText(isVaultSwitch && !alreadyApplied ? "Cancel" : "Keep working locally")
      .onClick(() => this.decide("keep"));

    new ButtonComponent(buttonRow)
      // "switch" would name an action that already happened; what this button
      // actually does on that lane is replace the local cache.
      .setButtonText(alreadyApplied ? "Discard and replace" : "Discard and switch")
      .setWarning()
      .onClick(() => this.decide("discard"));
  }

  private renderPathList(paths: string[]): void {
    const list = this.contentEl.createEl("ul", {
      cls: "vaultguard-account-switch-discard-paths",
    });
    for (const path of paths.slice(0, MAX_LISTED_PATHS)) {
      list.createEl("li", { text: path });
    }
    if (paths.length > MAX_LISTED_PATHS) {
      list.createEl("li", { text: `+${paths.length - MAX_LISTED_PATHS} more` });
    }
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-account-switch-discard-modal");
    this.contentEl.empty();
    // Dismissing is a refusal: the destructive reset never proceeds on an
    // implied answer, so Escape / the title-bar X settle the caller as
    // "keep" (working locally).
    if (!this.decided) {
      this.decided = true;
      this.resolveDecision("keep");
    }
  }

  /** Settle the caller before UI teardown, whose host hooks may throw. */
  private decide(decision: AccountSwitchDiscardDecision): void {
    if (this.decided) return;
    this.decided = true;
    this.resolveDecision(decision);
    this.close();
  }
}
