/**
 * At-rest `needs-recovery` guided recovery modal (Phase 13-03, Feature #2 UI).
 *
 * ONE guided flow reachable from TWO doors (D4):
 *   - door #1: the #1 indicator/banner/status-bar CTA (`startAtRestRecoveryFlow`)
 *   - door #2: the Settings → Advanced "Reset local encryption & re-download" button
 *
 * The modal is the honest, confirmed front-end for the 13-02 reset engine
 * (`plugin.resetLocalAtRestAndResync()`). It explains that the dead local
 * ciphertext is ALREADY unrecoverable and the server holds every file, runs the
 * guarded reset (whose own protected long-operation renders progress — this
 * modal does NOT draw a second progress bar), and on success surfaces the NEW
 * recovery code via `plugin.surfaceNewRecoveryCodeAfterReset()` (SC4).
 *
 * The non-destructive D5 alternate — "Enter recovery code…" — is always offered
 * (it works offline: the correct per-device code re-wraps the exact LAK), and is
 * emphasized when the reset can't run (offline / logged out).
 *
 * The engine's guard is authoritative; the enablement here is only UX
 * (`computeAtRestResetButtonState`). The confirm copy must stay honest — see the
 * body strings below and keep them consistent with `renderAtRestStatusBadge`.
 */

import { App, ButtonComponent, Modal, setIcon } from "obsidian";

import type { AtRestStatus } from "../crypto/at-rest-cipher";
import type { UserSession } from "../types";

/**
 * The minimal plugin surface the modal drives. `VaultGuardPlugin` satisfies this
 * structurally; using an interface (not the concrete class) keeps the modal free
 * of a circular import back into `main.ts` and makes it trivially testable.
 */
export interface AtRestRecoveryModalHost {
  getAtRestStatus(): AtRestStatus;
  getSession(): UserSession | null;
  isConnectedOnline(): boolean;
  /** The guarded 13-02 escape hatch. Throws (guard) when it can't safely run. */
  resetLocalAtRestAndResync(): Promise<void>;
  /** LO-02 — true while a reset is already running (a door opened elsewhere). */
  isAtRestResetInFlight(): boolean;
  /** SC4 — export + show the fresh code with a save prompt (no-op if not unlocked). */
  surfaceNewRecoveryCodeAfterReset(): Promise<void>;
  /** The non-destructive D5 alternate — opens the existing restore-from-code modal. */
  startAtRestRecoveryFromRecoveryCode(): void;
}

export interface AtRestResetButtonState {
  /** Whether the reset action is interactive. */
  enabled: boolean;
  /** Whether the reset control is meaningful at all (only in needs-recovery). */
  visible: boolean;
  /** Whether the recovery-code alternate must be offered alongside. */
  offerRecoveryCodeAlternate: boolean;
  /** Description copy — consistent with the needs-recovery badge wording. */
  description: string;
  /** Reason the reset is blocked (empty when enabled). */
  blockedReason: string;
  /** Primary CTA styling: the reset is the recommended action only when enabled. */
  cta: boolean;
}

/** The honest copy shown when the reset can't run (offline / logged out) — D5. */
export const AT_REST_RESET_BLOCKED_COPY =
  "Reset needs you signed in and online — we re-download your files from the server. You can still enter your recovery code below to unlock this device's existing files (that works offline).";

/** LO-02 — shown when a reset is already running (this door is a no-op then). */
export const AT_REST_RESET_IN_FLIGHT_COPY =
  "A local at-rest reset is already running. Please wait for it to finish.";

/**
 * The D4/D5 enablement matrix — the SINGLE source both the Settings button and
 * the modal read, so the "when does reset light up" rule can never drift.
 *
 *   - enabled  ⇔ needs-recovery AND a session AND online (deliberately the
 *                inverse of the other at-rest buttons, which are all disabled in
 *                needs-recovery). This mirrors the engine's authoritative guard,
 *                but the guard — not this — is the security gate.
 *   - visible  ⇔ needs-recovery (the control is meaningless otherwise).
 *   - the recovery-code alternate is offered whenever the control is visible.
 */
export function computeAtRestResetButtonState(input: {
  needsRecovery: boolean;
  hasSession: boolean;
  online: boolean;
}): AtRestResetButtonState {
  const { needsRecovery, hasSession, online } = input;

  if (!needsRecovery) {
    return {
      enabled: false,
      visible: false,
      offerRecoveryCodeAlternate: false,
      description:
        "Only available when this device can't unlock its local encryption key.",
      blockedReason: "",
      cta: false,
    };
  }

  const enabled = hasSession && online;
  return {
    enabled,
    visible: true,
    offerRecoveryCodeAlternate: true,
    description: enabled
      ? "This device can't unlock its local encryption key. Wipe the encrypted copies on THIS device and re-download every file from the server under a fresh key. Nothing recoverable is lost — the files that won't decrypt here are already unreadable, and the server keeps the authoritative copy. Nothing is deleted on the server."
      : AT_REST_RESET_BLOCKED_COPY,
    blockedReason: enabled ? "" : AT_REST_RESET_BLOCKED_COPY,
    cta: enabled,
  };
}

export class AtRestRecoveryModal extends Modal {
  private host: AtRestRecoveryModalHost;

  private resetBtn?: ButtonComponent;
  private altBtn?: ButtonComponent;
  private statusEl?: HTMLElement;
  private busy = false;

  /**
   * Last status text rendered. Exposed for tests — the obsidian mock's
   * `contentEl` is a bare object, so `statusEl` is absent under vitest and the
   * DOM writes are skipped; this field lets a test assert what WOULD be shown.
   */
  lastStatusMessage = "";
  /** True once the recovery-code alternate has been offered/emphasized (D5). */
  recoveryCodeAlternateOffered = false;

  constructor(app: App, host: AtRestRecoveryModalHost) {
    super(app);
    this.host = host;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-at-rest-recovery-reset-modal");
    const { contentEl } = this;
    contentEl.empty();

    const state = computeAtRestResetButtonState({
      needsRecovery: this.host.getAtRestStatus().kind === "needs-recovery",
      hasSession: Boolean(this.host.getSession()),
      online: this.host.isConnectedOnline(),
    });

    // Danger-tone header. NOTE: normal DOM heading (not `setHeading`, which is
    // reserved for settings tabs per the Obsidian review rules).
    const header = contentEl.createDiv({
      cls: "vaultguard-at-rest-recovery-reset-header",
    });
    const icon = header.createDiv({
      cls: "vaultguard-at-rest-recovery-reset-icon",
    });
    setIcon(icon, "shield-alert");
    header.createEl("h2", {
      text: "Reset local encryption & re-download",
      cls: "vaultguard-at-rest-recovery-reset-title",
    });

    // Honest body copy (T-13-12 — do not overstate "nothing lost").
    const body = contentEl.createDiv({
      cls: "vaultguard-modal-description vaultguard-at-rest-recovery-reset-body",
    });
    body.createEl("p", {
      text: "This device can't unlock its local encryption key, so the files here can't be decrypted and sync is paused.",
    });
    body.createEl("p", {
      text: "Resetting discards the encrypted copies on THIS device and re-downloads every file from the server under a fresh key. The files that won't decrypt here are already unreadable, so nothing recoverable is lost — and the server keeps the authoritative copy of everything. Nothing is deleted on the server.",
    });

    this.statusEl = contentEl.createDiv({
      cls: "vaultguard-modal-status vaultguard-at-rest-recovery-reset-status",
    });
    if (!state.enabled) {
      // D5: honest "signed in and online" reason; the alternate below is the way.
      this.setStatus(state.blockedReason, true);
      this.recoveryCodeAlternateOffered = true;
    }

    const actions = contentEl.createDiv({ cls: "vaultguard-modal-actions" });

    // LO-02: if a reset is already running (opened from another door), this one
    // is a no-op — disable the destructive action and say so, honestly.
    const inFlight = this.host.isAtRestResetInFlight();

    // Primary — the destructive reset. Warning-toned; disabled per the matrix
    // (and while another reset is in flight).
    const resetBtn = new ButtonComponent(actions);
    resetBtn.setButtonText("Reset & re-download").setWarning();
    resetBtn.setDisabled(!state.enabled || inFlight);
    resetBtn.onClick(() => void this.runReset());
    this.resetBtn = resetBtn;

    if (inFlight) this.setStatus(AT_REST_RESET_IN_FLIGHT_COPY, true);

    // Secondary — the non-destructive D5 alternate. Always available (offline
    // too); becomes the recommended CTA when the reset can't run.
    const altBtn = new ButtonComponent(actions);
    altBtn.setButtonText("Enter recovery code…");
    if (!state.enabled) altBtn.setCta();
    altBtn.onClick(() => this.openRecoveryCodeAlternate());
    this.altBtn = altBtn;

    // Cancel — a plain dismiss.
    new ButtonComponent(actions)
      .setButtonText("Not now")
      .onClick(() => this.close());
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-at-rest-recovery-reset-modal");
    this.contentEl.empty();
  }

  /**
   * The primary action (door-agnostic): run the guarded engine reset, then on
   * success surface the NEW recovery code (SC4). On the guard/engine throwing,
   * stay open, show the honest reason, and keep the recovery-code alternate
   * offered (D5). Exposed (not private) so it is directly testable without a DOM.
   */
  async runReset(): Promise<void> {
    if (this.busy) return;
    // LO-02: refuse if a reset is already running elsewhere. The engine's
    // reentrancy guard would also refuse, but its AtRestResetGuardError maps to
    // the offline/logged-out copy — this gives the correct "already running"
    // message without invoking the engine.
    if (this.host.isAtRestResetInFlight()) {
      this.setStatus(AT_REST_RESET_IN_FLIGHT_COPY, true);
      return;
    }
    this.busy = true;
    this.resetBtn?.setDisabled(true).setButtonText("Resetting…");
    this.setStatus(
      "Resetting local encryption and re-downloading from the server. This can take a while for large vaults — a progress window will appear.",
    );
    try {
      // The engine drives its own protected long-operation UI for progress.
      await this.host.resetLocalAtRestAndResync();
      // SC4 — surface the fresh recovery code with a save prompt.
      await this.host.surfaceNewRecoveryCodeAfterReset();
      this.close();
    } catch (err) {
      this.busy = false;
      this.resetBtn?.setDisabled(false).setButtonText("Reset & re-download");
      // Guard (offline / logged out / not-needs-recovery) or a re-pull failure.
      // Nothing recoverable was touched — offer the alternate and let them retry.
      this.setStatus(this.describeResetFailure(err), true);
      this.recoveryCodeAlternateOffered = true;
      this.altBtn?.setCta();
    }
  }

  /**
   * The D5 non-destructive alternate. Close this modal and hand off to the
   * existing restore-from-recovery-code flow (which re-asserts the surfaces on
   * success). Exposed for tests + the secondary button.
   */
  openRecoveryCodeAlternate(): void {
    this.close();
    this.host.startAtRestRecoveryFromRecoveryCode();
  }

  private describeResetFailure(err: unknown): string {
    // The 13-02 guard tags its refusal so we can show the honest D5 copy.
    if (err instanceof Error && err.name === "AtRestResetGuardError") {
      return AT_REST_RESET_BLOCKED_COPY;
    }
    const detail = err instanceof Error ? err.message : String(err);
    return `Couldn't finish the reset: ${detail} Nothing was deleted on the server — you can try again, or enter your recovery code below.`;
  }

  private setStatus(text: string, isError = false): void {
    this.lastStatusMessage = text;
    if (!this.statusEl) return;
    this.statusEl.setText(text);
    this.statusEl.toggleClass("vaultguard-at-rest-recovery-reset-error", isError);
  }
}
