/**
 * VaultGuard - PIN lifecycle modals (Phase 12, vault idle-lock)
 *
 * SetPinModal / ChangePinModal / DisablePinModal — the user-owned PIN UI (D3).
 * Each collects a secret (alphanumeric passphrase, input type=password — no
 * digit-only restriction), validates locally, shows inline errors instead of
 * throwing, and delegates the actual crypto to a plugin callback. No network.
 *
 * All four modals share the login modal's visual language (quick 260708-g9m):
 * a shield icon, a centered title + optional subtitle, login-style field groups
 * (the shared `.vaultguard-field-*` classes), and a bottom action row — via
 * createShieldIcon + a self-contained `.vaultguard-pin-modal*` CSS block.
 * Constructors, exports, callback contracts, and all validation are unchanged.
 */

import { App, ButtonComponent, Modal } from "obsidian";
import { PIN_MIN_LENGTH } from "../../crypto/pin-lock-manager";
import { createShieldIcon } from "../icons";

/** A login-style password field group (label + type=password input, autocomplete off). */
function passwordRow(
  container: HTMLElement,
  name: string,
  onChange: (value: string) => void
): void {
  const group = container.createDiv({ cls: "vaultguard-field-group" });
  group.createEl("label", { text: name, cls: "vaultguard-field-label" });
  const input = group.createEl("input", {
    cls: "vaultguard-field-input",
    attr: { type: "password", autocomplete: "off" },
  });
  input.addEventListener("input", () => onChange(input.value));
}

/** Set a PIN for the first time: PIN + confirm, validated, → onEnroll(secret). */
export class SetPinModal extends Modal {
  private pin = "";
  private confirm = "";
  constructor(
    app: App,
    private readonly onEnroll: (secret: string) => Promise<void>
  ) {
    super(app);
  }
  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("vaultguard-pin-modal");
    contentEl.addClass("vaultguard-pin-modal-content");

    const iconWrap = contentEl.createDiv({ cls: "vaultguard-pin-modal-icon" });
    createShieldIcon(iconWrap);

    contentEl.createEl("h2", {
      text: "Set a vault PIN",
      cls: "vaultguard-pin-modal-title",
    });
    contentEl.createEl("p", {
      cls: "vaultguard-pin-modal-subtitle",
      text: `Choose a PIN or passphrase (at least ${PIN_MIN_LENGTH} characters). When the vault goes idle it will lock and ask for this PIN — instead of logging you out.`,
    });
    passwordRow(contentEl, "PIN / passphrase", (v) => (this.pin = v));
    passwordRow(contentEl, "Confirm", (v) => (this.confirm = v));
    const err = contentEl.createDiv({ cls: "vaultguard-pin-modal-error" });
    const actions = contentEl.createDiv({ cls: "vaultguard-pin-modal-actions" });
    new ButtonComponent(actions)
      .setButtonText("Set PIN")
      .setCta()
      .onClick(async () => {
        err.setText("");
        if (this.pin.length < PIN_MIN_LENGTH) {
          err.setText(`Use at least ${PIN_MIN_LENGTH} characters.`);
          return;
        }
        if (this.pin !== this.confirm) {
          err.setText("The two entries don't match.");
          return;
        }
        try {
          await this.onEnroll(this.pin);
          this.close();
        } catch (e) {
          err.setText(e instanceof Error ? e.message : "Could not set the PIN.");
        }
      });
  }
  onClose(): void {
    this.modalEl.removeClass("vaultguard-pin-modal");
    this.contentEl.removeClass("vaultguard-pin-modal-content");
    this.contentEl.empty();
  }
}

/** Change the PIN: current + new + confirm, → onChange(current, next). */
export class ChangePinModal extends Modal {
  private current = "";
  private next = "";
  private confirm = "";
  constructor(
    app: App,
    private readonly onChange: (current: string, next: string) => Promise<void>
  ) {
    super(app);
  }
  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("vaultguard-pin-modal");
    contentEl.addClass("vaultguard-pin-modal-content");

    const iconWrap = contentEl.createDiv({ cls: "vaultguard-pin-modal-icon" });
    createShieldIcon(iconWrap);

    contentEl.createEl("h2", {
      text: "Change vault PIN",
      cls: "vaultguard-pin-modal-title",
    });
    passwordRow(contentEl, "Current PIN", (v) => (this.current = v));
    passwordRow(contentEl, "New PIN / passphrase", (v) => (this.next = v));
    passwordRow(contentEl, "Confirm new", (v) => (this.confirm = v));
    const err = contentEl.createDiv({ cls: "vaultguard-pin-modal-error" });
    const actions = contentEl.createDiv({ cls: "vaultguard-pin-modal-actions" });
    new ButtonComponent(actions)
      .setButtonText("Change PIN")
      .setCta()
      .onClick(async () => {
        err.setText("");
        if (this.next.length < PIN_MIN_LENGTH) {
          err.setText(`Use at least ${PIN_MIN_LENGTH} characters.`);
          return;
        }
        if (this.next !== this.confirm) {
          err.setText("The two new entries don't match.");
          return;
        }
        try {
          await this.onChange(this.current, this.next);
          this.close();
        } catch (e) {
          err.setText(e instanceof Error ? e.message : "Could not change the PIN.");
        }
      });
  }
  onClose(): void {
    this.modalEl.removeClass("vaultguard-pin-modal");
    this.contentEl.removeClass("vaultguard-pin-modal-content");
    this.contentEl.empty();
  }
}

/** Disable the PIN: authorize with the current PIN, → onDisable(secret). */
export class DisablePinModal extends Modal {
  private pin = "";
  constructor(
    app: App,
    private readonly onDisable: (secret: string) => Promise<void>
  ) {
    super(app);
  }
  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("vaultguard-pin-modal");
    contentEl.addClass("vaultguard-pin-modal-content");

    const iconWrap = contentEl.createDiv({ cls: "vaultguard-pin-modal-icon" });
    createShieldIcon(iconWrap);

    contentEl.createEl("h2", {
      text: "Remove vault PIN",
      cls: "vaultguard-pin-modal-title",
    });
    contentEl.createEl("p", {
      cls: "vaultguard-pin-modal-subtitle",
      text: "Enter your current PIN to confirm. This device will unlock the vault transparently again (no PIN prompt on idle).",
    });
    passwordRow(contentEl, "Current PIN", (v) => (this.pin = v));
    const err = contentEl.createDiv({ cls: "vaultguard-pin-modal-error" });
    const actions = contentEl.createDiv({ cls: "vaultguard-pin-modal-actions" });
    new ButtonComponent(actions)
      .setButtonText("Remove PIN")
      .setWarning()
      .onClick(async () => {
        err.setText("");
        try {
          await this.onDisable(this.pin);
          this.close();
        } catch (e) {
          err.setText(e instanceof Error ? e.message : "Could not remove the PIN.");
        }
      });
  }
  onClose(): void {
    this.modalEl.removeClass("vaultguard-pin-modal");
    this.contentEl.removeClass("vaultguard-pin-modal-content");
    this.contentEl.empty();
  }
}

/** Which callback the soft onboarding prompt fires for each of its two choices. */
export interface PinOnboardingPromptOptions {
  /** [Set PIN] — open the real SetPinModal → enroll. */
  onSetPin: () => void;
  /** [Not now] / Esc / backdrop — persist the once-ever flag, do nothing else. */
  onDismiss: () => void;
}

/**
 * A skippable, once-only "Set a PIN" nudge (quick 260708-el6). Shown at an
 * onboarding moment for a user in a lock-policy org who has no PIN yet, so
 * lock-instead-of-logout becomes discoverable (opt-out) rather than opt-in.
 *
 * Two buttons: [Not now] (dismiss) and [Set PIN] (opens the canonical
 * SetPinModal). Closing via Esc / backdrop with no click still counts as a
 * dismissal, so the caller's once-ever flag is always persisted (AC3). No
 * network, no crypto, no Platform branching — byte-identical on desktop and
 * mobile (mobile parity for AC5 comes for free by reusing this + SetPinModal).
 */
export class PinOnboardingPromptModal extends Modal {
  private chose = false;
  constructor(
    app: App,
    private readonly opts: PinOnboardingPromptOptions
  ) {
    super(app);
  }
  onOpen(): void {
    const { contentEl } = this;
    this.modalEl.addClass("vaultguard-pin-modal");
    contentEl.addClass("vaultguard-pin-modal-content");

    const iconWrap = contentEl.createDiv({ cls: "vaultguard-pin-modal-icon" });
    createShieldIcon(iconWrap);

    contentEl.createEl("h2", {
      text: "Set a PIN to unlock quickly",
      cls: "vaultguard-pin-modal-title",
    });
    contentEl.createEl("p", {
      cls: "vaultguard-pin-modal-subtitle",
      text: "Your team locks the vault when it's idle. Set a PIN to unlock with just the PIN instead of a full re-login. You can always set or change this later in Settings → VaultGuard.",
    });
    const actions = contentEl.createDiv({ cls: "vaultguard-pin-modal-actions" });
    new ButtonComponent(actions).setButtonText("Not now").onClick(() => {
      this.chose = true;
      this.opts.onDismiss();
      this.close();
    });
    new ButtonComponent(actions)
      .setButtonText("Set PIN")
      .setCta()
      .onClick(() => {
        this.chose = true;
        this.opts.onSetPin();
        this.close();
      });
  }
  onClose(): void {
    this.modalEl.removeClass("vaultguard-pin-modal");
    this.contentEl.removeClass("vaultguard-pin-modal-content");
    this.contentEl.empty();
    // Esc / backdrop close with no button click still counts as a dismissal so
    // the once-ever flag is set (AC3). The caller's markPinOnboardingPromptShown
    // is idempotent, so a stray double-call after a button click is harmless.
    if (!this.chose) {
      this.opts.onDismiss();
    }
  }
}
