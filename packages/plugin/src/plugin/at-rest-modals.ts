/**
 * At-rest encryption modals — display recovery code (one-time view) and
 * restore from a previously-saved code.
 *
 * The recovery code is the raw LAK formatted as `VG1-XXXX-...-XXXX`.
 * Anyone who holds it can decrypt the user's vault, so the display modal
 * is deliberately demanding: copy-to-clipboard, "I've saved it"
 * confirmation, and a warning that it will not be shown automatically
 * again. The restore modal is permissive about formatting (whitespace,
 * case, hyphens) so users can paste from a notes file or read off paper.
 */

import { App, ButtonComponent, Modal, Notice } from "obsidian";

export interface AtRestPasswordConfirmModalOptions {
  /** Short title shown at the top of the dialog (e.g. "View recovery code"). */
  title: string;
  /** Body copy explaining what action is gated and why we need re-auth. */
  description: string;
  /** Verifier — returns true if the supplied password matches the account. */
  onVerify: (password: string) => Promise<boolean>;
  /** Called once the password is verified; receives focus right after close. */
  onConfirmed: () => void;
}

/**
 * Re-authentication gate for high-stakes at-rest actions (revealing the
 * recovery code, decrypting the entire vault). Verifies the user's
 * Cognito password without mutating session state. The modal closes on
 * success; cancel / wrong password just leaves the dialog open with an
 * inline error so the user can retry.
 */
export class AtRestPasswordConfirmModal extends Modal {
  private opts: AtRestPasswordConfirmModalOptions;
  private confirmed = false;

  constructor(app: App, opts: AtRestPasswordConfirmModalOptions) {
    super(app);
    this.opts = opts;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-at-rest-confirm-modal");
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", { text: this.opts.title });
    contentEl.createEl("p", {
      text: this.opts.description,
      cls: "vaultguard-modal-description",
    });

    const input = contentEl.createEl("input", {
      type: "password",
      cls: "vaultguard-confirm-password-input",
    });
    input.placeholder = "Account password";
    input.autocomplete = "current-password";
    window.setTimeout(() => input.focus(), 50);

    const status = contentEl.createDiv({ cls: "vaultguard-modal-status" });

    const buttons = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(buttons)
      .setButtonText("Cancel")
      .onClick(() => this.close());

    const submit = new ButtonComponent(buttons);
    submit
      .setButtonText("Confirm")
      .setCta()
      .onClick(async () => {
        const password = input.value;
        if (!password) {
          status.setText("Enter your account password to continue.");
          return;
        }
        submit.setDisabled(true).setButtonText("Verifying…");
        status.setText("");
        try {
          const ok = await this.opts.onVerify(password);
          if (!ok) {
            status.setText("Wrong password. Try again.");
            submit.setDisabled(false).setButtonText("Confirm");
            input.select();
            return;
          }
          this.confirmed = true;
          this.close();
        } catch (err) {
          status.setText(
            `Couldn't verify: ${err instanceof Error ? err.message : String(err)}`
          );
          submit.setDisabled(false).setButtonText("Confirm");
        }
      });

    // Submit on Enter for keyboard-only flow.
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submit.buttonEl.click();
      }
    });
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-at-rest-confirm-modal");
    this.contentEl.empty();
    if (this.confirmed) this.opts.onConfirmed();
  }
}


export interface AtRestRecoveryCodeModalOptions {
  /** Pre-formatted code from `AtRestCipher.exportRecoveryCode()`. */
  code: string;
  /** Optional callback when the user confirms they've saved it. */
  onSaved?: () => void;
}

/**
 * One-time display of the recovery code. Forces a confirmation click so a
 * user who closes the modal accidentally still has to acknowledge that
 * they've stored the code somewhere safe.
 */
export class AtRestRecoveryCodeModal extends Modal {
  private code: string;
  private onSaved?: () => void;
  private confirmed = false;

  constructor(app: App, opts: AtRestRecoveryCodeModalOptions) {
    super(app);
    this.code = opts.code;
    this.onSaved = opts.onSaved;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-at-rest-recovery-modal");
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", { text: "VaultGuard recovery code" });

    const intro = contentEl.createEl("p");
    intro.appendText(
      "This code is unique to this device. It is not shared with other vault members, not stored on the server, and not the same as your account password. It's the only way to read this device's encrypted files if the OS keychain is reset, the disk is moved to another machine, or the plugin is reinstalled."
    );

    const warn = contentEl.createDiv({
      cls: "vaultguard-modal-warning",
    });
    warn.createEl("strong", { text: "Save it now." });
    warn.appendText(
      " Store it in a password manager or write it on paper and put it somewhere safe. Anyone who has this code can decrypt the files on this device — treat it like a master password. VaultGuard will not show it again automatically; you can reopen it from Settings, but you'll be asked for your account password each time."
    );

    const codeBox = contentEl.createEl("pre", {
      cls: "vaultguard-recovery-code",
    });
    codeBox.setText(this.code);

    const buttons = contentEl.createDiv({ cls: "vaultguard-modal-actions" });

    const copyBtn = new ButtonComponent(buttons);
    copyBtn
      .setButtonText("Copy to clipboard")
      .setCta()
      .onClick(async () => {
        try {
          await navigator.clipboard.writeText(this.code);
          new Notice("Recovery code copied to clipboard.", 4000);
          copyBtn.setButtonText("Copied ✓");
          window.setTimeout(() => copyBtn.setButtonText("Copy to clipboard"), 2000);
        } catch {
          new Notice(
            "Couldn't copy automatically — select the code above and copy it manually.",
            6000
          );
        }
      });

    const ackBtn = new ButtonComponent(buttons);
    ackBtn.setButtonText("I've saved my recovery code").onClick(() => {
      this.confirmed = true;
      this.close();
    });
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-at-rest-recovery-modal");
    this.contentEl.empty();
    if (this.confirmed) this.onSaved?.();
  }
}

export interface AtRestRestoreModalOptions {
  /**
   * Attempts to restore the cipher from `code`. Should resolve true when
   * the LAK was reconstituted successfully and false when the code is
   * malformed / fails the checksum.
   */
  onSubmit: (code: string) => Promise<boolean>;
  /** Called once a code has been accepted, after the modal closes. */
  onRestored?: () => void;
}

/**
 * Restore a vault from a recovery code on a new machine. Accepts the
 * formatted code as written, plus messy paste artefacts (whitespace,
 * mixed case). Reports a generic "code not recognised" error on failure
 * to avoid leaking whether prefix/length/checksum was the wrong part.
 */
export class AtRestRestoreModal extends Modal {
  private onSubmit: AtRestRestoreModalOptions["onSubmit"];
  private onRestored?: () => void;
  private restored = false;

  constructor(app: App, opts: AtRestRestoreModalOptions) {
    super(app);
    this.onSubmit = opts.onSubmit;
    this.onRestored = opts.onRestored;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-at-rest-restore-modal");
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", { text: "Restore VaultGuard from recovery code" });
    contentEl.createEl("p", {
      text:
        "Paste the recovery code you saved when you first set up at-rest encryption. After a successful restore your encrypted files will be readable again on this device.",
      cls: "vaultguard-modal-description",
    });

    const textarea = contentEl.createEl("textarea", {
      cls: "vaultguard-recovery-code-input",
    });
    textarea.placeholder = "VG1-XXXX-XXXX-...-XXXX";
    textarea.rows = 4;
    textarea.setAttribute("autocapitalize", "off");
    textarea.setAttribute("autocorrect", "off");
    textarea.setAttribute("spellcheck", "false");

    const status = contentEl.createDiv({
      cls: "vaultguard-modal-status",
    });

    const buttons = contentEl.createDiv({ cls: "vaultguard-modal-actions" });

    new ButtonComponent(buttons)
      .setButtonText("Cancel")
      .onClick(() => this.close());

    const submitBtn = new ButtonComponent(buttons);
    submitBtn
      .setButtonText("Restore")
      .setCta()
      .onClick(async () => {
        const code = textarea.value.trim();
        if (!code) {
          status.setText("Enter a recovery code to continue.");
          return;
        }
        submitBtn.setButtonText("Restoring…").setDisabled(true);
        status.setText("");
        try {
          const ok = await this.onSubmit(code);
          if (!ok) {
            status.setText(
              "That code isn't recognised. Check for typos — recovery codes start with VG1- and contain hex characters in groups of four."
            );
            submitBtn.setButtonText("Restore").setDisabled(false);
            return;
          }
          this.restored = true;
          new Notice("VaultGuard at-rest key restored.", 5000);
          this.close();
        } catch (err) {
          status.setText(
            `Restore failed: ${err instanceof Error ? err.message : String(err)}`
          );
          submitBtn.setButtonText("Restore").setDisabled(false);
        }
      });
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-at-rest-restore-modal");
    this.contentEl.empty();
    if (this.restored) this.onRestored?.();
  }
}
