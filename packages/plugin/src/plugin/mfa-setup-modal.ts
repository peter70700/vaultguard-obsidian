/**
 * MFA Setup Modal — Walks the user through TOTP device registration.
 *
 * Flow:
 * 1. Shows the TOTP secret (text + QR code) for the authenticator app
 * 2. User enters the 6-digit verification code
 * 3. On success, displays one-time recovery codes
 * 4. User must acknowledge saving the codes before closing
 */

import { App, Modal, ButtonComponent, Notice } from "obsidian";
import qrcode from "qrcode-generator";
import { createQrSvg } from "../ui/icons";

const RECOVERY_CODE_COUNT = 8;

export interface MfaSetupResult {
  /** Session token returned after TOTP verification, used to complete login */
  session: string;
  /** Generated recovery codes for the user to save */
  recoveryCodes: string[];
}

export class MfaSetupModal extends Modal {
  private secretCode: string;
  private email: string;
  private session: string;
  private onVerify: (code: string, session: string) => Promise<{ session: string; status: string }>;
  private onComplete: (result: MfaSetupResult) => void;
  private recoveryCodes: string[] = [];

  constructor(
    app: App,
    opts: {
      secretCode: string;
      email: string;
      session: string;
      onVerify: (code: string, session: string) => Promise<{ session: string; status: string }>;
      onComplete: (result: MfaSetupResult) => void;
    }
  ) {
    super(app);
    this.secretCode = opts.secretCode;
    this.email = opts.email;
    this.session = opts.session;
    this.onVerify = opts.onVerify;
    this.onComplete = opts.onComplete;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-mfa-setup-modal");
    this.contentEl.addClass("vaultguard-mfa-setup-content");
    this.renderSetupStep();
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-mfa-setup-modal");
    this.contentEl.removeClass("vaultguard-mfa-setup-content");
    this.contentEl.empty();
  }

  /** Step 1: Show secret + QR code, ask for verification code */
  private renderSetupStep(): void {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: "Set Up Two-Factor Authentication",
      cls: "vaultguard-modal-title",
    });
    contentEl.createEl("p", {
      text: "Scan the QR code below with your authenticator app (Google Authenticator, Authy, 1Password, etc.), then enter the 6-digit code to verify.",
      cls: "vaultguard-modal-description",
    });

    // QR code — rendered locally so the TOTP secret never leaves the device.
    const totpUri = `otpauth://totp/VaultGuard:${encodeURIComponent(this.email)}?secret=${this.secretCode}&issuer=VaultGuard`;
    const qr = qrcode(0, "M");
    qr.addData(totpUri);
    qr.make();

    const qrContainer = contentEl.createDiv({ cls: "vaultguard-mfa-qr-container" });
    qrContainer.setAttribute("aria-label", "TOTP QR Code");
    createQrSvg(qrContainer, qr, {
      cellSize: 5,
      margin: 2,
      cssClass: "vaultguard-mfa-qr",
    });

    // Manual entry fallback
    const manualContainer = contentEl.createDiv({ cls: "vaultguard-mfa-manual" });
    manualContainer.createEl("p", {
      text: "Can't scan? Enter this secret manually:",
      cls: "vaultguard-mfa-manual-label",
    });
    const secretDisplay = manualContainer.createEl("code", {
      text: this.formatSecret(this.secretCode),
      cls: "vaultguard-mfa-secret",
    });
    const copyBtn = manualContainer.createEl("button", {
      text: "Copy",
      cls: "vaultguard-mfa-copy-btn",
    });
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(this.secretCode);
      copyBtn.setText("Copied!");
      setTimeout(() => copyBtn.setText("Copy"), 2000);
    });

    // Verification code input
    const verifyGroup = contentEl.createDiv({ cls: "vaultguard-field-group" });
    verifyGroup.createEl("label", { text: "Verification Code", cls: "vaultguard-field-label" });
    const codeInput = verifyGroup.createEl("input", {
      cls: "vaultguard-field-input vaultguard-mfa-input",
      attr: { type: "text", placeholder: "123456", maxlength: "6", inputmode: "numeric", pattern: "[0-9]*" },
    });

    // Error display
    const errorEl = contentEl.createDiv({ cls: "vaultguard-login-error" });
    errorEl.hide();

    // Buttons
    const actionRow = contentEl.createDiv({ cls: "vaultguard-login-actions" });
    new ButtonComponent(actionRow).setButtonText("Cancel").onClick(() => this.close());

    const verifyBtn = new ButtonComponent(actionRow)
      .setButtonText("Verify & Enable")
      .setCta();

    verifyBtn.onClick(async () => {
      const code = codeInput.value.trim();
      if (!code || code.length !== 6) {
        errorEl.setText("Please enter the 6-digit code from your authenticator app.");
        errorEl.show();
        return;
      }

      verifyBtn.setDisabled(true);
      verifyBtn.setButtonText("Verifying...");
      errorEl.hide();

      try {
        const result = await this.onVerify(code, this.session);
        if (result.status === "SUCCESS") {
          this.recoveryCodes = this.generateRecoveryCodes();
          this.renderRecoveryCodesStep(result.session);
        } else {
          errorEl.setText("Verification failed. Please try again.");
          errorEl.show();
        }
      } catch (error) {
        errorEl.setText(error instanceof Error ? error.message : "Verification failed");
        errorEl.show();
      } finally {
        verifyBtn.setDisabled(false);
        verifyBtn.setButtonText("Verify & Enable");
      }
    });

    setTimeout(() => codeInput.focus(), 50);
  }

  /** Step 2: Show recovery codes, require acknowledgment */
  private renderRecoveryCodesStep(session: string): void {
    const { contentEl } = this;
    contentEl.empty();

    contentEl.createEl("h2", {
      text: "Save Your Recovery Codes",
      cls: "vaultguard-modal-title",
    });
    contentEl.createEl("p", {
      text: "If you lose access to your authenticator app, you can use these one-time recovery codes to sign in. Each code can only be used once.",
      cls: "vaultguard-mfa-recovery-warning",
    });

    // Recovery codes grid
    const codesContainer = contentEl.createDiv({ cls: "vaultguard-mfa-recovery-codes" });
    for (const code of this.recoveryCodes) {
      codesContainer.createEl("code", {
        text: code,
        cls: "vaultguard-mfa-recovery-code",
      });
    }

    // Copy all button
    const copyAllBtn = contentEl.createEl("button", {
      text: "Copy All Codes",
      cls: "vaultguard-mfa-copy-all-btn",
    });
    copyAllBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(this.recoveryCodes.join("\n"));
      copyAllBtn.setText("Copied!");
      setTimeout(() => copyAllBtn.setText("Copy All Codes"), 2000);
    });

    contentEl.createEl("p", {
      text: "Store these codes in a safe place (password manager, printed copy, etc.). You will not be able to see them again.",
      cls: "vaultguard-mfa-recovery-note",
    });

    // Acknowledgment checkbox
    const ackRow = contentEl.createDiv({ cls: "vaultguard-mfa-ack-row" });
    const checkbox = ackRow.createEl("input", { type: "checkbox", cls: "vaultguard-mfa-ack-checkbox" });
    ackRow.createEl("span", { text: "I have saved my recovery codes" });

    // Done button
    const actionRow = contentEl.createDiv({ cls: "vaultguard-login-actions" });
    const doneBtn = new ButtonComponent(actionRow)
      .setButtonText("Done")
      .setCta()
      .setDisabled(true);

    checkbox.addEventListener("change", () => {
      doneBtn.setDisabled(!checkbox.checked);
    });

    doneBtn.onClick(() => {
      this.onComplete({
        session,
        recoveryCodes: this.recoveryCodes,
      });
      this.close();
    });
  }

  /** Format the TOTP secret in groups of 4 for readability */
  private formatSecret(secret: string): string {
    return secret.replace(/(.{4})/g, "$1 ").trim();
  }

  /** Generate cryptographically random recovery codes */
  private generateRecoveryCodes(): string[] {
    const codes: string[] = [];
    for (let i = 0; i < RECOVERY_CODE_COUNT; i++) {
      const bytes = new Uint8Array(5);
      crypto.getRandomValues(bytes);
      const code = Array.from(bytes)
        .map((b) => b.toString(36).padStart(2, "0"))
        .join("")
        .substring(0, 10)
        .toUpperCase();
      // Format as XXXXX-XXXXX
      codes.push(code.substring(0, 5) + "-" + code.substring(5, 10));
    }
    return codes;
  }
}
