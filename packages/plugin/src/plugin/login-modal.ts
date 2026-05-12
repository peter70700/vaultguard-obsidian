import { App, Modal, ButtonComponent } from "obsidian";
import { setButtonLoading } from "../ui/loading-button";
import { createShieldIcon } from "../ui/icons";

export type EncryptionMode = 'server-managed' | 'hybrid-zk';

export interface LoginCredentials {
  orgSlug: string;
  email: string;
  password: string;
  mfaCode: string;
  /** Passphrase for hybrid-zk mode (separate from Cognito password) */
  passphrase: string;
  /** Whether this is a first-time ZK setup (passphrase creation) */
  zkSetup: boolean;
}

export class LoginModal extends Modal {
  private orgSlug: string = "";
  private email: string = "";
  private password: string = "";
  private mfaCode: string = "";
  private passphrase: string = "";
  private passphraseConfirm: string = "";
  private onSubmit: (credentials: LoginCredentials) => Promise<void>;
  private onForgotPassword?: (email: string) => Promise<void>;
  private onConfirmReset?: (email: string, code: string, newPassword: string) => Promise<void>;
  /**
   * Optional callback invoked when the user submits a recovery code from the
   * "Lost your authenticator?" flow. After it resolves, the user is told to
   * sign in again — Cognito will then route to MFA_SETUP since their MFA
   * preference was cleared server-side.
   */
  private onRecoveryCode?: (email: string, code: string) => Promise<void>;
  private submitBtn: ButtonComponent | null = null;
  private orgSlugContainer: HTMLElement | null = null;
  private mfaContainer: HTMLElement | null = null;
  private mfaInputEl: HTMLInputElement | null = null;
  private mfaHintEl: HTMLElement | null = null;
  private mfaLabelEl: HTMLElement | null = null;
  private mfaRecoveryLinkEl: HTMLElement | null = null;
  private passphraseContainer: HTMLElement | null = null;
  private errorEl: HTMLElement | null = null;
  private showMfa: boolean = false;
  /** Active when the MFA panel is in "enter recovery code" mode. */
  private recoveryMode: boolean = false;
  private encryptionMode: EncryptionMode;
  private isZkSetup: boolean;
  /** If org is already configured, pre-fill and hide the slug field. */
  private currentOrgSlug: string;
  /** If provided, prefills the email field (used by invite redemption). */
  private currentEmail: string;
  /** When true, opens directly in "set your password" mode for new invitees. */
  private firstTimeSetup: boolean;
  /** Whether the hosted org slug field is required before login. */
  private requireOrgSlug: boolean;

  constructor(
    app: App,
    onSubmit: (credentials: LoginCredentials) => Promise<void>,
    encryptionMode: EncryptionMode = 'server-managed',
    isZkSetup: boolean = false,
    currentOrgSlug: string = "",
    onForgotPassword?: (email: string) => Promise<void>,
    onConfirmReset?: (email: string, code: string, newPassword: string) => Promise<void>,
    currentEmail: string = "",
    firstTimeSetup: boolean = false,
    requireOrgSlug: boolean = true,
    onRecoveryCode?: (email: string, code: string) => Promise<void>
  ) {
    super(app);
    this.onSubmit = onSubmit;
    this.encryptionMode = encryptionMode;
    this.isZkSetup = isZkSetup;
    this.currentOrgSlug = currentOrgSlug;
    this.orgSlug = currentOrgSlug;
    this.onForgotPassword = onForgotPassword;
    this.onConfirmReset = onConfirmReset;
    this.currentEmail = currentEmail;
    this.email = currentEmail;
    this.firstTimeSetup = firstTimeSetup;
    this.requireOrgSlug = requireOrgSlug;
    this.onRecoveryCode = onRecoveryCode;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-login-modal");
    contentEl.addClass("vaultguard-login-modal-content");

    // Shield icon
    const iconWrap = contentEl.createDiv({ cls: "vaultguard-login-icon" });
    createShieldIcon(iconWrap);

    // Title
    contentEl.createEl("h2", { text: "VaultGuard Login", cls: "vaultguard-login-title" });
    contentEl.createEl("p", {
      text: "Sign in to access your secured vault.",
      cls: "vaultguard-login-subtitle",
    });

    // Error display
    this.errorEl = contentEl.createDiv({ cls: "vaultguard-login-error" });
    this.errorEl.style.display = "none";

    // Form
    const form = contentEl.createDiv({ cls: "vaultguard-login-form" });

    // Organization slug field (hidden if already configured)
    this.orgSlugContainer = form.createDiv({ cls: "vaultguard-field-group" });
    if (this.currentOrgSlug || !this.requireOrgSlug) {
      this.orgSlugContainer.style.display = "none";
    }
    this.orgSlugContainer.createEl("label", { text: "Organization", cls: "vaultguard-field-label" });
    this.orgSlugContainer.createEl("span", {
      text: "Enter the slug your admin gave you",
      cls: "vaultguard-field-hint",
    });
    const orgSlugInput = this.orgSlugContainer.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "text", placeholder: "acme-corp", spellcheck: "false" },
    });
    orgSlugInput.value = this.orgSlug;
    orgSlugInput.addEventListener("input", () => { this.orgSlug = orgSlugInput.value.trim().toLowerCase(); });
    orgSlugInput.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });

    // Email field
    const emailGroup = form.createDiv({ cls: "vaultguard-field-group" });
    emailGroup.createEl("label", { text: "Email", cls: "vaultguard-field-label" });
    const emailInput = emailGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "email", placeholder: "you@company.com", spellcheck: "false" },
    });
    if (this.email) {
      emailInput.value = this.email;
    }
    emailInput.addEventListener("input", () => { this.email = emailInput.value; });
    emailInput.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });

    // Password field
    const passGroup = form.createDiv({ cls: "vaultguard-field-group" });
    passGroup.createEl("label", { text: "Password", cls: "vaultguard-field-label" });
    const passInput = passGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "password", placeholder: "Password" },
    });
    passInput.addEventListener("input", () => { this.password = passInput.value; });
    passInput.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });

    // Forgot password link
    if (this.onForgotPassword && this.onConfirmReset) {
      const forgotLink = form.createDiv({ cls: "vaultguard-forgot-link" });
      forgotLink.createEl("a", { text: "Forgot password?", href: "#" });
      forgotLink.addEventListener("click", (e) => {
        e.preventDefault();
        this.showForgotPasswordForm();
      });
    }

    // MFA field (hidden by default)
    this.mfaContainer = form.createDiv({ cls: "vaultguard-field-group vaultguard-mfa-container" });
    this.mfaContainer.style.display = "none";
    this.mfaLabelEl = this.mfaContainer.createEl("label", { text: "MFA Code", cls: "vaultguard-field-label" });
    this.mfaHintEl = this.mfaContainer.createEl("span", {
      text: "Enter the 6-digit code from your authenticator app",
      cls: "vaultguard-field-hint",
    });
    const mfaInput = this.mfaContainer.createEl("input", {
      cls: "vaultguard-field-input vaultguard-mfa-input",
      attr: { type: "text", placeholder: "123456", maxlength: "6", inputmode: "numeric", pattern: "[0-9]*" },
    });
    this.mfaInputEl = mfaInput;
    mfaInput.addEventListener("input", () => { this.mfaCode = mfaInput.value; });
    mfaInput.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });

    // "Lost your authenticator?" link — only shown when the recovery callback
    // is wired. Toggles the MFA container into recovery-code mode.
    if (this.onRecoveryCode) {
      this.mfaRecoveryLinkEl = this.mfaContainer.createDiv({ cls: "vaultguard-forgot-link" });
      const link = this.mfaRecoveryLinkEl.createEl("a", { text: "Lost your authenticator? Use a recovery code", href: "#" });
      link.addEventListener("click", (e) => {
        e.preventDefault();
        this.toggleRecoveryMode();
      });
    }

    // Passphrase field (hybrid-zk mode only)
    this.passphraseContainer = form.createDiv({ cls: "vaultguard-field-group vaultguard-passphrase-container" });
    if (this.encryptionMode !== 'hybrid-zk') {
      this.passphraseContainer.style.display = "none";
    }

    if (this.isZkSetup) {
      // First-time setup: show warning and confirmation field
      const zkWarning = this.passphraseContainer.createDiv({ cls: "vaultguard-zk-warning" });
      zkWarning.createEl("strong", { text: "End-to-end encryption setup" });
      zkWarning.createEl("br");
      zkWarning.appendText(
        "Your passphrase protects your encryption keys. It is separate from your login password."
      );
      zkWarning.createEl("br");
      zkWarning.createEl("br");
      zkWarning.createEl("strong", {
        text: "If you lose this passphrase, your data cannot be recovered",
      });
      zkWarning.appendText(
        ' unless your organization administrator performs an emergency key recovery. There is no "forgot passphrase" reset.'
      );

      this.passphraseContainer.createEl("label", { text: "Encryption Passphrase", cls: "vaultguard-field-label" });
      const ppInput = this.passphraseContainer.createEl("input", {
        cls: "vaultguard-field-input",
        attr: { type: "password", placeholder: "Choose a strong passphrase" },
      });
      ppInput.addEventListener("input", () => { this.passphrase = ppInput.value; });

      this.passphraseContainer.createEl("label", { text: "Confirm Passphrase", cls: "vaultguard-field-label" });
      const ppConfirm = this.passphraseContainer.createEl("input", {
        cls: "vaultguard-field-input",
        attr: { type: "password", placeholder: "Confirm passphrase" },
      });
      ppConfirm.addEventListener("input", () => { this.passphraseConfirm = ppConfirm.value; });
      ppConfirm.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });
    } else {
      // Returning user: single passphrase field
      this.passphraseContainer.createEl("label", { text: "Encryption Passphrase", cls: "vaultguard-field-label" });
      this.passphraseContainer.createEl("span", {
        text: "This unlocks your end-to-end encryption keys locally.",
        cls: "vaultguard-field-hint",
      });
      const ppInput = this.passphraseContainer.createEl("input", {
        cls: "vaultguard-field-input",
        attr: { type: "password", placeholder: "Encryption passphrase" },
      });
      ppInput.addEventListener("input", () => { this.passphrase = ppInput.value; });
      ppInput.addEventListener("keydown", (e) => { if (e.key === "Enter") this.handleSubmit(); });
    }

    // Buttons
    const actionRow = contentEl.createDiv({ cls: "vaultguard-login-actions" });

    new ButtonComponent(actionRow)
      .setButtonText("Cancel")
      .onClick(() => this.close());

    this.submitBtn = new ButtonComponent(actionRow)
      .setButtonText("Sign In")
      .setCta()
      .onClick(() => this.handleSubmit());

    // Focus first visible input on open
    setTimeout(() => {
      if (this.currentOrgSlug || !this.requireOrgSlug) {
        emailInput.focus();
      } else {
        orgSlugInput.focus();
      }
    }, 50);

    // Invitee redemption: jump straight to "set your password" form.
    if (this.firstTimeSetup && this.onForgotPassword && this.onConfirmReset) {
      this.showForgotPasswordForm();
    }
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-login-modal");
    this.contentEl.removeClass("vaultguard-login-modal-content");
    this.contentEl.empty();
  }

  showMfaPrompt(): void {
    this.showMfa = true;
    this.recoveryMode = false;
    if (this.mfaContainer) {
      this.mfaContainer.style.display = "";
    }
    this.applyMfaModeUi();
    this.showError("");
    if (this.submitBtn) {
      this.submitBtn.setButtonText("Verify MFA");
    }
  }

  /** Flips the MFA panel between TOTP-code entry and recovery-code entry. */
  private toggleRecoveryMode(): void {
    this.recoveryMode = !this.recoveryMode;
    // Stale input from the other mode would silently submit, so clear it.
    this.mfaCode = "";
    if (this.mfaInputEl) {
      this.mfaInputEl.value = "";
    }
    this.applyMfaModeUi();
    this.showError("");
    if (this.submitBtn) {
      this.submitBtn.setButtonText(this.recoveryMode ? "Use Recovery Code" : "Verify MFA");
    }
  }

  /** Sync the MFA input/label/hint/link to whichever mode is active. */
  private applyMfaModeUi(): void {
    if (!this.mfaInputEl || !this.mfaLabelEl || !this.mfaHintEl) return;
    if (this.recoveryMode) {
      this.mfaLabelEl.setText("Recovery Code");
      this.mfaHintEl.setText(
        "Enter one of the recovery codes you saved when you set up MFA. This will reset your authenticator — you'll be asked to set up a new one on next sign-in."
      );
      this.mfaInputEl.setAttribute("placeholder", "XXXXX-XXXXX");
      this.mfaInputEl.setAttribute("maxlength", "20");
      this.mfaInputEl.removeAttribute("inputmode");
      this.mfaInputEl.removeAttribute("pattern");
      if (this.mfaRecoveryLinkEl) {
        const link = this.mfaRecoveryLinkEl.querySelector("a");
        if (link) link.setText("Have your authenticator? Use TOTP code");
      }
    } else {
      this.mfaLabelEl.setText("MFA Code");
      this.mfaHintEl.setText("Enter the 6-digit code from your authenticator app");
      this.mfaInputEl.setAttribute("placeholder", "123456");
      this.mfaInputEl.setAttribute("maxlength", "6");
      this.mfaInputEl.setAttribute("inputmode", "numeric");
      this.mfaInputEl.setAttribute("pattern", "[0-9]*");
      if (this.mfaRecoveryLinkEl) {
        const link = this.mfaRecoveryLinkEl.querySelector("a");
        if (link) link.setText("Lost your authenticator? Use a recovery code");
      }
    }
  }

  showError(message: string): void {
    if (!this.errorEl) return;
    // The errorEl is also reused as a transient success banner from the
    // recovery-code flow. Any new error call needs to drop the success class
    // so the styling reverts to error-red.
    this.errorEl.classList.remove("vaultguard-login-success");
    if (message) {
      this.errorEl.setText(message);
      this.errorEl.style.display = "";
    } else {
      this.errorEl.style.display = "none";
    }
  }

  private async handleSubmit(): Promise<void> {
    // Recovery-code submission has its own flow — it never touches password
    // or the regular login path. Handle it before the normal validation.
    if (this.showMfa && this.recoveryMode) {
      await this.handleRecoveryCodeSubmit();
      return;
    }

    if (this.requireOrgSlug && !this.orgSlug) {
      this.showError("Please enter your organization slug.");
      return;
    }
    if (!this.email) {
      this.showError("Please enter your email address.");
      return;
    }
    if (!this.password) {
      this.showError("Please enter your password.");
      return;
    }
    if (this.showMfa && !this.mfaCode) {
      this.showError("Please enter your MFA code.");
      return;
    }
    if (this.encryptionMode === 'hybrid-zk') {
      if (!this.passphrase) {
        this.showError("Please enter your encryption passphrase.");
        return;
      }
      if (this.isZkSetup) {
        if (this.passphrase.length < 12) {
          this.showError("Passphrase must be at least 12 characters for adequate security.");
          return;
        }
        if (this.passphrase !== this.passphraseConfirm) {
          this.showError("Passphrases do not match.");
          return;
        }
      }
    }

    this.showError("");

    const submitEl = this.submitBtn?.buttonEl;
    if (submitEl) {
      setButtonLoading(submitEl, true, { label: this.showMfa ? "Verifying" : "Signing in" });
    }

    try {
      await this.onSubmit({
        orgSlug: this.orgSlug,
        email: this.email,
        password: this.password,
        mfaCode: this.mfaCode,
        passphrase: this.passphrase,
        zkSetup: this.isZkSetup,
      });
      this.close();
    } catch (error) {
      const msg = error instanceof Error ? error.message : "Login failed";

      if (msg.toLowerCase().includes("mfa") || msg.toLowerCase().includes("challenge") || msg.toLowerCase().includes("2fa")) {
        this.showMfaPrompt();
      } else if (msg.toLowerCase().includes("incorrect passphrase")) {
        this.showError("Incorrect encryption passphrase. If you have lost your passphrase, contact your organization administrator for key recovery.");
      } else {
        this.showError(msg);
      }
    } finally {
      if (submitEl?.isConnected) {
        setButtonLoading(submitEl, false);
        // Keep the post-MFA label in sync with the current flow state.
        this.submitBtn?.setButtonText(this.showMfa ? "Verify MFA" : "Sign In");
      }
    }
  }

  /**
   * Replaces the modal content with a password reset form.
   * Shows email field (pre-filled), "Send Reset Code" button,
   * then after code is sent: code input, new password, confirm password, and "Reset Password" button.
   */
  private showForgotPasswordForm(): void {
    const { contentEl } = this;
    contentEl.empty();

    // Shield icon
    const iconWrap = contentEl.createDiv({ cls: "vaultguard-login-icon" });
    createShieldIcon(iconWrap);

    // Title — different copy for first-time invitees vs. returning users
    if (this.firstTimeSetup) {
      contentEl.createEl("h2", { text: "Set Your Password", cls: "vaultguard-login-title" });
      contentEl.createEl("p", {
        text: "Welcome to VaultGuard! Send a verification code to your email, then choose your password.",
        cls: "vaultguard-login-subtitle",
      });
    } else {
      contentEl.createEl("h2", { text: "Reset Password", cls: "vaultguard-login-title" });
      contentEl.createEl("p", {
        text: "Enter your email to receive a password reset code.",
        cls: "vaultguard-login-subtitle",
      });
    }

    // Error / success display
    const errorEl = contentEl.createDiv({ cls: "vaultguard-login-error" });
    errorEl.style.display = "none";

    const successEl = contentEl.createDiv({ cls: "vaultguard-reset-success" });
    successEl.style.display = "none";

    const showResetError = (msg: string) => {
      if (msg) {
        errorEl.setText(msg);
        errorEl.style.display = "";
        successEl.style.display = "none";
      } else {
        errorEl.style.display = "none";
      }
    };

    const showResetSuccess = (msg: string) => {
      if (msg) {
        successEl.setText(msg);
        successEl.style.display = "";
        errorEl.style.display = "none";
      } else {
        successEl.style.display = "none";
      }
    };

    const form = contentEl.createDiv({ cls: "vaultguard-login-form" });

    // Email field (pre-filled from login form)
    const emailGroup = form.createDiv({ cls: "vaultguard-field-group" });
    emailGroup.createEl("label", { text: "Email", cls: "vaultguard-field-label" });
    const resetEmailInput = emailGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "email", placeholder: "you@company.com", spellcheck: "false" },
    });
    resetEmailInput.value = this.email;

    // "Send Reset Code" button
    let sendCodeBtn: ButtonComponent;
    const sendCodeRow = form.createDiv({ cls: "vaultguard-reset-send-row" });
    sendCodeBtn = new ButtonComponent(sendCodeRow)
      .setButtonText("Send Reset Code")
      .setCta()
      .onClick(async () => {
        const email = resetEmailInput.value.trim();
        if (!email) {
          showResetError("Please enter your email address.");
          return;
        }

        setButtonLoading(sendCodeBtn.buttonEl, true, { label: "Sending" });
        showResetError("");

        try {
          await this.onForgotPassword!(email);
          showResetSuccess("If an account exists with this email, a reset code has been sent. Check your inbox.");
          // Show the confirmation fields
          confirmSection.style.display = "";
          setTimeout(() => codeInput.focus(), 50);
        } catch (err) {
          showResetError(err instanceof Error ? err.message : "Failed to send reset code.");
        } finally {
          if (sendCodeBtn.buttonEl.isConnected) {
            setButtonLoading(sendCodeBtn.buttonEl, false);
            sendCodeBtn.setButtonText("Resend Code");
          }
        }
      });

    // Confirmation section (hidden until code is sent)
    const confirmSection = form.createDiv({ cls: "vaultguard-reset-confirm-section" });
    confirmSection.style.display = "none";

    // Code field
    const codeGroup = confirmSection.createDiv({ cls: "vaultguard-field-group" });
    codeGroup.createEl("label", { text: "Reset Code", cls: "vaultguard-field-label" });
    codeGroup.createEl("span", {
      text: "Enter the code sent to your email",
      cls: "vaultguard-field-hint",
    });
    const codeInput = codeGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "text", placeholder: "123456", inputmode: "numeric" },
    });

    // New password field
    const newPassGroup = confirmSection.createDiv({ cls: "vaultguard-field-group" });
    newPassGroup.createEl("label", { text: "New Password", cls: "vaultguard-field-label" });
    newPassGroup.createEl("span", {
      text: "12+ characters with uppercase, lowercase, numbers, and symbols",
      cls: "vaultguard-field-hint",
    });
    const newPassInput = newPassGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "password", placeholder: "New password" },
    });

    // Confirm password field
    const confirmPassGroup = confirmSection.createDiv({ cls: "vaultguard-field-group" });
    confirmPassGroup.createEl("label", { text: "Confirm New Password", cls: "vaultguard-field-label" });
    const confirmPassInput = confirmPassGroup.createEl("input", {
      cls: "vaultguard-field-input",
      attr: { type: "password", placeholder: "Confirm new password" },
    });

    // "Reset Password" button
    let resetBtn: ButtonComponent;
    const resetRow = confirmSection.createDiv({ cls: "vaultguard-reset-send-row" });
    resetBtn = new ButtonComponent(resetRow)
      .setButtonText("Reset Password")
      .setCta()
      .onClick(async () => {
        const email = resetEmailInput.value.trim();
        const code = codeInput.value.trim();
        const newPass = newPassInput.value;
        const confirmPass = confirmPassInput.value;

        if (!code) {
          showResetError("Please enter the reset code.");
          return;
        }
        if (!newPass) {
          showResetError("Please enter a new password.");
          return;
        }
        if (newPass.length < 12) {
          showResetError("Password must be at least 12 characters.");
          return;
        }
        if (newPass !== confirmPass) {
          showResetError("Passwords do not match.");
          return;
        }

        setButtonLoading(resetBtn.buttonEl, true, { label: "Resetting" });
        showResetError("");

        try {
          await this.onConfirmReset!(email, code, newPass);
          showResetSuccess("Password reset successfully. You can now sign in with your new password.");
          // After a short delay, switch back to login form
          setTimeout(() => this.onOpen(), 2000);
        } catch (err) {
          showResetError(err instanceof Error ? err.message : "Password reset failed.");
        } finally {
          if (resetBtn.buttonEl.isConnected) {
            setButtonLoading(resetBtn.buttonEl, false);
          }
        }
      });

    confirmPassInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") resetBtn.buttonEl.click();
    });

    // Back to login link
    const actionRow = contentEl.createDiv({ cls: "vaultguard-login-actions" });
    new ButtonComponent(actionRow)
      .setButtonText("Back to Login")
      .onClick(() => this.onOpen());

    // Focus email input
    setTimeout(() => resetEmailInput.focus(), 50);
  }

  /**
   * Handles "Use Recovery Code" submissions. On success, surfaces a one-shot
   * message and switches the modal back to the password-entry state so the
   * user can sign in again — Cognito will route them to MFA_SETUP because
   * their MFA preference was cleared server-side.
   */
  private async handleRecoveryCodeSubmit(): Promise<void> {
    if (!this.onRecoveryCode) return;

    if (!this.email) {
      this.showError("Please enter your email address.");
      return;
    }
    const code = this.mfaCode.trim();
    if (!code) {
      this.showError("Please enter a recovery code.");
      return;
    }

    this.showError("");
    const submitEl = this.submitBtn?.buttonEl;
    if (submitEl) {
      setButtonLoading(submitEl, true, { label: "Verifying" });
    }

    try {
      await this.onRecoveryCode(this.email, code);
      // Reset MFA state: the next login will hit MFA_SETUP and the modal's
      // owner will reopen the setup modal automatically.
      this.recoveryMode = false;
      this.showMfa = false;
      this.mfaCode = "";
      if (this.mfaInputEl) this.mfaInputEl.value = "";
      if (this.mfaContainer) this.mfaContainer.style.display = "none";
      this.applyMfaModeUi();
      this.submitBtn?.setButtonText("Sign In");
      this.showError("");
      // Display a transient success message via the error banner (re-used as
      // an info banner) — keeps the modal lightweight.
      if (this.errorEl) {
        this.errorEl.setText(
          "Recovery code accepted. Sign in again with your password to set up a new authenticator."
        );
        this.errorEl.classList.add("vaultguard-login-success");
        this.errorEl.style.display = "";
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Recovery failed.";
      this.showError(msg);
    } finally {
      if (submitEl?.isConnected) {
        setButtonLoading(submitEl, false);
        this.submitBtn?.setButtonText(this.recoveryMode ? "Use Recovery Code" : (this.showMfa ? "Verify MFA" : "Sign In"));
      }
    }
  }
}
