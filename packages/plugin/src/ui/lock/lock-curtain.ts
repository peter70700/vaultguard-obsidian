/**
 * VaultGuard - Lock curtain (Phase 12, vault idle-lock)
 *
 * An OPAQUE, full-viewport overlay that blocks the workspace while the vault is
 * cryptographically locked (the LAK is evicted, so content is genuinely
 * undecryptable). It hosts the PIN / passphrase entry, an "Unlock" action, a
 * "Log in again" escape, and an error line.
 *
 * Design notes:
 * - Pure DOM, no Obsidian import, no network. The constructor takes a `Document`
 *   so it is unit-testable with an injected fake document (the plugin passes the
 *   real global `document` at runtime).
 * - A dismissible `Modal` is NOT a real boundary (Esc / click-out / hotkeys leak
 *   through), so this is a custom overlay with a very high z-index that captures
 *   keyboard + pointer — Obsidian's global hotkeys / command palette beneath it
 *   cannot fire while locked.
 * - OPAQUE by construction: a solid inline background fallback keeps it opaque
 *   even before styles.css loads, so already-rendered plaintext behind it can't
 *   show through (12-RESEARCH.md Pitfall 1). Visual polish + styles.css land in
 *   Plan 05; the class hooks are stable here.
 */

/** Root CSS class for the lock curtain (styled in Plan 05). */
export const LOCK_CURTAIN_CLS = "vaultguard-lock-curtain";

/**
 * SVG namespace for the decorative shield icon. The icon is built with the
 * INJECTED `doc` (never the global `document`) so the pure-DOM + injected-doc
 * contract holds and the curtain stays unit-testable — unlike `createShieldIcon`
 * in ../icons, which reaches for the global `document`.
 */
const SVG_NS = "http://www.w3.org/2000/svg";

export interface LockCurtainController {
  /**
   * Render the opaque curtain. `onSubmit` receives the typed secret (Enter or
   * the Unlock button); `onForgot` fires the "Log in again" escape. Idempotent:
   * a second call while shown is a no-op.
   */
  show(opts: {
    onSubmit: (secret: string) => void;
    onForgot: () => void;
    /** D1/O-2 seam: render a biometric-unlock button (never on current Obsidian). */
    biometricEnabled?: boolean;
    onBiometric?: () => void;
  }): void;
  /** Remove the curtain from the DOM. */
  hide(): void;
  /** Show an inline error (e.g. "Incorrect PIN.") and clear the input. */
  showError(message: string): void;
  /** Toggle the busy state (disables input + button while an unlock is in flight). */
  setBusy(busy: boolean): void;
}

export class LockCurtain implements LockCurtainController {
  private overlay: HTMLElement | null = null;
  private input: HTMLInputElement | null = null;
  private errorEl: HTMLElement | null = null;
  private submitBtn: HTMLButtonElement | null = null;
  private busy = false;

  constructor(private readonly doc: Document) {}

  show(opts: {
    onSubmit: (secret: string) => void;
    onForgot: () => void;
    biometricEnabled?: boolean;
    onBiometric?: () => void;
  }): void {
    if (this.overlay) return;
    const doc = this.doc;

    const overlay = doc.createElement("div");
    overlay.className = LOCK_CURTAIN_CLS;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Vault locked");

    // Opaque full-viewport top layer. The solid fallback colour guarantees
    // opacity even before styles.css (Plan 05) loads (Pitfall 1).
    const s = overlay.style;
    s.position = "fixed";
    s.inset = "0";
    s.zIndex = "2147483647";
    s.display = "flex";
    s.flexDirection = "column";
    s.alignItems = "center";
    s.justifyContent = "center";
    s.background = "var(--background-primary, #1e1e1e)";

    // Trap keyboard + pointer so Obsidian's global hotkeys / command palette
    // beneath the curtain can't fire while locked. Enter submits.
    overlay.addEventListener("keydown", (e: KeyboardEvent) => {
      e.stopPropagation();
      if (e.key === "Enter" && !this.busy) {
        this.submit(opts.onSubmit);
      }
    });
    overlay.addEventListener("mousedown", (e: Event) => e.stopPropagation());
    overlay.addEventListener("contextmenu", (e: Event) => {
      e.preventDefault();
      e.stopPropagation();
    });

    const card = doc.createElement("div");
    card.className = `${LOCK_CURTAIN_CLS}__card`;

    // Decorative shield icon (visual parity with the login modal, quick
    // 260708-g9m) — the FIRST child of the card. Built via the INJECTED doc's
    // createElementNS, best-effort: hosts/tests without createElementNS still get
    // the wrapper (and never throw), so the security boundary below is unchanged.
    const iconWrap = doc.createElement("div");
    iconWrap.className = `${LOCK_CURTAIN_CLS}__icon`;
    const anyDoc = doc as unknown as {
      createElementNS?: (ns: string, tag: string) => any;
    };
    if (typeof anyDoc.createElementNS === "function") {
      const svg = anyDoc.createElementNS(SVG_NS, "svg");
      svg.setAttribute("width", "48");
      svg.setAttribute("height", "48");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("fill", "none");
      svg.setAttribute("stroke", "currentColor");
      svg.setAttribute("stroke-width", "1.5");
      svg.setAttribute("stroke-linecap", "round");
      svg.setAttribute("stroke-linejoin", "round");
      const p1 = anyDoc.createElementNS(SVG_NS, "path");
      p1.setAttribute("d", "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z");
      const p2 = anyDoc.createElementNS(SVG_NS, "path");
      p2.setAttribute("d", "m9 12 2 2 4-4");
      svg.appendChild(p1);
      svg.appendChild(p2);
      iconWrap.appendChild(svg);
    }
    card.appendChild(iconWrap);

    const heading = doc.createElement("h2");
    heading.className = `${LOCK_CURTAIN_CLS}__title`;
    heading.textContent = "Vault locked";
    card.appendChild(heading);

    const sub = doc.createElement("p");
    sub.className = `${LOCK_CURTAIN_CLS}__subtitle`;
    sub.textContent =
      "VaultGuard locked this vault after inactivity. Enter your PIN to unlock — your notes stay encrypted until you do.";
    card.appendChild(sub);

    const input = doc.createElement("input");
    input.type = "password";
    input.className = `${LOCK_CURTAIN_CLS}__input`;
    input.setAttribute("autocomplete", "off");
    input.setAttribute("aria-label", "PIN or passphrase");
    input.placeholder = "PIN or passphrase";
    card.appendChild(input);

    const errorEl = doc.createElement("div");
    errorEl.className = `${LOCK_CURTAIN_CLS}__error`;
    errorEl.setAttribute("role", "alert");
    card.appendChild(errorEl);

    const submitBtn = doc.createElement("button");
    submitBtn.type = "button";
    submitBtn.className = `${LOCK_CURTAIN_CLS}__unlock`;
    submitBtn.textContent = "Unlock";
    submitBtn.addEventListener("click", () => {
      if (!this.busy) this.submit(opts.onSubmit);
    });
    card.appendChild(submitBtn);

    // D1/O-2 seam: a biometric-unlock button, rendered ONLY when the caller
    // reports the platform supports it (biometricAvailable()) — which is never
    // on current Obsidian, so this stays hidden today and drops in additively.
    if (opts.biometricEnabled && opts.onBiometric) {
      const bio = doc.createElement("button");
      bio.type = "button";
      bio.className = `${LOCK_CURTAIN_CLS}__biometric`;
      bio.textContent = "Unlock with biometrics";
      bio.addEventListener("click", () => {
        if (!this.busy) opts.onBiometric!();
      });
      card.appendChild(bio);
    }

    const forgot = doc.createElement("a");
    forgot.className = `${LOCK_CURTAIN_CLS}__forgot`;
    forgot.textContent = "Log in again";
    forgot.setAttribute("role", "button");
    forgot.setAttribute("tabindex", "0");
    forgot.addEventListener("click", (e: Event) => {
      e.preventDefault();
      opts.onForgot();
    });
    card.appendChild(forgot);

    overlay.appendChild(card);
    doc.body.appendChild(overlay);

    this.overlay = overlay;
    this.input = input;
    this.errorEl = errorEl;
    this.submitBtn = submitBtn;
    this.busy = false;

    try {
      input.focus();
    } catch {
      /* focus is best-effort (unavailable in some hosts/tests) */
    }
  }

  private submit(onSubmit: (secret: string) => void): void {
    onSubmit(this.input?.value ?? "");
  }

  showError(message: string): void {
    this.setBusy(false);
    if (this.errorEl) this.errorEl.textContent = message;
    if (this.input) {
      this.input.value = "";
      try {
        this.input.focus();
      } catch {
        /* best-effort */
      }
    }
  }

  setBusy(busy: boolean): void {
    this.busy = busy;
    if (this.submitBtn) {
      this.submitBtn.disabled = busy;
      this.submitBtn.textContent = busy ? "Unlocking…" : "Unlock";
    }
    if (this.input) this.input.disabled = busy;
  }

  hide(): void {
    if (this.overlay) {
      try {
        this.overlay.remove();
      } catch {
        /* best-effort */
      }
    }
    this.overlay = null;
    this.input = null;
    this.errorEl = null;
    this.submitBtn = null;
    this.busy = false;
  }
}
