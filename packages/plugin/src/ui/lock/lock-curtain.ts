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

/** Hidden-state class, toggled instead of an inline `display` assignment. */
export const LOCK_CURTAIN_HIDDEN_CLS = `${LOCK_CURTAIN_CLS}__hidden`;

/**
 * Toggle the hidden class through `className`, not `classList` or `style` — the
 * curtain's DOM contract is the injected `doc`, which unit tests satisfy with a
 * minimal element shape, and inline style assignment is an Obsidian
 * reviewer-blocking rule (`no-static-styles-assignment`).
 */
function setHidden(el: HTMLElement, hidden: boolean): void {
  const classes = String(el.className ?? "")
    .split(/\s+/)
    .filter((c) => c && c !== LOCK_CURTAIN_HIDDEN_CLS);
  if (hidden) classes.push(LOCK_CURTAIN_HIDDEN_CLS);
  el.className = classes.join(" ");
}

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
  /**
   * Ask a yes/no question INSIDE the curtain.
   *
   * Anything that needs a decision while the vault is locked has to render here.
   * An Obsidian `Modal` cannot: `.modal-container` is `z-index: var(--layer-modal)`
   * — 50 — and this curtain is 2147483647, so a modal opened over the lock is
   * painted behind an opaque surface and is invisible and unreachable.
   */
  confirm(opts: {
    title: string;
    body: string;
    confirmLabel: string;
    cancelLabel?: string;
    onConfirm: () => void;
  }): void;
}

export class LockCurtain implements LockCurtainController {
  private overlay: HTMLElement | null = null;
  private input: HTMLInputElement | null = null;
  private errorEl: HTMLElement | null = null;
  private submitBtn: HTMLButtonElement | null = null;
  private busy = false;
  private card: HTMLElement | null = null;
  /**
   * What the focus trap reclaims to. Normally the PIN field; while the in-curtain
   * confirm panel is open the field is `display: none`, and focusing a hidden
   * element silently does nothing — which would leave focus stranded on `body`
   * with the trap unable to recover it.
   */
  private reclaimTarget: HTMLElement | null = null;
  /** Document-level trap handlers, held so `hide()` can remove every one. */
  private docFocusIn: ((e: Event) => void) | null = null;
  private docKeyDown: ((e: Event) => void) | null = null;

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
    // Pointer down anywhere on the curtain — including the empty backdrop —
    // returns focus to the field. Cheap one-click recovery from any state where
    // focus ended up elsewhere, and it never fights a click on the buttons
    // (those are handled by the focus trap's "inside the overlay" test).
    overlay.addEventListener("mousedown", (e: Event) => {
      e.stopPropagation();
      const target = (e as unknown as { target?: unknown }).target;
      if (target === overlay) this.focusInput();
    });
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
      svg.setAttribute("viewBox", "0 0 96 96");
      svg.setAttribute("fill", "none");
      svg.setAttribute("stroke", "currentColor");
      svg.setAttribute("stroke-linejoin", "round");
      // The approved Mineral Governance mark at 48px. Geometry and stroke
      // weights are kept BYTE-IDENTICAL to `createShieldIcon` in ../icons —
      // this curtain renders at the same size and is meant to read as the same
      // mark, it only rebuilds it against the injected `doc` instead of the
      // global one. Change one, change both.
      for (const [d, width] of [
        ["M48 4 87 19v28c0 23-15 38-39 47C24 85 9 70 9 47V19L48 4Z", "2.24"],
        ["M48 11 80 23v23c0 20-12 33-32 42-20-9-32-22-32-42V23l32-12Z", "3.52"],
        ["M48 26 65 34v15c0 11-6 19-17 25-11-6-17-14-17-25V34l17-8Z", "2.72"],
      ]) {
        const path = anyDoc.createElementNS(SVG_NS, "path");
        path.setAttribute("d", d);
        path.setAttribute("stroke-width", width);
        svg.appendChild(path);
      }
      const lock = anyDoc.createElementNS(SVG_NS, "rect");
      lock.setAttribute("x", "42");
      lock.setAttribute("y", "41");
      lock.setAttribute("width", "12");
      lock.setAttribute("height", "12");
      lock.setAttribute("rx", "2");
      lock.setAttribute("fill", "currentColor");
      lock.setAttribute("stroke", "none");
      svg.appendChild(lock);
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
    this.card = card;
    this.input = input;
    this.errorEl = errorEl;
    this.submitBtn = submitBtn;
    this.busy = false;

    this.installFocusTrap();
    this.claimFocus();
  }

  /**
   * Hold the field against anything that takes focus away.
   *
   * This is not defensive padding — it is the fix for a confirmed theft. The
   * plugin detaches every content leaf immediately before showing the curtain,
   * which leaves Obsidian's `activeLeaf` unattached; `Workspace.onLayoutChange`
   * then queues `updateLayout` through `queueMicrotask`, and that deferred pass
   * creates a replacement leaf and calls `setActiveLeaf(leaf, {focus: true})`.
   * Our synchronous `input.focus()` runs BEFORE that microtask, so focus landed
   * in a workspace leaf hidden behind the opaque curtain and the PIN could not
   * be typed at all.
   *
   * Racing that one stealer with a later focus call would be guesswork, so the
   * trap is unconditional: focus that lands outside the overlay is pulled back,
   * and a key event that originates outside it is swallowed. The second half is
   * what makes this class's "Obsidian's global hotkeys cannot fire while
   * locked" claim actually true — the overlay-level listener only ever saw
   * events that were already inside the overlay, so a stolen focus silently
   * voided the boundary.
   *
   * Capture phase, so nothing downstream can consume the event first.
   */
  private installFocusTrap(): void {
    const doc = this.doc as unknown as {
      addEventListener?: (t: string, cb: (e: Event) => void, capture?: boolean) => void;
    };
    if (typeof doc.addEventListener !== "function") return;

    this.docFocusIn = (e: Event) => {
      if (!this.overlay) return;
      const target = (e as unknown as { target?: unknown }).target;
      if (this.containsNode(target)) return;
      this.focusInput();
    };
    this.docKeyDown = (e: Event) => {
      if (!this.overlay) return;
      const target = (e as unknown as { target?: unknown }).target;
      if (this.containsNode(target)) return;
      // Originated outside the curtain while the vault is locked: it must not
      // reach Obsidian's keymap, and the keystroke must not be silently eaten
      // either — pull focus back so the user's next character lands in the field.
      const ev = e as unknown as {
        preventDefault?: () => void;
        stopImmediatePropagation?: () => void;
        stopPropagation?: () => void;
      };
      ev.preventDefault?.();
      ev.stopImmediatePropagation?.();
      ev.stopPropagation?.();
      this.focusInput();
    };

    doc.addEventListener("focusin", this.docFocusIn, true);
    doc.addEventListener("keydown", this.docKeyDown, true);
  }

  private removeFocusTrap(): void {
    const doc = this.doc as unknown as {
      removeEventListener?: (t: string, cb: (e: Event) => void, capture?: boolean) => void;
    };
    if (typeof doc.removeEventListener === "function") {
      if (this.docFocusIn) doc.removeEventListener("focusin", this.docFocusIn, true);
      if (this.docKeyDown) doc.removeEventListener("keydown", this.docKeyDown, true);
    }
    this.docFocusIn = null;
    this.docKeyDown = null;
  }

  /** True when `node` is the overlay or lives inside it. */
  private containsNode(node: unknown): boolean {
    const overlay = this.overlay as unknown as {
      contains?: (n: unknown) => boolean;
    } | null;
    if (!overlay || !node) return false;
    if (node === overlay) return true;
    return typeof overlay.contains === "function" ? !!overlay.contains(node) : false;
  }

  /**
   * Focus the field now and again across the window in which the deferred
   * `updateLayout` fires. The microtask hop covers the exact documented
   * stealer; the frame and the short timeout cover a host that defers it
   * further (`wc` falls back to `setTimeout` when `queueMicrotask` is missing).
   * Every hop re-checks `this.overlay`, so a curtain torn down in between never
   * yanks focus out of the workspace the user just got back.
   */
  private claimFocus(): void {
    this.focusInput();
    const win = (this.doc as unknown as { defaultView?: unknown }).defaultView as
      | {
          queueMicrotask?: (cb: () => void) => void;
          requestAnimationFrame?: (cb: () => void) => void;
          setTimeout?: (cb: () => void, ms: number) => unknown;
        }
      | undefined;
    if (!win) return;
    const again = () => {
      if (this.overlay) this.focusInput();
    };
    try {
      win.queueMicrotask?.(again);
      win.requestAnimationFrame?.(again);
      win.setTimeout?.(again, 50);
    } catch {
      /* scheduling is best-effort — the trap below is the real guarantee */
    }
  }

  private focusInput(): void {
    const target = this.reclaimTarget ?? this.input;
    if (!target) return;
    if ((target as unknown as { disabled?: boolean }).disabled) return;
    try {
      target.focus();
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
      this.focusInput();
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

  confirm(opts: {
    title: string;
    body: string;
    confirmLabel: string;
    cancelLabel?: string;
    onConfirm: () => void;
  }): void {
    const card = this.card;
    if (!card) return;
    const doc = this.doc;

    // Hide the unlock form rather than destroying it: cancelling has to restore
    // the exact same input (and whatever the user had already typed) without
    // re-running show(), which would re-install the trap and re-render the card.
    const previous = [...((card.children ?? []) as unknown as HTMLElement[])];
    for (const child of previous) setHidden(child, true);

    const panel = doc.createElement("div");
    panel.className = `${LOCK_CURTAIN_CLS}__confirm`;

    const title = doc.createElement("h2");
    title.className = `${LOCK_CURTAIN_CLS}__title`;
    title.textContent = opts.title;
    panel.appendChild(title);

    const body = doc.createElement("p");
    body.className = `${LOCK_CURTAIN_CLS}__subtitle`;
    body.textContent = opts.body;
    panel.appendChild(body);

    const restore = () => {
      this.reclaimTarget = null;
      panel.remove();
      for (const child of previous) setHidden(child, false);
      this.focusInput();
    };

    const confirmBtn = doc.createElement("button");
    confirmBtn.type = "button";
    confirmBtn.className = `${LOCK_CURTAIN_CLS}__unlock ${LOCK_CURTAIN_CLS}__confirm-go`;
    confirmBtn.textContent = opts.confirmLabel;
    confirmBtn.addEventListener("click", () => {
      restore();
      opts.onConfirm();
    });
    panel.appendChild(confirmBtn);

    const cancelBtn = doc.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = `${LOCK_CURTAIN_CLS}__biometric`;
    cancelBtn.textContent = opts.cancelLabel ?? "Cancel";
    cancelBtn.addEventListener("click", restore);
    panel.appendChild(cancelBtn);

    card.appendChild(panel);
    this.reclaimTarget = confirmBtn;
    this.focusInput();
  }

  hide(): void {
    // FIRST, before anything can throw: a capture-phase focus trap that outlives
    // its curtain would fight every input in the app forever. Both handlers also
    // no-op on a null `overlay`, so the two guards are independent.
    this.removeFocusTrap();
    if (this.overlay) {
      try {
        this.overlay.remove();
      } catch {
        /* best-effort */
      }
    }
    this.overlay = null;
    this.card = null;
    this.reclaimTarget = null;
    this.input = null;
    this.errorEl = null;
    this.submitBtn = null;
    this.busy = false;
  }
}
