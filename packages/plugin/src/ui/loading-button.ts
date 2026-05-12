/**
 * Tiny helpers for showing inline loading feedback on buttons and form
 * controls during async operations. Reuses the existing
 * `.vaultguard-sb-spinner` styles so no new CSS is needed.
 */

import { setIcon } from "obsidian";

const SAVED_CONTENT = Symbol("vaultguard-loading-saved");
const SAVED_DISABLED = Symbol("vaultguard-loading-disabled");

interface ButtonWithSavedState extends HTMLButtonElement {
  [SAVED_CONTENT]?: Node[];
  [SAVED_DISABLED]?: boolean;
}

interface ControlWithSavedState extends HTMLElement {
  [SAVED_DISABLED]?: boolean;
}

/**
 * Toggles a button into a loading state: disables it and replaces its
 * content with a spinner (optionally followed by a label). Pass
 * `loading: false` to restore the original content and disabled flag.
 */
export function setButtonLoading(
  button: HTMLButtonElement,
  loading: boolean,
  options: { label?: string } = {}
): void {
  const btn = button as ButtonWithSavedState;
  if (loading) {
    if (!btn[SAVED_CONTENT]) {
      btn[SAVED_CONTENT] = Array.from(btn.childNodes).map((node) => node.cloneNode(true));
      btn[SAVED_DISABLED] = btn.disabled;
    }
    btn.disabled = true;
    btn.replaceChildren();
    const spinner = btn.createSpan({ cls: "vaultguard-sb-spinner vaultguard-btn-spinner" });
    setIcon(spinner, "loader");
    if (options.label) {
      btn.createSpan({ text: options.label });
    }
    return;
  }

  if (btn[SAVED_CONTENT]) {
    btn.replaceChildren(...btn[SAVED_CONTENT]!);
    btn.disabled = btn[SAVED_DISABLED] ?? false;
    delete btn[SAVED_CONTENT];
    delete btn[SAVED_DISABLED];
  } else {
    btn.disabled = false;
  }
}

/**
 * Disables a non-button control (select, input) and remembers its prior
 * disabled state so the caller can restore it after the async op.
 */
export function setControlBusy(
  control: HTMLElement & { disabled?: boolean },
  busy: boolean
): void {
  const el = control as ControlWithSavedState & { disabled?: boolean };
  if (busy) {
    if (el[SAVED_DISABLED] === undefined) {
      el[SAVED_DISABLED] = el.disabled ?? false;
    }
    el.disabled = true;
    return;
  }

  el.disabled = el[SAVED_DISABLED] ?? false;
  delete el[SAVED_DISABLED];
}

/**
 * Runs an async function while toggling a button into a loading state.
 * Always restores the button on completion, even on error.
 */
export async function withButtonLoading<T>(
  button: HTMLButtonElement,
  fn: () => Promise<T>,
  options: { label?: string } = {}
): Promise<T> {
  setButtonLoading(button, true, options);
  try {
    return await fn();
  } finally {
    setButtonLoading(button, false);
  }
}
