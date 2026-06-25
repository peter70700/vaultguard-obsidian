// Reusable collapsible primitive for the chat panel (AI-CHAT-PANEL.md §9, the
// `render/collapsible.ts` equivalent). Vanilla DOM, no deps — a header row with
// a chevron + label and a body that toggles open/closed. Used by the thinking
// renderer and the tool-call cards.

import { setIcon } from "obsidian";

const ROOT_CLS = "vaultguard-chat-collapsible";
const HEADER_CLS = "vaultguard-chat-collapsible-header";
const CHEVRON_CLS = "vaultguard-chat-collapsible-chevron";
const LABEL_CLS = "vaultguard-chat-collapsible-label";
const BODY_CLS = "vaultguard-chat-collapsible-body";
const OPEN_CLS = "is-open";
const COLLAPSED_CLS = "vaultguard-chat-is-collapsed";

export interface CollapsibleOptions {
  /** Initial open state. Defaults to false (collapsed). */
  open?: boolean;
  /** Extra class added to the root element (e.g. a variant marker). */
  extraClass?: string;
}

export interface Collapsible {
  /** The outer element to append to the message list. */
  root: HTMLElement;
  /** The clickable header — append label content here if not using setLabel. */
  header: HTMLElement;
  /** The body element — append rendered content here. */
  body: HTMLElement;
  /** Replace the header label text. */
  setLabel(text: string): void;
  /** Programmatically open or close. */
  setOpen(open: boolean): void;
  /** Re-apply layout state after streamed/late body content changes. */
  refreshLayout(): void;
  /** Current open state. */
  isOpen(): boolean;
}

/**
 * Create a collapsible block. The header toggles the body on click; the body
 * starts collapsed unless `open` is true.
 */
export function createCollapsible(parent: HTMLElement, options: CollapsibleOptions = {}): Collapsible {
  const root = parent.createDiv({ cls: ROOT_CLS });
  if (options.extraClass) root.addClass(options.extraClass);

  const header = root.createDiv({ cls: HEADER_CLS });
  const chevron = header.createSpan({ cls: CHEVRON_CLS });
  setIcon(chevron, "chevron-right");
  const label = header.createSpan({ cls: LABEL_CLS });

  const body = root.createDiv({ cls: BODY_CLS });

  let open = options.open === true;

  const apply = (): void => {
    // Layout is driven entirely by CSS keyed on these two classes (the
    // `.is-open` / `.vaultguard-chat-is-collapsed` rules in styles.css carry the
    // same display/height/overflow values, with `!important` where needed). Keep
    // this to class + attribute toggles so no inline styles are set — the
    // Obsidian `no-static-styles-assignment` rule forbids direct `.style` writes.
    root.toggleClass(OPEN_CLS, open);
    root.toggleClass(COLLAPSED_CLS, !open);
    header.hidden = false;
    header.setAttr("aria-expanded", String(open));
    body.hidden = !open;
  };
  apply();

  header.addEventListener("click", () => {
    const wasOpen = open;
    open = !open;
    apply();
    if (!wasOpen && open) {
      window.requestAnimationFrame(() => body.scrollIntoView({ block: "nearest", inline: "nearest" }));
    }
  });

  return {
    root,
    header,
    body,
    setLabel: (text: string) => label.setText(text),
    setOpen: (next: boolean) => {
      open = next;
      apply();
    },
    refreshLayout: apply,
    isOpen: () => open,
  };
}

export { ROOT_CLS as COLLAPSIBLE_ROOT_CLS };
