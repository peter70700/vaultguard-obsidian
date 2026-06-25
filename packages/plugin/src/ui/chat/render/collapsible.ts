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
    root.toggleClass(OPEN_CLS, open);
    root.toggleClass(COLLAPSED_CLS, !open);
    root.style.setProperty("display", "block", "important");
    root.style.setProperty("flex", "0 0 auto");
    root.style.setProperty("overflow", "hidden");
    header.hidden = false;
    header.setAttr("aria-expanded", String(open));
    header.style.setProperty("display", "flex", "important");
    header.style.setProperty("min-height", "30px");
    body.hidden = !open;
    if (open) {
      root.style.setProperty("height", "auto", "important");
      root.style.removeProperty("min-height");
      root.style.removeProperty("max-height");
      body.style.setProperty("display", "block", "important");
      body.style.setProperty("visibility", "visible", "important");
      body.style.setProperty("height", "auto", "important");
      body.style.setProperty("min-height", "0");
      body.style.removeProperty("max-height");
      body.style.setProperty("overflow", "visible");
    } else {
      root.style.setProperty("height", "32px", "important");
      root.style.setProperty("min-height", "32px");
      body.style.removeProperty("visibility");
      body.style.setProperty("overflow", "hidden");
      body.style.setProperty("height", "0", "important");
      body.style.setProperty("min-height", "0");
      body.style.setProperty("display", "none", "important");
    }
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
