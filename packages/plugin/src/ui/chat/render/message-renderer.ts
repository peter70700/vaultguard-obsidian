// User + assistant message bubbles (AI-CHAT-PANEL.md §9.2).
//
// User bubbles are plain text (never markdown-rendered — a user pasting `[[`
// or backticks should see them literally, and rendering user input as markdown
// is a needless surface). Assistant bubbles render markdown through Obsidian's
// own `MarkdownRenderer`, which gives wikilinks, code highlighting, and callouts
// for free — a leg up that a non-Obsidian chat UI can't match.
//
// This renderer NEVER touches the filesystem. It only formats strings the
// runtime hands it.

import { type App, type Component, MarkdownRenderer, setIcon } from "obsidian";

import type { AnthropicImageBlock } from "../anthropic-client";
import { stripChatThematicBreaks } from "../message-utils";

const MSG_CLS = "vaultguard-chat-message";
const USER_CLS = "vaultguard-chat-message-user";
const ASSISTANT_CLS = "vaultguard-chat-message-assistant";
const BUBBLE_CLS = "vaultguard-chat-bubble";

export interface AssistantBubble {
  root: HTMLElement;
  bubble: HTMLElement;
  /** Append (and markdown-render) more assistant text into this bubble. */
  appendMarkdown(md: string): boolean;
  /** The full raw markdown accumulated so far (drives the copy-message action). */
  getRawText(): string;
}

/**
 * Copy-to-clipboard affordance. Uses the Clipboard API (a local OS action, not a
 * network call — allowed under the Networking Rule). Flashes a check on success.
 */
function addCopyButton(host: HTMLElement, getText: () => string, label: string): HTMLElement {
  const btn = host.createSpan({
    cls: "vaultguard-chat-copy-btn clickable-icon",
    attr: { "aria-label": label, title: label },
  });
  setIcon(btn, "copy");
  btn.addEventListener("click", (evt) => {
    evt.stopPropagation();
    const text = getText();
    if (!text) return;
    void navigator.clipboard.writeText(text).then(
      () => {
        setIcon(btn, "check");
        window.setTimeout(() => setIcon(btn, "copy"), 1200);
      },
      () => {
        /* clipboard denied — leave the icon unchanged */
      },
    );
  });
  return btn;
}

/** Add a per-code-block copy button to every <pre> in a rendered chunk. */
function decorateCodeBlocks(chunk: HTMLElement): void {
  chunk.querySelectorAll("pre").forEach((preNode) => {
    const pre = preNode as HTMLElement;
    if (pre.querySelector(".vaultguard-chat-code-copy")) return;
    const code = pre.querySelector("code");
    pre.addClass("vaultguard-chat-code-pre");
    const btn = addCopyButton(pre, () => code?.textContent ?? pre.textContent ?? "", "Copy code");
    btn.addClass("vaultguard-chat-code-copy");
  });
}

function hasMeaningfulRenderedContent(el: HTMLElement): boolean {
  if ((el.textContent ?? "").trim()) return true;
  return Boolean(el.querySelector("img, video, audio, canvas, svg, pre, code, table, ul, ol"));
}

function removeChatRules(el: HTMLElement): void {
  // Literal HTML <hr> can bypass the markdown-line sanitizer; remove it from
  // assistant/error bubbles so divider-only chunks do not become stacked rules.
  el.querySelectorAll("hr").forEach((hr) => hr.remove());
}

function removeEmptyAssistantShellFrom(child: HTMLElement): void {
  const bubble = child.closest(`.${BUBBLE_CLS}`) as HTMLElement | null;
  if (!bubble || hasMeaningfulRenderedContent(bubble)) return;
  const root = bubble.closest(`.${MSG_CLS}.${ASSISTANT_CLS}`) as HTMLElement | null;
  if (root && !root.classList.contains(PENDING_CLS)) root.remove();
}

/**
 * Render assistant/error markdown without ever leaving an empty styled shell.
 *
 * The chat view streams plain text first, then finalizes via Obsidian's async
 * MarkdownRenderer. If that render rejects or yields no visible content, the
 * user must still see the text instead of a border/background-only line.
 */
export function renderMarkdownWithFallback(
  host: HTMLElement,
  app: App,
  component: Component,
  sourcePath: string,
  markdown: string,
): void {
  host.empty();

  const fallback = host.createDiv({
    cls: "vaultguard-chat-md-fallback",
    text: markdown,
  });
  const renderTarget = host.createDiv({ cls: "vaultguard-chat-md-render-target" });
  renderTarget.style.display = "none";

  void MarkdownRenderer.render(app, markdown, renderTarget, sourcePath, component).then(
    () => {
      removeChatRules(renderTarget);
      decorateCodeBlocks(renderTarget);

      if (!hasMeaningfulRenderedContent(renderTarget)) {
        const parent = host.parentElement;
        host.remove();
        if (parent instanceof HTMLElement) removeEmptyAssistantShellFrom(parent);
        return;
      }

      fallback.remove();
      while (renderTarget.firstChild) {
        host.appendChild(renderTarget.firstChild);
      }
      renderTarget.remove();
      decorateCodeBlocks(host);
    },
    () => {
      renderTarget.remove();
    },
  );
}

const PENDING_CLS = "vaultguard-chat-pending";

export interface PendingIndicator {
  /** Remove the placeholder bubble from the list. */
  remove(): void;
  /** Re-append to the end of the parent so it stays pinned below new content. */
  moveToEnd(): void;
  /** Replace the visible activity label with transport-specific progress text. */
  setLabel(text: string): void;
  /**
   * Toggle the "paused, waiting on a human answer" state. When on, the label
   * reads "Waiting for your answer…" and the animated dots freeze; when off, it
   * reverts to the working state so a resumed turn looks live again.
   */
  setWaiting(waiting: boolean): void;
}

/**
 * Render an assistant-aligned "Working…" indicator. Shown the moment a turn
 * starts (immediate feedback before the first token/delta) and kept for the
 * whole turn as a persistent activity signal — the caller pins it to the bottom
 * via {@link PendingIndicator.moveToEnd} as bubbles/tool cards append, and
 * removes it when the turn ends. Pure DOM; touches no filesystem, no vault.
 */
export function renderPendingIndicator(parent: HTMLElement): PendingIndicator {
  const root = parent.createDiv({ cls: `${MSG_CLS} ${ASSISTANT_CLS} ${PENDING_CLS}` });
  const bubble = root.createDiv({ cls: BUBBLE_CLS });
  const dots = bubble.createDiv({ cls: "vaultguard-chat-pending-dots" });
  dots.createSpan({ cls: "vaultguard-chat-pending-dot" });
  dots.createSpan({ cls: "vaultguard-chat-pending-dot" });
  dots.createSpan({ cls: "vaultguard-chat-pending-dot" });
  const label = bubble.createSpan({ cls: "vaultguard-chat-pending-label", text: "Working…" });
  let waiting = false;
  return {
    remove: () => root.remove(),
    moveToEnd: () => parent.appendChild(root),
    // Ignore transport status updates while paused on a human answer so a
    // late-arriving "Working…" doesn't clobber the waiting label.
    setLabel: (text: string) => {
      if (waiting) return;
      label.setText(text.trim() || "Working…");
    },
    setWaiting: (next: boolean) => {
      waiting = next;
      root.toggleClass("is-waiting", next);
      label.setText(next ? "Waiting for your answer…" : "Working…");
    },
  };
}

export interface UserMessageActions {
  /** Re-open this prompt for editing (truncates the conversation here). */
  onEdit(): void;
  /** Delete this prompt and everything after it. */
  onDelete(): void;
}

/** Render a user bubble (plain text + optional image thumbnails + hover actions). */
export function renderUserMessage(
  parent: HTMLElement,
  text: string,
  actions?: UserMessageActions,
  images?: AnthropicImageBlock[],
): HTMLElement {
  const root = parent.createDiv({ cls: `${MSG_CLS} ${USER_CLS}` });
  const bubble = root.createDiv({ cls: BUBBLE_CLS });

  if (images && images.length > 0) {
    const gallery = bubble.createDiv({ cls: "vaultguard-chat-bubble-images" });
    for (const img of images) {
      gallery.createEl("img", {
        cls: "vaultguard-chat-bubble-image",
        attr: { src: `data:${img.source.media_type};base64,${img.source.data}`, alt: "attachment" },
      });
    }
  }

  // Plain text — preserve newlines, never interpret markdown.
  if (text) bubble.createDiv({ cls: "vaultguard-chat-bubble-text", text });

  const canCopyPrompt = text.length > 0;
  if (actions || canCopyPrompt) {
    const tools = root.createDiv({ cls: "vaultguard-chat-user-actions" });
    if (canCopyPrompt) {
      addCopyButton(tools, () => text, "Copy prompt");
    }
    if (actions) {
      const editBtn = tools.createSpan({
        cls: "clickable-icon",
        attr: { "aria-label": "Edit message", title: "Edit message" },
      });
      setIcon(editBtn, "pencil");
      editBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        actions.onEdit();
      });
      const delBtn = tools.createSpan({
        cls: "clickable-icon",
        attr: { "aria-label": "Delete message", title: "Delete message and everything after" },
      });
      setIcon(delBtn, "trash");
      delBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        actions.onDelete();
      });
    }
  }

  return root;
}

/**
 * Create an assistant bubble. `app`/`component`/`sourcePath` are threaded to
 * `MarkdownRenderer.render` so links, embeds, and code blocks resolve against
 * the active vault context. The bubble can receive multiple markdown chunks
 * across a multi-step turn via `appendMarkdown`.
 */
export function renderAssistantMessage(
  parent: HTMLElement,
  app: App,
  component: Component,
  sourcePath: string,
  initialMarkdown = "",
): AssistantBubble {
  const root = parent.createDiv({ cls: `${MSG_CLS} ${ASSISTANT_CLS}` });
  const bubble = root.createDiv({ cls: BUBBLE_CLS });
  let raw = "";

  const appendMarkdown = (md: string): boolean => {
    // Drop stray markdown thematic breaks (Claude separates "working…" narration
    // steps with `---`, which Obsidian renders as full-width <hr> noise). A block
    // that sanitises to nothing (whitespace / separators only) renders no chunk.
    const text = stripChatThematicBreaks(md);
    if (!text) {
      if (!raw && !hasMeaningfulRenderedContent(bubble)) root.remove();
      return false;
    }
    // Track the raw markdown so the copy-message action yields source text, not
    // rendered HTML. Blocks are joined with a blank line so paragraphs/code
    // fences don't run together.
    raw = raw ? `${raw}\n\n${text}` : text;
    // Each chunk renders into its own wrapper so successive onText calls stack
    // cleanly without re-parsing earlier content.
    const chunk = bubble.createDiv({ cls: "vaultguard-chat-md-chunk" });
    renderMarkdownWithFallback(chunk, app, component, sourcePath, text);
    return true;
  };

  // Hover action: copy the whole assistant message as markdown.
  addCopyButton(root, () => raw, "Copy message").addClass("vaultguard-chat-message-copy");

  if (initialMarkdown) appendMarkdown(initialMarkdown);

  return { root, bubble, appendMarkdown, getRawText: () => raw };
}

export { MSG_CLS, USER_CLS, ASSISTANT_CLS, BUBBLE_CLS };
