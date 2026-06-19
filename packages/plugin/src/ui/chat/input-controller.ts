// Input controller for the chat panel (AI-CHAT-PANEL.md §9.6). Self-contained:
// it owns the textarea + send/stop button and talks to the view ONLY through
// callbacks (onSubmit / onCancel / onSlash). No view coupling, no filesystem.
//
//  - auto-grow textarea, capped at ~6 lines
//  - Enter = send, Shift+Enter = newline
//  - Esc = cancel a running turn (when busy)
//  - slash commands: built-in `/clear`, `/model <id>`, plus user-defined prompt
//    templates resolved via the resolveTemplate callback
//  - `@`-mention note picker (candidates supplied by the view; metadata only)
//  - optional image attachments (button + paste), desktop/API-key only

import { Notice, setIcon } from "obsidian";

const BAR_CLS = "vaultguard-chat-input-bar";
const TEXTAREA_CLS = "vaultguard-chat-input";
const SEND_BTN_CLS = "vaultguard-chat-send-btn";
const MAX_ROWS = 6;
const LINE_HEIGHT_PX = 22;

// Anthropic vision accepts only these media types; anything else 400s, so we
// reject unsupported images at attach time with a clear notice rather than
// failing the whole turn later.
const SUPPORTED_IMAGE_TYPES = new Set(["image/jpeg", "image/png", "image/gif", "image/webp"]);

export type SlashCommand =
  | { kind: "clear" }
  | { kind: "model"; model: string };

export interface MentionCandidate {
  /** Vault-relative path, e.g. "project-x/Plan.md" — what gets injected + read. */
  path: string;
  /** Basename for the primary label. */
  name: string;
}

export interface ImageAttachment {
  /** MIME type, e.g. "image/png". */
  mediaType: string;
  /** Base64 image bytes (no data: prefix). */
  data: string;
  /** Original filename for the thumbnail label / alt text. */
  name: string;
}

export interface InputControllerOptions {
  /** Show the image-attach affordance + accept pasted/dropped images. */
  enableImages?: boolean;
}

export interface InputControllerCallbacks {
  /** A plain message the user wants to send, optionally with image attachments. */
  onSubmit(text: string, images?: ImageAttachment[]): void;
  /**
   * Synchronous preflight for UI-level rejection before the controller clears
   * the draft/attachments (for example: no API key stored, or image-only input
   * in subscription mode). Return false to keep the input as-is.
   */
  canSubmit?(text: string, images?: ImageAttachment[]): boolean;
  /** Esc / Stop while a turn is running. */
  onCancel(): void;
  /** A recognized slash command. */
  onSlash(cmd: SlashCommand): void;
  /** An unrecognized slash command (so the view can surface a notice). */
  onUnknownSlash?(raw: string): void;
  /**
   * Resolve a non-built-in slash command as a user-defined prompt template.
   * Returns the expanded prompt to send, or null if no template matches `name`.
   */
  resolveTemplate?(name: string, arg: string): string | null;
  /**
   * Resolve note candidates for an `@`-mention query (the view supplies these
   * from the Obsidian vault file list — metadata only, never file content, so
   * the at-rest boundary is untouched). Omit to disable @-mentions.
   */
  getMentionCandidates?(query: string): MentionCandidate[];
}

const MENTION_LIMIT = 8;

export type ParsedSlash =
  | SlashCommand
  | { kind: "unknown"; raw: string; name: string; arg: string };

/**
 * Parse a leading-slash line into a SlashCommand. Returns null for non-slash
 * input. Unknown commands return `{kind:"unknown", name, arg, raw}` so the
 * caller can try to resolve them as a user-defined prompt template before
 * surfacing an "unknown command" notice. Built-ins (/clear, /model) always win.
 */
export function parseSlash(text: string): ParsedSlash | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("/")) return null;

  const [cmd, ...rest] = trimmed.slice(1).split(/\s+/);
  const arg = rest.join(" ").trim();
  const name = cmd.toLowerCase();

  switch (name) {
    case "clear":
      return { kind: "clear" };
    case "model":
      if (!arg) return { kind: "unknown", raw: trimmed, name, arg };
      return { kind: "model", model: arg };
    default:
      return { kind: "unknown", raw: trimmed, name, arg };
  }
}

export class InputController {
  private readonly textarea: HTMLTextAreaElement;
  private readonly sendBtn: HTMLButtonElement;
  private busy = false;

  // @-mention suggestion state.
  private readonly mentionPopup: HTMLElement;
  private mentionItems: MentionCandidate[] = [];
  private mentionActive = -1;
  private mentionAtIndex = -1;

  // Image attachment state (desktop, API-key mode).
  private readonly enableImages: boolean;
  private readonly attachmentsEl: HTMLElement | null = null;
  private pendingImages: ImageAttachment[] = [];

  constructor(
    parent: HTMLElement,
    private readonly callbacks: InputControllerCallbacks,
    options: InputControllerOptions = {},
  ) {
    this.enableImages = options.enableImages === true;
    const bar = parent.createDiv({ cls: BAR_CLS });

    this.mentionPopup = bar.createDiv({ cls: "vaultguard-chat-mention-popup" });
    this.mentionPopup.hide();

    if (this.enableImages) {
      this.attachmentsEl = bar.createDiv({ cls: "vaultguard-chat-attachments" });
      this.attachmentsEl.hide();
    }

    this.textarea = bar.createEl("textarea", {
      cls: TEXTAREA_CLS,
      attr: {
        placeholder: "Ask about your vault…  (Enter to send, Shift+Enter for newline)",
        rows: "1",
        spellcheck: "true",
      },
    });

    if (this.enableImages) this.buildAttachButton(bar);

    this.sendBtn = bar.createEl("button", {
      cls: SEND_BTN_CLS,
      attr: { type: "button", "aria-label": "Send" },
      text: "Send",
    });

    this.textarea.addEventListener("input", () => {
      this.autoGrow();
      this.updateMentions();
    });
    this.textarea.addEventListener("keydown", (evt) => this.onKeyDown(evt));
    // Defer hide so a mouse click on a suggestion still registers.
    this.textarea.addEventListener("blur", () => window.setTimeout(() => this.hideMentions(), 120));
    if (this.enableImages) {
      this.textarea.addEventListener("paste", (evt) => this.onPaste(evt));
    }
    this.sendBtn.addEventListener("click", () => {
      if (this.busy) this.callbacks.onCancel();
      else this.submit();
    });
  }

  focus(): void {
    this.textarea.focus();
  }

  /** Toggle running state: disables input + flips the button to "Stop". */
  setBusy(busy: boolean): void {
    this.busy = busy;
    this.textarea.disabled = busy;
    this.sendBtn.setText(busy ? "Stop" : "Send");
    this.sendBtn.toggleClass("is-busy", busy);
    this.sendBtn.setAttribute("aria-label", busy ? "Stop" : "Send");
    if (busy) this.hideMentions();
  }

  isBusy(): boolean {
    return this.busy;
  }

  clear(): void {
    this.textarea.value = "";
    this.autoGrow();
  }

  /** Replace the textarea contents (e.g. seeding an edited message for resend). */
  setText(text: string): void {
    this.textarea.value = text;
    this.autoGrow();
    const end = this.textarea.value.length;
    this.textarea.setSelectionRange(end, end);
  }

  private onKeyDown(evt: KeyboardEvent): void {
    // When the @-mention popup is open it owns the navigation keys.
    if (this.isMentionOpen()) {
      if (evt.key === "ArrowDown") {
        evt.preventDefault();
        this.moveMention(1);
        return;
      }
      if (evt.key === "ArrowUp") {
        evt.preventDefault();
        this.moveMention(-1);
        return;
      }
      if ((evt.key === "Enter" || evt.key === "Tab") && !evt.isComposing) {
        evt.preventDefault();
        this.acceptMention(this.mentionActive);
        return;
      }
      if (evt.key === "Escape") {
        evt.preventDefault();
        this.hideMentions();
        return;
      }
    }

    if (evt.key === "Escape" && this.busy) {
      evt.preventDefault();
      this.callbacks.onCancel();
      return;
    }
    if (evt.key === "Enter" && !evt.shiftKey && !evt.isComposing) {
      evt.preventDefault();
      if (!this.busy) this.submit();
    }
  }

  // ─── @-mention suggestions ─────────────────────────────────────────────────

  private isMentionOpen(): boolean {
    return this.mentionItems.length > 0 && !this.mentionPopup.hidden;
  }

  // Recompute the active `@` token from the caret and refresh the popup.
  private updateMentions(): void {
    if (this.busy || !this.callbacks.getMentionCandidates) {
      this.hideMentions();
      return;
    }
    const value = this.textarea.value;
    const caret = this.textarea.selectionStart ?? value.length;
    const upto = value.slice(0, caret);
    // An `@` at start/after-whitespace, followed by the (possibly empty) query.
    const match = /(^|\s)@([^\s@]*)$/.exec(upto);
    if (!match) {
      this.hideMentions();
      return;
    }
    this.mentionAtIndex = match.index + match[1].length;
    const query = match[2];
    this.mentionItems = this.callbacks.getMentionCandidates(query).slice(0, MENTION_LIMIT);
    if (this.mentionItems.length === 0) {
      this.hideMentions();
      return;
    }
    this.mentionActive = 0;
    this.renderMentions();
  }

  private renderMentions(): void {
    this.mentionPopup.empty();
    this.mentionItems.forEach((item, i) => {
      const row = this.mentionPopup.createDiv({
        cls: "vaultguard-chat-mention-item" + (i === this.mentionActive ? " is-active" : ""),
      });
      row.createSpan({ cls: "vaultguard-chat-mention-name", text: item.name });
      if (item.path !== item.name) {
        row.createSpan({ cls: "vaultguard-chat-mention-path", text: item.path });
      }
      row.addEventListener("mousedown", (evt) => {
        // mousedown (not click) so it fires before the textarea blur hides us.
        evt.preventDefault();
        this.acceptMention(i);
      });
    });
    this.mentionPopup.show();
  }

  private moveMention(delta: number): void {
    if (this.mentionItems.length === 0) return;
    const n = this.mentionItems.length;
    this.mentionActive = (this.mentionActive + delta + n) % n;
    this.renderMentions();
  }

  // Replace the active `@query` token with a wikilink to the chosen note.
  private acceptMention(index: number): void {
    const item = this.mentionItems[index];
    if (!item || this.mentionAtIndex < 0) {
      this.hideMentions();
      return;
    }
    const value = this.textarea.value;
    const caret = this.textarea.selectionStart ?? value.length;
    const before = value.slice(0, this.mentionAtIndex);
    const after = value.slice(caret);
    const insert = `[[${item.path}]] `;
    this.textarea.value = before + insert + after;
    const newCaret = (before + insert).length;
    this.textarea.setSelectionRange(newCaret, newCaret);
    this.hideMentions();
    this.autoGrow();
    this.textarea.focus();
  }

  private hideMentions(): void {
    this.mentionItems = [];
    this.mentionActive = -1;
    this.mentionAtIndex = -1;
    this.mentionPopup.empty();
    this.mentionPopup.hide();
  }

  // ─── Image attachments ──────────────────────────────────────────────────────

  private buildAttachButton(bar: HTMLElement): void {
    const fileInput = bar.createEl("input", {
      attr: { type: "file", accept: "image/*", multiple: "true" },
    });
    fileInput.hide();
    fileInput.addEventListener("change", () => {
      const files = fileInput.files;
      if (files) Array.from(files).forEach((f) => void this.addImageFile(f));
      fileInput.value = "";
    });

    const btn = bar.createEl("button", {
      cls: "vaultguard-chat-attach-btn clickable-icon",
      attr: { type: "button", "aria-label": "Attach image", title: "Attach image" },
    });
    setIcon(btn, "paperclip");
    btn.addEventListener("click", () => fileInput.click());
  }

  private onPaste(evt: ClipboardEvent): void {
    const items = evt.clipboardData?.items;
    if (!items) return;
    let handled = false;
    for (const item of Array.from(items)) {
      if (item.kind === "file" && item.type.startsWith("image/")) {
        const file = item.getAsFile();
        if (file) {
          void this.addImageFile(file);
          handled = true;
        }
      }
    }
    if (handled) evt.preventDefault();
  }

  private async addImageFile(file: File): Promise<void> {
    const dataUrl = await readAsDataUrl(file);
    const match = /^data:([^;]+);base64,(.*)$/.exec(dataUrl);
    if (!match) return;
    const mediaType = match[1].toLowerCase();
    if (!SUPPORTED_IMAGE_TYPES.has(mediaType)) {
      new Notice(
        `VaultGuard Chat: ${mediaType || "that file"} isn't a supported image ` +
          "(use PNG, JPEG, GIF, or WebP).",
      );
      return;
    }
    this.pendingImages.push({ mediaType, data: match[2], name: file.name || "image" });
    this.renderAttachments();
  }

  private renderAttachments(): void {
    if (!this.attachmentsEl) return;
    this.attachmentsEl.empty();
    if (this.pendingImages.length === 0) {
      this.attachmentsEl.hide();
      return;
    }
    this.pendingImages.forEach((img, i) => {
      const chip = this.attachmentsEl!.createDiv({ cls: "vaultguard-chat-attachment" });
      chip.createEl("img", {
        cls: "vaultguard-chat-attachment-thumb",
        attr: { src: `data:${img.mediaType};base64,${img.data}`, alt: img.name },
      });
      const remove = chip.createSpan({
        cls: "vaultguard-chat-attachment-remove clickable-icon",
        attr: { "aria-label": "Remove image", title: "Remove image" },
      });
      setIcon(remove, "x");
      remove.addEventListener("click", () => {
        this.pendingImages.splice(i, 1);
        this.renderAttachments();
      });
    });
    this.attachmentsEl.show();
  }

  private clearAttachments(): void {
    this.pendingImages = [];
    this.renderAttachments();
  }

  private submit(): void {
    const text = this.textarea.value.trim();
    const images = this.enableImages ? this.pendingImages : [];
    if (!text && images.length === 0) return;

    // Slash commands are text-only; skip parsing when images are attached.
    if (images.length === 0) {
      const slash = parseSlash(text);
      if (slash) {
        if (slash.kind === "unknown") {
          // Try a user-defined prompt template before declaring it unknown.
          const expanded = this.callbacks.resolveTemplate?.(slash.name, slash.arg);
          if (expanded != null) {
            if (this.callbacks.canSubmit?.(expanded) === false) return;
            this.clear();
            this.callbacks.onSubmit(expanded);
          } else {
            this.clear();
            this.callbacks.onUnknownSlash?.(slash.raw);
          }
        } else {
          this.clear();
          this.callbacks.onSlash(slash);
        }
        return;
      }
    }

    const imagesToSend = images.length ? [...images] : undefined;
    if (this.callbacks.canSubmit?.(text, imagesToSend) === false) return;
    this.clear();
    this.clearAttachments();
    this.callbacks.onSubmit(text, imagesToSend);
  }

  private autoGrow(): void {
    const ta = this.textarea;
    ta.setCssStyles({ height: "auto" });
    const maxHeight = MAX_ROWS * LINE_HEIGHT_PX;
    ta.setCssStyles({ height: `${Math.min(ta.scrollHeight, maxHeight)}px` });
    ta.setCssStyles({ overflowY: ta.scrollHeight > maxHeight ? "auto" : "hidden" });
  }
}

// Read a File as a base64 data URL. FileReader is a local browser API (no
// network), so it honors the Networking Rule.
function readAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error("Could not read the image file."));
    reader.readAsDataURL(file);
  });
}

export { BAR_CLS as INPUT_BAR_CLS };
