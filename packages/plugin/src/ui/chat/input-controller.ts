// Input controller for the chat panel (AI-CHAT-PANEL.md §9.6). Self-contained:
// it owns the textarea + send/stop button and talks to the view ONLY through
// callbacks (onSubmit / onCancel / onSlash). No view coupling, no filesystem.
//
//  - auto-grow textarea, capped at ~6 lines
//  - Enter = send, Shift+Enter = newline
//  - Esc = cancel a running turn (when busy)
//  - command palette: built-in `/clear`, `/model <id>`, `$` skills, plus
//    user-defined prompt templates resolved via the resolveTemplate callback
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
  | { kind: "history" }
  | { kind: "new-tab" }
  | { kind: "regenerate" }
  | { kind: "import-knowledge"; arg: string }
  | { kind: "format-vault"; arg: string }
  | { kind: "model"; model: string };

export type PromptCommandPrefix = "/" | "$";

export interface SlashCommandSuggestion {
  /** Command name without the leading slash/dollar prefix. */
  name: string;
  /** One-line hint shown in the dropdown. */
  description: string;
  /** Optional argument hint, e.g. "<model-id>". */
  argumentHint?: string;
  /** Trigger character. Slash commands use `/`; skills use `$`. */
  prefix?: PromptCommandPrefix;
  /** Text inserted when selected. Defaults to `<prefix><name> `. */
  replacement?: string;
  /** Built-ins render before skills/templates and cannot be shadowed. */
  source: "built-in" | "skill" | "template";
}

export const BUILT_IN_SLASH_COMMANDS: ReadonlyArray<SlashCommandSuggestion> = [
  {
    name: "clear",
    description: "Start a new conversation in the current tab.",
    source: "built-in",
  },
  {
    name: "new",
    description: "Alias for /clear.",
    source: "built-in",
  },
  {
    name: "new-tab",
    description: "Open a fresh numbered chat tab.",
    source: "built-in",
  },
  {
    name: "history",
    description: "Open previous chats.",
    source: "built-in",
  },
  {
    name: "regenerate",
    description: "Regenerate the last response.",
    source: "built-in",
  },
  {
    name: "import-knowledge",
    description: "Import a local folder: the agent surveys it and builds an organized vault KB.",
    argumentHint: "[focus, structure, or what to skip]",
    source: "built-in",
  },
  {
    name: "format-vault",
    description: "Plan and apply Obsidian Markdown formatting across visible vault documents.",
    argumentHint: "[scope or style]",
    source: "built-in",
  },
  {
    name: "format-documents",
    description: "Alias for /format-vault.",
    argumentHint: "[scope or style]",
    source: "built-in",
  },
  {
    name: "format-all-documents",
    description: "Alias for /format-vault.",
    argumentHint: "[scope or style]",
    source: "built-in",
  },
  {
    name: "model",
    description: "Switch model for future replies.",
    argumentHint: "<model-id>",
    source: "built-in",
  },
];

export const RESERVED_SLASH_COMMAND_NAMES = new Set(
  BUILT_IN_SLASH_COMMANDS.flatMap((cmd) =>
    cmd.name === "new" ? [cmd.name, "clear"] : [cmd.name],
  ),
);

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
   * Resolve a non-built-in slash command or `$` skill as a prompt template.
   * Returns the expanded prompt to send, or null if no template matches `name`.
   */
  resolveTemplate?(name: string, arg: string, prefix: PromptCommandPrefix): string | null;
  /**
   * Resolve note candidates for an `@`-mention query (the view supplies these
   * from the Obsidian vault file list — metadata only, never file content, so
   * the at-rest boundary is untouched). Omit to disable @-mentions.
   */
  getMentionCandidates?(query: string): MentionCandidate[];
  /** Slash-command suggestions for the dropdown; built-ins are added by default. */
  getSlashCommands?(): SlashCommandSuggestion[];
}

const MENTION_LIMIT = 8;

export type ParsedSlash =
  | SlashCommand
  | { kind: "unknown"; raw: string; name: string; arg: string };

export interface ParsedPromptInvocation {
  prefix: PromptCommandPrefix;
  raw: string;
  name: string;
  arg: string;
}

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
    case "new":
      return { kind: "clear" };
    case "new-tab":
      return { kind: "new-tab" };
    case "history":
      return { kind: "history" };
    case "regenerate":
      return { kind: "regenerate" };
    case "import-knowledge":
      return { kind: "import-knowledge", arg };
    case "format-vault":
    case "format-documents":
    case "format-all-documents":
      return { kind: "format-vault", arg };
    case "model":
      if (!arg) return { kind: "unknown", raw: trimmed, name, arg };
      return { kind: "model", model: arg };
    default:
      return { kind: "unknown", raw: trimmed, name, arg };
  }
}

export function parsePromptInvocation(text: string): ParsedPromptInvocation | null {
  const trimmed = text.trim();
  const prefix = trimmed.startsWith("$") ? "$" : trimmed.startsWith("/") ? "/" : null;
  if (!prefix) return null;
  const [cmd, ...rest] = trimmed.slice(1).split(/\s+/);
  const name = cmd.trim().toLowerCase();
  if (!name) return null;
  return {
    prefix,
    raw: trimmed,
    name,
    arg: rest.join(" ").trim(),
  };
}

export function filterSlashCommands(
  query: string,
  commands: ReadonlyArray<SlashCommandSuggestion>,
): SlashCommandSuggestion[] {
  const q = query.trim().toLowerCase();
  const seen = new Set<string>();
  return commands
    .filter((cmd) => {
      const name = cmd.name.trim().replace(/^\/+/, "");
      if (!name) return false;
      const key = name.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      if (!q) return true;
      return (
        key.includes(q) ||
        cmd.description.toLowerCase().includes(q) ||
        cmd.argumentHint?.toLowerCase().includes(q)
      );
    })
    .sort((a, b) => {
      if (a.source !== b.source) return sourceRank(a.source) - sourceRank(b.source);
      return a.name.localeCompare(b.name);
    });
}

function sourceRank(source: SlashCommandSuggestion["source"]): number {
  if (source === "built-in") return 0;
  if (source === "skill") return 1;
  return 2;
}

export class InputController {
  private readonly textarea: HTMLTextAreaElement;
  private readonly sendBtn: HTMLButtonElement;
  private busy = false;

  // Slash-command suggestion state.
  private readonly slashPopup: HTMLElement;
  private slashItems: SlashCommandSuggestion[] = [];
  private slashActive = -1;
  private slashAtIndex = -1;

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

    this.slashPopup = bar.createDiv({ cls: "vaultguard-chat-slash-popup" });
    this.slashPopup.hide();

    this.mentionPopup = bar.createDiv({ cls: "vaultguard-chat-mention-popup" });
    this.mentionPopup.hide();

    if (this.enableImages) {
      this.attachmentsEl = bar.createDiv({ cls: "vaultguard-chat-attachments" });
      this.attachmentsEl.hide();
    }

    this.textarea = bar.createEl("textarea", {
      cls: TEXTAREA_CLS,
      attr: {
        placeholder: "Ask about your vault...",
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
      this.updateSlashCommands();
      this.updateMentions();
    });
    this.textarea.addEventListener("keydown", (evt) => this.onKeyDown(evt));
    // Defer hide so a mouse click on a suggestion still registers.
    this.textarea.addEventListener("blur", () =>
      window.setTimeout(() => {
        this.hideMentions();
        this.hideSlashCommands();
      }, 120),
    );
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
    if (busy) this.hideSlashCommands();
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

    if (this.isSlashOpen()) {
      if (evt.key === "ArrowDown") {
        evt.preventDefault();
        this.moveSlash(1);
        return;
      }
      if (evt.key === "ArrowUp") {
        evt.preventDefault();
        this.moveSlash(-1);
        return;
      }
      if ((evt.key === "Enter" || evt.key === "Tab") && !evt.isComposing) {
        evt.preventDefault();
        this.acceptSlash(this.slashActive);
        return;
      }
      if (evt.key === "Escape") {
        evt.preventDefault();
        this.hideSlashCommands();
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

  // ─── Slash-command suggestions ────────────────────────────────────────────

  private isSlashOpen(): boolean {
    return this.slashItems.length > 0 && !this.slashPopup.hidden;
  }

  private updateSlashCommands(): void {
    if (this.busy) {
      this.hideSlashCommands();
      return;
    }

    const value = this.textarea.value;
    const caret = this.textarea.selectionStart ?? value.length;
    const upto = value.slice(0, caret);
    const match = /(^|\s)([/$])([^\s/$]*)$/.exec(upto);
    if (!match) {
      this.hideSlashCommands();
      return;
    }

    this.slashAtIndex = match.index + match[1].length;
    const prefix = match[2] as PromptCommandPrefix;
    const query = match[3] ?? "";
    const custom = this.callbacks.getSlashCommands?.() ?? [];
    const commands = [...BUILT_IN_SLASH_COMMANDS, ...custom].filter(
      (cmd) => (cmd.prefix ?? "/") === prefix,
    );
    this.slashItems = filterSlashCommands(query, commands).slice(0, 10);
    if (this.slashItems.length === 0) {
      this.hideSlashCommands();
      return;
    }
    this.slashActive = 0;
    this.renderSlashCommands();
  }

  private renderSlashCommands(): void {
    this.slashPopup.empty();
    this.slashItems.forEach((item, i) => {
      const row = this.slashPopup.createDiv({
        cls: "vaultguard-chat-slash-item" + (i === this.slashActive ? " is-active" : ""),
      });
      const line = row.createDiv({ cls: "vaultguard-chat-slash-line" });
      const prefix = item.prefix ?? "/";
      line.createSpan({ cls: "vaultguard-chat-slash-name", text: `${prefix}${item.name}` });
      if (item.argumentHint) {
        line.createSpan({ cls: "vaultguard-chat-slash-hint", text: item.argumentHint });
      }
      line.createSpan({
        cls: `vaultguard-chat-slash-source is-${item.source}`,
        text: item.source === "built-in" ? "built-in" : item.source,
      });
      row.createDiv({ cls: "vaultguard-chat-slash-desc", text: item.description });
      row.addEventListener("mousedown", (evt) => {
        evt.preventDefault();
        this.acceptSlash(i);
      });
      row.addEventListener("mouseenter", () => {
        this.slashActive = i;
        this.renderSlashCommands();
      });
    });
    this.hideMentions();
    this.slashPopup.show();
  }

  private moveSlash(delta: number): void {
    if (this.slashItems.length === 0) return;
    const n = this.slashItems.length;
    this.slashActive = (this.slashActive + delta + n) % n;
    this.renderSlashCommands();
  }

  private acceptSlash(index: number): void {
    const item = this.slashItems[index];
    if (!item || this.slashAtIndex < 0) {
      this.hideSlashCommands();
      return;
    }
    const value = this.textarea.value;
    const caret = this.textarea.selectionStart ?? value.length;
    const before = value.slice(0, this.slashAtIndex);
    const after = value.slice(caret);
    const replacement = item.replacement ?? `${item.prefix ?? "/"}${item.name} `;
    this.textarea.value = before + replacement + after;
    const newCaret = (before + replacement).length;
    this.textarea.setSelectionRange(newCaret, newCaret);
    this.hideSlashCommands();
    this.autoGrow();
    this.textarea.focus();
  }

  private hideSlashCommands(): void {
    this.slashItems = [];
    this.slashActive = -1;
    this.slashAtIndex = -1;
    this.slashPopup.empty();
    this.slashPopup.hide();
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
    this.hideSlashCommands();
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
          const expanded = this.callbacks.resolveTemplate?.(slash.name, slash.arg, "/");
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

      const invocation = parsePromptInvocation(text);
      if (invocation?.prefix === "$") {
        const expanded = this.callbacks.resolveTemplate?.(
          invocation.name,
          invocation.arg,
          invocation.prefix,
        );
        if (expanded != null) {
          if (this.callbacks.canSubmit?.(expanded) === false) return;
          this.clear();
          this.callbacks.onSubmit(expanded);
        } else {
          this.clear();
          this.callbacks.onUnknownSlash?.(invocation.raw);
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
