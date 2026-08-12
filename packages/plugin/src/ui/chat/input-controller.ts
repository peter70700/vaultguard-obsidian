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

import { Menu, Notice, setIcon } from "obsidian";

import {
  AttachmentValidationError,
  MAX_IMAGE_BYTES,
  MAX_PENDING_IMAGES,
  MAX_TURN_ATTACHMENT_PAYLOAD_BYTES,
  attachmentPayloadBytes,
  sanitizeAttachmentName,
  validateImageAttachment,
  type AttachmentCapabilities,
  type DocumentPin,
  type ImageAttachment,
} from "./attachment-model";
export type { ImageAttachment } from "./attachment-model";

const BAR_CLS = "vaultguard-chat-input-bar";
const TEXTAREA_CLS = "vaultguard-chat-input";
const SEND_BTN_CLS = "vaultguard-chat-send-btn";
const MAX_ROWS = 6;
const LINE_HEIGHT_PX = 22;


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
    description: "Switch model for future replies; no id opens the picker.",
    argumentHint: "[model-id]",
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

export interface InputControllerOptions {
  /** Show the desktop attachment menu and accept pasted images. */
  enableAttachments?: boolean;
  /** Backward-compatible alias used by older callers/tests. */
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
  /** Current provider/platform attachment capability, evaluated when the menu opens. */
  getAttachmentCapabilities?(): AttachmentCapabilities;
  /** Ask the view to select and pin one or more original documents. */
  onPinDocuments?(): void | Promise<void>;
  /** Remove a conversation-scoped document pin by opaque id. */
  onRemoveDocumentPin?(id: string): void | Promise<void>;
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
   * Resolve note candidates for an `@`-mention query. The view supplies these
   * from the Obsidian vault file list, filtered to the paths the user may
   * actually read — a suggestion is a disclosure, so the provider gates on the
   * same predicate as the read path (SD-13-F5). Omit to disable @-mentions.
   *
   * The union return type is deliberate: `await` accepts both, so a purely
   * synchronous provider keeps working unchanged.
   */
  getMentionCandidates?(query: string): MentionCandidate[] | Promise<MentionCandidate[]>;
  /** Slash-command suggestions for the dropdown; built-ins are added by default. */
  getSlashCommands?(): SlashCommandSuggestion[];
}

/**
 * How many `@`-mention suggestions the popup shows. Exported so the candidate
 * provider can bound its permission checks to exactly the visible count rather
 * than resolving a wider set the controller would discard.
 */
export const MENTION_LIMIT = 8;

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
      // An empty argument is a valid invocation, not a typo: accepting `/model`
      // from the `/` palette inserts exactly that, and the next Enter used to
      // land on "unknown command". Bare `/model` opens the picker instead.
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
  /**
   * Monotonic token for in-flight mention lookups. Candidate resolution is
   * async (it consults the permission store), so a slow earlier keystroke can
   * resolve after a newer one. Every lookup captures the token it started with
   * and drops its result if the token has moved on; `hideMentions()` bumps it
   * so a dismissed popup can never be repopulated from a stale lookup.
   */
  private mentionQuerySeq = 0;

  // Attachment state. Images are transient drafts; document pins are supplied
  // by the view from the active encrypted conversation.
  private readonly enableAttachments: boolean;
  private readonly attachmentsEl: HTMLElement | null = null;
  private attachmentBtn: HTMLButtonElement | null = null;
  private imageInput: HTMLInputElement | null = null;
  private pendingImages: ImageAttachment[] = [];
  private documentPins: DocumentPin[] = [];
  private attachmentGeneration = 0;
  private disposed = false;

  constructor(
    parent: HTMLElement,
    private readonly callbacks: InputControllerCallbacks,
    options: InputControllerOptions = {},
  ) {
    this.enableAttachments = options.enableAttachments === true || options.enableImages === true;
    const bar = parent.createDiv({ cls: BAR_CLS });

    this.slashPopup = bar.createDiv({ cls: "vaultguard-chat-slash-popup" });
    this.slashPopup.hide();

    this.mentionPopup = bar.createDiv({ cls: "vaultguard-chat-mention-popup" });
    this.mentionPopup.hide();

    if (this.enableAttachments) {
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

    if (this.enableAttachments) this.buildAttachmentButton(bar);

    this.sendBtn = bar.createEl("button", {
      cls: SEND_BTN_CLS,
      attr: { type: "button", "aria-label": "Send" },
      text: "Send",
    });

    this.textarea.addEventListener("input", () => {
      this.autoGrow();
      this.updateSlashCommands();
      void this.updateMentions();
    });
    this.textarea.addEventListener("keydown", (evt) => this.onKeyDown(evt));
    // Defer hide so a mouse click on a suggestion still registers.
    this.textarea.addEventListener("blur", () =>
      window.setTimeout(() => {
        this.hideMentions();
        this.hideSlashCommands();
      }, 120),
    );
    if (this.enableAttachments) {
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
    if (this.attachmentBtn) this.attachmentBtn.disabled = busy;
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

  /** Restore a complete unsent/user-edited draft, including image blocks. */
  setDraft(text: string, images: ImageAttachment[] = []): void {
    this.setText(text);
    this.attachmentGeneration += 1;
    this.pendingImages = images.map((image) => ({ ...image }));
    this.renderAttachments();
  }

  /** Render only the active conversation's reference pins. */
  setDocumentPins(pins: ReadonlyArray<DocumentPin>): void {
    this.documentPins = pins.map((pin) => ({ ...pin }));
    this.renderAttachments();
  }

  getPendingImages(): ImageAttachment[] {
    return this.pendingImages.map((image) => ({ ...image }));
  }

  getDraft(): { text: string; images: ImageAttachment[] } {
    return {
      text: this.textarea.value,
      images: this.getPendingImages(),
    };
  }

  dispose(): void {
    this.disposed = true;
    this.attachmentGeneration += 1;
    this.pendingImages = [];
    this.documentPins = [];
    this.renderAttachments();
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
  private async updateMentions(): Promise<void> {
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
    const atIndex = match.index + match[1].length;
    const query = match[2];
    const seq = ++this.mentionQuerySeq;

    let candidates: MentionCandidate[];
    try {
      candidates = await this.callbacks.getMentionCandidates(query);
    } catch {
      if (seq === this.mentionQuerySeq) this.hideMentions();
      return;
    }

    // Stale-query guard: a newer keystroke (or hideMentions) bumped the token
    // while this lookup was in flight — drop the result rather than rendering
    // suggestions for a query the user has already moved past.
    if (seq !== this.mentionQuerySeq) return;
    // The controller may have gone busy or the popup been dismissed mid-await.
    if (this.busy) {
      this.hideMentions();
      return;
    }

    // Assigned only after the guard: writing the anchor before the await would
    // let a stale lookup leave a stale insertion offset behind.
    this.mentionAtIndex = atIndex;
    this.mentionItems = candidates.slice(0, MENTION_LIMIT);
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
    // Invalidate any in-flight lookup so it cannot repopulate the popup after
    // Esc, blur, setBusy(true), or an accepted mention.
    this.mentionQuerySeq += 1;
    this.mentionItems = [];
    this.mentionActive = -1;
    this.mentionAtIndex = -1;
    this.mentionPopup.empty();
    this.mentionPopup.hide();
  }

  // ─── Image attachments ──────────────────────────────────────────────────────

  private buildAttachmentButton(bar: HTMLElement): void {
    this.imageInput = bar.createEl("input", {
      attr: {
        type: "file",
        accept: "image/png,image/jpeg,image/gif,image/webp",
        multiple: "true",
      },
    });
    this.imageInput.hide();
    this.imageInput.addEventListener("change", () => {
      const files = this.imageInput?.files;
      if (files) Array.from(files).forEach((file) => void this.addImageFile(file));
      if (this.imageInput) this.imageInput.value = "";
    });

    this.attachmentBtn = bar.createEl("button", {
      cls: "vaultguard-chat-attach-btn clickable-icon",
      attr: { type: "button", "aria-label": "Add attachment", title: "Add attachment" },
    });
    setIcon(this.attachmentBtn, "paperclip");
    this.attachmentBtn.addEventListener("click", (event) => this.openAttachmentMenu(event));
  }

  private openAttachmentMenu(event: MouseEvent): void {
    const capabilities = this.callbacks.getAttachmentCapabilities?.();
    const menu = new Menu();
    menu.addItem((item) =>
      item
        .setTitle("Add photos")
        .setIcon("image")
        .setDisabled(capabilities?.imageInput === false)
        .onClick(() => this.imageInput?.click()),
    );
    menu.addItem((item) =>
      item
        .setTitle("Pin document")
        .setIcon("file-text")
        .setDisabled(
          capabilities !== undefined &&
            !capabilities.textDocumentInput &&
            !capabilities.pdfDocumentInput,
        )
        .onClick(() => {
          const result = this.callbacks.onPinDocuments?.();
          if (result instanceof Promise) void result.catch(() => undefined);
        }),
    );
    menu.showAtMouseEvent(event);
  }

  private onPaste(event: ClipboardEvent): void {
    const clipboard = event.clipboardData;
    const items = clipboard?.items;
    if (!items) return;
    let handledImage = false;
    for (const item of Array.from(items)) {
      if (item.kind !== "file" || !item.type.startsWith("image/")) continue;
      const file = item.getAsFile();
      if (!file) continue;
      void this.addImageFile(file);
      handledImage = true;
    }
    const hasPlainText =
      Array.from(clipboard.types ?? []).includes("text/plain") &&
      clipboard.getData("text/plain").length > 0;
    if (handledImage && !hasPlainText) event.preventDefault();
  }

  private async addImageFile(file: File): Promise<void> {
    if (this.pendingImages.length >= MAX_PENDING_IMAGES) {
      new Notice(`VaultGuard Chat: add at most ${MAX_PENDING_IMAGES} photos per message.`);
      return;
    }
    const generation = this.attachmentGeneration;
    try {
      if (file.size > MAX_IMAGE_BYTES) {
        throw new AttachmentValidationError(
          "file-too-large",
          "Images must be 10 MB or smaller.",
        );
      }
      const bytes = await readFileBytes(file);
      if (this.disposed || generation !== this.attachmentGeneration) return;
      const mediaType = validateImageAttachment(bytes, file.type || undefined);
      if (this.pendingImages.length >= MAX_PENDING_IMAGES) {
        throw new AttachmentValidationError(
          "too-many-files",
          `Add at most ${MAX_PENDING_IMAGES} photos per message.`,
        );
      }
      const candidate: ImageAttachment = {
        mediaType,
        data: bytesToBase64(bytes),
        name: sanitizeAttachmentName(file.name || "image", "image"),
        byteLength: bytes.byteLength,
      };
      if (
        attachmentPayloadBytes([...this.pendingImages, candidate], []) >
        MAX_TURN_ATTACHMENT_PAYLOAD_BYTES
      ) {
        throw new AttachmentValidationError(
          "payload-too-large",
          "The combined attachment payload must be 32 MB or smaller.",
        );
      }
      this.pendingImages.push(candidate);
      this.renderAttachments();
    } catch (error) {
      const message =
        error instanceof AttachmentValidationError
          ? error.message
          : "That photo could not be read.";
      new Notice(`VaultGuard Chat: ${message}`);
    }
  }

  private renderAttachments(): void {
    if (!this.attachmentsEl) return;
    this.attachmentsEl.empty();
    if (this.pendingImages.length === 0 && this.documentPins.length === 0) {
      this.attachmentsEl.hide();
      return;
    }
    this.pendingImages.forEach((image, index) => {
      const chip = this.attachmentsEl!.createDiv({ cls: "vaultguard-chat-attachment" });
      chip.createEl("img", {
        cls: "vaultguard-chat-attachment-thumb",
        attr: {
          src: `data:${image.mediaType};base64,${image.data}`,
          alt: `Photo ${image.name}`,
        },
      });
      const details = chip.createDiv({ cls: "vaultguard-chat-attachment-details" });
      details.createSpan({ cls: "vaultguard-chat-attachment-name", text: image.name });
      details.createSpan({
        cls: "vaultguard-chat-attachment-meta",
        text: formatAttachmentBytes(image.byteLength),
      });
      const remove = chip.createEl("button", {
        cls: "vaultguard-chat-attachment-remove clickable-icon",
        attr: {
          type: "button",
          "aria-label": `Remove photo ${image.name}`,
          title: `Remove photo ${image.name}`,
        },
      });
      setIcon(remove, "x");
      remove.addEventListener("click", () => {
        this.pendingImages.splice(index, 1);
        this.renderAttachments();
        this.textarea.focus();
      });
    });

    this.documentPins.forEach((pin) => {
      const chip = this.attachmentsEl!.createDiv({
        cls: `vaultguard-chat-document-pin${pin.state === "unavailable" ? " is-unavailable" : ""}`,
      });
      const icon = chip.createSpan({ cls: "vaultguard-chat-document-pin-icon" });
      setIcon(icon, pin.state === "unavailable" ? "file-warning" : "file-text");
      const details = chip.createDiv({ cls: "vaultguard-chat-attachment-details" });
      details.createSpan({ cls: "vaultguard-chat-attachment-name", text: pin.displayName });
      details.createSpan({
        cls: "vaultguard-chat-attachment-meta",
        text:
          pin.state === "unavailable"
            ? "Unavailable - fix the original or unpin"
            : `${pin.format.toUpperCase()} - ${formatAttachmentBytes(pin.byteLength)}`,
      });
      const remove = chip.createEl("button", {
        cls: "vaultguard-chat-attachment-remove clickable-icon",
        attr: {
          type: "button",
          "aria-label": `Unpin document ${pin.displayName}`,
          title: `Unpin document ${pin.displayName}`,
        },
      });
      setIcon(remove, "x");
      remove.addEventListener("click", () => {
        const result = this.callbacks.onRemoveDocumentPin?.(pin.id);
        if (result instanceof Promise) void result.catch(() => undefined);
        this.textarea.focus();
      });
    });
    this.attachmentsEl.show();
  }

  private clearAttachments(): void {
    this.attachmentGeneration += 1;
    this.pendingImages = [];
    this.renderAttachments();
  }

  private submit(): void {
    const text = this.textarea.value.trim();
    const images = this.enableAttachments ? this.pendingImages : [];
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

// FileReader/arrayBuffer are local browser APIs (no network).
async function readFileBytes(file: File): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === "function") {
    return new Uint8Array(await file.arrayBuffer());
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () =>
      resolve(reader.result instanceof ArrayBuffer ? new Uint8Array(reader.result) : new Uint8Array());
    reader.onerror = () => reject(reader.error ?? new Error("Could not read the image file."));
    reader.readAsArrayBuffer(file);
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function formatAttachmentBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.ceil(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
export { BAR_CLS as INPUT_BAR_CLS };
