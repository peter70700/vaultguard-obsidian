// VaultGuardChatView — the visible, non-streamed chat sidebar (AI-CHAT-PANEL.md
// §9.1–§9.7). It drives the already-shipped runtime layer (ChatRuntime +
// VaultToolRuntime + AnthropicClient) and renders each progress step as it
// lands.
//
// ENCRYPTION BOUNDARY (§3, the whole point): this view NEVER calls
// originalAdapterMethods.*, app.vault.read/modify, node fs, or any filesystem
// API. Vault content is reached ONLY through a lease + agentBridge tool surface
// (via VaultToolRuntime). There is no raw fetch/EventSource here — the network
// is owned entirely by AnthropicClient (requestUrl).
//
// §11: with no stored Anthropic key (and no active Cloud session) the view shows
// a "connect" empty state and makes ZERO network calls.

import {
  ItemView,
  Menu,
  Notice,
  Platform,
  type ViewStateResult,
  WorkspaceLeaf,
  setIcon,
} from "obsidian";

import type VaultGuardPlugin from "../../plugin/main";
import type {
  AgentBridgeAskUserArgs,
  AgentBridgeAskUserDelivery,
  AgentBridgeAskUserResult,
  AgentBridgeConfirmPausedHandler,
} from "../../plugin/agent-bridge";
import {
  AnthropicClient,
  type AnthropicContentBlock,
  type AnthropicImageBlock,
  type AnthropicMessage,
  type AnthropicToolResultBlock,
} from "./anthropic-client";
import { AnthropicKeyStore } from "./api-key-store";
import { ChatRuntime } from "./chat-runtime";
import { ClaudeCliClient } from "./claude-cli/claude-cli-client";
import {
  getClaudeAuthStatus,
  type ClaudeAuthStatus,
} from "./claude-cli/claude-detector";
import { VaultToolRuntime } from "./vault-tool-runtime";
import { buildSystemPrompt } from "./system-prompt";
import {
  InputController,
  RESERVED_SLASH_COMMAND_NAMES,
  type ImageAttachment,
  type MentionCandidate,
  type PromptCommandPrefix,
  type SlashCommand,
  type SlashCommandSuggestion,
} from "./input-controller";
import {
  OBSIDIAN_CHAT_SKILLS,
  expandBuiltInSkill,
  expandPromptTemplate,
  firstPromptLine,
  parsePromptTemplate,
  promptTemplatePrefix,
  sameCommandName,
} from "./prompt-commands";
import { StatusPanel } from "./status-panel";
import {
  renderAssistantMessage,
  renderMarkdownWithFallback,
  renderPendingIndicator,
  renderUserMessage,
  type AssistantBubble,
  type PendingIndicator,
} from "./render/message-renderer";
import { renderToolCall, type ToolCallCard } from "./render/tool-call-renderer";
import {
  renderUserQuestion,
  type UserQuestionCard,
} from "./render/user-question-renderer";
import { extractThinking, renderThinking } from "./render/thinking-renderer";
import { StreamController } from "./stream-controller";
import {
  defaultTitle,
  newConversationId,
  pickInitialConversation,
  type ChatLeafState,
  type Conversation,
  type ConversationMeta,
  type ConversationStore,
  type PendingConfirmationAction,
  type PendingUserQuestion,
} from "./conversation-store";
import { generateTitle } from "./title-generator";
import {
  isUserPrompt,
  sliceBeforeUserTurn,
  userPromptImages,
  userPromptText,
} from "./message-utils";
import {
  AI_CHAT_MODELS,
  AI_CHAT_EFFORTS,
  AI_CHAT_MODEL_IDS,
  AI_CHAT_PERMISSION_MODES,
  chatPermissionWriteMode,
  permissionModeLabel,
} from "./models";
import type { AiChatPermissionMode, AnthropicEffort } from "../../types";
import {
  isLocalImportAvailable,
  pickSourceFolder,
} from "../import/local-file-importer";
import {
  buildImportKnowledgePrompt,
  formatImportCommand,
  inferProjectLabel,
  parseImportArg,
} from "./import-prompt";
import { buildFormatVaultPrompt } from "./format-vault-prompt";

export const VAULTGUARD_CHAT_VIEW_TYPE = "vaultguard-chat-view";

const ROOT_CLS = "vaultguard-chat";
const LIST_CLS = "vaultguard-chat-list";
const EMPTY_CLS = "vaultguard-chat-empty";
const HEADER_CLS = "vaultguard-chat-header";
const HEADER_TITLE_CLS = "vaultguard-chat-header-title";
const INPUT_NAV_CLS = "vaultguard-chat-input-nav-row";
const INPUT_NAV_ACTIONS_CLS = "vaultguard-chat-input-nav-actions";
const INPUT_NAV_BTN_CLS = "vaultguard-chat-input-nav-btn";
const TABS_CLS = "vaultguard-chat-tabs";
const TAB_CLS = "vaultguard-chat-tab";
const EXPANDED_TAB_TITLE_MAX = 32;

interface ChatConversationTab {
  key: string;
  conversationId: string | null;
  title: string;
}

export class VaultGuardChatView extends ItemView {
  private listEl: HTMLElement | null = null;
  private inputController: InputController | null = null;
  private statusPanel: StatusPanel | null = null;
  private inputNavRowEl: HTMLElement | null = null;
  private tabsEl: HTMLElement | null = null;
  private inputNavActionsEl: HTMLElement | null = null;
  private openTabs: ChatConversationTab[] = [];
  private activeTabKey: string | null = null;
  private nextTabSeq = 0;
  private expandedTabKeys = new Set<string>();

  private runtime: ChatRuntime | null = null;
  private leaseId: string | null = null;
  // True while an /import-knowledge source folder is armed on the bridge. The
  // gated vaultguard_import_* tools only work while this is active; it is
  // disarmed on conversation reset, view close, and a failed kickoff so the
  // tools go inert the moment the import flow ends.
  private importSessionActive = false;
  private model: string;
  private abortController: AbortController | null = null;

  // Subscription provider (Claude Code CLI). Lazily built on the first
  // subscription-mode turn; rebuilt when the provider/model changes. Null in
  // API-key mode. The client itself never touches a token — `claude`
  // authenticates from its own keychain.
  private cliClient: ClaudeCliClient | null = null;
  private cliSessionToolName: string | null = null;

  // Persistence (AI-CHAT-PANEL.md §10). `convo` is the in-memory mirror of the
  // current conversation; it is LAK-encrypted and autosaved after each turn.
  private store: ConversationStore | null = null;
  private convo: Conversation | null = null;
  // NOTE: do NOT name this `titleEl` — Obsidian's View base class owns a
  // `titleEl` property (the tab-title element) and shadowing it to null makes
  // Obsidian's own load() throw "Cannot read properties of null (setText)".
  private convoTitleEl: HTMLElement | null = null;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  // True once a generated (or restored) title is in place, so we don't
  // regenerate on later turns.
  private titleGenerated = false;

  // Per-turn render bookkeeping. Tracks which tool_use cards are still awaiting
  // their result so onToolResult can fill the right card.
  private pendingToolCards: ToolCallCard[] = [];
  private activeAssistantBubble: AssistantBubble | null = null;
  private activeUserQuestion: {
    card: UserQuestionCard;
    reject(err: Error): void;
  } | null = null;
  private queuedPausedAnswer: AgentBridgeAskUserResult | null = null;
  // The currently-rendered batched confirmation card (set_permission approvals),
  // or null when none is pending. Transient — the queue itself lives on the
  // conversation (pendingConfirmations) so it survives a reload.
  private pendingConfirmCard: UserQuestionCard | null = null;
  // A decision (approve/deny) made while a turn was still streaming, replayed
  // once the turn settles. null = nothing queued.
  private queuedConfirmDecision: boolean | null = null;

  // Persistent "Working…" indicator shown for the whole turn (from showPending()
  // at turn start until clearPending() in the finally / on error). scrollToBottom
  // pins it below the latest content so it reads as a live activity signal during
  // the multi-step tool-calling phase, not just before the first token.
  private pendingIndicator: PendingIndicator | null = null;

  // Tier-2 live streaming bubble (desktop + opt-in only). Null on Tier-1 turns.
  private streamController: StreamController | null = null;
  // The streaming preference baked into the current runtime, so a settings
  // change mid-session rebuilds the runtime with the new transport.
  private runtimeStreaming = false;

  // ─── In-panel multi-tab state (AI chat tabs) ───────────────────────────────
  // The plugin owns ONE Obsidian chat view. Conversation tabs live inside that
  // view, so switching tabs never spawns separate standalone chat panels.
  // `leafState` mirrors the Obsidian view state delivered by setState();
  // `resolveInitialConversation()` consumes it exactly once to restore the
  // active in-panel tab.
  private leafState: ChatLeafState | null = null;
  private initialConversationResolved = false;

  constructor(leaf: WorkspaceLeaf, private readonly plugin: VaultGuardPlugin) {
    super(leaf);
    this.model = plugin.settings.aiChatModel;
  }

  getViewType(): string {
    return VAULTGUARD_CHAT_VIEW_TYPE;
  }

  getDisplayText(): string {
    // Show the conversation title so stacked chat tabs are distinguishable.
    return this.convo?.title?.trim() || "VaultGuard Chat";
  }

  getIcon(): string {
    // Stock lucide icon — pre-registered by Obsidian, so it renders on every
    // version and in every surface (ribbon, tab), unlike a custom addIcon icon.
    return "message-square";
  }

  // ─── Persisted in-panel tab state ──────────────────────────────────────────
  // Persist ONLY the non-secret conversation ids into the leaf's Obsidian view
  // state (workspace.json — an excluded path). The conversation CONTENT stays
  // LAK-encrypted in ConversationStore, so the at-rest boundary is unchanged.
  getState(): Record<string, unknown> {
    const openConversationIds = this.openTabs
      .map((tab) => tab.conversationId)
      .filter((id): id is string => typeof id === "string" && id.length > 0);
    return {
      ...super.getState(),
      // Legacy key retained for smooth upgrades from older standalone chat tabs.
      conversationId: this.convo?.id ?? null,
      activeConversationId: this.convo?.id ?? null,
      openConversationIds,
      hasFreshTab: this.openTabs.some((tab) => tab.conversationId === null),
    };
  }

  async setState(state: ChatLeafState, result: ViewStateResult): Promise<void> {
    this.leafState = state ?? null;
    await super.setState(state, result);
    // setState can arrive after onOpen has built the chrome (workspace restore)
    // or before it. Resolve here only once the list element exists; otherwise
    // onOpen's deferred resolve picks it up.
    if (this.listEl) this.resolveInitialConversation();
  }

  async onOpen(): Promise<void> {
    // `contentEl` is the ItemView content element (== containerEl.children[1]
    // in current Obsidian); fall back defensively so a layout change can't leave
    // us with an undefined container and a silent blank panel.
    const container = (this.contentEl ??
      (this.containerEl.children[1] as HTMLElement)) as HTMLElement;
    container.empty();
    container.addClass(ROOT_CLS);

    // Build the core chrome synchronously. If ANYTHING here throws, surface it
    // IN the panel instead of rendering nothing — a blank view with the error
    // hidden in the console is the worst failure mode.
    try {
      this.store = this.plugin.getConversationStore();

      // Header: active conversation title. Chat-tab controls live above the
      // input composer, matching Claudian's compact numbered-tab placement.
      const header = container.createDiv({ cls: HEADER_CLS });
      this.convoTitleEl = header.createSpan({ cls: HEADER_TITLE_CLS, text: "New chat" });

      // Message list (scrollable, flex:1).
      this.listEl = container.createDiv({ cls: LIST_CLS });

      // Input nav row: compact numbered tabs on the left, actions on the right.
      // Multiple conversations stay open here; there is still only one Obsidian
      // chat view/leaf active at a time.
      this.inputNavRowEl = container.createDiv({ cls: INPUT_NAV_CLS });
      this.tabsEl = this.inputNavRowEl.createDiv({ cls: TABS_CLS });
      this.inputNavActionsEl = this.inputNavRowEl.createDiv({ cls: INPUT_NAV_ACTIONS_CLS });

      const newTabBtn = this.inputNavActionsEl.createSpan({
        cls: `${INPUT_NAV_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "New chat tab", title: "New chat tab" },
      });
      setIcon(newTabBtn, "square-plus");
      newTabBtn.addEventListener("click", () => this.openFreshChatTab());

      const newConversationBtn = this.inputNavActionsEl.createSpan({
        cls: `${INPUT_NAV_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "New conversation", title: "New conversation" },
      });
      setIcon(newConversationBtn, "square-pen");
      newConversationBtn.addEventListener("click", () => this.resetConversation());

      const historyBtn = this.inputNavActionsEl.createSpan({
        cls: `${INPUT_NAV_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "Previous chats", title: "Previous chats" },
      });
      setIcon(historyBtn, "history");
      historyBtn.addEventListener("click", (evt) => void this.openHistoryMenu(evt));

      const regenBtn = this.inputNavActionsEl.createSpan({
        cls: `${INPUT_NAV_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "Regenerate last response", title: "Regenerate last response" },
      });
      setIcon(regenBtn, "refresh-cw");
      regenBtn.addEventListener("click", () => void this.regenerateLast());

      // Input + status footer.
      this.inputController = new InputController(
        container,
        {
          onSubmit: (text, images) => void this.handleSubmit(text, images),
          canSubmit: (text, images) => this.canSubmit(text, images),
          onCancel: () => this.handleCancel(),
          onSlash: (cmd) => this.handleSlash(cmd),
          onUnknownSlash: (raw) => new Notice(`VaultGuard Chat: unknown command "${raw}".`),
          getMentionCandidates: (query) => this.mentionCandidates(query),
          getSlashCommands: () => this.slashCommandSuggestions(),
          resolveTemplate: (name, arg, prefix) => this.resolveTemplate(name, arg, prefix),
        },
        {
          // Vision input is API-key + desktop only (subscription CLI turns keep
          // no replayable image array; mobile uses the non-streaming path).
          enableImages:
            !Platform.isMobileApp && this.plugin.settings.aiChatProvider !== "subscription",
        },
      );

      this.statusPanel = new StatusPanel(
        container,
        this.model,
        this.plugin.settings.aiChatEffort,
        this.plugin.settings.aiChatPermissionMode,
        {
          onModelMenu: (evt) => this.openModelMenu(evt),
          onEffortMenu: (evt) => this.openEffortMenu(evt),
          onPermissionMenu: (evt) => this.openPermissionMenu(evt),
        },
      );
      this.statusPanel.setConnection(this.plugin.isConnectedOnline());
    } catch (e) {
      console.error("[VaultGuard Chat] failed to render the panel", e);
      container.empty();
      const errEl = container.createDiv({ cls: "vaultguard-chat-error" });
      const icon = errEl.createSpan({ cls: "vaultguard-chat-error-icon" });
      setIcon(icon, "alert-triangle");
      errEl.createSpan({
        text: `VaultGuard Chat failed to open: ${(e as Error)?.message ?? String(e)}`,
      });
      return;
    }

    // Provider auto-default + history restore are BEST-EFFORT and run AFTER the
    // panel is painted — they must never block first paint or blank the view.
    // The subscription detector spawns `claude`, which can be slow, so it is
    // explicitly NOT awaited here (that was the likely cause of a blank panel).
    void this.maybeAutoDefaultProvider()
      .catch((e) => console.error("[VaultGuard Chat] provider auto-default failed", e))
      .finally(() => {
        // First-run hint (no network/subprocess). API-key mode: show when no key
        // is stored. Subscription mode: the connect state is decided lazily on
        // first submit, so nothing is spawned here.
        try {
          if (
            this.plugin.settings.aiChatProvider !== "subscription" &&
            !new AnthropicKeyStore(this.plugin).hasKey()
          ) {
            this.renderConnectState();
          }
        } catch (e) {
          console.error("[VaultGuard Chat] connect-hint render failed", e);
        }
      });

    // Resolve which conversation this leaf shows. Defer one tick so a setState()
    // that Obsidian fires alongside onOpen during workspace restore lands first
    // (and wins over the most-recent fallback).
    window.setTimeout(() => this.resolveInitialConversation(), 0);

    this.inputController?.focus();
  }

  async onClose(): Promise<void> {
    this.handleCancel();
    this.endImportSessionIfActive();
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    this.runtime = null;
    this.cliClient?.reset();
    this.cliClient = null;
    this.leaseId = null;
    this.pendingToolCards = [];
    this.activeAssistantBubble = null;
    this.cancelActiveUserQuestion("VaultGuard Chat closed before the question was answered.");
    this.pendingIndicator = null;
    this.streamController = null;
    this.inputController = null;
    this.statusPanel = null;
    this.inputNavRowEl = null;
    this.tabsEl = null;
    this.inputNavActionsEl = null;
    this.openTabs = [];
    this.activeTabKey = null;
    this.expandedTabKeys.clear();
    this.listEl = null;
    this.convoTitleEl = null;
  }

  // ─── Connect / empty state (§11) ───────────────────────────────────────────

  private renderConnectState(): void {
    if (!this.listEl) return;
    // Don't duplicate the banner.
    if (this.listEl.querySelector(`.${EMPTY_CLS}`)) return;

    const empty = this.listEl.createDiv({ cls: EMPTY_CLS });
    const icon = empty.createDiv({ cls: "vaultguard-chat-empty-icon" });
    setIcon(icon, "message-square");
    empty.createEl("p", { text: "Connect Claude to chat about your vault." });
    empty.createEl("p", {
      cls: "vaultguard-chat-empty-hint",
      text:
        "Add your Anthropic API key in VaultGuard settings → AI Chat. " +
        "Until you do, this panel stays fully offline and makes no network calls.",
    });
  }

  // ─── Turn handling ─────────────────────────────────────────────────────────

  private canSubmit(text: string, images?: ImageAttachment[]): boolean {
    if (this.inputController?.isBusy()) return false;

    if (this.plugin.settings.aiChatProvider === "subscription") {
      if (images && images.length) {
        new Notice("VaultGuard Chat: image attachments need the API-key provider.");
        // A stale image-only submit after switching providers should not spawn
        // Claude Code with an empty prompt.
        if (!text.trim()) return false;
      }
      return true;
    }

    if (!new AnthropicKeyStore(this.plugin).hasKey()) {
      this.renderConnectState();
      new Notice("VaultGuard Chat: add your Anthropic API key in settings → AI Chat.");
      return false;
    }

    return true;
  }

  private async handleSubmit(text: string, images?: ImageAttachment[]): Promise<void> {
    if (!this.listEl || !this.inputController || !this.statusPanel) return;
    if (this.inputController.isBusy()) return;
    if (this.convo?.pendingUserQuestion) {
      this.clearPendingUserQuestion();
    }

    // Re-arm the import session from the conversation's remembered source root
    // before every turn. The bridge session is in-memory; without this it would
    // silently drop after the first turn (or on reload/resume), and the agent
    // would report a phantom "expired" session on its next source read.
    await this.ensureImportSessionArmed();

    if (this.plugin.settings.aiChatProvider === "subscription") {
      // Subscription (CLI) turns don't carry image blocks; drop with a hint.
      if (images && images.length) {
        if (!text.trim()) return;
      }
      await this.handleSubmitSubscription(text);
      return;
    }

    const imageBlocks = (images ?? []).map(
      (img): AnthropicImageBlock => ({
        type: "image",
        source: { type: "base64", media_type: img.mediaType, data: img.data },
      }),
    );

    // §11: read the key first; with none, render the connect state and make
    // ZERO outbound calls.
    const keyStore = new AnthropicKeyStore(this.plugin);
    const apiKey = await keyStore.getKey();
    if (!apiKey) {
      this.renderConnectState();
      new Notice("VaultGuard Chat: add your Anthropic API key in settings → AI Chat.");
      return;
    }

    // Clear the connect banner on the first real turn.
    this.listEl.querySelector(`.${EMPTY_CLS}`)?.remove();

    // Start a conversation lazily on the first turn so the title/header reflect
    // it before the model responds.
    if (!this.convo) this.startConversation(text);

    // Render the user bubble immediately, with edit/delete actions keyed to its
    // turn index (the count of prior user prompts in this conversation).
    const turnIndex = this.userTurnCount();
    renderUserMessage(this.listEl, text, this.userMessageActions(turnIndex), imageBlocks);
    this.scrollToBottom();

    // Desktop-only + opt-in. Mobile (or toggle off) always uses Tier-1 send().
    const streaming = this.streamingEnabled();
    // Rebuild the runtime if the streaming preference changed since it was built.
    if (this.runtime && this.runtimeStreaming !== streaming) {
      this.runtime = null;
    }

    // Lazily build the runtime + lease for the session.
    try {
      await this.ensureRuntime(apiKey, streaming);
    } catch (e) {
      this.renderError((e as Error).message || "Could not start the chat session.");
      return;
    }
    if (!this.runtime) return;

    const runtime = this.runtime;
    await this.executeTurn(apiKey, streaming, (signal) =>
      runtime.runTurn(text, signal, imageBlocks.length ? imageBlocks : undefined),
    );
  }

  // Shared busy/pending/streaming/finalize scaffolding for an API-key turn.
  // `run` performs the actual runtime call (a fresh turn or a regenerate) and is
  // handed the turn's AbortSignal. Persists + titles on completion.
  private async executeTurn(
    apiKey: string,
    streaming: boolean,
    run: (signal: AbortSignal) => Promise<void>,
  ): Promise<void> {
    if (!this.inputController || !this.statusPanel) return;

    this.statusPanel.setConnection(this.plugin.isConnectedOnline());
    this.inputController.setBusy(true);
    this.showPending();
    const controller = new AbortController();
    this.abortController = controller;
    this.activeAssistantBubble = null;
    // Fresh live-bubble controller per turn (streaming transport only).
    this.streamController = streaming ? this.makeStreamController() : null;

    try {
      await run(controller.signal);
    } catch (e) {
      // A user-initiated Stop aborts the in-flight request — not an error to
      // surface. (handleCancel nulls this.abortController, so check the local
      // controller's own signal instead.)
      if (!controller.signal.aborted) {
        this.renderError((e as Error).message || "The chat request failed.");
      }
    } finally {
      // Re-render any trailing streamed text as markdown before tearing down.
      this.streamController?.finalize();
      this.streamController = null;
      this.clearPending();
      this.inputController?.setBusy(false);
      this.abortController = null;
      this.activeAssistantBubble = null;
      this.pendingToolCards = [];
      this.scrollToBottom();
      // Snapshot the runtime's message history into the conversation and
      // persist it (encrypted at rest, debounced). Fail-soft on no LAK.
      this.captureAndSave(apiKey);
      this.flushQueuedPausedAnswer();
      this.flushQueuedConfirmDecision();
    }
  }

  // Re-answer the last prompt: drop the previous response from the runtime AND
  // the rendered list, then re-run the loop. API-key mode only — subscription
  // turns keep no replayable message array.
  private async regenerateLast(): Promise<void> {
    if (!this.listEl || !this.inputController || !this.statusPanel) return;
    if (this.inputController.isBusy()) return;

    if (this.plugin.settings.aiChatProvider === "subscription") {
      new Notice("VaultGuard Chat: regenerate isn't available in subscription mode.");
      return;
    }

    const keyStore = new AnthropicKeyStore(this.plugin);
    const apiKey = await keyStore.getKey();
    if (!apiKey) {
      this.renderConnectState();
      return;
    }

    const streaming = this.streamingEnabled();
    if (this.runtime && this.runtimeStreaming !== streaming) this.runtime = null;
    try {
      await this.ensureRuntime(apiKey, streaming);
    } catch (e) {
      this.renderError((e as Error).message || "Could not start the chat session.");
      return;
    }
    if (!this.runtime) return;

    const kept = this.runtime.truncateToLastUser();
    if (!kept) {
      new Notice("VaultGuard Chat: nothing to regenerate yet.");
      return;
    }

    // Re-render the conversation up to (and including) the last user prompt so
    // the dropped response disappears before the new one streams in.
    this.listEl.empty();
    this.renderMessages(kept);

    const runtime = this.runtime;
    await this.executeTurn(apiKey, streaming, (signal) => runtime.regenerateLast(signal));
  }

  // ─── Subscription provider (Claude Code CLI) ───────────────────────────────
  //
  // Drives the official `claude` binary with the user's own subscription login.
  // Vault access happens ONLY through the AgentBridge MCP server we point the
  // CLI at (lease-scoped, permission-checked, writeMode-gated). The
  // plugin never touches the subscription token. §11: zero subprocess is spawned
  // until the user has selected subscription AND `claude` is logged in.
  private async handleSubmitSubscription(text: string): Promise<void> {
    if (!this.listEl || !this.inputController || !this.statusPanel) return;

    if (Platform.isMobileApp) {
      this.renderError(
        "Subscription mode needs desktop Obsidian. Switch to the API-key provider in " +
          "settings → AI Chat to chat on mobile.",
      );
      return;
    }

    // §11 gate: confirm the CLI is installed + logged in BEFORE any subprocess
    // that could reach the vault. A not-ready state renders the connect banner
    // and spawns nothing further.
    let status: ClaudeAuthStatus;
    try {
      status = await getClaudeAuthStatus();
    } catch (e) {
      this.renderError(`Could not check Claude Code: ${(e as Error).message}`);
      return;
    }
    if (!status.loggedIn || !status.isSubscription) {
      this.renderSubscriptionConnectState(status);
      return;
    }

    this.listEl.querySelector(`.${EMPTY_CLS}`)?.remove();
    if (!this.convo) this.startConversation(text);

    renderUserMessage(this.listEl, text);
    this.scrollToBottom();

    // Subscription turns keep no Anthropic message array (the CLI owns its own
    // context), so we build a SYNTHETIC transcript here — otherwise the saved
    // conversation has empty messages and history reopens blank. Record the
    // user prompt now; the assistant reply is assembled from the stream below
    // and folded in (with tool results) in the finally block.
    this.convo?.messages.push({ role: "user", content: text });
    const assistantBlocks: AnthropicContentBlock[] = [];
    const toolResultBlocks: AnthropicToolResultBlock[] = [];
    const pendingToolUseIds: string[] = [];
    let toolUseSeq = 0;
    const appendAssistantText = (t: string): void => {
      const last = assistantBlocks[assistantBlocks.length - 1];
      if (last && last.type === "text") last.text += t;
      else assistantBlocks.push({ type: "text", text: t });
    };

    let client: ClaudeCliClient;
    try {
      client = await this.ensureCliClient(status.binaryPath as string);
    } catch (e) {
      this.renderError((e as Error).message || "Could not start the Claude Code session.");
      return;
    }

    this.statusPanel.setConnection(this.plugin.isConnectedOnline());
    this.statusPanel.setModel(this.model);
    this.statusPanel.setEffort(this.plugin.settings.aiChatEffort);
    this.inputController.setBusy(true);
    this.showPending();
    const controller = new AbortController();
    this.abortController = controller;
    this.activeAssistantBubble = null;
    this.cliSessionToolName = null;
    // Live-bubble controller for this streamed CLI turn: paints plain text per
    // delta and re-renders markdown once on finalize (mirrors the API-key
    // streaming path). Subscription mode is desktop-only, so streaming is safe.
    this.streamController = this.makeStreamController();

    try {
      await client.runTurn(
        text,
        {
          onTextDelta: (t) => {
            // Record the delta for the synthetic transcript, then stream it into
            // the live bubble (plain text now, markdown on finalize). Routing
            // per-token deltas through onText/appendMarkdown would block-wrap
            // every token and split words mid-line — the bug this fixes. The
            // "Working…" indicator stays (scrollToBottom keeps it pinned below).
            appendAssistantText(t);
            this.streamController?.onTextDelta(t);
          },
          onThinkingDelta: (t) => {
            // Accumulate into one collapsible via the controller (renderThinking
            // per delta would spawn a fresh "Thinking" box per token).
            this.streamController?.onThinkingDelta(t);
          },
          onToolCall: (name, input) => {
            // Synthetic id pairs this tool_use with its tool_result below so
            // renderMessages can re-attach the result on history reopen.
            const id = `sub-${toolUseSeq++}`;
            pendingToolUseIds.push(id);
            assistantBlocks.push({
              type: "tool_use",
              id,
              name,
              input: (input ?? {}) as Record<string, unknown>,
            });
            this.onToolCall(name, input);
          },
          onToolResult: (_name, result) => {
            const id = pendingToolUseIds.shift();
            if (id) {
              toolResultBlocks.push({
                type: "tool_result",
                tool_use_id: id,
                content: result.content,
                is_error: result.isError,
              });
            }
            this.onToolResult(result);
          },
          onResult: (info) => {
            if (typeof info.costUsd === "number") {
              this.statusPanel?.recordCostUsd(info.costUsd);
            }
          },
          onStatus: (message) => this.onCliStatus(message),
          onError: (message) => this.renderError(message),
        },
        controller.signal,
      );
    } catch (e) {
      // A user-initiated Stop aborts the CLI turn — not an error to surface.
      if (!controller.signal.aborted) {
        this.renderError((e as Error).message || "The Claude Code request failed.");
      }
    } finally {
      // Settle the final streamed text block into its markdown render (the last
      // block has no following tool call to trigger finalize).
      this.streamController?.finalize();
      this.streamController = null;
      this.clearPending();
      this.inputController?.setBusy(false);
      this.abortController = null;
      this.activeAssistantBubble = null;
      this.pendingToolCards = [];
      this.scrollToBottom();
      // Fold the streamed reply into the synthetic transcript: the assistant
      // turn (text + tool_use), then its tool results as a following user turn
      // so renderMessages re-attaches them to the cards on history reopen.
      if (this.convo && assistantBlocks.length) {
        this.convo.messages.push({ role: "assistant", content: assistantBlocks });
        if (toolResultBlocks.length) {
          this.convo.messages.push({ role: "user", content: toolResultBlocks });
        }
      }
      // Persist the conversation (now with real messages; fail-soft on no LAK).
      this.captureAndSaveSubscription();
      this.flushQueuedPausedAnswer();
      this.flushQueuedConfirmDecision();
    }
  }

  // Lazily start the AgentBridge HTTP/MCP server, mint a lease using the active
  // AI Chat permission mode, and build the ClaudeCliClient pointed at the
  // lease-scoped MCP endpoint.
  private async ensureCliClient(binaryPath: string): Promise<ClaudeCliClient> {
    if (this.cliClient) return this.cliClient;

    const server = await this.plugin.startAgentBridgeServer();
    const lease = await this.plugin.createAgentBridgeLease({
      agentName: "VaultGuard Chat (subscription)",
      scope: "/**",
      expiresWithSession: true,
      allowRead: true,
      writeMode: chatPermissionWriteMode(this.plugin.settings.aiChatPermissionMode),
      // In-app chat lease: enable the vaultguard_access permission-query tool.
      allowAccessQueries: true,
      // In-app chat lease: enable the gated /import-knowledge source-read tools.
      // They stay inert until the user runs /import-knowledge (which arms an
      // import session); minting the capability here just lets that flow work.
      allowImportRead: true,
      // In-app chat lease: enable Claude to ask follow-up questions through an
      // inline chat card instead of ending the turn and waiting manually.
      allowUserInteraction: true,
      // In-app chat lease: enable the vaultguard_set_permission tool. Every change
      // is still user-confirmed and re-authorized server-side (admin/file-admin).
      allowPermissionWrites: true,
      // In-app chat lease: enable the read-only vaultguard_audit tool. The backend
      // still gates the audit log to vault admins.
      allowAuditQueries: true,
      // In-app chat lease: enable the vaultguard_files tool (history/overview/
      // deleted/restore). The backend gates each op; restore is user-confirmed.
      allowFileHistory: true,
      // In-app chat lease: enable the vaultguard_share tool (list/create/revoke).
      // create/revoke are user-confirmed; the backend re-authorizes each.
      allowShareManagement: true,
      // In-app chat lease: enable the vaultguard_membership tool (add/remove/
      // set_role). Every op is user-confirmed and re-authorized as vault-admin.
      allowMembershipWrites: true,
    });
    this.leaseId = lease.leaseId;

    this.cliClient = new ClaudeCliClient({
      binaryPath,
      mcpUrl: server.mcpEndpoint,
      leaseToken: lease.token,
      model: this.model,
      permissionMode: this.plugin.settings.aiChatPermissionMode,
    });
    return this.cliClient;
  }

  // One-time provider auto-default. No-op once the user has chosen explicitly,
  // on mobile, or if the detector reports anything other than a logged-in
  // subscription. Spawns only `claude auth status` (read-only, no token).
  private async maybeAutoDefaultProvider(): Promise<void> {
    if (this.plugin.settings.aiChatProviderExplicit) return;
    if (Platform.isMobileApp) return;
    if (this.plugin.settings.aiChatProvider === "subscription") return;
    try {
      const status = await getClaudeAuthStatus();
      if (status.isSubscription && status.loggedIn) {
        this.plugin.settings.aiChatProvider = "subscription";
        await this.plugin.saveSettings();
      }
    } catch {
      // Detection failure → leave the default (apiKey) untouched.
    }
  }

  private captureAndSaveSubscription(): void {
    if (!this.convo) return;
    this.convo.model = this.model;
    this.convo.updatedAt = Date.now();
    this.scheduleSave();
  }

  // Subscription-mode connect banner (mirrors the API-key §11 connect state).
  private renderSubscriptionConnectState(status: ClaudeAuthStatus): void {
    if (!this.listEl) return;
    this.listEl.querySelector(`.${EMPTY_CLS}`)?.remove();
    const empty = this.listEl.createDiv({ cls: EMPTY_CLS });
    const icon = empty.createDiv({ cls: "vaultguard-chat-empty-icon" });
    setIcon(icon, "message-square");

    if (status.classification === "not-installed") {
      empty.createEl("p", { text: "Install Claude Code to chat with your subscription." });
      empty.createEl("p", {
        cls: "vaultguard-chat-empty-hint",
        text:
          "The Claude Code CLI isn't installed. Install it (see code.claude.com/docs/setup), " +
          "then sign in from VaultGuard settings → AI Chat.",
      });
      return;
    }

    empty.createEl("p", { text: "Sign in to Claude Code to chat about your vault." });
    empty.createEl("p", {
      cls: "vaultguard-chat-empty-hint",
      text:
        "Open VaultGuard settings → AI Chat and click Sign in. Until you do, this panel stays " +
        "fully offline and spawns no Claude Code process.",
    });
  }

  private handleCancel(): void {
    this.cancelActiveUserQuestion("Question cancelled.");
    if (this.abortController) {
      this.abortController.abort();
      this.abortController = null;
    }
  }

  private handleSlash(cmd: SlashCommand): void {
    if (cmd.kind === "clear") {
      this.resetConversation();
      new Notice("VaultGuard Chat: started a new conversation.");
      return;
    }
    if (cmd.kind === "new-tab") {
      this.openFreshChatTab();
      return;
    }
    if (cmd.kind === "history") {
      this.showHistoryPicker();
      return;
    }
    if (cmd.kind === "regenerate") {
      void this.regenerateLast();
      return;
    }
    if (cmd.kind === "import-knowledge") {
      void this.handleImportKnowledge(cmd.arg);
      return;
    }
    if (cmd.kind === "format-vault") {
      void this.handleFormatVault(cmd.arg);
      return;
    }
    if (cmd.kind === "model") {
      if (!AI_CHAT_MODEL_IDS.includes(cmd.model)) {
        new Notice(`VaultGuard Chat: unknown model "${cmd.model}".`);
        return;
      }
      this.setModel(cmd.model);
      new Notice(`VaultGuard Chat: switched to ${cmd.model} for this session.`);
    }
  }

  // ─── /format-vault: agent-driven Obsidian Markdown cleanup ────────────────
  //
  // The formatter is a normal chat turn, not a local vault crawler. The model
  // inventories and edits ONLY through VaultGuard's lease-scoped tools, so the
  // same read permissions, write confirmations, encryption boundary, and hidden
  // path blocks apply as any other AI Chat action.
  private async handleFormatVault(arg: string): Promise<void> {
    if (!this.inputController) return;
    if (this.inputController.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before formatting the vault.");
      return;
    }

    const prompt = buildFormatVaultPrompt(arg, this.plugin.settings.aiChatPermissionMode);
    new Notice("VaultGuard Chat: starting a vault formatting inventory...");
    await this.handleSubmit(prompt);
  }

  // ─── /import-knowledge: agent-driven extract + organize (sd4) ──────────────
  //
  // Desktop-only. Pick a local source folder, arm the bridge's import session
  // (which makes the gated vaultguard_import_* tools live for THIS source root),
  // then submit the constructed extract+organize prompt as a normal agent turn.
  // The session stays armed for the conversation (Phase 3 EXECUTE re-reads the
  // source across follow-up turns) and is disarmed on /clear, view close, or a
  // failed kickoff. The lease already carries allowImportRead from ensureRuntime
  // / ensureCliClient, so the tools become reachable the moment the session arms.
  private async handleImportKnowledge(arg: string): Promise<void> {
    if (!this.inputController || !this.listEl) return;
    if (this.inputController.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before starting an import.");
      return;
    }
    // Hard desktop gate — the picker uses the Electron dialog + Node fs.
    if (Platform.isMobileApp || !isLocalImportAvailable()) {
      new Notice("VaultGuard Chat: importing a folder requires Obsidian desktop.", 6000);
      return;
    }
    if (!this.plugin.getSession() || !this.plugin.settings.serverVaultId) {
      new Notice("VaultGuard Chat: sign in and pick a vault before importing.", 6000);
      return;
    }

    // Fail fast when this account can't create notes. Otherwise the agent runs
    // the entire survey and only hits the wall in Phase 3, where vaultguard_create
    // is denied *before* the confirm modal — a confusing, dead-end experience.
    if (!(await this.plugin.canCreateVaultNotes())) {
      const session = this.plugin.getSession();
      const role = session?.vaultMemberRole ?? session?.role ?? null;
      const who = role ? `your role here (${role})` : "this account";
      new Notice(
        `VaultGuard Chat: importing needs permission to create notes, but ${who} has read-only access to this vault. Ask a vault admin for editor access, or sign in with a write-capable account, then run /import-knowledge again.`,
        10000,
      );
      return;
    }

    // The chosen folder travels as a leading quoted token in the command
    // (`/import-knowledge "<path>" <instructions>`). When the user has not yet
    // supplied one, open the picker and PASTE the path back into the input so
    // it is visible and editable — they review it (and can add instructions)
    // then submit. Submitting WITH a path arms + remembers the session and runs.
    const { sourceRoot: argPath, instructions } = parseImportArg(arg);

    if (!argPath) {
      // 1a. No path yet — pick a folder and fill the input. Do NOT auto-submit.
      const picked = await pickSourceFolder();
      if (!picked) {
        new Notice("VaultGuard Chat: import cancelled.");
        return;
      }
      this.inputController.setText(formatImportCommand(picked, instructions));
      new Notice("VaultGuard Chat: folder selected — review it, add any instructions, then press Enter.", 6000);
      return;
    }

    // 1b. Path supplied — arm + remember the import session on the bridge
    //     (canonicalizes + validates the root). On failure, surface it clearly.
    let canonicalRoot: string;
    try {
      canonicalRoot = await this.plugin.beginAgentBridgeImportSession(argPath);
      this.importSessionActive = true;
    } catch (e) {
      new Notice(
        `VaultGuard Chat: could not open that folder — ${(e as Error).message || "unknown error"}`,
        7000,
      );
      return;
    }

    // Remember the canonical root on the conversation so the session survives
    // reloads / resumes and re-arms automatically before each turn.
    if (this.convo) {
      this.convo.importSourceRoot = canonicalRoot;
      this.scheduleSave();
    }

    // 2. Submit the constructed extract+organize prompt as a normal turn. We
    //    route through handleSubmit so both API-key and subscription providers
    //    work; a kickoff failure disarms the session so the tools don't linger.
    const label = inferProjectLabel(canonicalRoot);
    const prompt = buildImportKnowledgePrompt(label, instructions, this.plugin.settings.aiChatPermissionMode);
    new Notice("VaultGuard Chat: importing — the assistant is surveying the folder…");
    try {
      await this.handleSubmit(prompt);
    } catch (e) {
      this.endImportSessionIfActive();
      this.renderError((e as Error).message || "The import could not start.");
    }
  }

  // Re-arm the bridge import session from the active conversation's remembered
  // source root, if it has one and the bridge isn't already pointed at it. The
  // bridge session is in-memory and singleton, so this both survives reloads and
  // re-points the bridge when switching between import conversations/tabs. Best
  // effort: a vanished folder leaves the session inactive (the gated tools then
  // return the clear "run /import-knowledge again" error) rather than throwing.
  private async ensureImportSessionArmed(): Promise<void> {
    const root = this.convo?.importSourceRoot;
    if (!root) return;
    if (this.importSessionActive && this.plugin.hasActiveAgentBridgeImportSession()) return;
    try {
      await this.plugin.beginAgentBridgeImportSession(root);
      this.importSessionActive = true;
    } catch (e) {
      this.importSessionActive = false;
      console.debug(
        `[VaultGuard Chat] Import session re-arm failed for ${root}:`,
        (e as Error)?.message ?? e,
      );
    }
  }

  // Disarm the bridge import session if one is active. Idempotent; safe to call
  // from reset/close paths. Best-effort — a failure to disarm is logged by the
  // bridge, and the lease still dies on logout regardless.
  private endImportSessionIfActive(): void {
    if (!this.importSessionActive) return;
    this.importSessionActive = false;
    try {
      this.plugin.endAgentBridgeImportSession();
    } catch {
      // The bridge's endImportSession never throws in practice; swallow to keep
      // teardown paths clean.
    }
  }

  private resetConversation(): void {
    this.showFreshConversation({ createTab: false });
  }

  /** Public entry used by the command palette: open a fresh in-panel tab. */
  openFreshChatTab(): void {
    if (this.inputController?.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before switching chats.");
      return;
    }
    const existingFresh = this.openTabs.find((tab) => tab.conversationId === null);
    if (existingFresh) {
      void this.activateChatTab(existingFresh.key);
      this.inputController?.focus();
      return;
    }
    this.showFreshConversation({ createTab: true });
  }

  private showFreshConversation(opts: { createTab: boolean }): void {
    if (this.inputController?.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before switching chats.");
      return;
    }
    this.handleCancel();
    // A new/cleared conversation ends any armed import session — the gated
    // source-read tools must not survive into an unrelated conversation.
    this.endImportSessionIfActive();
    this.runtime?.reset();
    this.runtime = null;
    // Drop the CLI session so /clear starts a fresh Claude Code context too.
    this.cliClient?.reset();
    this.cliClient = null;
    if (this.listEl) this.listEl.empty();
    this.pendingToolCards = [];
    this.activeAssistantBubble = null;
    this.cancelActiveUserQuestion("Question cancelled.");
    this.pendingRestoreMessages = null;
    this.statusPanel?.resetSession();
    // Drop the current conversation; the next turn mints a fresh id in the
    // active in-panel tab.
    this.convo = null;
    this.titleGenerated = false;
    if (opts.createTab || !this.activeTabKey) {
      this.activeTabKey = this.createTabKey();
      this.openTabs.push({
        key: this.activeTabKey,
        conversationId: null,
        title: "New chat",
      });
    } else {
      const active = this.activeTab();
      if (active) {
        active.conversationId = null;
        active.title = "New chat";
      }
    }
    this.setHeaderTitle("New chat");
    this.renderTabStrip();
    this.persistLeafState();
    if (
      this.plugin.settings.aiChatProvider !== "subscription" &&
      !new AnthropicKeyStore(this.plugin).hasKey()
    ) {
      this.renderConnectState();
    }
  }

  private createTabKey(): string {
    this.nextTabSeq += 1;
    return `tab-${Date.now().toString(36)}-${this.nextTabSeq}`;
  }

  private activeTab(): ChatConversationTab | null {
    if (!this.activeTabKey) return null;
    return this.openTabs.find((tab) => tab.key === this.activeTabKey) ?? null;
  }

  private ensureActiveTab(): ChatConversationTab {
    let tab = this.activeTab();
    if (tab) return tab;
    tab = {
      key: this.createTabKey(),
      conversationId: this.convo?.id ?? null,
      title: this.convo?.title || "New chat",
    };
    this.activeTabKey = tab.key;
    this.openTabs.push(tab);
    return tab;
  }

  private selectConversationTab(id: string, title: string): void {
    let tab = this.openTabs.find((candidate) => candidate.conversationId === id);
    if (!tab) {
      tab = { key: this.createTabKey(), conversationId: id, title: title || "Untitled chat" };
      this.openTabs.push(tab);
    } else {
      tab.title = title || tab.title || "Untitled chat";
    }
    this.activeTabKey = tab.key;
    // A restored legacy workspace can have duplicate ids; keep the active one.
    this.openTabs = this.openTabs.filter(
      (candidate) => candidate.key === tab.key || candidate.conversationId !== id,
    );
    this.renderTabStrip();
  }

  private updateActiveTab(conversationId: string | null, title: string): void {
    const tab = this.ensureActiveTab();
    tab.conversationId = conversationId;
    tab.title = title || "New chat";
    if (conversationId) {
      this.openTabs = this.openTabs.filter(
        (candidate) =>
          candidate.key === tab.key || candidate.conversationId !== conversationId,
      );
    }
    this.renderTabStrip();
  }

  private seedRestoredTabs(openIds: string[], hasFreshTab: boolean): void {
    for (const id of openIds) {
      if (this.openTabs.some((tab) => tab.conversationId === id)) continue;
      this.openTabs.push({
        key: this.createTabKey(),
        conversationId: id,
        title: "Saved chat",
      });
    }
    if (hasFreshTab && !this.openTabs.some((tab) => tab.conversationId === null)) {
      this.openTabs.push({
        key: this.createTabKey(),
        conversationId: null,
        title: "New chat",
      });
    }
    if (!this.activeTabKey && this.openTabs.length > 0) {
      this.activeTabKey = this.openTabs[0].key;
    }
    this.renderTabStrip();
    void this.refreshOpenTabTitles();
  }

  private async refreshOpenTabTitles(): Promise<void> {
    if (!this.store || this.openTabs.length === 0) return;
    let metas: ConversationMeta[];
    try {
      metas = await this.store.list();
    } catch {
      return;
    }
    const byId = new Map(metas.map((meta) => [meta.id, meta.title]));
    let changed = false;
    for (const tab of this.openTabs) {
      if (!tab.conversationId) continue;
      const title = byId.get(tab.conversationId);
      if (title && tab.title !== title) {
        tab.title = title;
        changed = true;
      }
    }
    if (changed) this.renderTabStrip();
  }

  private renderTabStrip(): void {
    if (!this.tabsEl) return;
    const tabsEl = this.tabsEl;
    if (this.openTabs.length === 0) {
      this.ensureActiveTab();
    }
    this.pruneExpandedTabKeys();

    tabsEl.empty();
    const showTabs = this.openTabs.length >= 2;
    tabsEl.toggleClass("is-hidden", !showTabs);
    if (!showTabs) return;

    this.openTabs.forEach((tab, index) => {
      const isExpanded = this.expandedTabKeys.has(tab.key);
      const tabEl = tabsEl.createDiv({
        cls:
          `${TAB_CLS}${tab.key === this.activeTabKey ? " is-active" : ""}` +
          `${isExpanded ? " is-expanded" : ""}`,
        attr: {
          role: "tab",
          "aria-label": `${tab.title || "New chat"} (tab ${index + 1})`,
          title: `${tab.title || "New chat"}\nClick to switch, double-click to show title, right-click to close.`,
        },
      });
      tabEl.createSpan({
        cls: `${TAB_CLS}-label`,
        text: isExpanded ? this.truncatedTabTitle(tab.title) : String(index + 1),
      });
      tabEl.addEventListener("click", () => void this.activateChatTab(tab.key));
      tabEl.addEventListener("dblclick", (evt) => {
        evt.preventDefault();
        evt.stopPropagation();
        this.toggleExpandedTab(tab.key);
      });
      tabEl.addEventListener("contextmenu", (evt) => {
        evt.preventDefault();
        void this.closeChatTab(tab.key);
      });
    });
  }

  private toggleExpandedTab(key: string): void {
    if (this.expandedTabKeys.has(key)) {
      this.expandedTabKeys.delete(key);
    } else {
      this.expandedTabKeys.add(key);
    }
    this.renderTabStrip();
  }

  private pruneExpandedTabKeys(): void {
    const visible = new Set(this.openTabs.map((tab) => tab.key));
    for (const key of this.expandedTabKeys) {
      if (!visible.has(key)) this.expandedTabKeys.delete(key);
    }
  }

  private truncatedTabTitle(title: string): string {
    const value = title || "New chat";
    const chars = Array.from(value);
    if (chars.length <= EXPANDED_TAB_TITLE_MAX) return value;
    return `${chars.slice(0, EXPANDED_TAB_TITLE_MAX - 3).join("")}...`;
  }

  private async activateChatTab(key: string): Promise<void> {
    if (key === this.activeTabKey) return;
    if (this.inputController?.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before switching chats.");
      return;
    }
    const tab = this.openTabs.find((candidate) => candidate.key === key);
    if (!tab) return;
    this.activeTabKey = key;
    if (tab.conversationId) {
      await this.loadConversation(tab.conversationId);
    } else {
      this.showFreshConversation({ createTab: false });
    }
  }

  private async closeChatTab(key: string): Promise<void> {
    if (this.inputController?.isBusy()) {
      new Notice("VaultGuard Chat: stop the current reply before closing chats.");
      return;
    }
    const index = this.openTabs.findIndex((tab) => tab.key === key);
    if (index < 0) return;
    const wasActive = this.openTabs[index].key === this.activeTabKey;
    this.openTabs.splice(index, 1);
    if (this.openTabs.length === 0) {
      this.activeTabKey = null;
      this.showFreshConversation({ createTab: true });
      return;
    }
    if (!wasActive) {
      this.renderTabStrip();
      this.persistLeafState();
      return;
    }
    const next = this.openTabs[Math.min(index, this.openTabs.length - 1)];
    this.activeTabKey = next.key;
    if (next.conversationId) {
      await this.loadConversation(next.conversationId);
    } else {
      this.showFreshConversation({ createTab: false });
    }
  }

  // ─── Persistence (§10) ─────────────────────────────────────────────────────

  private startConversation(firstUserText: string): void {
    const now = Date.now();
    this.ensureActiveTab();
    this.convo = {
      id: newConversationId(),
      title: defaultTitle(firstUserText),
      model: this.model,
      createdAt: now,
      updatedAt: now,
      messages: [],
    };
    this.titleGenerated = false;
    this.updateActiveTab(this.convo.id, this.convo.title);
    this.setHeaderTitle(this.convo.title);
    this.persistLeafState();
  }

  // Snapshot runtime messages into the current conversation and autosave
  // (debounced). After the first successful exchange of a NEW conversation we
  // also generate a title (§4 Haiku). `apiKey` is present here because §11
  // guarantees we only reach this path when a key exists.
  private captureAndSave(apiKey: string): void {
    if (!this.convo || !this.runtime) return;
    this.convo.messages = this.runtime.getMessages();
    this.convo.model = this.model;
    this.convo.updatedAt = Date.now();
    this.scheduleSave();
    this.maybeGenerateTitle(apiKey);
  }

  // §4 + §11: one cheap Haiku title call after the first exchange. Key-gated by
  // construction (only called from captureAndSave, which only runs when a key
  // exists). Never blocks the turn and never throws — generateTitle returns a
  // fallback on any error.
  private maybeGenerateTitle(apiKey: string): void {
    if (this.titleGenerated || !this.convo) return;
    const msgs = this.convo.messages;
    const firstUser = firstUserText(msgs);
    const firstAssistant = firstAssistantText(msgs);
    // Need both sides of one exchange before titling.
    if (!firstUser || !firstAssistant) return;

    // Mark immediately so concurrent turns don't double-fire.
    this.titleGenerated = true;
    const convoId = this.convo.id;

    const client = new AnthropicClient({
      apiKey,
      model: this.model,
      effort: this.plugin.settings.aiChatEffort,
    });

    void generateTitle(client, firstUser, firstAssistant).then((title) => {
      // Only apply if we're still on the same conversation.
      if (!this.convo || this.convo.id !== convoId) return;
      this.convo.title = title;
      this.setHeaderTitle(title);
      this.scheduleSave();
    });
  }

  private scheduleSave(): void {
    if (!this.store || !this.convo) return;
    if (this.saveTimer) clearTimeout(this.saveTimer);
    const snapshot = this.convo;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      void this.store?.save(snapshot);
    }, 400);
  }

  private async restoreMostRecent(): Promise<void> {
    if (!this.store) return;
    let convo: Conversation | null = null;
    try {
      convo = await this.store.loadMostRecent();
    } catch {
      return; // fail-soft
    }
    if (!convo) return;
    this.selectConversationTab(convo.id, convo.title);
    this.convo = convo;
    this.titleGenerated = true; // restored conversations already have a title
    this.setHeaderTitle(convo.title);
    this.renderConversation(convo);
    // Rehydrate the runtime lazily so the next turn carries context. The
    // runtime is built on first submit; stash messages to apply then.
    this.pendingRestoreMessages = convo.messages;
    this.persistLeafState();
  }

  private pendingRestoreMessages: Conversation["messages"] | null = null;

  // Pick (once) which conversation this view opens on, from its persisted view
  // state: a specific id, a blank in-panel tab, or the most-recent conversation
  // for legacy open / upgrade paths with no active id.
  private resolveInitialConversation(): void {
    if (this.initialConversationResolved || !this.listEl) return;
    this.initialConversationResolved = true;
    const choice = pickInitialConversation(this.leafState);
    this.seedRestoredTabs(choice.openIds, choice.hasFreshTab);
    if (choice.mode === "load") {
      void this.loadConversation(choice.id).catch((e) =>
        console.error("[VaultGuard Chat] initial conversation load failed", e),
      );
    } else if (choice.mode === "recent") {
      void this.restoreMostRecent().catch((e) =>
        console.error("[VaultGuard Chat] restore failed", e),
      );
    } else {
      const freshTab = this.openTabs.find((tab) => tab.conversationId === null);
      if (freshTab) this.activeTabKey = freshTab.key;
      this.showFreshConversation({ createTab: this.openTabs.length === 0 });
    }
  }

  /** The conversation this view currently shows. */
  getConversationId(): string | null {
    return this.convo?.id ?? null;
  }

  // Render a persisted conversation read-only into the list.
  private renderConversation(convo: Conversation): void {
    this.renderMessages(convo.messages);
    this.renderPersistedPendingQuestion(convo.pendingUserQuestion ?? null);
    // Re-show any pending Approve/Deny confirmations so an approval that was
    // outstanding when Obsidian was closed can still be applied after reload.
    this.renderPendingConfirmations();
  }

  // Render a message array (persisted or truncated-for-regenerate) into the list.
  private renderMessages(messages: Conversation["messages"]): void {
    if (!this.listEl) return;
    this.listEl.querySelector(`.${EMPTY_CLS}`)?.remove();

    // Recover each tool call's landed result by tool_use_id so re-rendered cards
    // (restore / regenerate / edit / delete) show the result instead of a stuck
    // "Running…" spinner. tool_result blocks live in the following user turn,
    // which is otherwise skipped as internal plumbing.
    const toolResults = new Map<string, { content: string; isError: boolean }>();
    for (const msg of messages) {
      if (msg.role !== "user" || !Array.isArray(msg.content)) continue;
      for (const b of msg.content as AnthropicToolResultBlock[]) {
        if (b && b.type === "tool_result") {
          toolResults.set(b.tool_use_id, {
            content: typeof b.content === "string" ? b.content : JSON.stringify(b.content),
            isError: b.is_error === true,
          });
        }
      }
    }

    let userTurn = 0;
    for (const msg of messages) {
      if (msg.role === "user") {
        if (isUserPrompt(msg)) {
          renderUserMessage(
            this.listEl,
            userPromptText(msg),
            this.userMessageActions(userTurn),
            userPromptImages(msg),
          );
          userTurn++;
        }
        // tool_result user turns are internal plumbing — not shown.
        continue;
      }
      // assistant turn: render thinking, text, and tool calls.
      const blocks = msg.content as AnthropicContentBlock[];
      if (!Array.isArray(blocks)) continue;
      for (const block of blocks) {
        if (block.type === "thinking" && block.thinking) {
          renderThinking(this.listEl, block.thinking);
        } else if (block.type === "text" && block.text) {
          renderAssistantMessage(this.listEl, this.app, this, "", block.text);
        } else if (block.type === "tool_use") {
          const card = renderToolCall(this.listEl, block.name, block.input);
          const result = toolResults.get(block.id);
          if (result) card.setResult(result);
        }
      }
    }
    this.scrollToBottom();
  }

  private renderPersistedPendingQuestion(pending: PendingUserQuestion | null): void {
    if (!this.listEl || !pending) return;

    let card: UserQuestionCard;
    card = renderUserQuestion(this.listEl, pending.request, {
      answer: (result) => {
        card.setAnswered(result);
        void this.resumePausedQuestion(result);
      },
      cancel: () => {
        card.setCancelled("Question cancelled.");
        this.clearPendingUserQuestion();
      },
    });
    this.scrollToBottom();
  }

  private persistPendingUserQuestion(request: AgentBridgeAskUserArgs): PendingUserQuestion | null {
    if (!this.convo) return null;
    const pending: PendingUserQuestion = {
      id: `ask-${Date.now().toString(36)}`,
      createdAt: Date.now(),
      request: {
        question: request.question,
        context: request.context,
        options: request.options?.map((option) => ({ ...option })),
        allowFreeform: request.allowFreeform,
        placeholder: request.placeholder,
      },
    };
    this.convo.pendingUserQuestion = pending;
    this.convo.updatedAt = Date.now();
    this.scheduleSave();
    return pending;
  }

  private clearPendingUserQuestion(): void {
    if (!this.convo?.pendingUserQuestion) return;
    this.convo.pendingUserQuestion = null;
    this.convo.updatedAt = Date.now();
    this.scheduleSave();
  }

  private async resumePausedQuestion(result: AgentBridgeAskUserResult): Promise<void> {
    const pending = this.convo?.pendingUserQuestion ?? null;
    if (!pending) return;

    if (this.inputController?.isBusy()) {
      this.queuedPausedAnswer = result;
      return;
    }

    this.clearPendingUserQuestion();
    const answer = this.formatPausedQuestionAnswer(pending, result);
    await this.handleSubmit(answer);
  }

  private flushQueuedPausedAnswer(): void {
    if (!this.queuedPausedAnswer || this.inputController?.isBusy()) return;
    const result = this.queuedPausedAnswer;
    this.queuedPausedAnswer = null;
    void this.resumePausedQuestion(result);
  }

  private formatPausedQuestionAnswer(
    pending: PendingUserQuestion,
    result: AgentBridgeAskUserResult,
  ): string {
    const answer = result.selectedOptionLabel ?? result.answer;
    return [
      "Answer to your paused VaultGuard approval question:",
      "",
      `Question: ${pending.request.question}`,
      `Answer: ${answer}`,
    ].join("\n");
  }

  private setHeaderTitle(title: string): void {
    this.convoTitleEl?.setText(title || "New chat");
    this.updateActiveTab(this.convo?.id ?? null, title || "New chat");
    this.refreshTabTitle();
  }

  // The in-panel header is the source of truth for the title; refreshing the
  // Obsidian tab label is best-effort. `updateHeader` is an internal Workspace
  // API (it re-reads getDisplayText/getIcon), so guard it.
  private refreshTabTitle(): void {
    try {
      (this.leaf as unknown as { updateHeader?: () => void }).updateHeader?.();
    } catch {
      // Ignore — the tab label simply won't refresh on this Obsidian build.
    }
  }

  // Persist this view's open conversation-tab ids into workspace.json so a
  // reload restores the in-panel tabs. Debounced by Obsidian. (The tab label is
  // refreshed via setHeaderTitle, which every conversation-change site calls.)
  private persistLeafState(): void {
    this.app.workspace.requestSaveLayout();
  }

  /** Public entry for the `vaultguard-chat-history` command. */
  showHistoryPicker(): void {
    void this.buildHistoryMenu().then((menu) => {
      const anchor = this.convoTitleEl ?? this.containerEl;
      const rect = anchor.getBoundingClientRect();
      menu.showAtPosition({ x: rect.left, y: rect.bottom });
    });
  }

  // History picker: list persisted conversations and load the chosen one.
  private async openHistoryMenu(evt: MouseEvent): Promise<void> {
    const menu = await this.buildHistoryMenu();
    menu.showAtMouseEvent(evt);
  }

  private async buildHistoryMenu(): Promise<Menu> {
    const menu = new Menu();
    if (!this.store) {
      menu.addItem((item) =>
        item.setTitle("History needs local encryption unlocked").setDisabled(true),
      );
      return menu;
    }
    let metas: ConversationMeta[];
    try {
      metas = await this.store.list();
    } catch {
      metas = [];
    }
    if (metas.length === 0) {
      menu.addItem((item) => item.setTitle("No saved chats").setDisabled(true));
    } else {
      for (const meta of metas) {
        menu.addItem((item) =>
          item
            .setTitle(meta.title || "Untitled chat")
            .setIcon(meta.id === this.convo?.id ? "check" : "message-square")
            .onClick(() => void this.openConversationFromHistory(meta.id)),
        );
      }
    }
    return menu;
  }

  // History-picker entry: open the chosen conversation as an in-panel tab
  // instead of creating/focusing a separate standalone Obsidian chat leaf.
  private async openConversationFromHistory(id: string): Promise<void> {
    await this.loadConversation(id);
  }

  private async loadConversation(id: string): Promise<void> {
    if (!this.store) return;
    const convo = await this.store.load(id);
    if (!convo) {
      new Notice("VaultGuard Chat: could not load that conversation.");
      return;
    }
    this.selectConversationTab(convo.id, convo.title);
    this.handleCancel();
    this.runtime?.reset();
    this.runtime = null; // rebuild on next turn; rehydrate via pendingRestore
    this.cliClient?.reset();
    this.cliClient = null;
    if (this.listEl) this.listEl.empty();
    this.pendingToolCards = [];
    this.activeAssistantBubble = null;
    this.cancelActiveUserQuestion("Question cancelled.");
    this.statusPanel?.resetSession();
    this.convo = convo;
    this.titleGenerated = true; // restored conversations already have a title
    this.setHeaderTitle(convo.title);
    this.renderConversation(convo);
    this.pendingRestoreMessages = convo.messages;
    this.persistLeafState();
  }

  // ─── Runtime construction ──────────────────────────────────────────────────

  private async ensureRuntime(apiKey: string, streaming: boolean): Promise<void> {
    if (this.runtime) return;
    this.runtimeStreaming = streaming;

    // Mint a vault-wide lease for the session. The selected AI Chat permission
    // mode decides whether writes ask first or use the ephemeral skip-confirm
    // write mode; server-side file permissions still apply either way.
    const lease = await this.plugin.createAgentBridgeLease({
      agentName: "VaultGuard Chat",
      scope: "/**",
      expiresWithSession: true,
      allowRead: true,
      writeMode: chatPermissionWriteMode(this.plugin.settings.aiChatPermissionMode),
      // In-app chat lease: enable the vaultguard_access permission-query tool.
      allowAccessQueries: true,
      // In-app chat lease: enable the gated /import-knowledge source-read tools.
      // They stay inert until the user runs /import-knowledge (which arms an
      // import session); minting the capability here just lets that flow work.
      allowImportRead: true,
      // In-app chat lease: enable the interactive ask-user tool.
      allowUserInteraction: true,
      // In-app chat lease: enable the vaultguard_set_permission tool. Every change
      // is still user-confirmed and re-authorized server-side (admin/file-admin).
      allowPermissionWrites: true,
      // In-app chat lease: enable the read-only vaultguard_audit tool. The backend
      // still gates the audit log to vault admins.
      allowAuditQueries: true,
      // In-app chat lease: enable the vaultguard_files tool (history/overview/
      // deleted/restore). The backend gates each op; restore is user-confirmed.
      allowFileHistory: true,
      // In-app chat lease: enable the vaultguard_share tool (list/create/revoke).
      // create/revoke are user-confirmed; the backend re-authorizes each.
      allowShareManagement: true,
      // In-app chat lease: enable the vaultguard_membership tool (add/remove/
      // set_role). Every op is user-confirmed and re-authorized as vault-admin.
      allowMembershipWrites: true,
    });
    this.leaseId = lease.leaseId;

    const surface = this.plugin.getAgentBridge();
    const toolRuntime = new VaultToolRuntime(surface, lease.leaseId);
    const client = new AnthropicClient({
      apiKey,
      model: this.model,
      effort: this.plugin.settings.aiChatEffort,
    });

    this.runtime = new ChatRuntime({
      client,
      toolRuntime,
      config: {
        system: buildSystemPrompt(
          this.plugin.settings.aiChatSystemPrompt,
          this.plugin.settings.aiChatPermissionMode,
        ),
        model: this.model,
        streaming,
      },
      progress: {
        onAssistant: (msg) => this.onAssistant(msg),
        onText: (text) => this.onText(text),
        onTextDelta: (text) => {
          this.streamController?.onTextDelta(text);
        },
        onThinkingDelta: (text) => {
          this.streamController?.onThinkingDelta(text);
        },
        onToolCall: (name, input) => this.onToolCall(name, input),
        onToolResult: (_name, result) => this.onToolResult(result),
        onRefusal: () => this.onRefusal(),
        onStepLimit: () =>
          new Notice("VaultGuard Chat: reached the step limit for one turn."),
      },
    });

    // Rehydrate a restored conversation's history so the next turn has context.
    if (this.pendingRestoreMessages) {
      this.runtime.setMessages(this.pendingRestoreMessages);
      this.pendingRestoreMessages = null;
    }
  }

  // ─── Progress callbacks → renderers ────────────────────────────────────────

  private onAssistant(msg: AnthropicMessage): void {
    // Record token usage for the status footer.
    this.statusPanel?.recordUsage(msg.usage);

    if (this.streamController) {
      // Streaming transport: thinking + text were already painted live by the
      // controller. Settle the streamed text into its final markdown render;
      // a following block (e.g. after a tool call) starts a fresh bubble.
      this.streamController.finalize();
      this.activeAssistantBubble = null;
      this.scrollToBottom();
      return;
    }

    // Tier-1: render any thinking summary above the (forthcoming) text bubble.
    if (this.listEl) {
      const thinking = extractThinking(msg);
      if (thinking) renderThinking(this.listEl, thinking);
    }

    // A new assistant turn → start a fresh bubble for its text.
    this.activeAssistantBubble = null;
    this.scrollToBottom();
  }

  private onText(text: string): void {
    if (!this.listEl) return;
    if (!this.activeAssistantBubble) {
      const bubble = renderAssistantMessage(
        this.listEl,
        this.app,
        this,
        "",
        text,
      );
      this.activeAssistantBubble = bubble.root.isConnected ? bubble : null;
    } else {
      const rendered = this.activeAssistantBubble.appendMarkdown(text);
      if (!rendered && !this.activeAssistantBubble.getRawText()) {
        this.activeAssistantBubble = null;
      }
    }
    this.scrollToBottom();
  }

  private onToolCall(name: string, input: unknown): void {
    if (!this.listEl) return;
    // Settle any streamed text into markdown before the tool card lands.
    this.streamController?.finalize();
    const card = renderToolCall(this.listEl, name, input);
    this.pendingToolCards.push(card);
    // A tool call ends the current text bubble; the next text starts a new one.
    this.activeAssistantBubble = null;
    this.scrollToBottom();
  }

  private onToolResult(result: { content: string; isError: boolean }): void {
    const card = this.pendingToolCards.shift();
    card?.setResult(result);
    this.scrollToBottom();
  }

  private onCliStatus(message: string): void {
    this.pendingIndicator?.setLabel(message);
    this.scrollToBottom();
  }

  async askUserFromAgent(
    request: AgentBridgeAskUserArgs & { delivery?: AgentBridgeAskUserDelivery },
  ): Promise<AgentBridgeAskUserResult> {
    if (!this.listEl) {
      throw new Error("VaultGuard AI Chat is not open to answer this question.");
    }
    if (this.activeUserQuestion || this.convo?.pendingUserQuestion) {
      throw new Error("VaultGuard AI Chat is already waiting for an answer.");
    }

    if (request.delivery === "pause") {
      const pending = this.persistPendingUserQuestion(request);
      if (!pending) {
        throw new Error("VaultGuard AI Chat could not save the paused question.");
      }
      this.renderPersistedPendingQuestion(pending);
      this.pendingIndicator?.setWaiting(true);
      return {
        answer:
          "VaultGuard AI Chat displayed this question to the user and paused the turn.",
      };
    }

    // The turn is now paused on a human answer — flip the persistent indicator
    // from "Working…" to "Waiting for your answer…" (and freeze its dots) until
    // the question settles, so the UI doesn't claim Claude is still working.
    this.pendingIndicator?.setWaiting(true);

    return new Promise<AgentBridgeAskUserResult>((resolve, reject) => {
      let settled = false;
      const settle = (fn: () => void): void => {
        if (settled) return;
        settled = true;
        this.activeUserQuestion = null;
        this.pendingIndicator?.setWaiting(false);
        fn();
        this.scrollToBottom();
      };

      let card: UserQuestionCard;
      card = renderUserQuestion(this.listEl as HTMLElement, request, {
        answer: (result) =>
          settle(() => {
            card.setAnswered(result);
            resolve(result);
          }),
        cancel: () =>
          settle(() => {
            card.setCancelled("Question cancelled.");
            reject(new Error("User cancelled the question."));
          }),
      });
      this.activeUserQuestion = {
        card,
        reject: (err) =>
          settle(() => {
            card.setCancelled(err.message || "Question cancelled.");
            reject(err);
          }),
      };
      this.scrollToBottom();
    });
  }

  // Non-blocking confirmation entry (MCP/Claude-CLI path). The model issues
  // several set_permission calls in ONE turn; each lands here and is ENQUEUED
  // (never rejected — rejecting subsequent calls is what produced the "already
  // waiting for an answer" errors). All pending confirmations are shown as a
  // single batched Approve-all/Deny-all card; the plugin applies them on
  // approval, decoupled from the (likely already-ended) turn. Returns IMMEDIATELY
  // so the tool call can't block past Claude Code's tool timeout.
  async confirmWriteFromAgent(
    request: Parameters<AgentBridgeConfirmPausedHandler>[0],
  ): Promise<void> {
    if (!this.listEl) {
      throw new Error("VaultGuard AI Chat is not open to confirm this change.");
    }
    if (!this.convo) {
      throw new Error("VaultGuard AI Chat has no active conversation to confirm into.");
    }
    const src = request.action;
    const action: PendingConfirmationAction = {
      operation: src.operation,
      leaseId: src.leaseId,
      preview: src.preview,
      ...(src.setPermission ? { setPermission: { ...src.setPermission } } : {}),
      ...(src.share ? { share: { ...src.share } } : {}),
      ...(src.membership ? { membership: { ...src.membership } } : {}),
      ...(src.restore ? { restore: { ...src.restore } } : {}),
    };
    const queue = this.convo.pendingConfirmations ?? [];
    queue.push(action);
    this.convo.pendingConfirmations = queue;
    this.convo.updatedAt = Date.now();
    this.scheduleSave();
    this.renderPendingConfirmations();
    this.pendingIndicator?.setWaiting(true);
  }

  // (Re)render the single batched confirmation card for the whole pending queue.
  // Called as each set_permission lands and on conversation restore.
  private renderPendingConfirmations(): void {
    if (!this.listEl) return;
    // Drop any previously-rendered card so the list reflects the current queue.
    this.pendingConfirmCard?.root.remove();
    this.pendingConfirmCard = null;

    const queue = this.convo?.pendingConfirmations ?? [];
    if (queue.length === 0) {
      this.pendingIndicator?.setWaiting(false);
      return;
    }

    const lines = queue.map((a) => `• ${a.preview}`).join("\n");
    const request: AgentBridgeAskUserArgs = {
      question:
        queue.length === 1 ? "Approve this action?" : `Approve these ${queue.length} actions?`,
      context:
        `${lines}\n\nRequested by the AI assistant. Approving runs them on the ` +
        "server (re-authorized as you and audited); denying changes nothing.",
      options: [
        { id: "approve", label: queue.length === 1 ? "Approve" : "Approve all", value: "approve" },
        { id: "deny", label: queue.length === 1 ? "Deny" : "Deny all", value: "deny" },
      ],
      allowFreeform: false,
    };

    let card: UserQuestionCard;
    card = renderUserQuestion(this.listEl, request, {
      answer: (result) => {
        card.setAnswered(result);
        const approved =
          result.selectedOptionId === "approve" || result.selectedOptionValue === "approve";
        void this.resolvePendingConfirmations(approved);
      },
      cancel: () => {
        card.setCancelled("Cancelled — no permission changes applied.");
        void this.resolvePendingConfirmations(false);
      },
    });
    this.pendingConfirmCard = card;
    this.scrollToBottom();
  }

  // Apply (approve) or discard (deny) every queued confirmation, then feed ONE
  // summary turn back to the model so it acknowledges (not one per item, which
  // would re-trigger tool calls). Decoupled from the original turn: the changes
  // are applied by the plugin even if that turn has already ended.
  private async resolvePendingConfirmations(approved: boolean): Promise<void> {
    const queue = this.convo?.pendingConfirmations ?? [];
    if (queue.length === 0) return;

    // If a turn is still streaming, defer until it settles (mirrors ask_user).
    if (this.inputController?.isBusy()) {
      this.queuedConfirmDecision = approved;
      return;
    }

    this.pendingConfirmCard = null;
    if (this.convo) {
      this.convo.pendingConfirmations = null;
      this.convo.updatedAt = Date.now();
      this.scheduleSave();
    }
    this.pendingIndicator?.setWaiting(false);

    if (!approved) {
      await this.handleSubmit(
        `The user DENIED the following action(s); do not retry them, ask what they'd prefer:\n` +
          queue.map((a) => `- ${a.preview}`).join("\n"),
      );
      return;
    }

    const surface = this.plugin.getAgentBridge();
    const applied: string[] = [];
    const failed: string[] = [];
    for (const action of queue) {
      try {
        // Prefer the CURRENT chat lease (survives a reload that minted a new
        // one); fall back to the lease captured when the card was shown.
        const leaseId = this.leaseId ?? action.leaseId;
        // Returns a human-readable summary (for a share create, includes the URL)
        // so the model can relay the exact result to the user.
        const summary = await surface.applyConfirmedMutation(leaseId, action);
        applied.push(summary);
      } catch (e) {
        failed.push(`${action.preview} — ${(e as Error).message}`);
      }
    }

    const parts: string[] = [];
    if (applied.length > 0) {
      parts.push(
        `The user APPROVED and VaultGuard applied these action(s):\n` +
          applied.map((p) => `- ${p}`).join("\n"),
      );
    }
    if (failed.length > 0) {
      parts.push(
        `These failed to apply (tell the user plainly; do not silently retry):\n` +
          failed.map((p) => `- ${p}`).join("\n"),
      );
    }
    parts.push(
      "Do not repeat these actions. Confirm what was done to the user concisely; " +
        "if a share link was created, give the user its full URL.",
    );
    await this.handleSubmit(parts.join("\n\n"));
  }

  private flushQueuedConfirmDecision(): void {
    if (this.queuedConfirmDecision === null || this.inputController?.isBusy()) return;
    const approved = this.queuedConfirmDecision;
    this.queuedConfirmDecision = null;
    void this.resolvePendingConfirmations(approved);
  }

  private cancelActiveUserQuestion(message: string): void {
    const active = this.activeUserQuestion;
    if (!active) return;
    this.activeUserQuestion = null;
    active.card.setCancelled(message);
    active.reject(new Error(message));
  }

  private onRefusal(): void {
    this.renderError(
      "The model declined to answer this request (stop_reason: refusal). " +
        "Try rephrasing, or switch to Opus 4.8.",
    );
  }

  // ─── Streaming transport selection ─────────────────────────────────────────

  // Tier-2 streaming is opt-in (settings toggle) AND desktop-only. On mobile —
  // or with the toggle off — this returns false and the turn uses Tier-1 send().
  private streamingEnabled(): boolean {
    return this.plugin.settings.aiChatStreaming === true && !Platform.isMobileApp;
  }

  private makeStreamController(): StreamController | null {
    if (!this.listEl) return null;
    return new StreamController({
      list: this.listEl,
      app: this.app,
      component: this,
      scroll: () => this.scrollToBottom(),
    });
  }

  // ─── Model + helpers ───────────────────────────────────────────────────────

  // In-footer compact pickers. Each chip opens its own menu and applies the
  // choice immediately (rebuilding the runtime when that setting is baked into
  // the next turn's client/lease). In subscription mode the Anthropic model id
  // is advisory (the CLI owns the actual model), so we still record it for the
  // next session.
  private openModelMenu(evt: MouseEvent): void {
    const menu = new Menu();

    for (const m of AI_CHAT_MODELS) {
      menu.addItem((item) =>
        item
          .setTitle(m.label)
          .setChecked(m.id === this.model)
          .onClick(() => {
            if (m.id !== this.model) this.setModel(m.id);
          }),
      );
    }

    menu.showAtMouseEvent(evt);
  }

  private openEffortMenu(evt: MouseEvent): void {
    const menu = new Menu();
    const currentEffort = this.plugin.settings.aiChatEffort;
    for (const e of AI_CHAT_EFFORTS) {
      menu.addItem((item) =>
        item
          .setTitle(e.label)
          .setChecked(e.id === currentEffort)
          .onClick(() => void this.setEffort(e.id)),
      );
    }

    menu.showAtMouseEvent(evt);
  }

  private openPermissionMenu(evt: MouseEvent): void {
    const menu = new Menu();
    const currentPermissionMode = this.plugin.settings.aiChatPermissionMode;
    for (const mode of AI_CHAT_PERMISSION_MODES) {
      menu.addItem((item) =>
        item
          .setTitle(mode.label)
          .setChecked(mode.id === currentPermissionMode)
          .onClick(() => void this.setPermissionMode(mode.id)),
      );
    }

    menu.showAtMouseEvent(evt);
  }

  private async setEffort(effort: AnthropicEffort): Promise<void> {
    if (this.plugin.settings.aiChatEffort === effort) return;
    this.plugin.settings.aiChatEffort = effort;
    await this.plugin.saveSettings();
    this.statusPanel?.setEffort(effort);
    // Rebuild so the next turn's client carries the new effort.
    this.runtime = null;
    this.cliClient?.reset();
    this.cliClient = null;
    new Notice(`VaultGuard Chat: thinking effort → ${effort}`);
  }

  private async setPermissionMode(mode: AiChatPermissionMode): Promise<void> {
    if (this.plugin.settings.aiChatPermissionMode === mode) return;
    this.plugin.settings.aiChatPermissionMode = mode;
    await this.plugin.saveSettings();
    this.statusPanel?.setPermissionMode(mode);
    // Rebuild so the next turn mints a lease with the new write mode.
    this.runtime = null;
    this.cliClient?.reset();
    this.cliClient = null;
    new Notice(`VaultGuard Chat: permissions → ${permissionModeLabel(mode)}`);
  }

  private setModel(model: string): void {
    this.model = model;
    this.statusPanel?.setModel(model);
    // Persist so the choice survives a panel reopen / new chat (mirrors
    // setEffort) and stays in sync with the settings dropdown.
    this.plugin.settings.aiChatModel = model;
    void this.plugin.saveSettings();
    // Rebuild the runtime / CLI client on next turn so the new model applies.
    this.runtime = null;
    this.cliClient?.reset();
    this.cliClient = null;
  }

  async copyDomDebugReport(): Promise<void> {
    const report = this.buildDomDebugReport();
    console.groupCollapsed("[VaultGuard Chat] DOM debug report");
    console.log(report);
    console.groupEnd();

    try {
      if (!navigator.clipboard?.writeText) throw new Error("Clipboard API is unavailable.");
      await navigator.clipboard.writeText(report);
      new Notice("VaultGuard Chat: DOM debug report copied to clipboard.");
    } catch (e) {
      console.warn("[VaultGuard Chat] could not copy DOM debug report", e);
      new Notice("VaultGuard Chat: DOM debug report logged to the developer console.");
    }
  }

  private buildDomDebugReport(): string {
    const lines: string[] = [
      "VaultGuard Chat DOM debug report",
      `time: ${new Date().toISOString()}`,
      `provider: ${this.plugin.settings.aiChatProvider}`,
      `model: ${this.model}`,
      `pendingIndicator: ${this.pendingIndicator ? "present" : "absent"}`,
      `activeAssistantBubble: ${this.activeAssistantBubble ? "present" : "absent"}`,
    ];

    if (!this.listEl) {
      lines.push("listEl: null");
      return lines.join("\n");
    }

    const list = this.listEl;
    const listRect = list.getBoundingClientRect();
    lines.push(
      `list: rect=${this.chatDebugRect(listRect)} children=${list.children.length} scrollTop=${list.scrollTop} scrollHeight=${list.scrollHeight} clientHeight=${list.clientHeight}`,
    );

    const root = list.closest(`.${ROOT_CLS}`);
    if (root instanceof HTMLElement) {
      lines.push(`root: ${this.describeChatDebugElement(root, "root", list)}`);
    }

    lines.push("");
    lines.push(`direct children (${list.children.length}):`);
    Array.from(list.children)
      .filter((child): child is HTMLElement => child instanceof HTMLElement)
      .forEach((child, index) => {
        lines.push(this.describeChatDebugElement(child, `child[${index}]`, list));
      });

    const suspicious = this.findSuspiciousChatDebugElements(list);
    lines.push("");
    lines.push(`suspicious descendants (${suspicious.length}${suspicious.length >= 120 ? "+" : ""}):`);
    if (suspicious.length === 0) {
      lines.push("none");
    } else {
      suspicious.forEach((el, index) => {
        const path = this.chatDebugElementPath(el, list);
        lines.push(this.describeChatDebugElement(el, `suspect[${index}] ${path}`, list));
      });
    }

    lines.push("");
    lines.push("legend: a suspect is a visible thin/empty row, visible hr, visible render target, empty assistant/error shell, or chat row containing a direct hr.");
    return lines.join("\n");
  }

  private findSuspiciousChatDebugElements(list: HTMLElement): HTMLElement[] {
    const all = [list, ...Array.from(list.querySelectorAll("*"))].filter(
      (el): el is HTMLElement => el instanceof HTMLElement,
    );
    return all.filter((el) => this.chatDebugReasons(el, list).length > 0).slice(0, 120);
  }

  private describeChatDebugElement(el: HTMLElement, label: string, list: HTMLElement): string {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    const text = this.chatDebugText(el);
    const children = Array.from(el.children)
      .slice(0, 8)
      .map((child) => this.chatDebugShortTag(child))
      .join(" ");
    const reasons = this.chatDebugReasons(el, list);
    return [
      label,
      this.chatDebugShortTag(el),
      `rect=${this.chatDebugRect(rect)}`,
      `display=${style.display}`,
      `visibility=${style.visibility}`,
      `opacity=${style.opacity}`,
      `margin=${this.chatDebugBox(style, "margin")}`,
      `padding=${this.chatDebugBox(style, "padding")}`,
      `border=${this.chatDebugBox(style, "border", "Width")}`,
      `bg=${style.backgroundColor}`,
      `textLen=${(el.textContent ?? "").length}`,
      `text="${text}"`,
      `children=${el.children.length}${children ? ` [${children}]` : ""}`,
      reasons.length ? `reasons=${reasons.join(",")}` : "",
    ]
      .filter(Boolean)
      .join(" ");
  }

  private chatDebugReasons(el: HTMLElement, list: HTMLElement): string[] {
    const rect = el.getBoundingClientRect();
    const style = window.getComputedStyle(el);
    const visible = this.chatDebugIsVisible(style, rect);
    const reasons: string[] = [];
    const tag = el.tagName.toLowerCase();
    const text = this.chatDebugText(el);

    if (tag === "hr" && visible) reasons.push("visible-hr");
    if (el.matches(".vaultguard-chat-md-render-target") && visible) {
      reasons.push("visible-hidden-render-target");
    }
    if (el.matches(".vaultguard-chat-md-fallback") && visible && !text) {
      reasons.push("empty-visible-fallback");
    }
    if (el.matches(".vaultguard-chat-error") && visible && !text) {
      reasons.push("empty-error-shell");
    }
    if (el.matches(".vaultguard-chat-message-assistant:not(.vaultguard-chat-pending)") && visible) {
      const bubble = el.querySelector(".vaultguard-chat-bubble");
      if (bubble instanceof HTMLElement && !this.chatDebugHasMeaningfulContent(bubble)) {
        reasons.push("assistant-row-empty-bubble");
      }
    }
    if (el.parentElement === list && visible && !this.chatDebugHasMeaningfulContent(el)) {
      reasons.push("visible-empty-direct-chat-child");
    }
    if (
      visible &&
      rect.width >= Math.min(160, list.getBoundingClientRect().width * 0.45) &&
      rect.height > 0 &&
      rect.height <= 8 &&
      (!text || this.chatDebugHasLinePaint(style))
    ) {
      reasons.push("thin-visible-row");
    }
    if (
      visible &&
      !text &&
      rect.width >= Math.min(160, list.getBoundingClientRect().width * 0.45) &&
      rect.height > 8 &&
      rect.height <= 44 &&
      this.chatDebugHasLinePaint(style)
    ) {
      reasons.push("empty-painted-row");
    }

    const directHr = Array.from(el.children).some((child) => child.tagName.toLowerCase() === "hr");
    if (visible && directHr) reasons.push("contains-direct-hr");
    return reasons;
  }

  private chatDebugHasMeaningfulContent(el: HTMLElement): boolean {
    if (this.chatDebugText(el)) return true;
    return Boolean(el.querySelector("img, video, audio, canvas, pre, code, table, ul, ol, input, textarea, button"));
  }

  private chatDebugHasLinePaint(style: CSSStyleDeclaration): boolean {
    return (
      this.chatDebugPx(style.borderTopWidth) > 0 ||
      this.chatDebugPx(style.borderBottomWidth) > 0 ||
      this.chatDebugPaintedBackground(style.backgroundColor)
    );
  }

  private chatDebugPaintedBackground(color: string): boolean {
    const value = color.trim().toLowerCase();
    return Boolean(value && value !== "transparent" && value !== "rgba(0, 0, 0, 0)" && !value.endsWith(", 0)"));
  }

  private chatDebugIsVisible(style: CSSStyleDeclaration, rect: DOMRect): boolean {
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      rect.width > 0 &&
      rect.height > 0
    );
  }

  private chatDebugText(el: HTMLElement): string {
    return (el.textContent ?? "").replace(/\s+/g, " ").trim().slice(0, 160);
  }

  private chatDebugShortTag(el: Element): string {
    const tag = el.tagName.toLowerCase();
    const id = el.id ? `#${el.id}` : "";
    const cls = (el.getAttribute("class") ?? "")
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 6)
      .join(".");
    return `<${tag}${id}${cls ? `.${cls}` : ""}>`;
  }

  private chatDebugElementPath(el: HTMLElement, stop: HTMLElement): string {
    const parts: string[] = [];
    let cur: HTMLElement | null = el;
    while (cur && cur !== stop) {
      const parent: HTMLElement | null = cur.parentElement;
      const index = parent ? Array.from(parent.children).indexOf(cur) + 1 : 1;
      parts.unshift(`${this.chatDebugShortTag(cur)}:nth-child(${index})`);
      cur = parent;
    }
    return parts.length ? `list > ${parts.join(" > ")}` : "list";
  }

  private chatDebugRect(rect: DOMRect): string {
    return `${Math.round(rect.width)}x${Math.round(rect.height)}@${Math.round(rect.left)},${Math.round(rect.top)}`;
  }

  private chatDebugBox(style: CSSStyleDeclaration, prefix: "margin" | "padding" | "border", suffix = ""): string {
    const prop = (side: "Top" | "Right" | "Bottom" | "Left") => `${prefix}${side}${suffix}`;
    return `${style.getPropertyValue(this.chatDebugCssName(prop("Top")))}/${style.getPropertyValue(
      this.chatDebugCssName(prop("Right")),
    )}/${style.getPropertyValue(this.chatDebugCssName(prop("Bottom")))}/${style.getPropertyValue(
      this.chatDebugCssName(prop("Left")),
    )}`;
  }

  private chatDebugCssName(name: string): string {
    return name.replace(/[A-Z]/g, (m) => `-${m.toLowerCase()}`);
  }

  private chatDebugPx(value: string): number {
    const n = Number.parseFloat(value);
    return Number.isFinite(n) ? n : 0;
  }

  private renderError(message: string): void {
    this.clearPending();
    // Never render a blank error: renderMarkdownWithFallback removes the empty
    // body div but leaves the bordered shell + icon behind, which shows as a
    // stray red line. Coalesce empty/whitespace to a generic message so the
    // shell always has visible content.
    const text = message?.trim() || "The request failed without an error message.";
    if (!this.listEl) {
      new Notice(`VaultGuard Chat: ${text}`);
      return;
    }
    const el = this.listEl.createDiv({ cls: "vaultguard-chat-error" });
    const icon = el.createSpan({ cls: "vaultguard-chat-error-icon" });
    setIcon(icon, "alert-triangle");
    const body = el.createDiv({ cls: "vaultguard-chat-error-body" });
    renderMarkdownWithFallback(body, this.app, this, "", text);
    this.statusPanel?.setConnection(this.plugin.isConnectedOnline());
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    if (!this.listEl) return;
    // Keep the persistent "Working…" indicator pinned below the latest content
    // (bubbles / tool cards append after it; re-append moves it back to the end).
    this.pendingIndicator?.moveToEnd();
    this.listEl.scrollTop = this.listEl.scrollHeight;
  }

  // ─── Edit / delete messages ────────────────────────────────────────────────

  // The current message history (live runtime if built, else the
  // persisted/restored array waiting to rehydrate).
  private currentMessages(): Conversation["messages"] {
    if (this.runtime) return this.runtime.getMessages();
    return this.convo?.messages ?? this.pendingRestoreMessages ?? [];
  }

  private userTurnCount(): number {
    let c = 0;
    for (const m of this.currentMessages()) {
      if (isUserPrompt(m)) c++;
    }
    return c;
  }

  // Edit/delete need a replayable message array; the subscription (CLI) provider
  // keeps its own context, so the actions are API-key-only.
  private userMessageActions(turnIndex: number) {
    if (this.plugin.settings.aiChatProvider === "subscription") return undefined;
    return {
      onEdit: () => this.editUserTurn(turnIndex),
      onDelete: () => this.deleteUserTurn(turnIndex),
    };
  }

  // Drop the Nth user prompt and everything after it across all stores (runtime,
  // pending-restore, and the in-memory conversation). Returns the kept messages
  // + the removed prompt text, or null when out of range. Does NOT persist —
  // callers decide (edit re-seeds + saves; delete may reset an emptied chat).
  private truncateFromUserTurn(
    n: number,
  ): { kept: Conversation["messages"]; removedText: string } | null {
    // Delegate to the runtime when it's built (it owns the live message array);
    // otherwise slice the persisted/restored array directly. Both index user
    // prompts via isUserPrompt, so image-bearing turns truncate correctly.
    const res = this.runtime
      ? this.runtime.removeFromUserTurn(n)
      : sliceBeforeUserTurn(this.currentMessages(), n);
    if (!res) return null;

    this.pendingRestoreMessages = res.kept.length ? res.kept : null;
    if (this.convo) {
      this.convo.messages = res.kept;
      this.convo.updatedAt = Date.now();
    }
    return res;
  }

  private editUserTurn(turnIndex: number): void {
    if (!this.listEl || this.inputController?.isBusy()) return;
    const res = this.truncateFromUserTurn(turnIndex);
    if (!res) return;
    this.listEl.empty();
    this.renderMessages(res.kept);
    // Seed the input with the original prompt so the user can revise + resend.
    this.inputController?.setText(res.removedText);
    this.inputController?.focus();
    if (this.convo) this.scheduleSave();
  }

  private deleteUserTurn(turnIndex: number): void {
    if (!this.listEl || this.inputController?.isBusy()) return;
    const res = this.truncateFromUserTurn(turnIndex);
    if (!res) return;
    if (res.kept.length === 0) {
      // Whole conversation removed — delete the persisted envelope so it can't
      // resurrect on the next restore, then fall back to a clean New chat.
      const id = this.convo?.id;
      if (id) void this.store?.delete(id);
      this.resetConversation();
      return;
    }
    this.listEl.empty();
    this.renderMessages(res.kept);
    if (this.convo) this.scheduleSave();
  }

  // Expand a prompt template or built-in `$` skill. The returned text is what
  // the chat sends as the user's prompt; note content still has to be reached
  // through the permission-gated VaultGuard tools during the model turn.
  private resolveTemplate(name: string, arg: string, prefix: PromptCommandPrefix): string | null {
    if (prefix === "$") {
      const builtInSkill = expandBuiltInSkill(name, arg);
      if (builtInSkill != null) return builtInSkill;
    }

    const tpl = (this.plugin.settings.aiChatPromptTemplates ?? []).find((t) => {
      if (!t.name || !sameCommandName(t.name, name)) return false;
      return promptTemplatePrefix(t) === prefix;
    });
    if (!tpl || !tpl.prompt.trim()) return null;
    return expandPromptTemplate(tpl, arg);
  }

  private slashCommandSuggestions(): SlashCommandSuggestion[] {
    const seen = new Set<string>();
    const suggestions: SlashCommandSuggestion[] = [];
    for (const skill of OBSIDIAN_CHAT_SKILLS) {
      const key = `$${skill.name.toLowerCase()}`;
      suggestions.push({
        name: skill.name,
        description: skill.description,
        argumentHint: skill.argumentHint,
        prefix: "$",
        source: "skill",
      });
      seen.add(key);
    }
    for (const tpl of this.plugin.settings.aiChatPromptTemplates ?? []) {
      const name = (tpl.name ?? "").trim().replace(/^[/$]+/, "");
      const prefix = promptTemplatePrefix(tpl);
      const key = `${prefix}${name.toLowerCase()}`;
      if (!name || seen.has(key)) continue;
      if (prefix === "/" && RESERVED_SLASH_COMMAND_NAMES.has(name.toLowerCase())) continue;
      if (!/^[a-zA-Z0-9_-]+$/.test(name)) continue;
      const parsed = parsePromptTemplate(tpl.prompt);
      const description = parsed.description || firstPromptLine(tpl.prompt) || "Prompt template";
      suggestions.push({
        name,
        description,
        argumentHint: parsed.argumentHint,
        prefix,
        source: prefix === "$" ? "skill" : "template",
      });
      seen.add(key);
    }
    return suggestions;
  }

  // ─── @-mention note picker ─────────────────────────────────────────────────

  // Candidate notes for an `@`-mention. Reads ONLY the vault file list (TFile
  // metadata via the Obsidian API) — never file content — so the at-rest
  // boundary is untouched. The actual read still goes through the permission-
  // gated vaultguard_read tool when the model resolves the injected [[path]].
  private mentionCandidates(query: string): MentionCandidate[] {
    const files = this.app.vault.getMarkdownFiles();
    const q = query.toLowerCase();
    const scored = files
      .map((f) => {
        const name = f.basename.toLowerCase();
        const path = f.path.toLowerCase();
        let rank = -1;
        if (!q) rank = 2;
        else if (name.startsWith(q)) rank = 0;
        else if (name.includes(q)) rank = 1;
        else if (path.includes(q)) rank = 2;
        return { f, rank };
      })
      .filter((e) => e.rank >= 0)
      .sort((a, b) => a.rank - b.rank || a.f.basename.localeCompare(b.f.basename))
      .slice(0, 20)
      .map((e) => ({ path: e.f.path, name: e.f.basename }));
    return scored;
  }

  // ─── Pending "thinking…" indicator ─────────────────────────────────────────

  private showPending(): void {
    if (!this.listEl || this.pendingIndicator) return;
    this.pendingIndicator = renderPendingIndicator(this.listEl);
    this.scrollToBottom();
  }

  private clearPending(): void {
    this.pendingIndicator?.remove();
    this.pendingIndicator = null;
  }
}

// First user prompt's text in a message list (handles string + image turns).
function firstUserText(messages: Conversation["messages"]): string {
  for (const m of messages) {
    if (isUserPrompt(m)) return userPromptText(m);
  }
  return "";
}

// First assistant text block in a message list.
function firstAssistantText(messages: Conversation["messages"]): string {
  for (const m of messages) {
    if (m.role !== "assistant" || !Array.isArray(m.content)) continue;
    for (const block of m.content as AnthropicContentBlock[]) {
      if (block.type === "text" && block.text) return block.text;
    }
  }
  return "";
}
