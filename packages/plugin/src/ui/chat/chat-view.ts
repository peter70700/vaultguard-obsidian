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
  MarkdownRenderer,
  Menu,
  Notice,
  Platform,
  type ViewStateResult,
  WorkspaceLeaf,
  setIcon,
} from "obsidian";

import type VaultGuardPlugin from "../../plugin/main";
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
  type ImageAttachment,
  type MentionCandidate,
  type SlashCommand,
} from "./input-controller";
import { StatusPanel } from "./status-panel";
import {
  renderAssistantMessage,
  renderPendingIndicator,
  renderUserMessage,
  type AssistantBubble,
  type PendingIndicator,
} from "./render/message-renderer";
import { renderToolCall, type ToolCallCard } from "./render/tool-call-renderer";
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
} from "./conversation-store";
import { generateTitle } from "./title-generator";
import {
  isUserPrompt,
  sliceBeforeUserTurn,
  userPromptImages,
  userPromptText,
} from "./message-utils";
import { AI_CHAT_MODELS, AI_CHAT_EFFORTS, AI_CHAT_MODEL_IDS } from "./models";
import type { AnthropicEffort } from "../../types";

export const VAULTGUARD_CHAT_VIEW_TYPE = "vaultguard-chat-view";

const ROOT_CLS = "vaultguard-chat";
const LIST_CLS = "vaultguard-chat-list";
const EMPTY_CLS = "vaultguard-chat-empty";
const HEADER_CLS = "vaultguard-chat-header";
const HEADER_TITLE_CLS = "vaultguard-chat-header-title";
const HEADER_BTN_CLS = "vaultguard-chat-header-btn";

export class VaultGuardChatView extends ItemView {
  private listEl: HTMLElement | null = null;
  private inputController: InputController | null = null;
  private statusPanel: StatusPanel | null = null;

  private runtime: ChatRuntime | null = null;
  private leaseId: string | null = null;
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

  // "Assistant is thinking…" placeholder shown from turn start until the first
  // visible content (text / delta / tool call) lands. Removed by clearPending().
  private pendingIndicator: PendingIndicator | null = null;

  // Tier-2 live streaming bubble (desktop + opt-in only). Null on Tier-1 turns.
  private streamController: StreamController | null = null;
  // The streaming preference baked into the current runtime, so a settings
  // change mid-session rebuilds the runtime with the new transport.
  private runtimeStreaming = false;

  // ─── Per-leaf multi-tab state (AI chat tabs) ───────────────────────────────
  // Each chat leaf is scoped to its OWN conversation so multiple tabs can stay
  // open at once. `leafState` mirrors the Obsidian view state delivered by
  // setState(); `resolveInitialConversation()` consumes it exactly once to pick
  // which conversation (or a blank one) this leaf starts on.
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

  // ─── Per-leaf state (multi-tab) ────────────────────────────────────────────
  // Persist ONLY the non-secret conversation id into the leaf's Obsidian view
  // state (workspace.json — an excluded path). The conversation CONTENT stays
  // LAK-encrypted in ConversationStore, so the at-rest boundary is unchanged;
  // this just lets each tab reopen its own conversation after a reload.
  getState(): Record<string, unknown> {
    return { ...super.getState(), conversationId: this.convo?.id ?? null };
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

      // Header: conversation title + a "previous chats" / new-chat affordance.
      const header = container.createDiv({ cls: HEADER_CLS });
      this.convoTitleEl = header.createSpan({ cls: HEADER_TITLE_CLS, text: "New chat" });
      const historyBtn = header.createSpan({
        cls: `${HEADER_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "Previous chats", title: "Previous chats" },
      });
      setIcon(historyBtn, "history");
      historyBtn.addEventListener("click", (evt) => void this.openHistoryMenu(evt));
      const newBtn = header.createSpan({
        cls: `${HEADER_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "New chat", title: "New chat" },
      });
      setIcon(newBtn, "plus");
      newBtn.addEventListener("click", () => this.resetConversation());

      // Open a separate chat in its own right-sidebar tab. (The + button above
      // resets THIS panel in place; this one keeps the current chat and adds a
      // new tab beside it.)
      const newTabBtn = header.createSpan({
        cls: `${HEADER_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "New chat in new tab", title: "New chat in new tab" },
      });
      setIcon(newTabBtn, "message-square-plus");
      newTabBtn.addEventListener("click", () => void this.plugin.openNewVaultGuardChatTab());

      const regenBtn = header.createSpan({
        cls: `${HEADER_BTN_CLS} clickable-icon`,
        attr: { "aria-label": "Regenerate last response", title: "Regenerate last response" },
      });
      setIcon(regenBtn, "refresh-cw");
      regenBtn.addEventListener("click", () => void this.regenerateLast());

      // Message list (scrollable, flex:1).
      this.listEl = container.createDiv({ cls: LIST_CLS });

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
          resolveTemplate: (name, arg) => this.resolveTemplate(name, arg),
        },
        {
          // Vision input is API-key + desktop only (subscription CLI turns keep
          // no replayable image array; mobile uses the non-streaming path).
          enableImages:
            !Platform.isMobileApp && this.plugin.settings.aiChatProvider !== "subscription",
        },
      );

      this.statusPanel = new StatusPanel(container, this.model, {
        onModelMenu: (evt) => this.openModelMenu(evt),
      });
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
    this.pendingIndicator = null;
    this.streamController = null;
    this.inputController = null;
    this.statusPanel = null;
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
  // CLI at (lease-scoped, permission-checked, confirmWrite diff-gated). The
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
    this.statusPanel.setModel(`Claude subscription · ${status.subscriptionType ?? this.model}`);
    this.inputController.setBusy(true);
    this.showPending();
    const controller = new AbortController();
    this.abortController = controller;
    this.activeAssistantBubble = null;
    this.cliSessionToolName = null;

    try {
      await client.runTurn(
        text,
        {
          onTextDelta: (t) => {
            appendAssistantText(t);
            this.onText(t);
          },
          onThinkingDelta: (t) => {
            // Render thinking summary inline above the text bubble.
            this.clearPending();
            if (this.listEl) renderThinking(this.listEl, t);
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
    }
  }

  // Lazily start the AgentBridge HTTP/MCP server, mint a confirm-on-write lease,
  // and build the ClaudeCliClient pointed at the lease-scoped MCP endpoint.
  private async ensureCliClient(binaryPath: string): Promise<ClaudeCliClient> {
    if (this.cliClient) return this.cliClient;

    const server = await this.plugin.startAgentBridgeServer();
    const lease = await this.plugin.createAgentBridgeLease({
      agentName: "VaultGuard Chat (subscription)",
      scope: "/**",
      ttlMinutes: 60,
      allowRead: true,
      writeMode: "confirm",
    });
    this.leaseId = lease.leaseId;

    this.cliClient = new ClaudeCliClient({
      binaryPath,
      mcpUrl: server.mcpEndpoint,
      leaseToken: lease.token,
      model: this.model,
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
    if (cmd.kind === "model") {
      if (!AI_CHAT_MODEL_IDS.includes(cmd.model)) {
        new Notice(`VaultGuard Chat: unknown model "${cmd.model}".`);
        return;
      }
      this.setModel(cmd.model);
      new Notice(`VaultGuard Chat: switched to ${cmd.model} for this session.`);
    }
  }

  private resetConversation(): void {
    this.handleCancel();
    this.runtime?.reset();
    // Drop the CLI session so /clear starts a fresh Claude Code context too.
    this.cliClient?.reset();
    this.cliClient = null;
    if (this.listEl) this.listEl.empty();
    this.pendingToolCards = [];
    this.activeAssistantBubble = null;
    this.statusPanel?.resetSession();
    // Drop the current conversation; the next turn mints a fresh id.
    this.convo = null;
    this.titleGenerated = false;
    this.setHeaderTitle("New chat");
    this.persistLeafState();
    if (
      this.plugin.settings.aiChatProvider !== "subscription" &&
      !new AnthropicKeyStore(this.plugin).hasKey()
    ) {
      this.renderConnectState();
    }
  }

  // ─── Persistence (§10) ─────────────────────────────────────────────────────

  private startConversation(firstUserText: string): void {
    const now = Date.now();
    this.convo = {
      id: newConversationId(),
      title: defaultTitle(firstUserText),
      model: this.model,
      createdAt: now,
      updatedAt: now,
      messages: [],
    };
    this.titleGenerated = false;
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

  // Pick (once) which conversation this leaf opens on, from its persisted view
  // state: a specific id (restored tab), a blank chat (explicit new tab), or the
  // most-recent conversation (legacy open / upgrade path for a tab with no id).
  private resolveInitialConversation(): void {
    if (this.initialConversationResolved || !this.listEl) return;
    this.initialConversationResolved = true;
    const choice = pickInitialConversation(this.leafState);
    if (choice.mode === "load") {
      void this.loadConversation(choice.id).catch((e) =>
        console.error("[VaultGuard Chat] initial conversation load failed", e),
      );
    } else if (choice.mode === "recent") {
      void this.restoreMostRecent().catch((e) =>
        console.error("[VaultGuard Chat] restore failed", e),
      );
    }
    // choice.mode === "fresh": leave the panel blank — the onOpen connect-hint
    // already covers the no-key banner.
  }

  /** The conversation this leaf currently shows (for cross-tab dedupe). */
  getConversationId(): string | null {
    return this.convo?.id ?? null;
  }

  // Render a persisted conversation read-only into the list.
  private renderConversation(convo: Conversation): void {
    this.renderMessages(convo.messages);
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

  private setHeaderTitle(title: string): void {
    this.convoTitleEl?.setText(title || "New chat");
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

  // Persist this leaf's conversation binding into workspace.json so a reload
  // restores THIS tab's conversation. Debounced by Obsidian. (The tab label is
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

  // History-picker entry: if the chosen conversation is already open in another
  // chat tab, focus that tab instead of opening a duplicate (two leaves editing
  // one conversation would race the autosave). Otherwise load it into this tab.
  private async openConversationFromHistory(id: string): Promise<void> {
    const other = this.app.workspace
      .getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE)
      .find(
        (leaf) =>
          leaf.view !== this &&
          leaf.view instanceof VaultGuardChatView &&
          leaf.view.getConversationId() === id,
      );
    if (other) {
      void this.app.workspace.revealLeaf(other);
      return;
    }
    await this.loadConversation(id);
  }

  private async loadConversation(id: string): Promise<void> {
    if (!this.store) return;
    const convo = await this.store.load(id);
    if (!convo) {
      new Notice("VaultGuard Chat: could not load that conversation.");
      return;
    }
    this.handleCancel();
    this.runtime?.reset();
    this.runtime = null; // rebuild on next turn; rehydrate via pendingRestore
    this.cliClient?.reset();
    this.cliClient = null;
    if (this.listEl) this.listEl.empty();
    this.pendingToolCards = [];
    this.activeAssistantBubble = null;
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

    // Mint a vault-wide, confirm-on-write lease for the session. Writes route
    // through the existing confirmAgentWrite modal inside applyPatch/create.
    const lease = await this.plugin.createAgentBridgeLease({
      agentName: "VaultGuard Chat",
      scope: "/**",
      ttlMinutes: 60,
      allowRead: true,
      writeMode: "confirm",
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
        system: buildSystemPrompt(this.plugin.settings.aiChatSystemPrompt),
        model: this.model,
        streaming,
      },
      progress: {
        onAssistant: (msg) => this.onAssistant(msg),
        onText: (text) => this.onText(text),
        onTextDelta: (text) => {
          this.clearPending();
          this.streamController?.onTextDelta(text);
        },
        onThinkingDelta: (text) => {
          this.clearPending();
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
    // Record usage for the cost meter.
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
    this.clearPending();
    if (!this.activeAssistantBubble) {
      this.activeAssistantBubble = renderAssistantMessage(
        this.listEl,
        this.app,
        this,
        "",
        text,
      );
    } else {
      this.activeAssistantBubble.appendMarkdown(text);
    }
    this.scrollToBottom();
  }

  private onToolCall(name: string, input: unknown): void {
    if (!this.listEl) return;
    this.clearPending();
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

  // In-footer model + effort picker (replaces the old click-to-cycle). Lists
  // every configured model with a check on the active one, plus an effort
  // submenu, and applies the choice immediately (rebuilding the runtime so the
  // next turn uses it). In subscription mode the Anthropic model id is advisory
  // (the CLI owns the actual model), so we still record it for the next session.
  private openModelMenu(evt: MouseEvent): void {
    const menu = new Menu();

    menu.addItem((item) => item.setTitle("Model").setIsLabel(true));
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

    menu.addSeparator();
    menu.addItem((item) => item.setTitle("Thinking effort").setIsLabel(true));
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

  private async setEffort(effort: AnthropicEffort): Promise<void> {
    if (this.plugin.settings.aiChatEffort === effort) return;
    this.plugin.settings.aiChatEffort = effort;
    await this.plugin.saveSettings();
    // Rebuild so the next turn's client carries the new effort.
    this.runtime = null;
    this.cliClient?.reset();
    this.cliClient = null;
    new Notice(`VaultGuard Chat: thinking effort → ${effort}`);
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

  private renderError(message: string): void {
    this.clearPending();
    if (!this.listEl) {
      new Notice(`VaultGuard Chat: ${message}`);
      return;
    }
    const el = this.listEl.createDiv({ cls: "vaultguard-chat-error" });
    const icon = el.createSpan({ cls: "vaultguard-chat-error-icon" });
    setIcon(icon, "alert-triangle");
    void MarkdownRenderer.render(this.app, message, el.createSpan(), "", this);
    this.statusPanel?.setConnection(this.plugin.isConnectedOnline());
    this.scrollToBottom();
  }

  private scrollToBottom(): void {
    if (this.listEl) this.listEl.scrollTop = this.listEl.scrollHeight;
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

  // Expand a user-defined slash-command prompt template. Returns the prompt body
  // with {{input}} replaced by the trailing text (and a trailing "{{input}}"
  // dropped when no arg is given), or null when no template matches.
  private resolveTemplate(name: string, arg: string): string | null {
    const tpl = (this.plugin.settings.aiChatPromptTemplates ?? []).find(
      (t) => t.name && t.name.toLowerCase() === name.toLowerCase(),
    );
    if (!tpl || !tpl.prompt.trim()) return null;
    if (tpl.prompt.includes("{{input}}")) {
      return tpl.prompt.replace(/\{\{input\}\}/g, arg);
    }
    // No placeholder: append any trailing text so `/foo bar` still passes "bar".
    return arg ? `${tpl.prompt}\n\n${arg}` : tpl.prompt;
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
