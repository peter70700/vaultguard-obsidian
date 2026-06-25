// Live-bubble glue for Tier-2 streaming (AI-CHAT-PANEL.md §9.2/§9.4). The chat
// view owns ONE StreamController per streamed turn; the runtime's delta handlers
// forward into it so the assistant bubble (and thinking summary) grow
// token-by-token. On block finalization it re-renders the accumulated text as
// markdown — exactly what the non-streaming path produces — so the final DOM is
// identical regardless of transport.
//
// Vanilla DOM only (no React). Touches NO filesystem and NO vault content.

import type { App, Component } from "obsidian";

import { createCollapsible, type Collapsible } from "./render/collapsible";
import { renderAssistantMessage, type AssistantBubble } from "./render/message-renderer";

const THINKING_CLS = "vaultguard-chat-thinking";
const THINKING_TEXT_CLS = "vaultguard-chat-thinking-text";
const STREAM_TEXT_CLS = "vaultguard-chat-stream-text";

export interface StreamControllerDeps {
  /** The scrollable message list the bubbles append into. */
  list: HTMLElement;
  app: App;
  /** The view, threaded to MarkdownRenderer for link/embed resolution. */
  component: Component;
  /** Scroll the list to the bottom after each delta. */
  scroll(): void;
}

export class StreamController {
  private thinking: Collapsible | null = null;
  private thinkingText = "";

  private bubble: AssistantBubble | null = null;
  private streamEl: HTMLElement | null = null;
  private text = "";

  constructor(private readonly deps: StreamControllerDeps) {}

  /** Append a thinking-summary delta, lazily creating the collapsible. */
  onThinkingDelta(delta: string): void {
    if (!delta) return;
    if (!this.thinking) {
      this.thinking = createCollapsible(this.deps.list, { open: false, extraClass: THINKING_CLS });
      this.thinking.setLabel("Thinking");
      this.thinking.body.createDiv({ cls: THINKING_TEXT_CLS });
    }
    this.thinkingText += delta;
    const textEl = this.thinking.body.querySelector(`.${THINKING_TEXT_CLS}`);
    if (textEl) textEl.setText(this.thinkingText);
    this.deps.scroll();
  }

  /**
   * Append a visible-text delta. While streaming we paint plain text (cheap, no
   * per-token markdown re-parse); the markdown re-render happens in `finalize`.
   */
  onTextDelta(delta: string): void {
    if (!delta) return;
    if (!this.bubble) {
      // An empty initial bubble we fill with a plain-text streaming node; the
      // markdown chunk is added on finalize.
      this.bubble = renderAssistantMessage(this.deps.list, this.deps.app, this.deps.component, "");
      this.streamEl = this.bubble.bubble.createDiv({ cls: STREAM_TEXT_CLS });
    }
    this.text += delta;
    if (this.streamEl) this.streamEl.setText(this.text);
    this.deps.scroll();
  }

  /**
   * Finalize the current text bubble: drop the plain-text streaming node and
   * re-render the accumulated text as markdown so links/code/callouts resolve.
   * Called when a content block stops or the assistant turn ends.
   */
  finalize(): void {
    if (this.bubble && this.streamEl) {
      this.streamEl.remove();
      this.streamEl = null;
      const rendered = this.text ? this.bubble.appendMarkdown(this.text) : false;
      if (!rendered && !this.bubble.getRawText()) this.bubble.root.remove();
    }
    // Reset per-block state; a following block (e.g. after a tool call) starts a
    // fresh bubble.
    this.bubble = null;
    this.streamEl = null;
    this.text = "";
  }
}

export { STREAM_TEXT_CLS };
