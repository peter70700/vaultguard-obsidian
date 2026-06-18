// Status footer for the chat panel (AI-CHAT-PANEL.md §9.7). Shows the current
// model (clickable → cycle through the configured list), the connection state,
// and per-turn / running-session usage with a $ estimate from the §4 price
// table. Surfacing cost builds trust and catches a stuck agentic loop early.
//
// Self-contained: it talks to the view only through the `onCycleModel` callback
// and the `recordUsage` / `setModel` / `setConnection` setters. No filesystem,
// no network.

import { setIcon } from "obsidian";

import type { AnthropicUsage } from "./anthropic-client";
import { modelLabel } from "./models";

const FOOTER_CLS = "vaultguard-chat-status";
const MODEL_CLS = "vaultguard-chat-status-model";
const CONN_CLS = "vaultguard-chat-status-conn";
const USAGE_CLS = "vaultguard-chat-status-usage";

// $ / million tokens, from AI-CHAT-PANEL.md §4. Cache reads bill at 0.1× input.
export interface ModelPrice {
  inPerMTok: number;
  outPerMTok: number;
}

export const MODEL_PRICING: Record<string, ModelPrice> = {
  "claude-opus-4-8": { inPerMTok: 5, outPerMTok: 25 },
  "claude-sonnet-4-6": { inPerMTok: 3, outPerMTok: 15 },
  "claude-haiku-4-5": { inPerMTok: 1, outPerMTok: 5 },
  "claude-fable-5": { inPerMTok: 10, outPerMTok: 50 },
};

const CACHE_READ_MULTIPLIER = 0.1;

/**
 * Cost of one usage record in USD for a given model. Cache-read input tokens
 * (when present) are billed at 0.1× the normal input rate and are NOT also
 * counted as fresh input. Unknown models cost 0 (we don't guess a price).
 */
export function usageCostUsd(model: string, usage: AnthropicUsage | undefined): number {
  if (!usage) return 0;
  const price = MODEL_PRICING[model];
  if (!price) return 0;

  const cacheRead = usage.cache_read_input_tokens ?? 0;
  const freshInput = Math.max(0, (usage.input_tokens ?? 0) - cacheRead);
  const cacheCreation = usage.cache_creation_input_tokens ?? 0;

  const inputCost =
    ((freshInput + cacheCreation) / 1_000_000) * price.inPerMTok +
    (cacheRead / 1_000_000) * price.inPerMTok * CACHE_READ_MULTIPLIER;
  const outputCost = ((usage.output_tokens ?? 0) / 1_000_000) * price.outPerMTok;

  return inputCost + outputCost;
}

function formatUsd(amount: number): string {
  if (amount === 0) return "$0.00";
  if (amount < 0.01) return `$${amount.toFixed(4)}`;
  return `$${amount.toFixed(2)}`;
}

function formatUsageLine(usage: AnthropicUsage): string {
  const parts: string[] = [];
  const cacheRead = usage.cache_read_input_tokens ?? 0;
  if (cacheRead > 0) {
    parts.push(`in ${usage.input_tokens} (${cacheRead} cached)`);
  } else {
    parts.push(`in ${usage.input_tokens}`);
  }
  parts.push(`out ${usage.output_tokens}`);
  return parts.join(" · ");
}

export interface StatusPanelCallbacks {
  /** Click on the model chip — open the model / effort picker menu. */
  onModelMenu(evt: MouseEvent): void;
}

export class StatusPanel {
  private readonly modelEl: HTMLElement;
  private readonly modelLabelEl: HTMLElement;
  private readonly connEl: HTMLElement;
  private readonly usageEl: HTMLElement;
  private sessionCostUsd = 0;
  private model: string;

  constructor(
    parent: HTMLElement,
    model: string,
    private readonly callbacks: StatusPanelCallbacks,
  ) {
    this.model = model;

    const footer = parent.createDiv({ cls: FOOTER_CLS });

    this.modelEl = footer.createSpan({
      cls: `${MODEL_CLS} clickable-icon`,
      attr: { "aria-label": "Switch model", title: "Switch model / effort" },
    });
    this.modelLabelEl = this.modelEl.createSpan({ cls: `${MODEL_CLS}-label` });
    const chevron = this.modelEl.createSpan({ cls: `${MODEL_CLS}-chevron` });
    setIcon(chevron, "chevron-down");
    this.modelEl.addEventListener("click", (evt) => this.callbacks.onModelMenu(evt));

    this.connEl = footer.createSpan({ cls: CONN_CLS });
    this.usageEl = footer.createSpan({ cls: USAGE_CLS });

    this.renderModel();
    this.setConnection(false);
    this.renderUsage(null);
  }

  setModel(model: string): void {
    this.model = model;
    this.renderModel();
  }

  setConnection(online: boolean): void {
    this.connEl.setText(online ? "● online" : "○ offline");
    this.connEl.toggleClass("is-online", online);
    this.connEl.toggleClass("is-offline", !online);
  }

  /** Record one step's usage; accumulates the running session cost. */
  recordUsage(usage: AnthropicUsage | undefined): void {
    if (!usage) return;
    this.sessionCostUsd += usageCostUsd(this.model, usage);
    this.renderUsage(usage);
  }

  /**
   * Record a per-turn cost reported directly in USD (the subscription /
   * Claude Code CLI provider emits `total_cost_usd` instead of token usage, so
   * we accumulate it straight rather than pricing tokens locally).
   */
  recordCostUsd(costUsd: number): void {
    if (!Number.isFinite(costUsd) || costUsd < 0) return;
    this.sessionCostUsd += costUsd;
    this.renderUsage(null);
  }

  /** Reset the running session cost (e.g. on `/clear`). */
  resetSession(): void {
    this.sessionCostUsd = 0;
    this.renderUsage(null);
  }

  getSessionCostUsd(): number {
    return this.sessionCostUsd;
  }

  private renderModel(): void {
    // Show the friendly label for configured models; subscription mode passes a
    // pre-formatted string (e.g. "Claude subscription · max") which falls
    // through modelLabel() unchanged.
    this.modelLabelEl.setText(modelLabel(this.model));
  }

  private renderUsage(usage: AnthropicUsage | null): void {
    const cost = formatUsd(this.sessionCostUsd);
    if (usage) {
      this.usageEl.setText(`${formatUsageLine(usage)} · ${cost} session`);
    } else {
      this.usageEl.setText(`${cost} session`);
    }
  }
}

export { FOOTER_CLS as STATUS_FOOTER_CLS };
