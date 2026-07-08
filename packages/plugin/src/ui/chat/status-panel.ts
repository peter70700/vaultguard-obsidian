// Status footer for the chat panel (AI-CHAT-PANEL.md §9.7). Shows compact,
// independently-clickable model / effort / permission chips, the connection
// state, and per-turn token usage. The footer deliberately does not show a
// running dollar session cost.
//
// Self-contained: it talks to the view only through the `onCycleModel` callback
// and the `recordUsage` / `setModel` / `setConnection` setters. No filesystem,
// no network.

import { setIcon } from "obsidian";

import type { AnthropicUsage } from "./anthropic-client";
import { compactModelLabel, effortLabel, permissionModeStatusLabel } from "./models";
import type { AiChatEffort, AiChatPermissionMode } from "../../types";

const FOOTER_CLS = "vaultguard-chat-status";
const MODEL_CLS = "vaultguard-chat-status-model";
const EFFORT_CLS = "vaultguard-chat-status-effort";
const PERMISSION_CLS = "vaultguard-chat-status-permission";
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
  /** Click on the model chip — open the model picker menu. */
  onModelMenu(evt: MouseEvent): void;
  /** Click on the effort chip — open the thinking-effort picker menu. */
  onEffortMenu(evt: MouseEvent): void;
  /** Click on the permission chip — open the AI Chat permission picker menu. */
  onPermissionMenu(evt: MouseEvent): void;
}

export function statusModelLabel(model: string): string {
  return compactModelLabel(model).replace(/^(Claude|GPT)\s+/i, "");
}

export function statusEffortLabel(effort: AiChatEffort): string {
  const label = effortLabel(effort);
  return label === "Extra high" ? "X-high" : label;
}

export function statusPermissionLabel(permissionMode: AiChatPermissionMode): string {
  return permissionModeStatusLabel(permissionMode);
}

export class StatusPanel {
  private readonly modelEl: HTMLElement;
  private readonly modelLabelEl: HTMLElement;
  private readonly effortEl: HTMLElement;
  private readonly effortLabelEl: HTMLElement;
  private readonly permissionEl: HTMLElement;
  private readonly permissionLabelEl: HTMLElement;
  private readonly connEl: HTMLElement;
  private readonly usageEl: HTMLElement;
  private sessionCostUsd = 0;
  private model: string;
  private effort: AiChatEffort;
  private permissionMode: AiChatPermissionMode;

  constructor(
    parent: HTMLElement,
    model: string,
    effort: AiChatEffort,
    permissionMode: AiChatPermissionMode,
    private readonly callbacks: StatusPanelCallbacks,
  ) {
    this.model = model;
    this.effort = effort;
    this.permissionMode = permissionMode;

    const footer = parent.createDiv({ cls: FOOTER_CLS });

    this.modelEl = this.createChip(footer, MODEL_CLS, "Switch model", (evt) =>
      this.callbacks.onModelMenu(evt),
    );
    this.modelLabelEl = this.modelEl.createSpan({ cls: `${MODEL_CLS}-label` });
    this.addChevron(this.modelEl);

    this.effortEl = this.createChip(footer, EFFORT_CLS, "Switch thinking effort", (evt) =>
      this.callbacks.onEffortMenu(evt),
    );
    this.effortLabelEl = this.effortEl.createSpan({ cls: `${EFFORT_CLS}-label` });
    this.addChevron(this.effortEl);

    this.permissionEl = this.createChip(footer, PERMISSION_CLS, "Switch AI Chat permissions", (evt) =>
      this.callbacks.onPermissionMenu(evt),
    );
    this.permissionLabelEl = this.permissionEl.createSpan({ cls: `${PERMISSION_CLS}-label` });
    this.addChevron(this.permissionEl);

    this.usageEl = footer.createSpan({ cls: USAGE_CLS });
    this.connEl = footer.createSpan({
      cls: CONN_CLS,
      attr: { "aria-label": "Connection status", title: "Offline" },
    });

    this.renderModel();
    this.renderEffort();
    this.renderPermission();
    this.setConnection(false);
    this.renderUsage(null);
  }

  setModel(model: string): void {
    this.model = model;
    this.renderModel();
  }

  setEffort(effort: AiChatEffort): void {
    this.effort = effort;
    this.renderEffort();
  }

  setPermissionMode(permissionMode: AiChatPermissionMode): void {
    this.permissionMode = permissionMode;
    this.renderPermission();
  }

  setConnection(online: boolean): void {
    this.connEl.setText("●");
    this.connEl.setAttribute("aria-label", online ? "Online" : "Offline");
    this.connEl.setAttribute("title", online ? "Online" : "Offline");
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
    const label = statusModelLabel(this.model);
    this.modelLabelEl.setText(label);
    this.modelEl.setAttribute("title", `Model: ${label}`);
  }

  private renderEffort(): void {
    const label = statusEffortLabel(this.effort);
    this.effortLabelEl.setText(label);
    this.effortEl.setAttribute("title", `Thinking effort: ${label}`);
  }

  private renderPermission(): void {
    const label = statusPermissionLabel(this.permissionMode);
    this.permissionLabelEl.setText(label);
    this.permissionEl.setAttribute("title", `AI Chat permissions: ${label}`);
  }

  private renderUsage(usage: AnthropicUsage | null): void {
    this.usageEl.setText(usage ? formatUsageLine(usage) : "");
  }

  private createChip(
    parent: HTMLElement,
    cls: string,
    label: string,
    onClick: (evt: MouseEvent) => void,
  ): HTMLElement {
    const chip = parent.createSpan({
      cls: `vaultguard-chat-status-chip ${cls} clickable-icon`,
      attr: { "aria-label": label, title: label },
    });
    chip.addEventListener("click", onClick);
    return chip;
  }

  private addChevron(chip: HTMLElement): void {
    const chevron = chip.createSpan({ cls: "vaultguard-chat-status-chip-chevron" });
    setIcon(chevron, "chevron-down");
  }
}

export { FOOTER_CLS as STATUS_FOOTER_CLS };
