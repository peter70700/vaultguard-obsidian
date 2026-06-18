// Collapsible card per tool call (AI-CHAT-PANEL.md §9.3). This is the user's
// trust surface — it shows EXACTLY what the model touched: the tool name, its
// primary argument, the full args, and the returned result (or the denial /
// error reason). Denied/error results render with an error class.
//
// The renderer NEVER reaches the filesystem — it only formats the tool_use
// input and the tool_result string that the runtime already produced.

import { setIcon } from "obsidian";

import type { ToolResult } from "../vault-tool-runtime";
import { createCollapsible, type Collapsible } from "./collapsible";

const CARD_CLS = "vaultguard-chat-tool-card";
const HEADER_ICON_CLS = "vaultguard-chat-tool-icon";
const SECTION_CLS = "vaultguard-chat-tool-section";
const SECTION_LABEL_CLS = "vaultguard-chat-tool-section-label";
const CODE_CLS = "vaultguard-chat-tool-code";
const ERROR_CLS = "is-error";
const PENDING_CLS = "is-pending";

// The single argument most worth showing in the collapsed header for each tool.
const PRIMARY_ARG: Record<string, string> = {
  vaultguard_list: "scope",
  vaultguard_search: "query",
  vaultguard_read: "path",
  vaultguard_apply_patch: "path",
  vaultguard_create: "path",
  vaultguard_graph: "op",
};

/**
 * Pick the most informative argument value to show in the collapsed header.
 * Falls back to the first string-ish property, then to "".
 */
export function primaryArg(tool: string, input: unknown): string {
  if (!input || typeof input !== "object") return "";
  const obj = input as Record<string, unknown>;
  const key = PRIMARY_ARG[tool];
  const direct = key ? obj[key] : undefined;
  if (typeof direct === "string" && direct) return direct;
  if (typeof direct === "number") return String(direct);
  for (const v of Object.values(obj)) {
    if (typeof v === "string" && v) return v;
  }
  return "";
}

/**
 * Classify a tool result for styling. A result is an error when the runtime
 * flagged `isError`. (Transport/auth failures never reach here — they abort the
 * turn before a tool_result exists.)
 */
export function classifyResult(result: ToolResult): "ok" | "error" {
  return result.isError ? "error" : "ok";
}

function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

// A result `content` is JSON for ok results, a plain message for errors. Pretty-
// print JSON when it parses; otherwise show the raw string.
function formatResultContent(content: string): string {
  const trimmed = content.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2);
    } catch {
      return content;
    }
  }
  return content;
}

export interface ToolCallCard {
  root: HTMLElement;
  /** Fill the card body with the tool result once it lands. */
  setResult(result: ToolResult): void;
}

/**
 * Render a tool-call card. Starts in a pending state (the result section shows
 * a spinner) until `setResult` is called.
 */
export function renderToolCall(parent: HTMLElement, tool: string, input: unknown): ToolCallCard {
  const collapsible: Collapsible = createCollapsible(parent, { open: false, extraClass: CARD_CLS });
  collapsible.root.addClass(PENDING_CLS);

  const arg = primaryArg(tool, input);
  collapsible.setLabel(arg ? `${tool} · ${arg}` : tool);

  const icon = collapsible.header.createSpan({ cls: HEADER_ICON_CLS });
  setIcon(icon, "wrench");
  // Keep the icon visually first inside the header label area.
  collapsible.header.prepend(icon);

  // Args section.
  const argsSection = collapsible.body.createDiv({ cls: SECTION_CLS });
  argsSection.createDiv({ cls: SECTION_LABEL_CLS, text: "Arguments" });
  argsSection.createEl("pre", { cls: CODE_CLS }).createEl("code", { text: prettyJson(input) });

  // Result section — populated by setResult.
  const resultSection = collapsible.body.createDiv({ cls: SECTION_CLS });
  resultSection.createDiv({ cls: SECTION_LABEL_CLS, text: "Result" });
  const resultBody = resultSection.createDiv();
  resultBody.createSpan({ text: "Running…", cls: "vaultguard-chat-tool-pending-text" });

  return {
    root: collapsible.root,
    setResult: (result: ToolResult) => {
      collapsible.root.removeClass(PENDING_CLS);
      resultBody.empty();
      if (classifyResult(result) === "error") {
        collapsible.root.addClass(ERROR_CLS);
        resultBody.createDiv({
          cls: "vaultguard-chat-tool-error-text",
          text: result.content || "The tool call failed.",
        });
        // Auto-expand errors so the user sees the denial without a click.
        collapsible.setOpen(true);
      } else {
        collapsible.root.removeClass(ERROR_CLS);
        resultBody.createEl("pre", { cls: CODE_CLS }).createEl("code", {
          text: formatResultContent(result.content),
        });
      }
    },
  };
}

export { CARD_CLS as TOOL_CARD_CLS };
