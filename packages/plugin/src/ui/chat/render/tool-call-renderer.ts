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
const TOOL_COPY_CLS = "vaultguard-chat-tool-copy";
const ERROR_CLS = "is-error";
const PENDING_CLS = "is-pending";

// The single argument most worth showing in the collapsed header for each tool.
const PRIMARY_ARG: Record<string, string> = {
  vaultguard_list: "scope",
  vaultguard_search: "query",
  vaultguard_read: "path",
  vaultguard_apply_patch: "path",
  vaultguard_create: "path",
  vaultguard_delete: "path",
  vaultguard_rename: "path",
  vaultguard_graph: "op",
  vaultguard_access: "op",
  vaultguard_audit: "path",
  vaultguard_files: "op",
  vaultguard_share: "op",
  vaultguard_membership: "op",
  vaultguard_ask_user: "question",
  vaultguard_import_list: "path",
  vaultguard_import_read: "path",
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

function hasDisplayableArgs(value: unknown): boolean {
  if (value == null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value as Record<string, unknown>).length > 0;
  return String(value).trim().length > 0;
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

/**
 * Copy-to-clipboard affordance for expanded tool cards. Kept local to this
 * renderer because tool calls copy a structured transcript, not markdown.
 */
function addToolCopyButton(host: HTMLElement, getText: () => string, label: string): HTMLElement {
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

function renderCopyableCode(parent: HTMLElement, text: string, copyLabel: string): HTMLElement {
  const pre = parent.createEl("pre", { cls: CODE_CLS });
  pre.addClass("vaultguard-chat-code-pre");
  pre.createEl("code", { text });
  addToolCopyButton(pre, () => text, copyLabel).addClass("vaultguard-chat-code-copy");
  return pre;
}

/** Format the full expanded tool card as copy-pasteable transcript text. */
export function formatToolCallCopyText(tool: string, input: unknown, result: ToolResult | null): string {
  const sections = [`Tool: ${tool}`];

  if (hasDisplayableArgs(input)) {
    sections.push("", "Arguments:", prettyJson(input));
  }

  if (!result) {
    sections.push("", "Result:", "Running...");
  } else if (classifyResult(result) === "error") {
    sections.push("", "Result (error):", result.content || "The tool call failed.");
  } else {
    sections.push("", "Result:", formatResultContent(result.content));
  }

  return sections.join("\n");
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
  let currentResult: ToolResult | null = null;

  const arg = primaryArg(tool, input);
  collapsible.setLabel(arg ? `${tool} · ${arg}` : tool);

  const icon = collapsible.header.createSpan({ cls: HEADER_ICON_CLS });
  setIcon(icon, "wrench");
  // Keep the icon visually first inside the header label area.
  collapsible.header.prepend(icon);
  addToolCopyButton(
    collapsible.header,
    () => formatToolCallCopyText(tool, input, currentResult),
    "Copy tool usage",
  ).addClass(TOOL_COPY_CLS);

  // Result first: for Claude Code MCP calls the input is often `{}`, while the
  // useful audit payload is the result. Keep pending cards informative too.
  const resultSection = collapsible.body.createDiv({ cls: SECTION_CLS });
  resultSection.createDiv({ cls: SECTION_LABEL_CLS, text: "Result" });
  const resultBody = resultSection.createDiv();
  resultBody.createSpan({ text: "Running…", cls: "vaultguard-chat-tool-pending-text" });

  // Args section. Omit empty `{}` inputs so expanded cards don't look blank.
  if (hasDisplayableArgs(input)) {
    const argsSection = collapsible.body.createDiv({ cls: SECTION_CLS });
    argsSection.createDiv({ cls: SECTION_LABEL_CLS, text: "Arguments" });
    renderCopyableCode(argsSection, prettyJson(input), "Copy arguments");
  }

  return {
    root: collapsible.root,
    setResult: (result: ToolResult) => {
      currentResult = result;
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
        renderCopyableCode(resultBody, formatResultContent(result.content), "Copy result");
      }
      collapsible.refreshLayout();
    },
  };
}

export { CARD_CLS as TOOL_CARD_CLS };
