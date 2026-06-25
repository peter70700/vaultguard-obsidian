/**
 * VaultGuard — HTML → Markdown converter (pure, offline).
 *
 * Uses `turndown` (MIT) + `turndown-plugin-gfm` (MIT) for GFM tables,
 * strikethrough, and task lists. NO Obsidian / fs / network imports.
 *
 * SECURITY NOTE: output is untrusted note text (see ./types.ts) — Turndown
 * already drops `<script>`/`<style>` content, but no sanitization guarantee is
 * made; downstream treats the result like any other vault file.
 */

import TurndownService from "turndown";
import { gfm } from "turndown-plugin-gfm";

import { decodeUtf8 } from "./types";
import type { ConvertInput, ConvertResult } from "./types";

/**
 * Build a Turndown instance configured for clean, GFM-flavoured Markdown.
 * A fresh instance per call keeps the converters stateless/pure (no shared
 * mutable service across files).
 */
function makeTurndown(): TurndownService {
  const td = new TurndownService({
    headingStyle: "atx", // `# H1` not underline style
    bulletListMarker: "-",
    codeBlockStyle: "fenced",
    emDelimiter: "_",
    strongDelimiter: "**",
    linkStyle: "inlined",
  });
  // GFM: tables, strikethrough (~~x~~), task list items ([ ]/[x]).
  td.use(gfm);
  // Drop non-content nodes outright so they never leak into the note.
  td.remove(["script", "style", "noscript", "head", "title"]);
  return td;
}

/**
 * Raw HTML → Markdown. Exported so `docx.ts` (which produces HTML via mammoth)
 * can reuse the exact same conversion path. Throws only on a genuine Turndown
 * failure; callers wrap in the dispatcher's try/catch → `kind:"skipped"`.
 */
export function htmlToMarkdown(html: string): string {
  return makeTurndown().turndown(html).trim();
}

/** Converter entry for `.html` / `.htm` files. */
export async function convertHtml(input: ConvertInput): Promise<ConvertResult> {
  const html = decodeUtf8(input.bytes);
  const markdown = htmlToMarkdown(html);
  if (markdown.length === 0) {
    return {
      kind: "skipped",
      reason: "HTML produced no extractable text content",
    };
  }
  return { kind: "converted", markdown };
}
