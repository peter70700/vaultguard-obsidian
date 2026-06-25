/**
 * VaultGuard — DOCX → Markdown converter (pure, offline).
 *
 * Two-stage, all-JS pipeline: `mammoth` (BSD-2-Clause) renders the .docx to
 * semantic HTML, then `html.ts`'s `htmlToMarkdown` (Turndown + GFM) produces the
 * final Markdown. NO Obsidian / fs / network imports.
 *
 * SECURITY NOTE: output is untrusted note text (see ./types.ts).
 */

import { convertToHtml } from "mammoth";

import { htmlToMarkdown } from "./html";
import { toUint8Array } from "./types";
import type { ConvertInput, ConvertResult } from "./types";

/** Converter entry for `.docx` files. */
export async function convertDocx(input: ConvertInput): Promise<ConvertResult> {
  // Mammoth's Node entry reads `buffer`; its browser entry reads `arrayBuffer`.
  // The Obsidian bundle can select either entry depending on esbuild package
  // fields, so pass both views over the same bytes.
  const view = toUint8Array(input.bytes);
  const buffer = Buffer.from(view.buffer, view.byteOffset, view.byteLength);
  const arrayBuffer = new Uint8Array(view).buffer;

  const result = await convertToHtml({ buffer, arrayBuffer });
  const html = result.value ?? "";
  const markdown = htmlToMarkdown(html);

  if (markdown.length === 0) {
    return {
      kind: "skipped",
      reason: "DOCX produced no extractable text content",
    };
  }

  // mammoth surfaces unsupported-feature notices as messages; bubble any up as
  // non-fatal warnings so the user knows fidelity was lossy.
  const warnings = (result.messages ?? [])
    .filter((m) => m && (m.type === "warning" || m.type === "error"))
    .map((m) => m.message)
    .slice(0, 5);

  return {
    kind: "converted",
    markdown,
    ...(warnings.length > 0 ? { warnings } : {}),
  };
}
