/**
 * VaultGuard — CSV → Markdown table converter (pure, offline).
 *
 * Uses `papaparse` (MIT). The first row is treated as a header (papaparse's
 * default for `parse(text)` with `header:false` still returns row arrays; we
 * promote row 0 to the table header). NO Obsidian / fs / network imports.
 *
 * SECURITY NOTE: output is untrusted note text (see ./types.ts).
 */

import Papa from "papaparse";

import { decodeUtf8 } from "./types";
import type { ConvertInput, ConvertResult } from "./types";

/** Escape a cell for a GFM table: pipes break columns, newlines break rows. */
function escapeCell(value: unknown): string {
  const s = value == null ? "" : String(value);
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ").trim();
}

/** Render a matrix of string rows as a GFM Markdown table. */
function rowsToMarkdownTable(rows: string[][]): string {
  if (rows.length === 0) return "";

  // Normalise ragged rows to the widest row so the table is rectangular.
  const width = rows.reduce((max, r) => Math.max(max, r.length), 0);
  if (width === 0) return "";

  const pad = (r: string[]): string[] => {
    const out = r.map(escapeCell);
    while (out.length < width) out.push("");
    return out;
  };

  const [first, ...rest] = rows;
  const header = pad(first);
  const separator = header.map(() => "---");
  const body = rest.map(pad);

  const lines = [
    `| ${header.join(" | ")} |`,
    `| ${separator.join(" | ")} |`,
    ...body.map((r) => `| ${r.join(" | ")} |`),
  ];
  return lines.join("\n");
}

/** Converter entry for `.csv` / `.tsv` files. */
export async function convertCsv(input: ConvertInput): Promise<ConvertResult> {
  const text = decodeUtf8(input.bytes);
  const delimiter = input.ext === "tsv" ? "\t" : "";

  const parsed = Papa.parse<string[]>(text, {
    skipEmptyLines: true,
    ...(delimiter ? { delimiter } : {}),
  });

  const rows = (parsed.data ?? []).filter(
    (r): r is string[] => Array.isArray(r) && r.length > 0,
  );

  if (rows.length === 0) {
    return { kind: "skipped", reason: "CSV had no parseable rows" };
  }

  const table = rowsToMarkdownTable(rows);
  if (table.length === 0) {
    return { kind: "skipped", reason: "CSV produced an empty table" };
  }

  // papaparse reports malformed rows as non-fatal errors; surface a count.
  const warnings =
    parsed.errors && parsed.errors.length > 0
      ? [`${parsed.errors.length} row(s) had CSV parse warnings`]
      : undefined;

  return {
    kind: "converted",
    markdown: table,
    ...(warnings ? { warnings } : {}),
  };
}
