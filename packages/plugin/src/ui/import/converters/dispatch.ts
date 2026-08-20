/**
 * VaultGuard — Extension → converter dispatcher (pure, offline).
 *
 * Routes a file's bytes to the right Tier-1 converter by lower-cased extension:
 *   - .md/.markdown/.txt        → passthrough (decoded UTF-8 text)
 *   - .html/.htm                → HTML → Markdown (Turndown + GFM)
 *   - .docx                     → DOCX → HTML → Markdown (mammoth + Turndown)
 *   - .csv/.tsv                 → GFM Markdown table (papaparse)
 *   - curated code extensions   → fenced code block with a language hint
 *   - .mermaid/.mmd             → ```mermaid fence (Obsidian renders it natively)
 *   - .svg                      → ```xml fence of the source, plus a warning
 *   - .pdf                      → SKIPPED ("PDF import not yet supported")
 *   - .xlsx/.xls                → SKIPPED ("XLSX import not yet supported")
 *   - everything else (images,
 *     archives, binaries, …)    → SKIPPED ("unsupported file type: .<ext>")
 *
 * SCOPE (locked): PDF and XLSX are intentionally deferred. PDF (pdf.js via
 * pdf2md/unpdf) is ~491 KB gzip — too heavy for the v1 bundle. XLSX's `exceljs`
 * is heavy and the `xlsx`/SheetJS npm package carries CVE-2023-30533. Neither is
 * bundled; their `.pdf`/`.xlsx`/`.xls` routes return a clean `skipped` result so
 * those files are reported, never errored.
 *
 * Every converter call is wrapped in try/catch here: a single corrupt file
 * yields `{ kind:"skipped", reason }` instead of throwing — one bad file never
 * aborts the whole import.
 *
 * NO Obsidian / fs / network / Platform imports (keeps the module unit-testable
 * and the pipeline 100% offline).
 */

import { convertCsv } from "./csv";
import { convertDocx } from "./docx";
import { convertHtml } from "./html";
import { decodeUtf8 } from "./types";
import type { ConvertInput, ConvertResult, Converter } from "./types";

/** Extensions that are already Markdown/plain text → passthrough verbatim. */
const PASSTHROUGH_EXTS = new Set(["md", "markdown", "txt", "text"]);

/**
 * XLSX/XLS are recognised but intentionally NOT converted in this cut (see the
 * scope note above). They are reported as skipped so the user sees them.
 */
const XLSX_EXTS = new Set(["xlsx", "xls", "xlsm", "xlsb"]);

/** PDF is recognised but deferred in v1 (pdf.js ≈ 491 KB gzip) → reported as skipped. */
const PDF_EXTS = new Set(["pdf"]);

/**
 * SVG (a common Claude artifact type) is imported as FENCED SOURCE, not as a
 * rendered image. This is a STRUCTURAL limit, not a deferral:
 *
 * Writing the bytes as an attachment and emitting `![[name.svg]]` would render
 * a BROKEN image whenever at-rest encryption is on. Obsidian loads media
 * through `adapter.getResourcePath()` → `app://`, which reads the on-disk bytes
 * directly and so sees `VG1` ciphertext. `interceptedGetResourcePath`
 * (at-rest-adapter-runtime.ts) exists to serve a decrypted blob instead — but it
 * only does so for `isKnownBinaryExtensionPath()`, and `svg` is DELIBERATELY
 * absent from that map (binary-content.ts): an SVG is valid UTF-8, so it must
 * ride the text sync pipeline losslessly and must never be labelled binary.
 *
 * So the embed would be strictly worse than the fence until either that
 * classification changes (it must not) or the resource-path override grows an
 * SVG case. Fencing is lossless and always readable; the warning tells the user
 * exactly what they got.
 */
const SVG_EXTS = new Set(["svg"]);

/**
 * Curated code/config extensions → wrap the file text in a fenced code block.
 * The value is the Markdown language hint placed after the opening fence.
 */
const CODE_EXT_TO_LANG: Record<string, string> = {
  ts: "ts",
  tsx: "tsx",
  js: "js",
  jsx: "jsx",
  mjs: "js",
  cjs: "js",
  py: "python",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  kt: "kotlin",
  swift: "swift",
  c: "c",
  h: "c",
  cpp: "cpp",
  cc: "cpp",
  hpp: "cpp",
  cs: "csharp",
  php: "php",
  sh: "bash",
  bash: "bash",
  zsh: "bash",
  ps1: "powershell",
  sql: "sql",
  json: "json",
  jsonc: "json",
  yaml: "yaml",
  yml: "yaml",
  toml: "toml",
  ini: "ini",
  xml: "xml",
  css: "css",
  scss: "scss",
  less: "less",
  // Mermaid rides the code route on purpose: Obsidian renders a ```mermaid
  // fence natively, so the fenced form IS the rendered form — no converter,
  // no dependency, no loss.
  mermaid: "mermaid",
  mmd: "mermaid",
};

/** Direct (non-text) converters keyed by extension. */
const CONVERTERS: Record<string, Converter> = {
  html: convertHtml,
  htm: convertHtml,
  docx: convertDocx,
  csv: convertCsv,
  tsv: convertCsv,
};

/**
 * Classify a (lower-cased) extension into the route the dispatcher will take.
 * Exposed so callers (e.g. the gated import-list tool) can label a file's kind
 * without re-running its bytes through the converter.
 */
export type DispatchRoute =
  | "passthrough"
  | "code"
  | "convert"
  | "svg-fence"
  | "pdf-skip"
  | "xlsx-skip"
  | "unsupported";

export function classifyExtension(extRaw: string): DispatchRoute {
  const ext = normalizeExt(extRaw);
  if (PASSTHROUGH_EXTS.has(ext)) return "passthrough";
  if (PDF_EXTS.has(ext)) return "pdf-skip";
  if (XLSX_EXTS.has(ext)) return "xlsx-skip";
  if (SVG_EXTS.has(ext)) return "svg-fence";
  if (ext in CONVERTERS) return "convert";
  if (ext in CODE_EXT_TO_LANG) return "code";
  return "unsupported";
}

/** Lower-case and strip a single leading dot from an extension. */
export function normalizeExt(ext: string): string {
  return ext.replace(/^\.+/, "").toLowerCase();
}

/**
 * Wrap decoded file text in a fenced code block with a language hint.
 * Exported so the clipboard artifact path fences identically instead of
 * re-implementing the 4-backtick escape and drifting from it.
 */
export function toFencedCode(text: string, lang: string): string {
  // Use a 4-backtick fence so source that itself contains ``` doesn't break out.
  return ["````" + lang, text.replace(/\s+$/, ""), "````"].join("\n");
}

/**
 * Dispatch one file's bytes to the correct converter. Pure and total: NEVER
 * throws — any converter failure is caught and returned as `kind:"skipped"`.
 */
export async function dispatchConvert(input: ConvertInput): Promise<ConvertResult> {
  const ext = normalizeExt(input.ext);
  const route = classifyExtension(ext);

  try {
    switch (route) {
      case "passthrough":
        return { kind: "passthrough", markdown: decodeUtf8(input.bytes) };

      case "code": {
        const lang = CODE_EXT_TO_LANG[ext] ?? "";
        return { kind: "converted", markdown: toFencedCode(decodeUtf8(input.bytes), lang) };
      }

      case "convert": {
        const converter = CONVERTERS[ext];
        return await converter({ ...input, ext });
      }

      case "svg-fence":
        return {
          kind: "converted",
          markdown: toFencedCode(decodeUtf8(input.bytes), "xml"),
          warnings: ["SVG imported as source — inline preview is not supported yet"],
        };

      case "pdf-skip":
        return { kind: "skipped", reason: "PDF import not yet supported" };

      case "xlsx-skip":
        return { kind: "skipped", reason: "XLSX import not yet supported" };

      case "unsupported":
      default:
        return { kind: "skipped", reason: `unsupported file type: .${ext}` };
    }
  } catch (err) {
    // A corrupt/unreadable file must never crash the import — report it.
    const reason = err instanceof Error ? err.message : String(err);
    return { kind: "skipped", reason: reason || "conversion failed" };
  }
}
