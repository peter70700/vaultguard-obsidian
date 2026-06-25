/**
 * VaultGuard — Local import converter contract (Tier-1, offline, pure).
 *
 * Every converter in this folder is PURE: bytes in → Markdown string out. They
 * import NO Obsidian, NO `fs`, NO network, NO `Platform` — that is exactly what
 * makes them unit-testable in Vitest without mocks and keeps the import pipeline
 * 100% offline (zero `requestUrl`/`fetch`).
 *
 * SECURITY NOTE (prompt-injection surface): imported content is later readable
 * by the in-app AI agent (the `read` tool). It is treated as UNTRUSTED note text
 * exactly like any other vault file — no special sanitization happens here. The
 * import summary Notice repeats this caution to the user.
 */

/** Input handed to a single-format converter. */
export interface ConvertInput {
  /** Raw file bytes. Converters accept either an ArrayBuffer or a Uint8Array. */
  bytes: ArrayBuffer | Uint8Array;
  /** Lower-cased file extension WITHOUT the leading dot (e.g. `"docx"`). */
  ext: string;
  /** File base name without extension (e.g. `"report"` for `report.docx`). */
  baseName: string;
}

/**
 * Result of dispatching/converting one file.
 *
 * - `converted`   — bytes were transformed into Markdown (`markdown` set).
 * - `passthrough` — file was already text/Markdown; `markdown` is the decoded text.
 * - `skipped`     — unsupported/binary/corrupt; `reason` explains why (NEVER throws).
 */
export type ConvertKind = "converted" | "passthrough" | "skipped";

export interface ConvertResult {
  kind: ConvertKind;
  /** Present for `converted` | `passthrough`. */
  markdown?: string;
  /** Present for `skipped` — human-readable reason. */
  reason?: string;
  /** Non-fatal notes (e.g. "low text layer — likely a scanned PDF"). */
  warnings?: string[];
}

/** A single-format converter: pure bytes → ConvertResult. */
export type Converter = (input: ConvertInput) => Promise<ConvertResult>;

/** Coerce either input byte shape into a Uint8Array view (no copy when possible). */
export function toUint8Array(bytes: ArrayBuffer | Uint8Array): Uint8Array {
  return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
}

/**
 * Decode bytes as UTF-8 text. Used by passthrough (.md/.txt) and the
 * code-fence fallback. `fatal: false` so malformed sequences degrade to U+FFFD
 * instead of throwing — a corrupt text file becomes readable-ish Markdown, not
 * an import crash.
 */
export function decodeUtf8(bytes: ArrayBuffer | Uint8Array): string {
  const view = toUint8Array(bytes);
  return new TextDecoder("utf-8", { fatal: false }).decode(view);
}
