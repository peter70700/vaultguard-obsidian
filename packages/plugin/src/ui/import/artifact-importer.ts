/**
 * VaultGuard — "Save Claude artifact" ingestion (clipboard + local file).
 *
 * The only impure module in the artifact feature: it reads the clipboard, reads
 * files, and writes notes. All classification (./artifact-detect.ts), all
 * conversion (./converters/), and all note assembly (./artifact-note.ts) stay
 * pure and are exercised directly by unit tests.
 *
 * NETWORKING: NONE. Not `requestUrl`, not `fetch` — nothing. A Claude artifact
 * cannot be fetched: `claude.ai/code/artifact/<uuid>` answers an unauthenticated
 * GET with HTTP 200 and an empty ~14 KB wrapper shell, and the real content
 * lives on a per-artifact `*.frame.claudeusercontent.com` subdomain that 404s
 * without the user's session. The artifact only ever arrives because the USER
 * hands it over — a copy or a download. That is the whole design.
 *
 * AT-REST: notes are written with `app.vault.create()`, which calls
 * `adapter.write()` and therefore lands on the plugin's interception — the same
 * LAK encryption and permission check an ordinary "New note" gets.
 * `originalAdapterMethods.*` is never touched (Local At-Rest Rule).
 *
 * SECURITY NOTE: artifact text is UNTRUSTED note content, readable later by the
 * in-app agent's `read` tool exactly like any other note. Nothing here
 * sanitizes it; only the frontmatter block is authored by us.
 */

import { Notice, TFile } from "obsidian";
import type { App } from "obsidian";

import { artifactKindForExtension, detectArtifactKind } from "./artifact-detect";
import type { ArtifactKind } from "./artifact-detect";
import { buildArtifactNote, uniqueNotePath } from "./artifact-note";
import type { ArtifactOrigin } from "./artifact-note";
import { convertCsv } from "./converters/csv";
import { classifyExtension, dispatchConvert, toFencedCode } from "./converters/dispatch";
import { htmlToMarkdown } from "./converters/html";
import { makeImportSourceFs, pickSourceFiles } from "./local-file-importer";

/** Everything the importer needs from the plugin. Narrow on purpose. */
export interface ArtifactImportContext {
  app: App;
  /** Vault-relative destination folder, already normalized by settings. */
  artifactImportFolder: string;
  ensureParentFoldersForPath(path: string): Promise<void>;
  logError(message: string, error: unknown): void;
}

/**
 * Upper bound on a single clipboard capture, in characters.
 *
 * Detection runs several whole-string regexes and splits the text into lines,
 * all on the UI thread. A pathological clipboard (someone copied a log file)
 * would freeze Obsidian with no explanation. 5 million characters is far beyond
 * any real artifact, so the cap only ever fires on content that was never going
 * to make a sensible note — and it fails with a message instead of a hang.
 */
const MAX_CLIPBOARD_CHARS = 5_000_000;

/** Outcome of importing one artifact. */
interface ArtifactImportOutcome {
  path?: string;
  skippedReason?: string;
  warnings?: string[];
}

/**
 * Convert a naked clipboard string to Markdown according to its sniffed kind.
 * Fencing goes through the dispatcher's `toFencedCode` so the clipboard path
 * can never drift from the file path's escaping.
 */
async function markdownFromText(text: string, kind: ArtifactKind, lang?: string): Promise<string> {
  switch (kind) {
    case "html":
      return htmlToMarkdown(text);
    case "svg":
      return toFencedCode(text, "xml");
    case "mermaid":
      return toFencedCode(text, "mermaid");
    case "code":
      return toFencedCode(text, lang ?? "");
    case "csv": {
      const result = await convertCsv({
        bytes: new TextEncoder().encode(text),
        ext: "csv",
        baseName: "artifact",
      });
      // A CSV that papaparse cannot table is still worth keeping verbatim.
      return result.markdown ?? text;
    }
    default:
      return text;
  }
}

/**
 * Single write site for both ingestion paths: resolve a free path, create any
 * missing folders, and write through the intercepted adapter.
 */
async function writeArtifactNote(
  ctx: ArtifactImportContext,
  input: {
    markdown: string;
    kind: ArtifactKind;
    origin: ArtifactOrigin;
    title?: string;
    sourceName?: string;
  },
): Promise<string> {
  const note = buildArtifactNote({
    markdown: input.markdown,
    kind: input.kind,
    capturedIso: new Date().toISOString(),
    origin: input.origin,
    title: input.title,
    sourceName: input.sourceName,
  });

  const path = uniqueNotePath(
    ctx.artifactImportFolder,
    note.baseName,
    (candidate) => ctx.app.vault.getAbstractFileByPath(candidate) !== null,
  );

  await ctx.ensureParentFoldersForPath(path);
  await ctx.app.vault.create(path, note.body);
  return path;
}

/** Open a freshly created note so the user lands on what they just saved. */
async function revealNote(ctx: ArtifactImportContext, path: string): Promise<void> {
  const file = ctx.app.vault.getAbstractFileByPath(path);
  if (file instanceof TFile) {
    await ctx.app.workspace.getLeaf(true).openFile(file);
  }
}

/**
 * Path A — capture whatever is on the clipboard as a note.
 *
 * Works on mobile: the Clipboard API is available there, and nothing in this
 * path touches Electron or `fs`.
 */
export async function importArtifactFromClipboard(ctx: ArtifactImportContext): Promise<void> {
  let text: string;
  try {
    if (!navigator.clipboard?.readText) {
      new Notice("VaultGuard: the clipboard is not available in this Obsidian window.");
      return;
    }
    text = await navigator.clipboard.readText();
  } catch (err) {
    ctx.logError("Artifact import: clipboard read failed", err);
    new Notice("VaultGuard: could not read the clipboard. Grant clipboard access and retry.");
    return;
  }

  if (text.trim().length === 0) {
    new Notice("VaultGuard: the clipboard is empty — copy a Claude artifact first.");
    return;
  }

  if (text.length > MAX_CLIPBOARD_CHARS) {
    new Notice(
      `VaultGuard: that clipboard content is too large to import (${Math.round(
        text.length / 1_000_000,
      )} MB). Save it to a file and use "Import Claude artifact file…" instead.`,
      10_000,
    );
    return;
  }

  try {
    const detection = detectArtifactKind(text);
    const markdown = await markdownFromText(text, detection.kind, detection.lang);
    // The file path gets this check for free from `convertHtml`, which reports
    // `skipped` for content-free HTML. The clipboard path calls
    // `htmlToMarkdown` directly (it has a string, not bytes), so it has to make
    // the same check itself — otherwise markup with no text, which is easy to
    // select by accident, produced a note that was nothing but frontmatter.
    if (markdown.trim().length === 0) {
      new Notice("VaultGuard: that clipboard content had no text to import.");
      return;
    }
    const path = await writeArtifactNote(ctx, {
      markdown,
      kind: detection.kind,
      origin: "clipboard",
    });
    await revealNote(ctx, path);
    new Notice(`VaultGuard: saved ${detection.kind} artifact to ${path}`);
  } catch (err) {
    ctx.logError("Artifact import: clipboard capture failed", err);
    new Notice("VaultGuard: could not save the artifact. See the console for details.");
  }
}

/** Import one already-read file. Never throws — a bad file is a skip. */
async function importOneFile(
  ctx: ArtifactImportContext,
  file: { bytes: Uint8Array; ext: string; baseName: string; fileName: string },
): Promise<ArtifactImportOutcome> {
  if (classifyExtension(file.ext) === "unsupported") {
    return { skippedReason: `${file.fileName}: unsupported file type` };
  }

  const converted = await dispatchConvert({
    bytes: file.bytes,
    ext: file.ext,
    baseName: file.baseName,
  });
  if (converted.kind === "skipped" || !converted.markdown) {
    return { skippedReason: `${file.fileName}: ${converted.reason ?? "nothing to import"}` };
  }

  const path = await writeArtifactNote(ctx, {
    markdown: converted.markdown,
    kind: artifactKindForExtension(file.ext),
    origin: "file",
    title: file.baseName,
    sourceName: file.fileName,
  });
  return { path, warnings: converted.warnings };
}

/**
 * Path B — import one or more downloaded artifact files.
 *
 * Desktop-only: it needs the Electron picker and Node `fs`. One bad file never
 * aborts the batch — `dispatchConvert` already returns `kind:"skipped"` rather
 * than throwing, and a genuine read failure is caught per file.
 */
export async function importArtifactFiles(ctx: ArtifactImportContext): Promise<void> {
  const sourceFs = makeImportSourceFs();
  if (!sourceFs) {
    new Notice("VaultGuard: importing artifact files requires the desktop app.");
    return;
  }

  const paths = await pickSourceFiles();
  if (!paths || paths.length === 0) return;

  const created: string[] = [];
  const skipped: string[] = [];
  const warnings: string[] = [];

  for (const absPath of paths) {
    const fileName = sourceFs.basename(absPath);
    try {
      const bytes = await sourceFs.readFile(absPath);
      const ext = sourceFs.extname(absPath);
      const baseName = ext ? fileName.slice(0, -(ext.length + 1)) : fileName;
      const outcome = await importOneFile(ctx, { bytes, ext, baseName, fileName });
      if (outcome.path) created.push(outcome.path);
      if (outcome.skippedReason) skipped.push(outcome.skippedReason);
      if (outcome.warnings?.length) warnings.push(...outcome.warnings);
    } catch (err) {
      ctx.logError(`Artifact import: failed to import ${fileName}`, err);
      skipped.push(`${fileName}: read or write failed`);
    }
  }

  if (created.length === 1 && skipped.length === 0) {
    await revealNote(ctx, created[0]);
  }

  const summary = [
    `VaultGuard: imported ${created.length} artifact${created.length === 1 ? "" : "s"}`,
    skipped.length > 0 ? `, skipped ${skipped.length}` : "",
    skipped.length > 0 ? `\n${skipped.join("\n")}` : "",
    warnings.length > 0 ? `\n${[...new Set(warnings)].join("\n")}` : "",
  ].join("");
  new Notice(summary, skipped.length > 0 || warnings.length > 0 ? 12_000 : 5_000);
}
