/**
 * VaultGuard — Claude artifact → note assembly (pure, offline).
 *
 * Turns converted Markdown plus a little provenance into the exact bytes that
 * land on disk, and works out where they land. Everything here is pure: the
 * capture timestamp is INJECTED and the vault is reached only through an
 * `exists` predicate, so the whole module is unit-testable with no clock, no
 * Obsidian, and no filesystem.
 *
 * NO Obsidian / fs / network / Platform imports (see ./converters/types.ts).
 *
 * SECURITY NOTE: the artifact body is untrusted note text. The ONLY thing this
 * module authors is the frontmatter block; the body is passed through verbatim.
 * The title is YAML-escaped because artifact titles routinely contain `:`,
 * which would otherwise break the frontmatter and swallow the rest of the note.
 */

import type { ArtifactKind } from "./artifact-detect";

/** Where the artifact came from — recorded in frontmatter as `origin`. */
export type ArtifactOrigin = "clipboard" | "file";

export interface ArtifactNoteInput {
  /** Converted Markdown body (already through the converters). */
  markdown: string;
  kind: ArtifactKind;
  /** ISO-8601 capture instant. Injected so the output is deterministic. */
  capturedIso: string;
  origin: ArtifactOrigin;
  /** Preferred title — the file stem for file imports. Undefined for clipboard. */
  title?: string;
  /** Original file name, recorded for file imports so the trail is complete. */
  sourceName?: string;
}

export interface ArtifactNote {
  /** Human title, also written into frontmatter. */
  title: string;
  /** Sanitized base name WITHOUT the `.md` extension. */
  baseName: string;
  /** Full note text: frontmatter block + body. */
  body: string;
}

/** Obsidian rejects these in file names; `#^[]` additionally break wikilinks. */
const ILLEGAL_FILENAME_CHARS = /[\\/:*?"<>|#^[\]]/g;
// biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control bytes is the point
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/g;

/** Cap file names well under the ~255-byte limit, leaving room for " 12.md". */
const MAX_BASENAME_LENGTH = 80;

const FALLBACK_TITLE = "Claude artifact";

/** `2026-08-19T07:00:25.185Z` → `2026-08-19 07-00`; "" when the shape is wrong. */
function stampFromIso(capturedIso: string): string {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(capturedIso)) return "";
  return `${capturedIso.slice(0, 10)} ${capturedIso.slice(11, 16).replace(":", "-")}`;
}

/** A line that opens or closes a fenced block (3+ backticks or tildes). */
const FENCE_LINE = /^\s*(`{3,}|~{3,})/;

/** A shebang — never a title, and mangles badly once `#` and `/` are stripped. */
const SHEBANG_LINE = /^#!/;

/** Leading comment markers stripped from a first-line fallback title. */
const COMMENT_PREFIX = /^\s*(\/\/+|#+|--|\/\*+|\*+|<!--)\s*/;

/**
 * First ATX heading's text, or undefined. Trailing closing `#`s are stripped.
 *
 * Fenced blocks are SKIPPED, and that is the whole point: a code artifact is
 * wrapped in a fence from end to end, so every `#` comment inside it (Python,
 * bash, YAML, Makefile…) looks exactly like an ATX heading. Without this, a
 * stray `# TODO: fix later` halfway down a script became the note's title.
 */
export function firstHeadingText(markdown: string): string | undefined {
  let insideFence = false;
  for (const line of markdown.split("\n")) {
    if (FENCE_LINE.test(line)) {
      insideFence = !insideFence;
      continue;
    }
    if (insideFence) continue;

    const match = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (match) {
      const text = match[1].trim();
      if (text.length > 0) return text;
    }
  }
  return undefined;
}

/**
 * Title resolution, in descending order of trustworthiness:
 *   1. an explicit title (the file stem — the user named that file)
 *   2. the artifact's own first heading
 *   3. the first non-empty line, truncated
 *   4. a timestamped fallback
 */
export function resolveArtifactTitle(input: {
  markdown: string;
  title?: string;
  capturedIso: string;
}): string {
  const explicit = input.title?.trim();
  if (explicit) return explicit;

  const heading = firstHeadingText(input.markdown);
  if (heading) return heading;

  for (const line of input.markdown.split("\n")) {
    const trimmed = line.trim();
    // Fence openers, frontmatter rules and shebangs are never a title. A
    // shebang matters specifically: `#!/usr/bin/env bash` survives as
    // "! usr bin env bash" once the illegal-filename characters are stripped,
    // which is worse than no title at all.
    if (
      trimmed.length === 0 ||
      FENCE_LINE.test(trimmed) ||
      trimmed === "---" ||
      SHEBANG_LINE.test(trimmed)
    ) {
      continue;
    }
    // A code artifact's first real line is often a comment. Its text is a fine
    // low-confidence title; its marker is not.
    const candidate = trimmed.replace(COMMENT_PREFIX, "").trim();
    if (candidate.length === 0) continue;
    return candidate.length > MAX_BASENAME_LENGTH
      ? candidate.slice(0, MAX_BASENAME_LENGTH).trimEnd()
      : candidate;
  }

  const stamp = stampFromIso(input.capturedIso);
  return stamp ? `${FALLBACK_TITLE} ${stamp}` : FALLBACK_TITLE;
}

/** Make a title safe as an Obsidian file name (no extension, never empty). */
export function sanitizeNoteFileName(title: string): string {
  const cleaned = title
    .replace(CONTROL_CHARS, " ")
    .replace(ILLEGAL_FILENAME_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim()
    // Leading dots hide the file on POSIX; trailing dots/spaces break Windows.
    .replace(/^[.\s]+/, "")
    .replace(/[.\s]+$/, "");

  const capped = cleaned.slice(0, MAX_BASENAME_LENGTH).replace(/[.\s]+$/, "");
  return capped.length > 0 ? capped : FALLBACK_TITLE;
}

/** Strip stray slashes so a configured folder can never escape the vault. */
function normalizeFolder(folder: string): string {
  return folder.replace(/^\/+/, "").replace(/\/+$/, "").trim();
}

/**
 * First free path for `baseName` in `folder`, using Obsidian's own collision
 * convention (`Name.md`, `Name 2.md`, `Name 3.md`, …). `exists` is injected so
 * this is testable without a vault; callers pass
 * `(p) => app.vault.getAbstractFileByPath(p) !== null`.
 *
 * The counter is bounded — an `exists` that always returns true (a permission
 * quirk, a racing sync) must not spin forever, so we give up and hand back the
 * next candidate, letting the caller's `vault.create()` surface the real error
 * instead of hanging. Staying pure matters more here than a clever fallback:
 * no clock, no randomness, same inputs → same path.
 */
export function uniqueNotePath(
  folder: string,
  baseName: string,
  exists: (path: string) => boolean,
): string {
  const dir = normalizeFolder(folder);
  const pathFor = (name: string): string => (dir ? `${dir}/${name}.md` : `${name}.md`);

  const first = pathFor(baseName);
  if (!exists(first)) return first;

  for (let suffix = 2; suffix <= 999; suffix += 1) {
    const candidate = pathFor(`${baseName} ${suffix}`);
    if (!exists(candidate)) return candidate;
  }
  return pathFor(`${baseName} 1000`);
}

/** Quote and escape a value for a YAML double-quoted scalar. */
function yamlString(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** A top-level (unindented) YAML key line, e.g. `title:` or `tags:`. */
const TOP_LEVEL_KEY = /^([A-Za-z0-9_-]+)\s*:/;

interface SplitNote {
  /** The artifact's OWN frontmatter lines (without the `---` fences), or null. */
  frontmatter: string[] | null;
  /** Everything after the artifact's own frontmatter block. */
  body: string;
}

/**
 * Split an artifact's own leading frontmatter off its body.
 *
 * Claude writes plenty of `.md` artifacts that already carry frontmatter.
 * Prepending a second block would leave the note with two: Obsidian parses only
 * the first, so the artifact's own keys would render as an `<hr>` followed by
 * plain text and its tags would silently stop working. Splitting lets us MERGE
 * into the block that is already there.
 */
function splitLeadingFrontmatter(markdown: string): SplitNote {
  const lines = markdown.split("\n");
  if (lines[0]?.trim() !== "---") return { frontmatter: null, body: markdown };

  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i].trim() === "---") {
      return {
        frontmatter: lines.slice(1, i),
        body: lines.slice(i + 1).join("\n").replace(/^\n+/, ""),
      };
    }
  }
  // An opening `---` with no close is not frontmatter — treat it as content.
  return { frontmatter: null, body: markdown };
}

/** Top-level keys already declared in the artifact's own frontmatter. */
function declaredKeys(frontmatter: string[]): Set<string> {
  const keys = new Set<string>();
  for (const line of frontmatter) {
    const match = TOP_LEVEL_KEY.exec(line);
    if (match) keys.add(match[1].toLowerCase());
  }
  return keys;
}

/** Read a scalar value out of the artifact's own frontmatter, unquoted. */
function frontmatterValue(frontmatter: string[], key: string): string | undefined {
  for (const line of frontmatter) {
    const match = TOP_LEVEL_KEY.exec(line);
    if (!match || match[1].toLowerCase() !== key) continue;
    const raw = line.slice(line.indexOf(":") + 1).trim();
    const unquoted = /^"(.*)"$/.exec(raw) ?? /^'(.*)'$/.exec(raw);
    const value = (unquoted ? unquoted[1] : raw).trim();
    if (value.length > 0) return value;
  }
  return undefined;
}

/**
 * Assemble the finished note. Frontmatter records enough provenance to answer
 * "where did this come from?" months later without keeping the chat around.
 */
export function buildArtifactNote(input: ArtifactNoteInput): ArtifactNote {
  const split = splitLeadingFrontmatter(input.markdown);
  const own = split.frontmatter;

  const title = resolveArtifactTitle({
    markdown: split.body,
    // An explicit title (the file stem) still wins; otherwise the artifact's
    // own `title:` outranks a heading dug out of the body.
    title: input.title ?? (own ? frontmatterValue(own, "title") : undefined),
    capturedIso: input.capturedIso,
  });
  const baseName = sanitizeNoteFileName(title);

  const existing = own ? declaredKeys(own) : new Set<string>();
  const addIfAbsent = (key: string, lines: string[]): string[] =>
    existing.has(key) ? [] : lines;

  const provenance = [
    ...addIfAbsent("title", [`title: ${yamlString(title)}`]),
    ...addIfAbsent("source", ["source: claude-artifact"]),
    ...addIfAbsent("artifact-type", [`artifact-type: ${input.kind}`]),
    ...addIfAbsent("captured", [`captured: ${input.capturedIso}`]),
    ...addIfAbsent("origin", [`origin: ${input.origin}`]),
    ...(input.sourceName
      ? addIfAbsent("source-file", [`source-file: ${yamlString(input.sourceName)}`])
      : []),
    // A `tags:` the artifact already declares is left completely alone. Merging
    // into someone else's YAML sequence means guessing between block and flow
    // form, and a corrupted tags list is a worse outcome than a missing
    // classification tag.
    ...addIfAbsent("tags", ["tags:", "  - claude/artifact"]),
  ];

  const frontmatter = ["---", ...(own ?? []), ...provenance, "---"].join("\n");
  const body = split.body.replace(/\s+$/, "");
  return { title, baseName, body: `${frontmatter}\n\n${body}\n` };
}
