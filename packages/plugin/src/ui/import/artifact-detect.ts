/**
 * VaultGuard — Claude artifact kind detection (pure, offline).
 *
 * A Claude artifact arrives as a naked string when it comes off the clipboard:
 * the "Copy" button in claude.ai hands over the artifact body with no filename,
 * no MIME type, and no metadata. This module is the only thing standing between
 * that string and a sensible note, so it has to guess the kind from the bytes.
 *
 * File imports do NOT use the sniffer — they have a real extension, so they go
 * through `classifyExtension()` in ./converters/dispatch.ts and only borrow
 * `artifactKindForExtension()` below to label the note's frontmatter.
 *
 * NO Obsidian / fs / network / Platform imports — same contract as
 * ./converters/types.ts, which is what keeps this unit-testable without mocks.
 *
 * SECURITY NOTE: detection classifies, it does not sanitize. The text is
 * untrusted note content exactly like any other imported file.
 */

/** The artifact shapes we can turn into a note. */
export type ArtifactKind = "html" | "svg" | "mermaid" | "code" | "csv" | "markdown";

export interface ArtifactDetection {
  kind: ArtifactKind;
  /**
   * Markdown fence language hint for `kind:"code"` (e.g. `"ts"`). Undefined
   * when the language is unknown — callers then emit a bare fence rather than
   * guessing wrong and mislabelling the block.
   */
  lang?: string;
}

/**
 * Structural tags that mark a document-level HTML artifact. Deliberately SHORT:
 * markdown routinely contains inline HTML (`<span>`, `<br>`, `<img>`), and
 * classifying such a document as HTML would push it through Turndown and mangle
 * the Markdown the user already had. Only a leading structural tag counts.
 */
const HTML_LEADING_TAGS = ["<!doctype html", "<html", "<body", "<div", "<section", "<table"];

/** Mermaid diagram headers — the first non-empty line of a mermaid artifact. */
const MERMAID_HEADER =
  /^(graph\s+(TB|TD|BT|RL|LR)\b|flowchart\b|sequenceDiagram\b|classDiagram(-v2)?\b|stateDiagram(-v2)?\b|erDiagram\b|journey\b|gantt\b|pie\b|mindmap\b|timeline\b|gitGraph\b|quadrantChart\b|requirementDiagram\b|C4Context\b)/;

/**
 * Tight start-of-document code signals. Each one anchors to the first
 * meaningful line AND requires code-ish continuation, so English prose that
 * merely opens with the word "import" or "class" does not match.
 */
const CODE_LEADING = [
  /^#!\//,
  /^import\s+[\w{*[]/,
  /^from\s+["'\w.]/,
  /^export\s+(default|const|let|var|function|class|async|type|interface|\{)/,
  /^(async\s+)?function\s+\w+\s*\(/,
  /^(const|let|var)\s+\w+\s*[:=]/,
  /^(public|private|protected|static)\s+\w/,
  /^class\s+\w+[\s({:]/,
  /^def\s+\w+\s*\(/,
  /^package\s+[\w.]+;?$/,
  /^(using|namespace)\s+[\w.]+;?$/,
  /^<\?php\b/,
];

/**
 * STRONG markdown signals — line-anchored constructs that essentially cannot
 * appear by accident in code or CSV. Weak signals (bold, links, `-` bullets)
 * are deliberately NOT here: a JSDoc block's ` * text` lines look exactly like
 * bullets, which used to drag code artifacts into the markdown branch.
 */
const MARKDOWN_STRONG = [
  /^#{1,6}\s+\S/m, // ATX heading
  /^```/m, // fenced block
  /^\s*\|?\s*:?-{3,}:?\s*\|/m, // GFM table delimiter row
  /^>\s+\S/m, // blockquote
  /^\s*- \[[ xX]\]\s/m, // task list
];

/**
 * Delimiters considered when sniffing a delimited-values artifact.
 *
 * `;` is deliberately EXCLUDED even though semicolon-delimited CSV exists in
 * European locales: every line of C-family code ends in exactly one semicolon,
 * so a consistent count of 1 made `doThing();\ndoOther();` look like a perfect
 * two-column CSV. Code artifacts are far likelier than semicolon CSV here, and
 * a semicolon `.csv` FILE still parses correctly because papaparse detects the
 * delimiter itself — only this content sniff gives it up.
 */
const CSV_DELIMITERS = [",", "\t"] as const;

/** First line with visible content, or "" when the text is blank. */
function firstMeaningfulLine(text: string): string {
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return "";
}

function looksLikeHtml(trimmedLower: string): boolean {
  return HTML_LEADING_TAGS.some((tag) => trimmedLower.startsWith(tag));
}

function looksLikeSvg(trimmedLower: string): boolean {
  if (trimmedLower.startsWith("<svg")) return true;
  // An SVG file may open with an XML prolog and/or a DOCTYPE before <svg.
  return trimmedLower.startsWith("<?xml") && trimmedLower.includes("<svg");
}

function hasStrongMarkdown(text: string): boolean {
  return MARKDOWN_STRONG.some((re) => re.test(text));
}

/**
 * Delimited-values sniff: at least two non-empty lines that all carry the SAME
 * non-zero count of one delimiter. Requiring consistency (not just presence) is
 * what keeps ordinary prose containing commas out of the CSV branch.
 */
function looksLikeCsv(text: string): boolean {
  const lines = text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .slice(0, 10);
  if (lines.length < 2) return false;

  return CSV_DELIMITERS.some((delimiter) => {
    const counts = lines.map((line) => countOutsideQuotes(line, delimiter));
    const first = counts[0];
    if (first < 1) return false;
    return counts.every((count) => count === first);
  });
}

/** Count `delimiter` occurrences that fall outside a double-quoted region. */
function countOutsideQuotes(line: string, delimiter: string): number {
  let count = 0;
  let inQuotes = false;
  for (const char of line) {
    if (char === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (!inQuotes && char === delimiter) count += 1;
  }
  return count;
}

/**
 * Fallback density heuristic for code that does not announce itself on line 1
 * (a bare function body, a config fragment, a diff of statements). Prose almost
 * never sustains this ratio of structural punctuation.
 */
function looksLikeCodeByDensity(text: string): boolean {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length < 2) return false;

  const structural = lines.filter((line) => /[;{}]\s*$/.test(line.trim())).length;
  return structural / lines.length >= 0.3;
}

/**
 * Best-effort fence language. Small on purpose: a wrong hint is worse than none
 * (it mislabels the block and can break Obsidian's highlighter), so anything we
 * are not confident about returns undefined and the caller emits a bare fence.
 */
function guessCodeLanguage(text: string, firstLine: string): string | undefined {
  if (/^#!.*\b(bash|sh|zsh)\b/.test(firstLine)) return "bash";
  if (/^#!.*\bpython/.test(firstLine)) return "python";
  if (/^<\?php\b/.test(firstLine)) return "php";
  if (/^(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|WITH)\b/i.test(firstLine)) return "sql";
  if (/^(def|from|import)\s/.test(firstLine) && /:\s*$/m.test(text)) return "python";

  const looksTypeScript =
    /\b(interface|type)\s+\w+\s*[={]/.test(text) ||
    /:\s*(string|number|boolean|void|unknown|never)\b/.test(text);
  const looksJsx = /<[A-Z]\w*[\s/>]/.test(text) && /<\/[A-Z]\w*>|\/>/.test(text);
  if (looksJsx) return looksTypeScript ? "tsx" : "jsx";
  if (looksTypeScript) return "ts";

  if (/^(import|export)\s/.test(firstLine) || /\b(const|let|function)\s+\w+/.test(text)) {
    return "js";
  }
  return undefined;
}

/**
 * Classify a naked artifact string.
 *
 * Order is the contract and each step earns its place:
 *   1. svg       — unambiguous root element
 *   2. html      — document-level structural tag (never inline HTML)
 *   3. mermaid   — first line is a diagram header
 *   4. code      — first line is an unambiguous code opener
 *   5. markdown  — a STRONG markdown construct is present
 *   6. csv       — consistent delimiter counts across lines
 *   7. code      — structural-punctuation density
 *   8. markdown  — fallback: prose is markdown
 */
export function detectArtifactKind(text: string): ArtifactDetection {
  const trimmed = text.trim();
  if (trimmed.length === 0) return { kind: "markdown" };

  const trimmedLower = trimmed.toLowerCase();
  if (looksLikeSvg(trimmedLower)) return { kind: "svg" };
  if (looksLikeHtml(trimmedLower)) return { kind: "html" };

  const firstLine = firstMeaningfulLine(trimmed);
  if (MERMAID_HEADER.test(firstLine)) return { kind: "mermaid" };

  if (CODE_LEADING.some((re) => re.test(firstLine))) {
    return { kind: "code", lang: guessCodeLanguage(trimmed, firstLine) };
  }

  if (hasStrongMarkdown(trimmed)) return { kind: "markdown" };
  if (looksLikeCsv(trimmed)) return { kind: "csv" };
  if (looksLikeCodeByDensity(trimmed)) {
    return { kind: "code", lang: guessCodeLanguage(trimmed, firstLine) };
  }

  return { kind: "markdown" };
}

/**
 * Label an imported FILE with an artifact kind for its frontmatter. The file
 * path already told us the type, so this never sniffs content — it only maps a
 * (lower-cased, dot-stripped) extension onto the same vocabulary the clipboard
 * path produces, so both origins write identical `artifact-type` values.
 */
export function artifactKindForExtension(ext: string): ArtifactKind {
  const normalized = ext.replace(/^\.+/, "").toLowerCase();
  switch (normalized) {
    case "html":
    case "htm":
      return "html";
    case "svg":
      return "svg";
    case "mermaid":
    case "mmd":
      return "mermaid";
    case "csv":
    case "tsv":
      return "csv";
    case "md":
    case "markdown":
    case "txt":
    case "text":
    case "docx":
      return "markdown";
    default:
      return "code";
  }
}
