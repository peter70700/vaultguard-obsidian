export const SEMANTIC_CHUNKER_VERSION = "p2-v1";
export const SEMANTIC_TARGET_CHARS = 2_000;
export const SEMANTIC_MAX_OVERLAP = 200;
export const SEMANTIC_MAX_CHUNKS_PER_NOTE = 32;
export const SEMANTIC_MAX_HEADING_CODE_POINTS = 160;

export interface SemanticMarkdownChunk {
  index: number;
  start: number;
  end: number;
  text: string;
  heading?: string;
}

export interface SemanticChunkResult {
  chunks: SemanticMarkdownChunk[];
  truncated: boolean;
}

interface HeadingOffset {
  offset: number;
  label: string;
}

function boundedHeading(value: string): string | undefined {
  const clean = value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  if (!clean) return undefined;
  return [...clean].slice(0, SEMANTIC_MAX_HEADING_CODE_POINTS).join("");
}

function collectHeadings(markdown: string): HeadingOffset[] {
  const headings: HeadingOffset[] = [];
  const pattern = /^(?: {0,3})(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$/gmu;
  for (const match of markdown.matchAll(pattern)) {
    const label = boundedHeading(match[2] ?? "");
    if (label && typeof match.index === "number") headings.push({ offset: match.index, label });
  }
  return headings;
}

function avoidSurrogateSplit(markdown: string, raw: number, direction: "start" | "end"): number {
  let offset = Math.max(0, Math.min(markdown.length, raw));
  if (direction === "start" && offset < markdown.length) {
    const code = markdown.charCodeAt(offset);
    if (code >= 0xdc00 && code <= 0xdfff) offset += 1;
  } else if (direction === "end" && offset > 0) {
    const code = markdown.charCodeAt(offset - 1);
    if (code >= 0xd800 && code <= 0xdbff) offset -= 1;
  }
  return offset;
}

function findBoundary(markdown: string, start: number, desiredEnd: number): number {
  if (desiredEnd >= markdown.length) return markdown.length;
  const minimum = Math.min(desiredEnd, start + Math.floor(SEMANTIC_TARGET_CHARS * 0.55));
  const window = markdown.slice(start, desiredEnd);

  const paragraph = window.lastIndexOf("\n\n");
  if (paragraph >= minimum - start) return start + paragraph + 2;

  const headingCandidates = [...window.matchAll(/\n(?= {0,3}#{1,6}[ \t]+)/gmu)];
  const lastHeading = headingCandidates.at(-1);
  if (
    lastHeading &&
    typeof lastHeading.index === "number" &&
    lastHeading.index >= minimum - start
  ) {
    return start + lastHeading.index + 1;
  }

  const newline = window.lastIndexOf("\n");
  if (newline >= minimum - start) return start + newline + 1;
  const space = window.lastIndexOf(" ");
  if (space >= minimum - start) return start + space + 1;
  return desiredEnd;
}

/** Deterministic current-note chunking. Offsets are UTF-16 indices for String.slice. */
export function chunkMarkdown(markdown: string): SemanticChunkResult {
  if (typeof markdown !== "string" || markdown.trim().length === 0) {
    return { chunks: [], truncated: false };
  }

  const headings = collectHeadings(markdown);
  const chunks: SemanticMarkdownChunk[] = [];
  let start = 0;
  let headingIndex = -1;

  while (start < markdown.length && chunks.length < SEMANTIC_MAX_CHUNKS_PER_NOTE) {
    start = avoidSurrogateSplit(markdown, start, "start");
    while (headingIndex + 1 < headings.length && headings[headingIndex + 1]!.offset <= start) {
      headingIndex += 1;
    }

    const desiredEnd = Math.min(markdown.length, start + SEMANTIC_TARGET_CHARS);
    let end = avoidSurrogateSplit(markdown, findBoundary(markdown, start, desiredEnd), "end");
    if (end <= start) {
      end = avoidSurrogateSplit(markdown, desiredEnd, "end");
      if (end <= start) break;
    }
    const text = markdown.slice(start, end);
    if (text.trim().length > 0) {
      chunks.push({
        index: chunks.length,
        start,
        end,
        text,
        ...(headingIndex >= 0 ? { heading: headings[headingIndex]!.label } : {}),
      });
    }
    if (end >= markdown.length) break;

    let next = Math.max(start + 1, end - SEMANTIC_MAX_OVERLAP);
    next = avoidSurrogateSplit(markdown, next, "start");
    if (next <= start) next = end;
    start = next;
  }

  const finalEnd = chunks.at(-1)?.end ?? 0;
  return { chunks, truncated: finalEnd < markdown.length };
}
