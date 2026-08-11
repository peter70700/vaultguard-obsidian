/**
 * Pure, authority-free Markdown transformations for Agent Bridge semantic
 * operations. This module never reads or writes the vault. Callers must apply
 * lease, path, permission, confirmation, and audit policy before using a
 * transformed result.
 */

export const AGENT_NOTE_OPERATION_LIMITS = {
  insertedContentChars: 262_144,
  sectionChars: 300,
  propertyKeyChars: 120,
  propertyStringChars: 10_000,
  propertyListItems: 100,
  taskTextChars: 10_000,
  listedTasks: 200,
  serializedFrontmatterChars: 1_048_576,
} as const;

export type AgentNoteOperationErrorCode =
  | "invalid"
  | "stale"
  | "not_found"
  | "ambiguous"
  | "unavailable";

/** Stable, content-redacted error returned by pure semantic transforms. */
export class AgentNoteOperationError extends Error {
  constructor(
    public readonly code: AgentNoteOperationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "AgentNoteOperationError";
  }
}

export type AgentTextHasher = (value: string) => Promise<string>;

/** SHA-256 of the exact UTF-8 string, returned as lower-case hexadecimal. */
export async function sha256Text(value: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new AgentNoteOperationError(
      "unavailable",
      "SHA-256 is unavailable in this runtime.",
    );
  }
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export function isSha256Hash(value: string): boolean {
  return /^[a-f0-9]{64}$/iu.test(value);
}

type Newline = "\r\n" | "\n" | "\r";

interface SourceLine {
  number: number;
  start: number;
  end: number;
  endWithEol: number;
  text: string;
  eol: string;
}

interface FrontmatterBoundary {
  bomLength: number;
  hasFrontmatter: boolean;
  yamlStart: number;
  yamlEnd: number;
  closeStart: number;
  closeEnd: number;
  bodyStart: number;
}

function fail(code: AgentNoteOperationErrorCode, message: string): never {
  throw new AgentNoteOperationError(code, message);
}

function detectNewline(content: string): Newline {
  return content.match(/\r\n|\n|\r/u)?.[0] as Newline | undefined ?? "\n";
}

function normalizeNewlines(content: string, newline: Newline): string {
  return content.replace(/\r\n|\r|\n/gu, "\n").replace(/\n/gu, newline);
}

function scanLines(content: string, baseOffset = 0): SourceLine[] {
  const lines: SourceLine[] = [];
  const expression = /\r\n|\n|\r/gu;
  let start = 0;
  let match: RegExpExecArray | null;
  while ((match = expression.exec(content)) !== null) {
    const end = match.index;
    lines.push({
      number: lines.length + 1,
      start: baseOffset + start,
      end: baseOffset + end,
      endWithEol: baseOffset + expression.lastIndex,
      text: content.slice(start, end),
      eol: match[0],
    });
    start = expression.lastIndex;
  }
  if (start < content.length || lines.length === 0) {
    lines.push({
      number: lines.length + 1,
      start: baseOffset + start,
      end: baseOffset + content.length,
      endWithEol: baseOffset + content.length,
      text: content.slice(start),
      eol: "",
    });
  }
  return lines;
}

function inspectFrontmatter(content: string): FrontmatterBoundary {
  const bomLength = content.startsWith("\uFEFF") ? 1 : 0;
  const lines = scanLines(content.slice(bomLength), bomLength);
  const first = lines[0];
  if (!first || first.text !== "---") {
    return {
      bomLength,
      hasFrontmatter: false,
      yamlStart: bomLength,
      yamlEnd: bomLength,
      closeStart: bomLength,
      closeEnd: bomLength,
      bodyStart: bomLength,
    };
  }
  if (!first.eol) {
    return fail("invalid", "Markdown frontmatter is malformed.");
  }
  const closing = lines.slice(1).find(
    (line) => line.text === "---" || line.text === "...",
  );
  if (!closing) {
    return fail("invalid", "Markdown frontmatter is malformed.");
  }
  return {
    bomLength,
    hasFrontmatter: true,
    yamlStart: first.endWithEol,
    yamlEnd: closing.start,
    closeStart: closing.start,
    closeEnd: closing.end,
    bodyStart: closing.endWithEol,
  };
}

function isLineBreak(value: string | undefined): boolean {
  return value === "\r" || value === "\n";
}

function validateBoundedText(
  value: string,
  maximum: number,
  label: "content" | "section" | "task text" | "property key",
  options: { allowEmpty?: boolean; allowNewlines?: boolean } = {},
): void {
  if (typeof value !== "string") {
    return fail("invalid", `The ${label} is invalid.`);
  }
  if (!options.allowEmpty && value.length === 0) {
    return fail("invalid", `The ${label} is invalid.`);
  }
  if (value.length > maximum || value.includes("\0")) {
    return fail("invalid", `The ${label} exceeds its safe bound.`);
  }
  if (!options.allowNewlines && /\r|\n/u.test(value)) {
    return fail("invalid", `The ${label} must be a single line.`);
  }
}

interface FenceState {
  marker: "`" | "~";
  length: number;
}

function nextFenceState(line: string, current: FenceState | null): FenceState | null {
  const match = /^ {0,3}(`{3,}|~{3,})(.*)$/u.exec(line);
  if (!match) return current;
  const run = match[1];
  const marker = run[0] as "`" | "~";
  if (!current) return { marker, length: run.length };
  if (
    marker === current.marker &&
    run.length >= current.length &&
    match[2].trim().length === 0
  ) {
    return null;
  }
  return current;
}

interface MarkdownHeading {
  level: number;
  title: string;
  start: number;
  endWithEol: number;
}

function markdownHeadings(content: string, bodyStart: number): MarkdownHeading[] {
  const headings: MarkdownHeading[] = [];
  let fence: FenceState | null = null;
  const bomLength = content.startsWith("\uFEFF") ? 1 : 0;
  for (const line of scanLines(content.slice(bomLength), bomLength)) {
    if (line.start < bodyStart) continue;
    const previousFence = fence;
    fence = nextFenceState(line.text, fence);
    if (previousFence || fence) continue;
    const match = /^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*)$/u.exec(line.text);
    if (!match) continue;
    let title = (match[2] ?? "").trim();
    title = title.replace(/[ \t]+#+[ \t]*$/u, "").trim();
    headings.push({
      level: match[1].length,
      title,
      start: line.start,
      endWithEol: line.endWithEol,
    });
  }
  return headings;
}

function insertionOffsetForSection(
  content: string,
  section: string,
  position: "append" | "prepend",
): number {
  validateBoundedText(
    section,
    AGENT_NOTE_OPERATION_LIMITS.sectionChars,
    "section",
  );
  if (section.trim() !== section) {
    return fail("invalid", "The section name is invalid.");
  }
  const boundary = inspectFrontmatter(content);
  const headings = markdownHeadings(content, boundary.bodyStart);
  const matches = headings
    .map((heading, index) => ({ heading, index }))
    .filter(({ heading }) => heading.title === section);
  if (matches.length === 0) {
    return fail("not_found", "The requested section was not found.");
  }
  if (matches.length > 1) {
    return fail("ambiguous", "The requested section is ambiguous.");
  }
  const { heading, index } = matches[0];
  if (position === "prepend") return heading.endWithEol;
  const nextPeer = headings
    .slice(index + 1)
    .find((candidate) => candidate.level <= heading.level);
  return nextPeer?.start ?? content.length;
}

function insertAtOffset(
  content: string,
  offset: number,
  inserted: string,
  newline: Newline,
): { content: string; insertedStart: number; insertedEnd: number } {
  const emptyBomOnly = content === "\uFEFF" && offset === 1;
  const needsLeadingSeparator =
    offset > 0 &&
    !emptyBomOnly &&
    !isLineBreak(content[offset - 1]) &&
    !isLineBreak(inserted[0]);
  const needsTrailingSeparator =
    offset < content.length &&
    !isLineBreak(content[offset]) &&
    !isLineBreak(inserted[inserted.length - 1]);
  const leading = needsLeadingSeparator ? newline : "";
  const trailing = needsTrailingSeparator ? newline : "";
  const insertedStart = offset + leading.length;
  return {
    content:
      content.slice(0, offset) +
      leading +
      inserted +
      trailing +
      content.slice(offset),
    insertedStart,
    insertedEnd: insertedStart + inserted.length,
  };
}

export interface NoteTextInsertion {
  position: "append" | "prepend";
  content: string;
  section?: string;
}

export interface NoteTextInsertionResult {
  content: string;
  changed: true;
  insertedChars: number;
  insertedStart: number;
  insertedEnd: number;
}

/** Append or prepend a bounded block without rewriting unrelated Markdown. */
export function insertNoteText(
  original: string,
  input: NoteTextInsertion,
): NoteTextInsertionResult {
  validateBoundedText(
    input.content,
    AGENT_NOTE_OPERATION_LIMITS.insertedContentChars,
    "content",
    { allowNewlines: true },
  );
  if (input.position !== "append" && input.position !== "prepend") {
    return fail("invalid", "The note insertion position is invalid.");
  }
  const newline = detectNewline(original);
  const inserted = normalizeNewlines(input.content, newline);
  let offset: number;
  if (input.section !== undefined) {
    offset = insertionOffsetForSection(
      original,
      input.section,
      input.position,
    );
  } else if (input.position === "append") {
    offset = original.length;
  } else {
    const boundary = inspectFrontmatter(original);
    offset = boundary.hasFrontmatter ? boundary.bodyStart : boundary.bomLength;
  }
  const result = insertAtOffset(original, offset, inserted, newline);
  return {
    ...result,
    changed: true,
    insertedChars: input.content.length,
  };
}

export type AgentPropertyScalar = string | number | boolean | null;
export type AgentPropertyValue = AgentPropertyScalar | AgentPropertyScalar[];
export type AgentPropertyValueType =
  | "string"
  | "number"
  | "boolean"
  | "date"
  | "list"
  | "null";

export interface AgentFrontmatterCodec {
  parse(source: string): unknown;
  stringify(value: Readonly<Record<string, unknown>>): string;
}

export interface AgentPropertyReadResult {
  exists: boolean;
  value?: AgentPropertyValue;
  valueType?: Exclude<AgentPropertyValueType, "date">;
}

export interface AgentPropertySetInput {
  key: string;
  value: AgentPropertyValue;
  valueType?: AgentPropertyValueType;
}

export interface AgentPropertyMutationResult {
  content: string;
  changed: boolean;
}

const RESERVED_PROPERTY_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
  "<<",
]);

function normalizeYamlKey(rawKey: string): string | null {
  const trimmed = rawKey.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replace(/''/gu, "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      return typeof parsed === "string" ? parsed : null;
    } catch {
      return null;
    }
  }
  if (/^[?\[\{]/u.test(trimmed)) return null;
  return trimmed;
}

function topLevelYamlKey(line: string): string | null {
  if (!line || /^[ \t#-]/u.test(line)) return null;
  let singleQuoted = false;
  let doubleQuoted = false;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (doubleQuoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') doubleQuoted = false;
      continue;
    }
    if (singleQuoted) {
      if (character === "'" && line[index + 1] === "'") index += 1;
      else if (character === "'") singleQuoted = false;
      continue;
    }
    if (character === '"') doubleQuoted = true;
    else if (character === "'") singleQuoted = true;
    else if (character === "#") return null;
    else if (character === ":") return normalizeYamlKey(line.slice(0, index));
  }
  return null;
}

function assertUnambiguousFrontmatter(source: string): void {
  const seen = new Set<string>();
  for (const line of source.split(/\r\n|\n|\r/u)) {
    const key = topLevelYamlKey(line);
    if (key === null) continue;
    const normalized = key.toLocaleLowerCase("en-US");
    if (RESERVED_PROPERTY_KEYS.has(normalized)) {
      return fail("invalid", "Markdown frontmatter contains a reserved key.");
    }
    if (seen.has(normalized)) {
      return fail("ambiguous", "Markdown frontmatter contains duplicate keys.");
    }
    seen.add(normalized);
  }
  // Reject YAML aliases, anchors, and explicit tags outside quoted strings.
  const unquoted = source.replace(/"(?:\\.|[^"\\])*"|'(?:''|[^'])*'/gu, "");
  if (/(?:^|[\s:[{,])(?:[*&][A-Za-z0-9_-]+|!!?[A-Za-z])/mu.test(unquoted)) {
    return fail("invalid", "Markdown frontmatter uses unsupported YAML syntax.");
  }
}

function validatePropertyKey(key: string): void {
  validateBoundedText(
    key,
    AGENT_NOTE_OPERATION_LIMITS.propertyKeyChars,
    "property key",
  );
  if (key.trim() !== key || key.includes(":")) {
    return fail("invalid", "The property key is invalid.");
  }
  if (RESERVED_PROPERTY_KEYS.has(key.toLocaleLowerCase("en-US"))) {
    return fail("invalid", "The property key is reserved.");
  }
}

function validIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?$/u.test(value)) {
    return false;
  }
  return Number.isFinite(Date.parse(value));
}

function validatePropertyScalar(value: unknown): asserts value is AgentPropertyScalar {
  if (typeof value === "string") {
    if (
      value.length > AGENT_NOTE_OPERATION_LIMITS.propertyStringChars ||
      value.includes("\0")
    ) {
      return fail("invalid", "The property value exceeds its safe bound.");
    }
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      return fail("invalid", "The property number must be finite.");
    }
    return;
  }
  if (typeof value !== "boolean" && value !== null) {
    return fail("invalid", "The property value type is unsupported.");
  }
}

function validatePropertyValue(
  value: unknown,
  valueType?: AgentPropertyValueType,
): AgentPropertyValue {
  if (Array.isArray(value)) {
    if (
      valueType !== undefined &&
      valueType !== "list"
    ) {
      return fail("invalid", "The property value type does not match its marker.");
    }
    if (value.length > AGENT_NOTE_OPERATION_LIMITS.propertyListItems) {
      return fail("invalid", "The property list exceeds its safe bound.");
    }
    return value.map((entry) => {
      validatePropertyScalar(entry);
      return entry;
    });
  }
  validatePropertyScalar(value);
  if (valueType === "list") {
    return fail("invalid", "The property value type does not match its marker.");
  }
  if (valueType === "date") {
    if (typeof value !== "string" || !validIsoDate(value)) {
      return fail("invalid", "The date property must use an ISO value.");
    }
  } else if (valueType !== undefined) {
    const inferred = inferPropertyValueType(value);
    if (valueType !== inferred) {
      return fail("invalid", "The property value type does not match its marker.");
    }
  }
  return value;
}

function inferPropertyValueType(
  value: AgentPropertyValue,
): Exclude<AgentPropertyValueType, "date"> {
  if (Array.isArray(value)) return "list";
  if (value === null) return "null";
  if (typeof value === "string") return "string";
  if (typeof value === "number") return "number";
  return "boolean";
}

interface ParsedProperties {
  boundary: FrontmatterBoundary;
  properties: Record<string, unknown>;
}

function parseProperties(
  content: string,
  codec: AgentFrontmatterCodec,
): ParsedProperties {
  const boundary = inspectFrontmatter(content);
  if (!boundary.hasFrontmatter) {
    return { boundary, properties: Object.create(null) as Record<string, unknown> };
  }
  const source = content.slice(boundary.yamlStart, boundary.yamlEnd);
  assertUnambiguousFrontmatter(source);
  let parsed: unknown;
  try {
    parsed = codec.parse(source);
  } catch {
    return fail("invalid", "Markdown frontmatter could not be parsed safely.");
  }
  if (parsed === null || parsed === undefined) {
    return { boundary, properties: Object.create(null) as Record<string, unknown> };
  }
  if (typeof parsed !== "object" || Array.isArray(parsed)) {
    return fail("invalid", "Markdown frontmatter must be a property map.");
  }
  const properties: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const key of Reflect.ownKeys(parsed)) {
    if (typeof key !== "string") {
      return fail("invalid", "Markdown frontmatter contains an unsupported key.");
    }
    const descriptor = Object.getOwnPropertyDescriptor(parsed, key);
    if (!descriptor || !("value" in descriptor)) {
      return fail("invalid", "Markdown frontmatter contains an unsupported value.");
    }
    Object.defineProperty(properties, key, {
      value: descriptor.value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return { boundary, properties };
}

function propertyValuesEqual(left: AgentPropertyValue, right: AgentPropertyValue): boolean {
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
  }
  return left === right;
}

function serializeProperties(
  content: string,
  parsed: ParsedProperties,
  codec: AgentFrontmatterCodec,
): string {
  let serialized: string;
  try {
    serialized = codec.stringify(parsed.properties);
  } catch {
    return fail("invalid", "Markdown frontmatter could not be serialized safely.");
  }
  if (typeof serialized !== "string") {
    return fail("invalid", "Markdown frontmatter could not be serialized safely.");
  }
  if (serialized.length > AGENT_NOTE_OPERATION_LIMITS.serializedFrontmatterChars) {
    return fail("invalid", "Markdown frontmatter exceeds its safe bound.");
  }
  const newline = detectNewline(content);
  serialized = normalizeNewlines(serialized, newline)
    .replace(/^(?:\r\n|\r|\n)+/u, "")
    .replace(/(?:\r\n|\r|\n)+$/u, "");
  if (parsed.boundary.hasFrontmatter) {
    return (
      content.slice(0, parsed.boundary.yamlStart) +
      (serialized ? `${serialized}${newline}` : "") +
      content.slice(parsed.boundary.closeStart)
    );
  }
  const bom = content.slice(0, parsed.boundary.bomLength);
  const body = content.slice(parsed.boundary.bomLength);
  return (
    `${bom}---${newline}${serialized}${newline}---` +
    (body ? `${newline}${body}` : "")
  );
}

/** Read one safe typed property. Parser/provider errors are never reflected. */
export function readNoteProperty(
  content: string,
  key: string,
  codec: AgentFrontmatterCodec,
): AgentPropertyReadResult {
  validatePropertyKey(key);
  const parsed = parseProperties(content, codec);
  if (!Object.prototype.hasOwnProperty.call(parsed.properties, key)) {
    return { exists: false };
  }
  const value = validatePropertyValue(parsed.properties[key]);
  return { exists: true, value, valueType: inferPropertyValueType(value) };
}

/** Set one safe typed property while preserving the body byte-for-byte. */
export function setNoteProperty(
  content: string,
  input: AgentPropertySetInput,
  codec: AgentFrontmatterCodec,
): AgentPropertyMutationResult {
  validatePropertyKey(input.key);
  const value = validatePropertyValue(input.value, input.valueType);
  const parsed = parseProperties(content, codec);
  if (Object.prototype.hasOwnProperty.call(parsed.properties, input.key)) {
    const current = validatePropertyValue(parsed.properties[input.key]);
    if (propertyValuesEqual(current, value)) return { content, changed: false };
  }
  Object.defineProperty(parsed.properties, input.key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
  return { content: serializeProperties(content, parsed, codec), changed: true };
}

/** Remove exactly one property. A missing key is a verified no-op. */
export function removeNoteProperty(
  content: string,
  key: string,
  codec: AgentFrontmatterCodec,
): AgentPropertyMutationResult {
  validatePropertyKey(key);
  const parsed = parseProperties(content, codec);
  if (!Object.prototype.hasOwnProperty.call(parsed.properties, key)) {
    return { content, changed: false };
  }
  Reflect.deleteProperty(parsed.properties, key);
  return { content: serializeProperties(content, parsed, codec), changed: true };
}

export type MarkdownTaskMarker = "-" | "+" | "*";

export interface MarkdownTaskReference {
  line: number;
  status: string;
  text: string;
  originalTextHash: string;
  indent: string;
  marker: MarkdownTaskMarker;
  textTruncated?: true;
}

export interface MarkdownTaskListResult {
  tasks: MarkdownTaskReference[];
  truncated: boolean;
}

interface ParsedTaskLine {
  line: SourceLine;
  bom: string;
  sourceForHash: string;
  indent: string;
  marker: MarkdownTaskMarker;
  markerSpacing: string;
  status: string;
  suffix: string;
  gap: string;
  text: string;
}

function isPrintableStatus(status: string): boolean {
  return (
    Array.from(status).length === 1 &&
    !/[\p{Cc}\p{Cs}\r\n]/u.test(status)
  );
}

function validateTaskStatus(status: string): void {
  if (!isPrintableStatus(status)) {
    return fail("invalid", "The Markdown task status is invalid.");
  }
}

function taskLineParts(line: SourceLine): ParsedTaskLine | null {
  const bom = line.number === 1 && line.text.startsWith("\uFEFF") ? "\uFEFF" : "";
  const sourceForHash = bom ? line.text.slice(1) : line.text;
  const match = /^([ \t]*)([-+*])([ \t]+)\[([^\]\r\n])\](.*)$/u.exec(
    sourceForHash,
  );
  if (!match || !isPrintableStatus(match[4])) return null;
  const suffix = match[5];
  if (suffix && !/^[ \t]/u.test(suffix)) return null;
  const gap = /^[ \t]+/u.exec(suffix)?.[0] ?? "";
  return {
    line,
    bom,
    sourceForHash,
    indent: match[1],
    marker: match[2] as MarkdownTaskMarker,
    markerSpacing: match[3],
    status: match[4],
    suffix,
    gap,
    text: suffix.slice(gap.length),
  };
}

function markdownTaskLines(content: string): ParsedTaskLine[] {
  const boundary = inspectFrontmatter(content);
  const tasks: ParsedTaskLine[] = [];
  let fence: FenceState | null = null;
  for (
    const line of scanLines(
      content.slice(boundary.bomLength),
      boundary.bomLength,
    )
  ) {
    if (line.start < boundary.bodyStart) continue;
    const visibleLine = line.text;
    const previousFence = fence;
    fence = nextFenceState(visibleLine, fence);
    if (previousFence || fence) continue;
    const parsed = taskLineParts(line);
    if (parsed) tasks.push(parsed);
  }
  return tasks;
}

function boundedTaskText(text: string): { text: string; textTruncated?: true } {
  if (text.length <= AGENT_NOTE_OPERATION_LIMITS.taskTextChars) return { text };
  return {
    text: text.slice(0, AGENT_NOTE_OPERATION_LIMITS.taskTextChars),
    textTruncated: true,
  };
}

async function taskReference(
  parsed: ParsedTaskLine,
  hasher: AgentTextHasher,
): Promise<MarkdownTaskReference> {
  return {
    line: parsed.line.number,
    status: parsed.status,
    ...boundedTaskText(parsed.text),
    originalTextHash: await hasher(parsed.sourceForHash),
    indent: parsed.indent,
    marker: parsed.marker,
  };
}

export interface MarkdownTaskListOptions {
  status?: string;
  limit?: number;
  hashText?: AgentTextHasher;
}

/** List bounded checkbox-task records outside YAML and fenced code blocks. */
export async function listMarkdownTasks(
  content: string,
  options: MarkdownTaskListOptions = {},
): Promise<MarkdownTaskListResult> {
  if (options.status !== undefined) validateTaskStatus(options.status);
  const limit = options.limit ?? AGENT_NOTE_OPERATION_LIMITS.listedTasks;
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > AGENT_NOTE_OPERATION_LIMITS.listedTasks
  ) {
    return fail("invalid", "The Markdown task limit is invalid.");
  }
  const matches = markdownTaskLines(content).filter(
    (task) => options.status === undefined || task.status === options.status,
  );
  const selected = matches.slice(0, limit);
  const hasher = options.hashText ?? sha256Text;
  return {
    tasks: await Promise.all(selected.map((task) => taskReference(task, hasher))),
    truncated: matches.length > limit,
  };
}

export interface MarkdownTaskCreateInput {
  text: string;
  status?: string;
  section?: string;
  hashText?: AgentTextHasher;
}

export interface MarkdownTaskMutationResult {
  content: string;
  changed: boolean;
  task: MarkdownTaskReference;
}

/** Create one literal Markdown task. Recurrence-like text is never interpreted. */
export async function createMarkdownTask(
  content: string,
  input: MarkdownTaskCreateInput,
): Promise<MarkdownTaskMutationResult> {
  validateBoundedText(
    input.text,
    AGENT_NOTE_OPERATION_LIMITS.taskTextChars,
    "task text",
    { allowEmpty: true },
  );
  const status = input.status ?? " ";
  validateTaskStatus(status);
  const taskSource = `- [${status}]${input.text ? ` ${input.text}` : ""}`;
  const inserted = insertNoteText(content, {
    position: "append",
    content: taskSource,
    section: input.section,
  });
  const line =
    (inserted.content.slice(0, inserted.insertedStart).match(/\r\n|\n|\r/gu)
      ?.length ?? 0) + 1;
  const hasher = input.hashText ?? sha256Text;
  return {
    content: inserted.content,
    changed: true,
    task: {
      line,
      status,
      text: input.text,
      originalTextHash: await hasher(taskSource),
      indent: "",
      marker: "-",
    },
  };
}

export interface MarkdownTaskMutationInput {
  operation: "update" | "toggle" | "set_status";
  line: number;
  originalTextHash: string;
  text?: string;
  status?: string;
  hashText?: AgentTextHasher;
}

/** Mutate only the task at the exact one-based line and original line hash. */
export async function mutateMarkdownTask(
  content: string,
  input: MarkdownTaskMutationInput,
): Promise<MarkdownTaskMutationResult> {
  if (!Number.isInteger(input.line) || input.line < 1) {
    return fail("invalid", "The Markdown task line is invalid.");
  }
  if (!isSha256Hash(input.originalTextHash)) {
    return fail("invalid", "The Markdown task reference hash is invalid.");
  }
  if (!(["update", "toggle", "set_status"] as const).includes(input.operation)) {
    return fail("invalid", "The Markdown task operation is invalid.");
  }
  const taskLines = markdownTaskLines(content);
  const parsed = taskLines.find(
    (candidate) => candidate.line.number === input.line,
  );
  if (!parsed) {
    return fail("stale", "The Markdown task reference is stale.");
  }
  const hasher = input.hashText ?? sha256Text;
  const observedHash = await hasher(parsed.sourceForHash);
  if (observedHash.toLocaleLowerCase("en-US") !== input.originalTextHash.toLocaleLowerCase("en-US")) {
    return fail("stale", "The Markdown task reference is stale.");
  }
  if (
    taskLines.some(
      (candidate) =>
        candidate !== parsed && candidate.sourceForHash === parsed.sourceForHash,
    )
  ) {
    return fail("ambiguous", "The Markdown task reference is ambiguous.");
  }

  let status = parsed.status;
  let suffix = parsed.suffix;
  if (input.operation === "update") {
    if (input.text === undefined) {
      return fail("invalid", "The Markdown task update text is required.");
    }
    validateBoundedText(
      input.text,
      AGENT_NOTE_OPERATION_LIMITS.taskTextChars,
      "task text",
      { allowEmpty: true },
    );
    suffix = input.text ? `${parsed.gap || " "}${input.text}` : "";
  } else if (input.operation === "set_status") {
    if (input.status === undefined) {
      return fail("invalid", "The Markdown task status is required.");
    }
    validateTaskStatus(input.status);
    status = input.status;
  } else {
    status = parsed.status === " " ? "x" : " ";
  }

  const sourceForHash = `${parsed.indent}${parsed.marker}${parsed.markerSpacing}[${status}]${suffix}`;
  const replacement = `${parsed.bom}${sourceForHash}`;
  const changed = replacement !== parsed.line.text;
  const nextContent = changed
    ? content.slice(0, parsed.line.start) + replacement + content.slice(parsed.line.end)
    : content;
  const gap = /^[ \t]+/u.exec(suffix)?.[0] ?? "";
  return {
    content: nextContent,
    changed,
    task: {
      line: input.line,
      status,
      ...boundedTaskText(suffix.slice(gap.length)),
      originalTextHash: await hasher(sourceForHash),
      indent: parsed.indent,
      marker: parsed.marker,
    },
  };
}
