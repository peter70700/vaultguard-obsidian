/**
 * Deterministic template preparation for Agent Bridge commands.
 *
 * The service has no filesystem or Obsidian authority. It reads only through a
 * narrow provider, verifies that every source is inside the configured core
 * Templates folder or the exact VaultGuard allow-list, and prepares content for
 * the bridge-owned permission/confirmation/stale-check/write pipeline.
 */

export const AGENT_TEMPLATE_DEFAULT_LIMIT = 50;
export const AGENT_TEMPLATE_MAX_LIMIT = 200;
export const AGENT_TEMPLATE_DEFAULT_MAX_BYTES = 65_536;
export const AGENT_TEMPLATE_MAX_BYTES = 262_144;
export const AGENT_TEMPLATE_MAX_UNIQUE_ATTEMPTS = 1_000;

export const AGENT_TEMPLATE_PLACEHOLDERS = [
  "date",
  "time",
  "title",
  "destination",
] as const;

export type AgentTemplatePlaceholder = typeof AGENT_TEMPLATE_PLACEHOLDERS[number];
export type AgentTemplateSourceBoundary =
  | "core-templates"
  | "vaultguard-allow-list"
  | "core-templates-and-allow-list";

export interface AgentTemplateDescriptor {
  path: string;
  name: string;
  available: boolean;
  supportedPlaceholders: readonly AgentTemplatePlaceholder[];
  sourceBoundary: AgentTemplateSourceBoundary;
}

export interface AgentTemplateListResult {
  templates: readonly AgentTemplateDescriptor[];
  truncated: boolean;
}

export interface AgentTemplateTextRead {
  content: string;
  /** True when the provider stopped before the complete template. */
  truncated?: boolean;
}

type MaybePromise<T> = T | Promise<T>;

export interface AgentTemplateProvider {
  /** Null means the Obsidian core Templates provider is unavailable. */
  getCoreTemplateFolder(): MaybePromise<string | null>;
  /** Paths discovered by the core Templates provider. */
  listCoreTemplatePaths(): MaybePromise<readonly string[]>;
  /** Exact vault-relative paths explicitly approved in VaultGuard settings. */
  listAllowlistedTemplatePaths(): MaybePromise<readonly string[]>;
  pathExists(path: string): MaybePromise<boolean>;
  readText(path: string, maxBytes: number): MaybePromise<AgentTemplateTextRead>;
}

export interface AgentTemplateReadResult {
  descriptor: AgentTemplateDescriptor;
  content: string;
  byteLength: number;
  truncated: boolean;
}

export interface AgentTemplatePreviewInput {
  templatePath: string;
  destination?: string;
  variables?: Readonly<Record<string, string>>;
  maxBytes?: number;
  now?: Date | string;
}

export interface AgentTemplatePreviewResult {
  templatePath: string;
  destination: string | null;
  content: string;
  byteLength: number;
  truncated: boolean;
}

export interface AgentTemplatePrepareInsertInput {
  templatePath: string;
  path: string;
  position?: "append" | "prepend";
  section?: string;
  variables?: Readonly<Record<string, string>>;
  expectedContentHash: string;
  now?: Date | string;
}

export interface AgentTemplatePreparedInsert {
  templatePath: string;
  path: string;
  position: "append" | "prepend";
  section?: string;
  content: string;
  byteLength: number;
  expectedContentHash: string;
}

export interface AgentTemplatePrepareCreateInput {
  templatePath: string;
  path?: string;
  uniqueName?: string;
  variables?: Readonly<Record<string, string>>;
  now?: Date | string;
}

export interface AgentTemplatePreparedCreate {
  templatePath: string;
  path: string;
  content: string;
  byteLength: number;
  uniquePath: boolean;
}

export interface AgentTemplateRenderContext {
  destination?: string;
  variables?: Readonly<Record<string, string>>;
  now?: Date | string;
}

interface TrustedTemplateEntry {
  path: string;
  sources: Set<"core" | "allow-list">;
}

function invalid(message: string): never {
  throw new Error(`Invalid template request: ${message}`);
}

function normalizeVaultRelativePath(path: string, label: string): string {
  if (typeof path !== "string" || path.length === 0 || path.length > 1_024) {
    return invalid(`${label} must be a non-empty vault-relative path.`);
  }
  if (path.trim() !== path || path.includes("\0")) {
    return invalid(`${label} is not a canonical vault-relative path.`);
  }

  const normalized = path.replace(/\\/g, "/");
  if (
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized) ||
    normalized.startsWith("//")
  ) {
    return invalid(`${label} must be vault-relative.`);
  }
  const segments = normalized.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return invalid(`${label} contains an unsafe segment.`);
  }
  return normalized;
}

function normalizeMarkdownPath(path: string, label: string): string {
  const normalized = normalizeVaultRelativePath(path, label);
  if (!normalized.toLowerCase().endsWith(".md")) {
    return invalid(`${label} must identify a Markdown file.`);
  }
  return normalized;
}

function normalizeCoreFolder(folder: string): string {
  if (folder === "") return "";
  return normalizeVaultRelativePath(folder, "core template folder").replace(/\/$/, "");
}

function isInsideFolder(path: string, folder: string): boolean {
  return folder === "" || path.startsWith(`${folder}/`);
}

function descriptorBoundary(entry: TrustedTemplateEntry): AgentTemplateSourceBoundary {
  if (entry.sources.size === 2) return "core-templates-and-allow-list";
  return entry.sources.has("core") ? "core-templates" : "vaultguard-allow-list";
}

function templateName(path: string): string {
  const fileName = path.slice(path.lastIndexOf("/") + 1);
  return fileName.slice(0, -3);
}

function validatedLimit(limit: number | undefined): number {
  if (limit === undefined) return AGENT_TEMPLATE_DEFAULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > AGENT_TEMPLATE_MAX_LIMIT) {
    return invalid(`limit must be an integer from 1 to ${AGENT_TEMPLATE_MAX_LIMIT}.`);
  }
  return limit;
}

function validatedMaxBytes(maxBytes: number | undefined): number {
  if (maxBytes === undefined) return AGENT_TEMPLATE_DEFAULT_MAX_BYTES;
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > AGENT_TEMPLATE_MAX_BYTES) {
    return invalid(`maxBytes must be an integer from 1 to ${AGENT_TEMPLATE_MAX_BYTES}.`);
  }
  return maxBytes;
}

function truncateUtf8(content: string, maxBytes: number): {
  content: string;
  byteLength: number;
  truncated: boolean;
} {
  const encoded = new TextEncoder().encode(content);
  if (encoded.byteLength <= maxBytes) {
    return { content, byteLength: encoded.byteLength, truncated: false };
  }

  let end = maxBytes;
  while (end > 0 && (encoded[end] & 0xc0) === 0x80) end -= 1;
  return {
    content: new TextDecoder().decode(encoded.slice(0, end)),
    byteLength: encoded.byteLength,
    truncated: true,
  };
}

function validatedNow(value: Date | string | undefined): Date {
  const date = value instanceof Date
    ? new Date(value.getTime())
    : value === undefined
      ? new Date()
      : new Date(value);
  if (!Number.isFinite(date.getTime())) return invalid("now must be a valid timestamp.");
  return date;
}

function titleFromDestination(destination: string | undefined): string {
  if (destination === undefined) return "";
  const name = destination.slice(destination.lastIndexOf("/") + 1);
  return name.toLowerCase().endsWith(".md") ? name.slice(0, -3) : name;
}

function validatedVariables(
  variables: Readonly<Record<string, string>> | undefined,
): Partial<Record<AgentTemplatePlaceholder, string>> {
  if (variables === undefined) return {};
  if (typeof variables !== "object" || variables === null || Array.isArray(variables)) {
    return invalid("variables must be an object.");
  }
  const entries = Object.entries(variables);
  if (entries.length > 16) return invalid("variables may contain at most 16 entries.");

  const result: Partial<Record<AgentTemplatePlaceholder, string>> = {};
  for (const [key, value] of entries) {
    if (!(AGENT_TEMPLATE_PLACEHOLDERS as readonly string[]).includes(key)) {
      return invalid(`unsupported template variable ${JSON.stringify(key)}.`);
    }
    if (
      typeof value !== "string" ||
      value.length > 1_000 ||
      value.includes("\0") ||
      value.includes("{{") ||
      value.includes("}}") ||
      value.includes("<%") ||
      value.includes("%>")
    ) {
      return invalid(`template variable ${JSON.stringify(key)} is invalid.`);
    }
    result[key as AgentTemplatePlaceholder] = value;
  }
  return result;
}

/**
 * Literal, single-pass substitution. It intentionally rejects Templater blocks,
 * unknown mustache tokens, unmatched delimiters, and never recursively expands
 * replacement values.
 */
export function renderAgentTemplate(
  source: string,
  context: AgentTemplateRenderContext = {},
): string {
  if (typeof source !== "string") return invalid("template content must be text.");
  if (new TextEncoder().encode(source).byteLength > AGENT_TEMPLATE_MAX_BYTES) {
    return invalid(`template content exceeds ${AGENT_TEMPLATE_MAX_BYTES} bytes.`);
  }
  if (source.includes("<%") || source.includes("%>")) {
    return invalid("executable template blocks are not supported.");
  }

  const destination = context.destination === undefined
    ? undefined
    : normalizeMarkdownPath(context.destination, "destination");
  const variables = validatedVariables(context.variables);
  const now = validatedNow(context.now);
  const values: Record<AgentTemplatePlaceholder, string> = {
    date: variables.date ?? now.toISOString().slice(0, 10),
    time: variables.time ?? now.toISOString().slice(11, 16),
    title: variables.title ?? titleFromDestination(destination),
    destination: variables.destination ?? destination ?? "",
  };

  const tokens = /{{\s*([^{}]+?)\s*}}/g;
  const unmatched = source.replace(tokens, "");
  if (unmatched.includes("{{") || unmatched.includes("}}")) {
    return invalid("template contains an unmatched placeholder delimiter.");
  }
  const rendered = source.replace(tokens, (_whole, rawName: string) => {
    const name = rawName.trim();
    if (!(AGENT_TEMPLATE_PLACEHOLDERS as readonly string[]).includes(name)) {
      return invalid(`unsupported template placeholder ${JSON.stringify(name)}.`);
    }
    return values[name as AgentTemplatePlaceholder];
  });

  if (new TextEncoder().encode(rendered).byteLength > AGENT_TEMPLATE_MAX_BYTES) {
    return invalid(`rendered template exceeds ${AGENT_TEMPLATE_MAX_BYTES} bytes.`);
  }
  return rendered;
}

function validatedExpectedHash(hash: string): string {
  if (typeof hash !== "string" || !/^[a-fA-F0-9]{64}$/.test(hash)) {
    return invalid("expectedContentHash must be a SHA-256 hex digest.");
  }
  return hash.toLowerCase();
}

function validatedSection(section: string | undefined): string | undefined {
  if (section === undefined) return undefined;
  if (
    typeof section !== "string" ||
    section.length === 0 ||
    section.length > 300 ||
    section.includes("\0")
  ) {
    return invalid("section must contain between 1 and 300 characters.");
  }
  return section;
}

function uniqueBasePath(value: string): string {
  const normalized = normalizeVaultRelativePath(value, "uniqueName");
  const withExtension = normalized.toLowerCase().endsWith(".md")
    ? normalized
    : `${normalized}.md`;
  return normalizeMarkdownPath(withExtension, "uniqueName");
}

export class AgentTemplateService {
  constructor(private readonly provider: AgentTemplateProvider) {}

  private async trustedEntries(): Promise<Map<string, TrustedTemplateEntry>> {
    const result = new Map<string, TrustedTemplateEntry>();
    const add = (path: string, source: "core" | "allow-list"): void => {
      const existing = result.get(path);
      if (existing) existing.sources.add(source);
      else result.set(path, { path, sources: new Set([source]) });
    };

    const coreFolderRaw = await this.provider.getCoreTemplateFolder();
    if (coreFolderRaw !== null) {
      const coreFolder = normalizeCoreFolder(coreFolderRaw);
      for (const rawPath of await this.provider.listCoreTemplatePaths()) {
        try {
          const path = normalizeMarkdownPath(rawPath, "core template path");
          if (isInsideFolder(path, coreFolder)) add(path, "core");
        } catch {
          // Malformed or out-of-bound provider entries are not trusted.
        }
      }
    }

    for (const rawPath of await this.provider.listAllowlistedTemplatePaths()) {
      try {
        add(normalizeMarkdownPath(rawPath, "allow-listed template path"), "allow-list");
      } catch {
        // Malformed allow-list entries fail closed and do not break other entries.
      }
    }
    return result;
  }

  private async descriptor(entry: TrustedTemplateEntry): Promise<AgentTemplateDescriptor> {
    let available: boolean;
    try {
      available = await this.provider.pathExists(entry.path);
    } catch {
      available = false;
    }
    return {
      path: entry.path,
      name: templateName(entry.path),
      available,
      supportedPlaceholders: AGENT_TEMPLATE_PLACEHOLDERS,
      sourceBoundary: descriptorBoundary(entry),
    };
  }

  private async requireTrusted(templatePath: string): Promise<AgentTemplateDescriptor> {
    const normalized = normalizeMarkdownPath(templatePath, "templatePath");
    const entry = (await this.trustedEntries()).get(normalized);
    if (entry === undefined) throw new Error("Template is outside the trusted template boundary.");
    const descriptor = await this.descriptor(entry);
    if (!descriptor.available) throw new Error("Trusted template is unavailable.");
    return descriptor;
  }

  private async readCompleteAndRender(
    templatePath: string,
    context: AgentTemplateRenderContext,
  ): Promise<{ templatePath: string; content: string; byteLength: number }> {
    const descriptor = await this.requireTrusted(templatePath);
    let read: AgentTemplateTextRead;
    try {
      read = await this.provider.readText(descriptor.path, AGENT_TEMPLATE_MAX_BYTES);
    } catch {
      throw new Error("Trusted template could not be read.");
    }
    if (!read || typeof read.content !== "string") {
      throw new Error("Trusted template provider returned an invalid result.");
    }
    const sourceBytes = new TextEncoder().encode(read.content).byteLength;
    if (read.truncated === true || sourceBytes > AGENT_TEMPLATE_MAX_BYTES) {
      throw new Error("Trusted template exceeds the supported size bound.");
    }
    const content = renderAgentTemplate(read.content, context);
    return {
      templatePath: descriptor.path,
      content,
      byteLength: new TextEncoder().encode(content).byteLength,
    };
  }

  async list(limit?: number): Promise<AgentTemplateListResult> {
    const boundedLimit = validatedLimit(limit);
    const entries = Array.from((await this.trustedEntries()).values()).sort((left, right) =>
      left.path.localeCompare(right.path),
    );
    const descriptors: AgentTemplateDescriptor[] = [];
    for (const entry of entries.slice(0, boundedLimit)) {
      descriptors.push(await this.descriptor(entry));
    }
    return { templates: descriptors, truncated: entries.length > boundedLimit };
  }

  async read(templatePath: string, maxBytes?: number): Promise<AgentTemplateReadResult> {
    const descriptor = await this.requireTrusted(templatePath);
    const boundedMax = validatedMaxBytes(maxBytes);
    let read: AgentTemplateTextRead;
    try {
      read = await this.provider.readText(descriptor.path, boundedMax);
    } catch {
      throw new Error("Trusted template could not be read.");
    }
    if (!read || typeof read.content !== "string") {
      throw new Error("Trusted template provider returned an invalid result.");
    }
    const bounded = truncateUtf8(read.content, boundedMax);
    return {
      descriptor,
      content: bounded.content,
      byteLength: bounded.byteLength,
      truncated: bounded.truncated || read.truncated === true,
    };
  }

  async preview(input: AgentTemplatePreviewInput): Promise<AgentTemplatePreviewResult> {
    const destination = input.destination === undefined
      ? undefined
      : normalizeMarkdownPath(input.destination, "destination");
    const rendered = await this.readCompleteAndRender(input.templatePath, {
      destination,
      variables: input.variables,
      now: input.now,
    });
    const bounded = truncateUtf8(rendered.content, validatedMaxBytes(input.maxBytes));
    return {
      templatePath: rendered.templatePath,
      destination: destination ?? null,
      content: bounded.content,
      byteLength: bounded.byteLength,
      truncated: bounded.truncated,
    };
  }

  async prepareInsert(input: AgentTemplatePrepareInsertInput): Promise<AgentTemplatePreparedInsert> {
    const path = normalizeMarkdownPath(input.path, "path");
    const position = input.position ?? "append";
    if (position !== "append" && position !== "prepend") {
      return invalid("position must be append or prepend.");
    }
    const rendered = await this.readCompleteAndRender(input.templatePath, {
      destination: path,
      variables: input.variables,
      now: input.now,
    });
    const section = validatedSection(input.section);
    return {
      templatePath: rendered.templatePath,
      path,
      position,
      ...(section === undefined ? {} : { section }),
      content: rendered.content,
      byteLength: rendered.byteLength,
      expectedContentHash: validatedExpectedHash(input.expectedContentHash),
    };
  }

  async resolveUniquePath(uniqueName: string): Promise<string> {
    const basePath = uniqueBasePath(uniqueName);
    if (!(await this.provider.pathExists(basePath))) return basePath;

    const stem = basePath.slice(0, -3);
    for (let suffix = 2; suffix <= AGENT_TEMPLATE_MAX_UNIQUE_ATTEMPTS; suffix += 1) {
      const candidate = `${stem} ${suffix}.md`;
      if (!(await this.provider.pathExists(candidate))) return candidate;
    }
    throw new Error("No unique destination is available within the bounded search.");
  }

  async prepareCreate(input: AgentTemplatePrepareCreateInput): Promise<AgentTemplatePreparedCreate> {
    if ((input.path === undefined) === (input.uniqueName === undefined)) {
      return invalid("create requires exactly one of path or uniqueName.");
    }

    const uniquePath = input.uniqueName !== undefined;
    const path = uniquePath
      ? await this.resolveUniquePath(input.uniqueName as string)
      : normalizeMarkdownPath(input.path as string, "path");
    if (!uniquePath && await this.provider.pathExists(path)) {
      throw new Error("Template creation refuses to overwrite an existing note.");
    }

    const rendered = await this.readCompleteAndRender(input.templatePath, {
      destination: path,
      variables: input.variables,
      now: input.now,
    });
    return {
      templatePath: rendered.templatePath,
      path,
      content: rendered.content,
      byteLength: rendered.byteLength,
      uniquePath,
    };
  }
}
