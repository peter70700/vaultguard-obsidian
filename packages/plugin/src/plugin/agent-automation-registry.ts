/**
 * Governed automation policy and execution planning for Agent Bridge.
 *
 * This module deliberately knows nothing about Obsidian's private command
 * manager or the Agent Bridge lease model. It accepts a narrow, injected
 * command runtime and returns alias-only descriptors/receipts. The bridge owns
 * lease, scope, exclusion, permission, confirmation, and audit enforcement;
 * this service owns registry normalization, dependency/context validation,
 * single invocation, and observable postcondition verification.
 *
 * Governance is not a sandbox: once an approved third-party command runs, that
 * plugin executes with its own Obsidian authority. For that reason unsafe
 * command classes are hard-denied and every observable side effect is upgraded
 * to an always-confirmed write risk.
 */

export const AUTOMATION_REGISTRY_SCHEMA_VERSION = 1 as const;

const MAX_POLICIES = 64;
const MAX_ALIAS_LENGTH = 64;
const MAX_DESCRIPTION_LENGTH = 240;
const MAX_COMMAND_ID_LENGTH = 256;
const MAX_REVISION_LENGTH = 128;
const MAX_ARGUMENTS = 12;
const MAX_ENUM_VALUES = 32;
const MAX_ALLOWED_PATHS = 16;
const MAX_IDEMPOTENCY_ENTRIES = 128;
const MAX_ALIAS_RESULTS = 100;
const DEFAULT_ALIAS_RESULTS = 50;
const DEFAULT_POSTCONDITION_ATTEMPTS = 5;
const DEFAULT_POSTCONDITION_DELAY_MS = 50;

const SAFE_ALIAS = /^[a-z][a-z0-9-]{0,63}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_COMMAND_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;
const SAFE_ARGUMENT_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const SAFE_VERSION = /^v?\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?$/;

export type AutomationContextRequirement = "none" | "active_file" | "markdown_file";
export type AutomationRisk = "read" | "write" | "destructive" | "network" | "unknown";
export type AutomationConfirmationPolicy = "lease" | "always";
export type AutomationArgumentType = "string" | "number" | "boolean" | "enum" | "path";
export type AutomationRuntimeSource = "core" | "community" | "unknown";
export type AutomationPlatform = "desktop" | "mobile";

export type AutomationPolicyErrorCode =
  | "denied"
  | "invalid"
  | "stale"
  | "unavailable"
  | "failed";

export class AutomationPolicyError extends Error {
  readonly code: AutomationPolicyErrorCode;

  constructor(code: AutomationPolicyErrorCode, message: string) {
    super(message);
    this.name = "AutomationPolicyError";
    this.code = code;
  }
}

export interface AutomationArgumentDefinition {
  name: string;
  type: AutomationArgumentType;
  required: boolean;
  enumValues?: string[];
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

export type AutomationPostcondition =
  | {
      kind: "file_exists";
      pathArgument?: string;
      expected: boolean;
    }
  | {
      kind: "file_changed";
      pathArgument?: string;
    }
  | {
      kind: "active_file_changed";
    };

export interface AutomationPolicyEntry {
  id: string;
  alias: string;
  description: string;
  enabled: boolean;
  revision: string;
  /** Private. Never include this field in agent-visible descriptors or receipts. */
  commandId: string;
  /** Private dependency constraint. Never include it in agent-visible output. */
  pluginId?: string;
  minimumPluginVersion?: string;
  maximumPluginVersionExclusive?: string;
  minimumObsidianVersion?: string;
  /** Private authorization policy. The bridge rechecks every resolved path. */
  allowedPaths: string[];
  context: AutomationContextRequirement;
  risk: AutomationRisk;
  confirmation: AutomationConfirmationPolicy;
  arguments: AutomationArgumentDefinition[];
  postcondition: AutomationPostcondition;
}

export interface AutomationRegistrySettings {
  schemaVersion: typeof AUTOMATION_REGISTRY_SCHEMA_VERSION;
  enabled: boolean;
  entries: AutomationPolicyEntry[];
}

export const DEFAULT_AUTOMATION_REGISTRY: AutomationRegistrySettings = Object.freeze({
  schemaVersion: AUTOMATION_REGISTRY_SCHEMA_VERSION,
  enabled: false,
  entries: Object.freeze([]) as unknown as AutomationPolicyEntry[],
});

export interface AutomationRuntimeCommand {
  id: string;
  name: string;
  source: AutomationRuntimeSource;
  pluginId?: string;
  pluginVersion?: string;
  pluginEnabled?: boolean;
}

export interface AutomationRuntimeContext {
  platform: AutomationPlatform;
  obsidianVersion?: string;
  activeFilePath?: string | null;
}

export interface AutomationCommandRuntime {
  isAvailable(): boolean;
  getContext(): AutomationRuntimeContext;
  /** Human-only discovery surface. It must never be returned by Agent Bridge. */
  list(): AutomationRuntimeCommand[];
  find(commandId: string): AutomationRuntimeCommand | null;
  execute(
    commandId: string,
    expected: AutomationRuntimeCommand | undefined,
    expectedActiveFilePath: string,
  ): Promise<boolean> | boolean;
}

export interface AutomationFileObservation {
  exists: boolean;
  /** A content/version fingerprint. Never included in the public receipt. */
  fingerprint?: string;
}

export interface AutomationAliasArgumentSummary {
  name: string;
  type: AutomationArgumentType;
  required: boolean;
  enumValues?: string[];
}

export interface AutomationAliasSummary {
  alias: string;
  description: string;
  risk: AutomationRisk;
  requiresConfirmation: boolean;
  pathRequired: boolean;
  arguments: AutomationAliasArgumentSummary[];
  available: true;
}

export interface AutomationAliasListResult {
  aliases: AutomationAliasSummary[];
  truncated: boolean;
}

export interface AutomationRunInput {
  alias: string;
  /**
   * Optional on the model's initial request. A paused confirmation records the
   * internally observed revision and passes it back during revalidation.
   */
  revision?: string;
  path?: string;
  arguments?: Record<string, unknown>;
  idempotencyKey?: string;
}

export interface AutomationExecutionPlan {
  alias: string;
  revision: string;
  risk: AutomationRisk;
  requiresConfirmation: boolean;
  targetPaths: string[];
  arguments: Record<string, string | number | boolean>;
  idempotencyKey?: string;
  postcondition: AutomationPostcondition;
  postconditionPath?: string;
  /** Private execution fields. Never serialize a plan into model-visible output. */
  command: AutomationRuntimeCommand;
  commandId: string;
  policyFingerprint: string;
  requestFingerprint: string;
  requestPath?: string;
  /** Ambient active-file target authorized when this plan was created. */
  activeFilePath: string;
}

export interface AutomationPostconditionReceipt {
  kind: AutomationPostcondition["kind"];
  path?: string;
  passed: boolean;
}

export interface AutomationExecutionReceipt {
  alias: string;
  risk: AutomationRisk;
  /** True only when this call invoked the runtime, never for an idempotent replay. */
  invoked: boolean;
  /** Only the policy's declared bounded postcondition was checked. */
  declaredPostconditionVerified: boolean;
  verificationScope: "declared_postcondition_only";
  idempotentReplay: boolean;
  postcondition: AutomationPostconditionReceipt;
}

export interface AgentAutomationRegistryDeps {
  getSettings(): unknown;
  runtime: AutomationCommandRuntime;
  /** At-rest-safe file observation supplied by bridge wiring. */
  observeFile?: (path: string) => Promise<AutomationFileObservation>;
  postconditionAttempts?: number;
  postconditionDelayMs?: number;
  delay?: (milliseconds: number) => Promise<void>;
}

export type ForbiddenAutomationClass =
  | "invalid-command-reference"
  | "arbitrary-code"
  | "plugin-lifecycle"
  | "git-mutation"
  | "publish"
  | "sync-restore"
  | "cursor-or-hotkey-automation";

const ARBITRARY_CODE_PLUGIN_IDS = new Set([
  "execute-code",
  "obsidian-shellcommands",
  "shell-commands",
  "terminal",
  "templater-obsidian",
]);

const GIT_PLUGIN_IDS = new Set(["obsidian-git"]);

function commandTokens(value: string): string[] {
  return value.toLocaleLowerCase().split(/[:._/@-]+/).filter(Boolean);
}

/**
 * Static, non-overridable deny classification for command categories excluded
 * by the feature specification. The result is structural and safe to audit;
 * callers must not echo the backing command id in an error.
 */
export function classifyForbiddenAutomationCommand(input: {
  commandId: string;
  pluginId?: string;
}): ForbiddenAutomationClass | null {
  const commandId = String(input.commandId ?? "").trim();
  const pluginId = String(input.pluginId ?? "").trim().toLocaleLowerCase();
  if (
    !commandId ||
    commandId.length > MAX_COMMAND_ID_LENGTH ||
    !SAFE_COMMAND_ID.test(commandId)
  ) {
    return "invalid-command-reference";
  }

  const lower = commandId.toLocaleLowerCase();
  const tokens = new Set(commandTokens(lower));
  if (
    ARBITRARY_CODE_PLUGIN_IDS.has(pluginId) ||
    tokens.has("shell") ||
    tokens.has("terminal") ||
    tokens.has("eval") ||
    tokens.has("javascript") ||
    (tokens.has("execute") && tokens.has("code")) ||
    (tokens.has("run") && tokens.has("code"))
  ) {
    return "arbitrary-code";
  }

  if (
    lower === "app:reload" ||
    tokens.has("uninstall") ||
    tokens.has("disable") ||
    tokens.has("enable") ||
    (tokens.has("plugin") &&
      (tokens.has("install") || tokens.has("reload") || tokens.has("update"))) ||
    (tokens.has("plugins") &&
      (tokens.has("install") ||
        tokens.has("reload") ||
        tokens.has("update") ||
        tokens.has("disable") ||
        tokens.has("enable")))
  ) {
    return "plugin-lifecycle";
  }

  if (GIT_PLUGIN_IDS.has(pluginId) || tokens.has("git")) return "git-mutation";
  if (tokens.has("publish")) return "publish";
  if (
    tokens.has("sync") &&
    (tokens.has("restore") || tokens.has("rollback") || tokens.has("version"))
  ) {
    return "sync-restore";
  }
  if (
    tokens.has("cursor") ||
    tokens.has("hotkey") ||
    tokens.has("hotkeys") ||
    tokens.has("selection")
  ) {
    return "cursor-or-hotkey-automation";
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function cleanText(value: unknown, maximum: number): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
  if (!cleaned || cleaned.length > maximum) return null;
  return cleaned;
}

function cleanOptionalVersion(value: unknown): string | undefined | null {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length <= 64 && SAFE_VERSION.test(trimmed) ? trimmed : null;
}

function normalizePolicyScope(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let scope = value.trim();
  if (!scope || scope.length > 512 || /[\\\u0000]/.test(scope)) return null;
  if (/^[A-Za-z]:/.test(scope) || /^[a-z][a-z0-9+.-]*:\/\//i.test(scope)) return null;
  scope = scope.replace(/^\/+/, "");
  const segments = scope.split("/").filter(Boolean);
  if (segments.length === 0) return "/**";
  for (const segment of segments) {
    const lower = segment.toLocaleLowerCase();
    if (
      segment === "." ||
      segment === ".." ||
      segment.startsWith(".") ||
      lower.includes("%2e")
    ) {
      return null;
    }
  }
  return `/${segments.join("/")}`;
}

/** Narrow vault-relative path parsing before the bridge applies canonical policy. */
export function normalizeAutomationVaultPath(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let path = value.trim();
  if (!path || path.length > 1024 || /[\\\u0000]/.test(path)) return null;
  if (/^[A-Za-z]:/.test(path) || /^[a-z][a-z0-9+.-]*:\/\//i.test(path)) return null;
  path = path.replace(/^\/+/, "");
  const segments = path.split("/").filter(Boolean);
  if (segments.length === 0) return null;
  for (const segment of segments) {
    const lower = segment.toLocaleLowerCase();
    if (
      segment === "." ||
      segment === ".." ||
      segment.startsWith(".") ||
      lower.includes("%2e")
    ) {
      return null;
    }
  }
  return segments.join("/");
}

function matchesGlob(path: string, glob: string): boolean {
  const candidate = `/${path}`;
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === "*" && glob[index + 1] === "*") {
      pattern += ".*";
      index += 1;
    } else if (char === "*") {
      pattern += "[^/]*";
    } else if (char === "?") {
      pattern += "[^/]";
    } else {
      pattern += char.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  pattern += "$";
  try {
    return new RegExp(pattern).test(candidate);
  } catch {
    return false;
  }
}

function normalizeArguments(value: unknown): AutomationArgumentDefinition[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_ARGUMENTS) return null;
  const output: AutomationArgumentDefinition[] = [];
  const names = new Set<string>();
  for (const raw of value) {
    if (!isRecord(raw)) return null;
    const name = cleanText(raw.name, 64);
    if (!name || !SAFE_ARGUMENT_NAME.test(name) || names.has(name)) return null;
    const type = raw.type;
    if (
      type !== "string" &&
      type !== "number" &&
      type !== "boolean" &&
      type !== "enum" &&
      type !== "path"
    ) {
      return null;
    }
    const definition: AutomationArgumentDefinition = {
      name,
      type,
      required: raw.required === true,
    };
    if (type === "string" || type === "path") {
      const requested = typeof raw.maxLength === "number" ? raw.maxLength : 512;
      definition.maxLength = Math.max(1, Math.min(1024, Math.floor(requested)));
    }
    if (type === "number") {
      if (raw.minimum !== undefined && (typeof raw.minimum !== "number" || !Number.isFinite(raw.minimum))) {
        return null;
      }
      if (raw.maximum !== undefined && (typeof raw.maximum !== "number" || !Number.isFinite(raw.maximum))) {
        return null;
      }
      const minimum = typeof raw.minimum === "number" ? raw.minimum : undefined;
      const maximum = typeof raw.maximum === "number" ? raw.maximum : undefined;
      if (minimum !== undefined && maximum !== undefined && minimum > maximum) return null;
      definition.minimum = minimum;
      definition.maximum = maximum;
    }
    if (type === "enum") {
      if (!Array.isArray(raw.enumValues) || raw.enumValues.length < 1 || raw.enumValues.length > MAX_ENUM_VALUES) {
        return null;
      }
      const enumValues: string[] = [];
      for (const candidate of raw.enumValues) {
        const item = cleanText(candidate, 128);
        if (!item || enumValues.includes(item)) return null;
        enumValues.push(item);
      }
      definition.enumValues = enumValues;
    }
    names.add(name);
    output.push(definition);
  }
  return output;
}

function normalizePostcondition(
  value: unknown,
  argumentsList: AutomationArgumentDefinition[],
): AutomationPostcondition | null {
  if (!isRecord(value)) return null;
  if (value.kind === "active_file_changed") return { kind: "active_file_changed" };
  if (value.kind !== "file_exists" && value.kind !== "file_changed") return null;
  let pathArgument: string | undefined;
  if (value.pathArgument !== undefined) {
    const candidate = cleanText(value.pathArgument, 64);
    if (!candidate || !SAFE_ARGUMENT_NAME.test(candidate)) return null;
    const definition = argumentsList.find((item) => item.name === candidate);
    if (!definition || definition.type !== "path") return null;
    pathArgument = candidate;
  }
  if (value.kind === "file_exists") {
    return {
      kind: "file_exists",
      pathArgument,
      expected: value.expected !== false,
    };
  }
  return { kind: "file_changed", pathArgument };
}

function normalizeRisk(
  value: unknown,
  postcondition: AutomationPostcondition,
): AutomationRisk | null {
  if (
    value !== "read" &&
    value !== "write" &&
    value !== "destructive" &&
    value !== "network" &&
    value !== "unknown"
  ) {
    return null;
  }
  // A declared file mutation cannot remain classified as a read merely because
  // persisted settings say so. Upgrade rather than trust an optimistic label.
  if (value === "read" && postcondition.kind !== "active_file_changed") return "write";
  return value;
}

function normalizePolicy(value: unknown): AutomationPolicyEntry | null {
  if (!isRecord(value)) return null;
  const alias = cleanText(value.alias, MAX_ALIAS_LENGTH);
  if (!alias || !SAFE_ALIAS.test(alias)) return null;
  const idCandidate = cleanText(value.id, 128) ?? alias;
  if (!SAFE_ID.test(idCandidate)) return null;
  const description = cleanText(value.description, MAX_DESCRIPTION_LENGTH);
  const revision = cleanText(value.revision, MAX_REVISION_LENGTH);
  const commandId = cleanText(value.commandId, MAX_COMMAND_ID_LENGTH);
  if (!description || !revision || !commandId || !SAFE_COMMAND_ID.test(commandId)) return null;

  const pluginIdRaw =
    value.pluginId === undefined ? undefined : (cleanText(value.pluginId, 128) ?? undefined);
  if (value.pluginId !== undefined && (!pluginIdRaw || !SAFE_ID.test(pluginIdRaw))) return null;
  if (classifyForbiddenAutomationCommand({ commandId, pluginId: pluginIdRaw }) !== null) return null;

  const minimumPluginVersion = cleanOptionalVersion(value.minimumPluginVersion);
  const maximumPluginVersionExclusive = cleanOptionalVersion(value.maximumPluginVersionExclusive);
  const minimumObsidianVersion = cleanOptionalVersion(value.minimumObsidianVersion);
  if (
    minimumPluginVersion === null ||
    maximumPluginVersionExclusive === null ||
    minimumObsidianVersion === null
  ) {
    return null;
  }
  if (
    !pluginIdRaw &&
    (minimumPluginVersion !== undefined || maximumPluginVersionExclusive !== undefined)
  ) {
    return null;
  }

  if (!Array.isArray(value.allowedPaths) || value.allowedPaths.length > MAX_ALLOWED_PATHS) return null;
  const allowedPaths: string[] = [];
  for (const rawScope of value.allowedPaths) {
    const scope = normalizePolicyScope(rawScope);
    if (!scope) return null;
    if (!allowedPaths.includes(scope)) allowedPaths.push(scope);
  }

  const context = value.context;
  if (context !== "none" && context !== "active_file" && context !== "markdown_file") {
    return null;
  }
  const argumentsList = normalizeArguments(value.arguments);
  if (!argumentsList) return null;
  const postcondition = normalizePostcondition(value.postcondition, argumentsList);
  if (!postcondition) return null;
  const risk = normalizeRisk(value.risk, postcondition);
  if (!risk) return null;
  const requestedConfirmation = value.confirmation === "lease" ? "lease" : "always";
  const confirmation: AutomationConfirmationPolicy = risk === "read" ? requestedConfirmation : "always";

  return {
    id: idCandidate,
    alias,
    description,
    enabled: value.enabled === true,
    revision,
    commandId,
    pluginId: pluginIdRaw,
    minimumPluginVersion,
    maximumPluginVersionExclusive,
    minimumObsidianVersion,
    allowedPaths,
    context,
    risk,
    confirmation,
    arguments: argumentsList,
    postcondition,
  };
}

/** Tolerant, bounded, default-deny parser for persisted plugin settings. */
export function normalizeAutomationRegistry(value: unknown): AutomationRegistrySettings {
  if (
    !isRecord(value) ||
    value.schemaVersion !== AUTOMATION_REGISTRY_SCHEMA_VERSION ||
    !Array.isArray(value.entries)
  ) {
    return {
      schemaVersion: AUTOMATION_REGISTRY_SCHEMA_VERSION,
      enabled: false,
      entries: [],
    };
  }
  const entries: AutomationPolicyEntry[] = [];
  const aliases = new Set<string>();
  const ids = new Set<string>();
  for (const raw of value.entries.slice(0, MAX_POLICIES)) {
    const entry = normalizePolicy(raw);
    if (!entry || aliases.has(entry.alias) || ids.has(entry.id)) continue;
    aliases.add(entry.alias);
    ids.add(entry.id);
    entries.push(entry);
  }
  return {
    schemaVersion: AUTOMATION_REGISTRY_SCHEMA_VERSION,
    enabled: value.enabled === true,
    entries,
  };
}

interface ParsedVersion {
  numeric: number[];
  prerelease: string[] | null;
}

function parseVersion(value: string): ParsedVersion | null {
  const trimmed = String(value ?? "").trim();
  if (!SAFE_VERSION.test(trimmed)) return null;
  const [main, prereleaseRaw] = trimmed.replace(/^v/i, "").split("-", 2);
  const numeric = main.split(".").map((segment) => Number.parseInt(segment, 10));
  while (numeric.length < 4) numeric.push(0);
  return {
    numeric,
    prerelease: prereleaseRaw ? prereleaseRaw.split(".") : null,
  };
}

/** Returns null rather than guessing when either version is malformed. */
export function compareAutomationVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;
  for (let index = 0; index < Math.max(left.numeric.length, right.numeric.length); index += 1) {
    const difference = (left.numeric[index] ?? 0) - (right.numeric[index] ?? 0);
    if (difference !== 0) return difference;
  }
  if (left.prerelease === null && right.prerelease === null) return 0;
  if (left.prerelease === null) return 1;
  if (right.prerelease === null) return -1;
  for (let index = 0; index < Math.max(left.prerelease.length, right.prerelease.length); index += 1) {
    const leftPart = left.prerelease[index];
    const rightPart = right.prerelease[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumber = /^\d+$/.test(leftPart) ? Number(leftPart) : null;
    const rightNumber = /^\d+$/.test(rightPart) ? Number(rightPart) : null;
    if (leftNumber !== null && rightNumber !== null) return leftNumber - rightNumber;
    if (leftNumber !== null) return -1;
    if (rightNumber !== null) return 1;
    return leftPart.localeCompare(rightPart);
  }
  return 0;
}

function versionInRange(
  installed: string | undefined,
  minimum: string | undefined,
  maximumExclusive: string | undefined,
): boolean {
  if (minimum === undefined && maximumExclusive === undefined) return true;
  if (!installed) return false;
  if (minimum !== undefined) {
    const comparison = compareAutomationVersions(installed, minimum);
    if (comparison === null || comparison < 0) return false;
  }
  if (maximumExclusive !== undefined) {
    const comparison = compareAutomationVersions(installed, maximumExclusive);
    if (comparison === null || comparison >= 0) return false;
  }
  return true;
}

function safeAliasForMessage(value: unknown): string {
  return typeof value === "string" && SAFE_ALIAS.test(value) ? ` "${value}"` : "";
}

function invalid(message: string): never {
  throw new AutomationPolicyError("invalid", message);
}

function unavailable(alias: string): never {
  throw new AutomationPolicyError(
    "unavailable",
    `Governed automation${safeAliasForMessage(alias)} is unavailable in the current runtime.`,
  );
}

function contextUnavailable(alias: string): never {
  throw new AutomationPolicyError(
    "unavailable",
    `Automation${safeAliasForMessage(alias)} context is unavailable.`,
  );
}

function stablePolicyFingerprint(entry: AutomationPolicyEntry): string {
  return JSON.stringify(entry);
}

function stableRequestFingerprint(input: {
  alias: string;
  revision: string;
  path?: string;
  activeFilePath: string;
  arguments: Record<string, string | number | boolean>;
}): string {
  const sortedArguments = Object.fromEntries(
    Object.entries(input.arguments).sort(([left], [right]) => left.localeCompare(right)),
  );
  return JSON.stringify({ ...input, arguments: sortedArguments });
}

function sameStringArray(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function validateArguments(
  entry: AutomationPolicyEntry,
  value: unknown,
): Record<string, string | number | boolean> {
  const raw = value === undefined ? {} : value;
  if (!isRecord(raw)) invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
  const definitions = new Map(entry.arguments.map((definition) => [definition.name, definition]));
  for (const key of Object.keys(raw)) {
    if (!definitions.has(key)) {
      invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
    }
  }
  const output: Record<string, string | number | boolean> = {};
  for (const definition of entry.arguments) {
    const argument = raw[definition.name];
    if (argument === undefined) {
      if (definition.required) {
        invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
      }
      continue;
    }
    if (definition.type === "boolean") {
      if (typeof argument !== "boolean") {
        invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
      }
      output[definition.name] = argument;
      continue;
    }
    if (definition.type === "number") {
      if (
        typeof argument !== "number" ||
        !Number.isFinite(argument) ||
        (definition.minimum !== undefined && argument < definition.minimum) ||
        (definition.maximum !== undefined && argument > definition.maximum)
      ) {
        invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
      }
      output[definition.name] = argument;
      continue;
    }
    if (typeof argument !== "string") {
      invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
    }
    if (definition.type === "enum") {
      if (!definition.enumValues?.includes(argument)) {
        invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
      }
      output[definition.name] = argument;
      continue;
    }
    if (argument.length < 1 || argument.length > (definition.maxLength ?? 512)) {
      invalid(`Automation${safeAliasForMessage(entry.alias)} arguments are invalid.`);
    }
    if (definition.type === "path") {
      const normalizedPath = normalizeAutomationVaultPath(argument);
      if (!normalizedPath) invalid(`Automation${safeAliasForMessage(entry.alias)} path is invalid.`);
      output[definition.name] = normalizedPath;
    } else {
      output[definition.name] = argument;
    }
  }
  return output;
}

function assertCommandEligibility(
  entry: AutomationPolicyEntry,
  command: AutomationRuntimeCommand | null,
  context: AutomationRuntimeContext,
): asserts command is AutomationRuntimeCommand {
  if (!command || command.id !== entry.commandId) unavailable(entry.alias);
  if (
    classifyForbiddenAutomationCommand({
      commandId: command.id,
      pluginId: command.pluginId ?? entry.pluginId,
    }) !== null
  ) {
    throw new AutomationPolicyError(
      "denied",
      `Governed automation${safeAliasForMessage(entry.alias)} is not approved for execution.`,
    );
  }
  if (context.platform !== "desktop") unavailable(entry.alias);
  if (
    entry.minimumObsidianVersion !== undefined &&
    !versionInRange(context.obsidianVersion, entry.minimumObsidianVersion, undefined)
  ) {
    unavailable(entry.alias);
  }
  if (entry.pluginId) {
    if (
      command.source !== "community" ||
      command.pluginId !== entry.pluginId ||
      command.pluginEnabled !== true ||
      !versionInRange(
        command.pluginVersion,
        entry.minimumPluginVersion,
        entry.maximumPluginVersionExclusive,
      )
    ) {
      unavailable(entry.alias);
    }
  } else if (command.source !== "core") {
    unavailable(entry.alias);
  }
}

function activeContextPath(
  entry: AutomationPolicyEntry,
  context: AutomationRuntimeContext,
): string {
  // Obsidian's generic command dispatcher operates against ambient workspace
  // state. Without an active-file requirement there is no target the bridge
  // can authorize, so context:none policies are never executable or listed.
  if (entry.context === "none") contextUnavailable(entry.alias);
  const active = normalizeAutomationVaultPath(context.activeFilePath);
  if (!active) contextUnavailable(entry.alias);
  if (entry.context === "markdown_file" && !active.toLocaleLowerCase().endsWith(".md")) {
    contextUnavailable(entry.alias);
  }
  return active;
}

function assertSuppliedPathsMatchActiveContext(
  entry: AutomationPolicyEntry,
  activePath: string,
  requestedPath: string | undefined,
  argumentsValue: Record<string, string | number | boolean>,
): void {
  if (requestedPath && requestedPath !== activePath) contextUnavailable(entry.alias);
  for (const definition of entry.arguments) {
    if (definition.type !== "path") continue;
    const argumentPath = argumentsValue[definition.name];
    if (typeof argumentPath === "string" && argumentPath !== activePath) {
      contextUnavailable(entry.alias);
    }
  }
}

function pathAllowed(entry: AutomationPolicyEntry, path: string): boolean {
  return entry.allowedPaths.some((scope) => matchesGlob(path, scope));
}

function resolvePostconditionPath(
  entry: AutomationPolicyEntry,
  requestedPath: string | undefined,
  argumentsValue: Record<string, string | number | boolean>,
  activePath: string | undefined,
): string | undefined {
  if (entry.postcondition.kind === "active_file_changed") return undefined;
  const argumentName = entry.postcondition.pathArgument;
  if (argumentName) {
    const value = argumentsValue[argumentName];
    return typeof value === "string" ? normalizeAutomationVaultPath(value) ?? undefined : undefined;
  }
  return requestedPath ?? activePath;
}

interface RuntimeValidationResult {
  command: AutomationRuntimeCommand;
  context: AutomationRuntimeContext;
}

interface IdempotencyRecord {
  requestFingerprint: string;
  receipt: AutomationExecutionReceipt;
}

interface InFlightRecord {
  requestFingerprint: string;
  promise: Promise<AutomationExecutionReceipt>;
}

export class AgentAutomationRegistry {
  private readonly idempotency = new Map<string, IdempotencyRecord>();
  private readonly inFlight = new Map<string, InFlightRecord>();
  private readonly consumedPlans = new WeakSet<object>();

  constructor(private readonly deps: AgentAutomationRegistryDeps) {}

  getNormalizedSettings(): AutomationRegistrySettings {
    return normalizeAutomationRegistry(this.deps.getSettings());
  }

  listApprovedAliases(limit = DEFAULT_ALIAS_RESULTS): AutomationAliasListResult {
    const settings = this.getNormalizedSettings();
    if (!settings.enabled || !this.runtimeAvailable()) return { aliases: [], truncated: false };
    const boundedLimit = Math.max(1, Math.min(MAX_ALIAS_RESULTS, Math.floor(limit)));
    const eligible: AutomationAliasSummary[] = [];
    for (const entry of settings.entries) {
      if (!entry.enabled) continue;
      try {
        const validation = this.validateRuntime(entry);
        activeContextPath(entry, validation.context);
      } catch {
        continue;
      }
      eligible.push({
        alias: entry.alias,
        description: entry.description,
        risk: entry.risk,
        requiresConfirmation: this.requiresConfirmation(entry),
        pathRequired:
          entry.postcondition.kind !== "active_file_changed" &&
          entry.postcondition.pathArgument === undefined &&
          entry.context === "none",
        arguments: entry.arguments.map((argument) => ({
          name: argument.name,
          type: argument.type,
          required: argument.required,
          ...(argument.enumValues ? { enumValues: [...argument.enumValues] } : {}),
        })),
        available: true,
      });
    }
    eligible.sort((left, right) => left.alias.localeCompare(right.alias));
    return {
      aliases: eligible.slice(0, boundedLimit),
      truncated: eligible.length > boundedLimit,
    };
  }

  planRun(input: AutomationRunInput): AutomationExecutionPlan {
    const settings = this.getNormalizedSettings();
    const requestedAlias = typeof input.alias === "string" ? input.alias : "";
    if (!settings.enabled) {
      throw new AutomationPolicyError("denied", "Governed automation is disabled.");
    }
    if (!SAFE_ALIAS.test(requestedAlias)) {
      throw new AutomationPolicyError("denied", "The requested automation alias is not approved.");
    }
    const entry = settings.entries.find(
      (candidate) => candidate.enabled && candidate.alias === requestedAlias,
    );
    if (!entry) {
      throw new AutomationPolicyError(
        "denied",
        `Automation${safeAliasForMessage(requestedAlias)} is not approved.`,
      );
    }
    if (input.revision !== undefined && input.revision !== entry.revision) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(entry.alias)} changed after it was observed.`,
      );
    }
    const requestPath =
      input.path === undefined ? undefined : (normalizeAutomationVaultPath(input.path) ?? undefined);
    if (input.path !== undefined && !requestPath) {
      invalid(`Automation${safeAliasForMessage(entry.alias)} path is invalid.`);
    }
    const argumentsValue = validateArguments(entry, input.arguments);
    const explicitlyRequestedPaths = [requestPath];
    for (const definition of entry.arguments) {
      if (definition.type !== "path") continue;
      const argumentPath = argumentsValue[definition.name];
      if (typeof argumentPath === "string") explicitlyRequestedPaths.push(argumentPath);
    }
    for (const path of explicitlyRequestedPaths) {
      if (path && !pathAllowed(entry, path)) {
        throw new AutomationPolicyError(
          "denied",
          `Automation${safeAliasForMessage(entry.alias)} path is not approved.`,
        );
      }
    }
    const validation = this.validateRuntime(entry);
    const activePath = activeContextPath(entry, validation.context);
    assertSuppliedPathsMatchActiveContext(entry, activePath, requestPath, argumentsValue);
    const targetPaths: string[] = [];
    const addPath = (path: string | undefined): void => {
      if (path && !targetPaths.includes(path)) targetPaths.push(path);
    };
    addPath(activePath);
    addPath(requestPath);
    for (const definition of entry.arguments) {
      if (definition.type !== "path") continue;
      const path = argumentsValue[definition.name];
      if (typeof path === "string") addPath(path);
    }
    const postconditionPath = resolvePostconditionPath(
      entry,
      requestPath,
      argumentsValue,
      activePath,
    );
    if (entry.postcondition.kind !== "active_file_changed" && !postconditionPath) {
      invalid(`Automation${safeAliasForMessage(entry.alias)} path is invalid.`);
    }
    addPath(postconditionPath);
    for (const path of targetPaths) {
      if (!pathAllowed(entry, path)) {
        throw new AutomationPolicyError(
          "denied",
          `Automation${safeAliasForMessage(entry.alias)} path is not approved.`,
        );
      }
    }
    if ((entry.risk === "write" || entry.risk === "destructive") && targetPaths.length === 0) {
      invalid(`Automation${safeAliasForMessage(entry.alias)} path is invalid.`);
    }
    const idempotencyKey = this.normalizeIdempotencyKey(input.idempotencyKey, entry.alias);
    const requestFingerprint = stableRequestFingerprint({
      alias: entry.alias,
      revision: entry.revision,
      path: requestPath,
      activeFilePath: activePath,
      arguments: argumentsValue,
    });
    return {
      alias: entry.alias,
      revision: entry.revision,
      risk: entry.risk,
      requiresConfirmation: this.requiresConfirmation(entry),
      targetPaths,
      arguments: argumentsValue,
      idempotencyKey,
      postcondition: entry.postcondition,
      postconditionPath,
      command: { ...validation.command },
      commandId: entry.commandId,
      policyFingerprint: stablePolicyFingerprint(entry),
      requestFingerprint,
      requestPath,
      activeFilePath: activePath,
    };
  }

  /**
   * Re-check policy revision, command mapping, dependency/version, current
   * context, arguments, and private path policy after a confirmation pause.
   */
  revalidatePlan(plan: AutomationExecutionPlan): AutomationExecutionPlan {
    const settings = this.getNormalizedSettings();
    const entry = settings.enabled
      ? settings.entries.find((candidate) => candidate.enabled && candidate.alias === plan.alias)
      : undefined;
    if (
      !entry ||
      entry.revision !== plan.revision ||
      stablePolicyFingerprint(entry) !== plan.policyFingerprint
    ) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(plan.alias)} changed after confirmation.`,
      );
    }
    const argumentsValue = validateArguments(entry, plan.arguments);
    const validation = this.validateRuntime(entry);
    const activePath = activeContextPath(entry, validation.context);
    if (activePath !== plan.activeFilePath) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(plan.alias)} context changed after confirmation.`,
      );
    }
    assertSuppliedPathsMatchActiveContext(entry, activePath, plan.requestPath, argumentsValue);
    const postconditionPath = resolvePostconditionPath(
      entry,
      plan.requestPath,
      argumentsValue,
      activePath,
    );
    const targetPaths: string[] = [];
    const addPath = (path: string | undefined): void => {
      if (path && !targetPaths.includes(path)) targetPaths.push(path);
    };
    addPath(activePath);
    addPath(plan.requestPath);
    for (const definition of entry.arguments) {
      if (definition.type !== "path") continue;
      const path = argumentsValue[definition.name];
      if (typeof path === "string") addPath(path);
    }
    addPath(postconditionPath);
    if (
      !sameStringArray(targetPaths, plan.targetPaths) ||
      postconditionPath !== plan.postconditionPath ||
      targetPaths.some((path) => !pathAllowed(entry, path))
    ) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(plan.alias)} context changed after confirmation.`,
      );
    }
    const requestFingerprint = stableRequestFingerprint({
      alias: entry.alias,
      revision: entry.revision,
      path: plan.requestPath,
      activeFilePath: activePath,
      arguments: argumentsValue,
    });
    if (requestFingerprint !== plan.requestFingerprint) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(plan.alias)} request changed after confirmation.`,
      );
    }
    return {
      ...plan,
      command: { ...validation.command },
      commandId: entry.commandId,
      postcondition: entry.postcondition,
      postconditionPath,
      targetPaths,
      arguments: argumentsValue,
      activeFilePath: activePath,
    };
  }

  /**
   * Execute an already-confirmed plan exactly once, then verify only the
   * declared bounded postcondition. A failed postcondition never retries the
   * command and never marks the declared postcondition as verified.
   */
  async executePlan(plan: AutomationExecutionPlan): Promise<AutomationExecutionReceipt> {
    const cacheKey = plan.idempotencyKey
      ? `${plan.alias}:${plan.idempotencyKey}`
      : undefined;
    if (cacheKey) {
      const cached = this.idempotency.get(cacheKey);
      if (cached) {
        if (cached.requestFingerprint !== plan.requestFingerprint) {
          throw new AutomationPolicyError(
            "stale",
            `Automation${safeAliasForMessage(plan.alias)} idempotency key was reused for a different request.`,
          );
        }
        return this.asReplay(cached.receipt);
      }
      const running = this.inFlight.get(cacheKey);
      if (running) {
        if (running.requestFingerprint !== plan.requestFingerprint) {
          throw new AutomationPolicyError(
            "stale",
            `Automation${safeAliasForMessage(plan.alias)} idempotency key was reused for a different request.`,
          );
        }
        return this.asReplay(await running.promise);
      }
    } else if (this.consumedPlans.has(plan)) {
      throw new AutomationPolicyError(
        "stale",
        `Automation${safeAliasForMessage(plan.alias)} plan was already consumed.`,
      );
    }
    this.consumedPlans.add(plan);

    const execution = this.performExecution(plan);
    if (cacheKey) {
      this.inFlight.set(cacheKey, {
        requestFingerprint: plan.requestFingerprint,
        promise: execution,
      });
    }
    try {
      const receipt = await execution;
      if (cacheKey && receipt.declaredPostconditionVerified) {
        this.rememberIdempotent(cacheKey, plan.requestFingerprint, receipt);
      }
      return receipt;
    } finally {
      if (cacheKey) this.inFlight.delete(cacheKey);
    }
  }

  clearProcessState(): void {
    this.idempotency.clear();
    this.inFlight.clear();
  }

  private runtimeAvailable(): boolean {
    try {
      return this.deps.runtime.isAvailable();
    } catch {
      return false;
    }
  }

  private validateRuntime(entry: AutomationPolicyEntry): RuntimeValidationResult {
    if (!this.runtimeAvailable()) unavailable(entry.alias);
    let context: AutomationRuntimeContext;
    let command: AutomationRuntimeCommand | null;
    try {
      context = this.deps.runtime.getContext();
      command = this.deps.runtime.find(entry.commandId);
    } catch {
      unavailable(entry.alias);
    }
    assertCommandEligibility(entry, command, context!);
    return { command, context: context! };
  }

  private requiresConfirmation(entry: AutomationPolicyEntry): boolean {
    return entry.confirmation === "always" || entry.risk !== "read";
  }

  private normalizeIdempotencyKey(value: unknown, alias: string): string | undefined {
    if (value === undefined) return undefined;
    if (
      typeof value !== "string" ||
      value.length < 1 ||
      value.length > 128 ||
      /[\u0000-\u001F\u007F]/.test(value)
    ) {
      invalid(`Automation${safeAliasForMessage(alias)} idempotency key is invalid.`);
    }
    return value;
  }

  private async performExecution(
    originalPlan: AutomationExecutionPlan,
  ): Promise<AutomationExecutionReceipt> {
    let plan = this.revalidatePlan(originalPlan);
    const before = await this.observeBefore(plan);
    // Observation may await I/O while a settings/context change happens. Repeat
    // the full private-policy check immediately before the one invocation.
    plan = this.revalidatePlan(plan);
    let invoked = false;
    try {
      invoked = await this.deps.runtime.execute(
        plan.commandId,
        plan.command,
        plan.activeFilePath,
      );
    } catch {
      throw new AutomationPolicyError(
        "failed",
        `Automation${safeAliasForMessage(plan.alias)} could not be invoked.`,
      );
    }
    if (!invoked) {
      return {
        alias: plan.alias,
        risk: plan.risk,
        invoked: false,
        declaredPostconditionVerified: false,
        verificationScope: "declared_postcondition_only",
        idempotentReplay: false,
        postcondition: this.publicPostcondition(plan, false),
      };
    }
    const passed = await this.pollPostcondition(plan, before);
    return {
      alias: plan.alias,
      risk: plan.risk,
      invoked: true,
      declaredPostconditionVerified: passed,
      verificationScope: "declared_postcondition_only",
      idempotentReplay: false,
      postcondition: this.publicPostcondition(plan, passed),
    };
  }

  private async observeBefore(
    plan: AutomationExecutionPlan,
  ): Promise<AutomationFileObservation | string | null> {
    if (plan.postcondition.kind === "active_file_changed") {
      return normalizeAutomationVaultPath(this.deps.runtime.getContext().activeFilePath);
    }
    if (!plan.postconditionPath || !this.deps.observeFile) {
      throw new AutomationPolicyError(
        "unavailable",
        `Automation${safeAliasForMessage(plan.alias)} postcondition cannot be observed.`,
      );
    }
    const observation = await this.deps.observeFile(plan.postconditionPath);
    if (
      !observation ||
      typeof observation.exists !== "boolean" ||
      (observation.fingerprint !== undefined && typeof observation.fingerprint !== "string")
    ) {
      throw new AutomationPolicyError(
        "unavailable",
        `Automation${safeAliasForMessage(plan.alias)} postcondition cannot be observed.`,
      );
    }
    if (
      plan.postcondition.kind === "file_changed" &&
      (!observation.exists || !observation.fingerprint)
    ) {
      throw new AutomationPolicyError(
        "unavailable",
        `Automation${safeAliasForMessage(plan.alias)} postcondition cannot be observed.`,
      );
    }
    return observation;
  }

  private async pollPostcondition(
    plan: AutomationExecutionPlan,
    before: AutomationFileObservation | string | null,
  ): Promise<boolean> {
    const attempts = Math.max(
      1,
      Math.min(10, Math.floor(this.deps.postconditionAttempts ?? DEFAULT_POSTCONDITION_ATTEMPTS)),
    );
    const delayMs = Math.max(
      0,
      Math.min(1000, Math.floor(this.deps.postconditionDelayMs ?? DEFAULT_POSTCONDITION_DELAY_MS)),
    );
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      if (await this.verifyPostcondition(plan, before)) return true;
      if (attempt + 1 < attempts && delayMs > 0) await this.delay(delayMs);
    }
    return false;
  }

  private async verifyPostcondition(
    plan: AutomationExecutionPlan,
    before: AutomationFileObservation | string | null,
  ): Promise<boolean> {
    if (plan.postcondition.kind === "active_file_changed") {
      const after = normalizeAutomationVaultPath(this.deps.runtime.getContext().activeFilePath);
      return Boolean(after && after !== before);
    }
    if (!plan.postconditionPath || !this.deps.observeFile) return false;
    const after = await this.deps.observeFile(plan.postconditionPath);
    if (plan.postcondition.kind === "file_exists") {
      return after.exists === plan.postcondition.expected;
    }
    const beforeFile = before as AutomationFileObservation;
    return Boolean(
      beforeFile.exists &&
        beforeFile.fingerprint &&
        after.exists &&
        after.fingerprint &&
        beforeFile.fingerprint !== after.fingerprint,
    );
  }

  private publicPostcondition(
    plan: AutomationExecutionPlan,
    passed: boolean,
  ): AutomationPostconditionReceipt {
    return {
      kind: plan.postcondition.kind,
      ...(plan.postconditionPath ? { path: plan.postconditionPath } : {}),
      passed,
    };
  }

  private async delay(milliseconds: number): Promise<void> {
    if (this.deps.delay) return this.deps.delay(milliseconds);
    await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
  }

  private rememberIdempotent(
    key: string,
    requestFingerprint: string,
    receipt: AutomationExecutionReceipt,
  ): void {
    this.idempotency.delete(key);
    this.idempotency.set(key, {
      requestFingerprint,
      receipt: { ...receipt, postcondition: { ...receipt.postcondition } },
    });
    while (this.idempotency.size > MAX_IDEMPOTENCY_ENTRIES) {
      const oldest = this.idempotency.keys().next().value as string | undefined;
      if (!oldest) break;
      this.idempotency.delete(oldest);
    }
  }

  private asReplay(receipt: AutomationExecutionReceipt): AutomationExecutionReceipt {
    return {
      ...receipt,
      invoked: false,
      idempotentReplay: true,
      postcondition: { ...receipt.postcondition },
    };
  }
}
