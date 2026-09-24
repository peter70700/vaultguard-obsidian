import { sha256Hex } from "./sha256.js";
import { isStableId } from "./ids.js";

export const WORKSPACE_PATH_POLICY_SCHEMA_VERSION = "1.0.0" as const;

export type WorkspacePathCaseMode = "sensitive" | "insensitive";
export type WorkspacePathUnicodeMode = "preserve" | "NFC" | "NFD";
export type WorkspacePathKind = "file" | "folder";

export type WorkspacePathExclusion =
  | { readonly kind: "exact"; readonly path: string }
  | { readonly kind: "subtree"; readonly path: string }
  | { readonly kind: "basename"; readonly value: string }
  | { readonly kind: "suffix"; readonly value: string };

export interface VaultPathPolicy {
  readonly schemaVersion: typeof WORKSPACE_PATH_POLICY_SCHEMA_VERSION;
  readonly vaultId: string;
  readonly policyVersion: number;
  readonly caseMode: WorkspacePathCaseMode;
  readonly unicodeMode: WorkspacePathUnicodeMode;
  readonly maxDepth: number;
  readonly maxPathBytes: number;
  readonly maxSegmentBytes: number;
  readonly exclusions: readonly WorkspacePathExclusion[];
}

export interface NormalizedWorkspacePath {
  readonly vaultId: string;
  /** Syntactically normalized path with the caller's case and Unicode spelling preserved. */
  readonly displayPath: string;
  /** Policy-normalized comparison value. Never substitute this value for displayPath on export. */
  readonly canonicalPath: string;
  readonly canonicalPathHash: string;
  readonly segments: readonly string[];
  readonly basename: string;
  readonly parentPath: string;
  readonly policyVersion: number;
  readonly kind: WorkspacePathKind;
}

export type PathExclusionReason =
  | "hidden-segment"
  | "system-segment"
  | "secret-basename"
  | "secret-suffix"
  | "configured-exact"
  | "configured-subtree"
  | "configured-basename"
  | "configured-suffix";

export interface PathExclusionMatch {
  readonly reason: PathExclusionReason;
  readonly matched: string;
}

export type PathCollisionReason =
  | "duplicate"
  | "case"
  | "unicode"
  | "case-and-unicode"
  | "file-folder";

export interface PathCollisionInput {
  readonly path: string;
  readonly kind: WorkspacePathKind;
  /** Stable caller-owned key used only to make diagnostics reproducible. */
  readonly sourceKey?: string;
}

export interface PathCollisionMember extends PathCollisionInput {
  readonly displayPath: string;
  readonly canonicalPath: string;
}

export interface PathCollision {
  readonly canonicalPath: string;
  readonly canonicalPathHash: string;
  readonly reasons: readonly PathCollisionReason[];
  readonly members: readonly PathCollisionMember[];
}

export type PathPolicyMigrationPlan =
  | {
      readonly status: "ready";
      readonly fromPolicyVersion: number;
      readonly toPolicyVersion: number;
      readonly paths: readonly NormalizedWorkspacePath[];
    }
  | {
      readonly status: "blocked";
      readonly fromPolicyVersion: number;
      readonly toPolicyVersion: number;
      readonly collisions: readonly PathCollision[];
      readonly invalid: readonly { readonly path: string; readonly code: WorkspacePathErrorCode }[];
    };

export type WorkspacePathErrorCode =
  | "INVALID_PATH"
  | "PATH_EXCLUDED"
  | "PATH_POLICY_INVALID"
  | "PATH_POLICY_MISMATCH";

export class WorkspacePathError extends Error {
  readonly code: WorkspacePathErrorCode;
  readonly path?: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(
    code: WorkspacePathErrorCode,
    message: string,
    options: { readonly path?: string; readonly details?: Readonly<Record<string, unknown>> } = {},
  ) {
    super(message);
    this.name = "WorkspacePathError";
    this.code = code;
    this.path = options.path;
    this.details = options.details;
  }
}

const DEFAULT_MAX_DEPTH = 128;
const DEFAULT_MAX_PATH_BYTES = 1_024;
const DEFAULT_MAX_SEGMENT_BYTES = 255;
const WINDOWS_RESERVED_BASENAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const FORBIDDEN_CROSS_PLATFORM_CHARS = /[<>:"|?*]/u;
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/u;
const SYSTEM_SEGMENTS = new Set([".git", ".obsidian", ".terraform", ".vaultguard", "node_modules"]);
const SECRET_BASENAMES = new Set([
  ".env",
  ".npmrc",
  "credentials.json",
  "id_dsa",
  "id_ed25519",
  "id_ecdsa",
  "id_rsa",
]);
const SECRET_SUFFIXES = [
  ".auto.tfvars",
  ".env",
  ".key",
  ".p12",
  ".pem",
  ".pfx",
  ".tfstate",
  ".tfstate.backup",
  ".tfvars",
] as const;

export function createVaultPathPolicy(input: {
  readonly vaultId: string;
  readonly policyVersion: number;
  readonly caseMode: WorkspacePathCaseMode;
  readonly unicodeMode: WorkspacePathUnicodeMode;
  readonly maxDepth?: number;
  readonly maxPathBytes?: number;
  readonly maxSegmentBytes?: number;
  readonly exclusions?: readonly WorkspacePathExclusion[];
}): VaultPathPolicy {
  if (input.exclusions !== undefined && !Array.isArray(input.exclusions)) {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path exclusions must be an array.");
  }
  if ((input.exclusions?.length ?? 0) > 256) {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path policy exceeds the 256-rule exclusion limit.");
  }
  if (!isStableId("vault", input.vaultId)) {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path policy requires a safe vaultId.");
  }
  assertPositiveInteger(input.policyVersion, "policyVersion", 2_147_483_647);
  if (input.caseMode !== "sensitive" && input.caseMode !== "insensitive") {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path policy has an unsupported case mode.");
  }
  if (input.unicodeMode !== "preserve" && input.unicodeMode !== "NFC" && input.unicodeMode !== "NFD") {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path policy has an unsupported Unicode mode.");
  }

  const maxDepth = input.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxPathBytes = input.maxPathBytes ?? DEFAULT_MAX_PATH_BYTES;
  const maxSegmentBytes = input.maxSegmentBytes ?? DEFAULT_MAX_SEGMENT_BYTES;
  assertPositiveInteger(maxDepth, "maxDepth", 1_024);
  assertPositiveInteger(maxPathBytes, "maxPathBytes", 16_384);
  assertPositiveInteger(maxSegmentBytes, "maxSegmentBytes", 1_024);
  if (maxSegmentBytes > maxPathBytes) {
    throw new WorkspacePathError(
      "PATH_POLICY_INVALID",
      "maxSegmentBytes cannot exceed maxPathBytes.",
    );
  }

  const basePolicy: VaultPathPolicy = {
    schemaVersion: WORKSPACE_PATH_POLICY_SCHEMA_VERSION,
    vaultId: input.vaultId,
    policyVersion: input.policyVersion,
    caseMode: input.caseMode,
    unicodeMode: input.unicodeMode,
    maxDepth,
    maxPathBytes,
    maxSegmentBytes,
    exclusions: [],
  };
  const exclusions = (input.exclusions ?? []).map((rule) => normalizeExclusion(rule, basePolicy));
  exclusions.sort(compareExclusions);
  for (let index = 1; index < exclusions.length; index += 1) {
    if (compareExclusions(exclusions[index - 1], exclusions[index]) === 0) {
      throw new WorkspacePathError("PATH_POLICY_INVALID", "Vault path policy contains a duplicate exclusion rule.");
    }
  }
  return freezePolicy({ ...basePolicy, exclusions });
}

export function normalizeWorkspacePath(
  rawPath: string,
  policy: VaultPathPolicy,
  options: { readonly kind?: WorkspacePathKind; readonly allowExcluded?: boolean } = {},
): NormalizedWorkspacePath {
  assertPolicy(policy);
  if (options.kind !== undefined && options.kind !== "file" && options.kind !== "folder") {
    throw invalidPath(rawPath, "Workspace path kind must be file or folder.");
  }
  if (typeof rawPath !== "string" || rawPath.length === 0) {
    throw invalidPath(rawPath, "Workspace path is required.");
  }
  if (hasUnpairedSurrogate(rawPath)) {
    throw invalidPath(rawPath, "Workspace path contains an unpaired Unicode surrogate.");
  }
  if (CONTROL_CHARS.test(rawPath)) {
    throw invalidPath(rawPath, "Workspace path contains a control character.");
  }
  if (/^[A-Za-z]:[\\/]/u.test(rawPath) || /^[\\/]/u.test(rawPath)) {
    throw invalidPath(rawPath, "Workspace path must not be absolute or UNC-addressed.");
  }

  const displayPath = rawPath
    .replace(/\\/gu, "/")
    .replace(/\/{2,}/gu, "/")
    .replace(/\/+$/gu, "");
  if (!displayPath) throw invalidPath(rawPath, "Workspace path is required.");

  const segments = displayPath.split("/");
  if (segments.length > policy.maxDepth) {
    throw invalidPath(rawPath, `Workspace path exceeds the ${policy.maxDepth}-segment depth limit.`);
  }
  if (utf8ByteLength(displayPath) > policy.maxPathBytes) {
    throw invalidPath(rawPath, `Workspace path exceeds the ${policy.maxPathBytes}-byte limit.`);
  }
  for (const segment of segments) validateSegment(segment, rawPath, policy);

  const canonicalSegments = segments.map((segment) => canonicalizeSegment(segment, policy));
  const canonicalPath = canonicalSegments.join("/");
  const normalized: NormalizedWorkspacePath = Object.freeze({
    vaultId: policy.vaultId,
    displayPath,
    canonicalPath,
    canonicalPathHash: sha256Hex(canonicalPath),
    segments: Object.freeze([...segments]),
    basename: segments[segments.length - 1],
    parentPath: segments.slice(0, -1).join("/"),
    policyVersion: policy.policyVersion,
    kind: options.kind ?? "file",
  });

  const exclusion = matchWorkspacePathExclusion(normalized, policy);
  if (exclusion && options.allowExcluded !== true) {
    throw new WorkspacePathError(
      "PATH_EXCLUDED",
      `Workspace path is excluded by ${exclusion.reason}.`,
      { path: rawPath, details: { ...exclusion } },
    );
  }
  return normalized;
}

export function matchWorkspacePathExclusion(
  path: NormalizedWorkspacePath,
  policy: VaultPathPolicy,
): PathExclusionMatch | null {
  assertPathPolicyBinding(path, policy);
  const canonicalSegments = path.canonicalPath.split("/");
  const displaySegments = path.displayPath.split("/");
  const securitySegments = displaySegments.map((segment) => segment.normalize("NFC").toLowerCase());
  const systemIndex = securitySegments.findIndex((segment) => SYSTEM_SEGMENTS.has(segment));
  if (systemIndex !== -1) {
    return Object.freeze({ reason: "system-segment", matched: displaySegments[systemIndex] });
  }
  const hiddenIndex = displaySegments.findIndex((segment) => segment.startsWith("."));
  if (hiddenIndex !== -1) {
    return Object.freeze({ reason: "hidden-segment", matched: displaySegments[hiddenIndex] });
  }

  const basename = canonicalSegments[canonicalSegments.length - 1];
  const securityBasename = securitySegments[securitySegments.length - 1];
  if (SECRET_BASENAMES.has(securityBasename)) {
    return Object.freeze({ reason: "secret-basename", matched: displaySegments[displaySegments.length - 1] });
  }
  const secretSuffix = SECRET_SUFFIXES.find((suffix) => securityBasename.endsWith(suffix));
  if (secretSuffix) return Object.freeze({ reason: "secret-suffix", matched: secretSuffix });

  for (const exclusion of policy.exclusions) {
    if (exclusion.kind === "exact" && path.canonicalPath === exclusion.path) {
      return Object.freeze({ reason: "configured-exact", matched: exclusion.path });
    }
    if (
      exclusion.kind === "subtree" &&
      (path.canonicalPath === exclusion.path || path.canonicalPath.startsWith(`${exclusion.path}/`))
    ) {
      return Object.freeze({ reason: "configured-subtree", matched: exclusion.path });
    }
    if (exclusion.kind === "basename" && basename === exclusion.value) {
      return Object.freeze({ reason: "configured-basename", matched: exclusion.value });
    }
    if (exclusion.kind === "suffix" && basename.endsWith(exclusion.value)) {
      return Object.freeze({ reason: "configured-suffix", matched: exclusion.value });
    }
  }
  return null;
}

export function detectWorkspacePathCollisions(
  inputs: readonly PathCollisionInput[],
  policy: VaultPathPolicy,
  options: { readonly allowExcluded?: boolean } = {},
): readonly PathCollision[] {
  const groups = new Map<string, PathCollisionMember[]>();
  for (const input of inputs) {
    const normalized = normalizeWorkspacePath(input.path, policy, {
      kind: input.kind,
      allowExcluded: options.allowExcluded,
    });
    const member: PathCollisionMember = Object.freeze({
      ...input,
      displayPath: normalized.displayPath,
      canonicalPath: normalized.canonicalPath,
    });
    const group = groups.get(normalized.canonicalPath) ?? [];
    group.push(member);
    groups.set(normalized.canonicalPath, group);
  }

  const collisions: PathCollision[] = [];
  for (const [canonicalPath, members] of groups) {
    if (members.length < 2) continue;
    members.sort(compareCollisionMembers);
    const reasons = classifyCollisionReasons(members, policy);
    collisions.push(Object.freeze({
      canonicalPath,
      canonicalPathHash: sha256Hex(canonicalPath),
      reasons: Object.freeze(reasons),
      members: Object.freeze([...members]),
    }));
  }
  collisions.sort((left, right) => compareStrings(left.canonicalPath, right.canonicalPath));
  return Object.freeze(collisions);
}

export function planWorkspacePathPolicyMigration(input: {
  readonly fromPolicy: VaultPathPolicy;
  readonly toPolicy: VaultPathPolicy;
  readonly paths: readonly PathCollisionInput[];
}): PathPolicyMigrationPlan {
  if (input.fromPolicy.vaultId !== input.toPolicy.vaultId) {
    throw new WorkspacePathError("PATH_POLICY_MISMATCH", "Path policies belong to different vaults.");
  }
  if (input.toPolicy.policyVersion <= input.fromPolicy.policyVersion) {
    throw new WorkspacePathError(
      "PATH_POLICY_INVALID",
      "A path policy migration must advance the policy version.",
    );
  }

  const paths: NormalizedWorkspacePath[] = [];
  const invalid: { path: string; code: WorkspacePathErrorCode }[] = [];
  for (const candidate of [...input.paths].sort(compareCollisionInputs)) {
    try {
      paths.push(normalizeWorkspacePath(candidate.path, input.toPolicy, { kind: candidate.kind }));
    } catch (error) {
      if (!(error instanceof WorkspacePathError)) throw error;
      invalid.push({ path: candidate.path, code: error.code });
    }
  }
  const validInputs = input.paths.filter((candidate) => !invalid.some((entry) => entry.path === candidate.path));
  const collisions = detectWorkspacePathCollisions(validInputs, input.toPolicy);
  if (invalid.length > 0 || collisions.length > 0) {
    invalid.sort((left, right) => compareStrings(left.path, right.path) || compareStrings(left.code, right.code));
    return Object.freeze({
      status: "blocked",
      fromPolicyVersion: input.fromPolicy.policyVersion,
      toPolicyVersion: input.toPolicy.policyVersion,
      collisions,
      invalid: Object.freeze(invalid),
    });
  }
  paths.sort((left, right) => compareStrings(left.canonicalPath, right.canonicalPath));
  return Object.freeze({
    status: "ready",
    fromPolicyVersion: input.fromPolicy.policyVersion,
    toPolicyVersion: input.toPolicy.policyVersion,
    paths: Object.freeze(paths),
  });
}

function normalizeExclusion(rule: WorkspacePathExclusion, policy: VaultPathPolicy): WorkspacePathExclusion {
  if (!rule || typeof rule !== "object") {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Path exclusion must be an object.");
  }
  if (rule.kind === "exact" || rule.kind === "subtree") {
    if (Object.keys(rule).some((key) => key !== "kind" && key !== "path")) {
      throw new WorkspacePathError("PATH_POLICY_INVALID", `Unknown ${rule.kind} exclusion field.`);
    }
    const normalized = normalizeWorkspacePath(rule.path, policy, { allowExcluded: true, kind: "folder" });
    return Object.freeze({ kind: rule.kind, path: normalized.canonicalPath });
  }
  if (rule.kind === "basename" || rule.kind === "suffix") {
    if (Object.keys(rule).some((key) => key !== "kind" && key !== "value")) {
      throw new WorkspacePathError("PATH_POLICY_INVALID", `Unknown ${rule.kind} exclusion field.`);
    }
    if (typeof rule.value !== "string" || !rule.value || rule.value.includes("/") || rule.value.includes("\\")) {
      throw new WorkspacePathError("PATH_POLICY_INVALID", `Invalid ${rule.kind} exclusion value.`);
    }
    if (CONTROL_CHARS.test(rule.value) || hasUnpairedSurrogate(rule.value)) {
      throw new WorkspacePathError("PATH_POLICY_INVALID", `Invalid ${rule.kind} exclusion value.`);
    }
    return Object.freeze({ kind: rule.kind, value: canonicalizeValue(rule.value, policy) });
  }
  throw new WorkspacePathError("PATH_POLICY_INVALID", "Unsupported path exclusion kind.");
}

function validateSegment(segment: string, rawPath: string, policy: VaultPathPolicy): void {
  if (!segment || segment === "." || segment === "..") {
    throw invalidPath(rawPath, "Workspace path contains an empty or traversal segment.");
  }
  if (utf8ByteLength(segment) > policy.maxSegmentBytes) {
    throw invalidPath(rawPath, `Workspace path segment exceeds the ${policy.maxSegmentBytes}-byte limit.`);
  }
  if (FORBIDDEN_CROSS_PLATFORM_CHARS.test(segment)) {
    throw invalidPath(rawPath, "Workspace path contains a cross-platform reserved character.");
  }
  if (/[. ]$/u.test(segment)) {
    throw invalidPath(rawPath, "Workspace path segment cannot end in a dot or space.");
  }
  if (WINDOWS_RESERVED_BASENAME.test(segment)) {
    throw invalidPath(rawPath, "Workspace path uses a cross-platform reserved name.");
  }
}

function canonicalizeSegment(segment: string, policy: VaultPathPolicy): string {
  return canonicalizeValue(segment, policy);
}

function canonicalizeValue(value: string, policy: VaultPathPolicy): string {
  let canonical = policy.unicodeMode === "preserve" ? value : value.normalize(policy.unicodeMode);
  if (policy.caseMode === "insensitive") canonical = canonical.toLowerCase();
  if (policy.unicodeMode !== "preserve") canonical = canonical.normalize(policy.unicodeMode);
  return canonical;
}

function classifyCollisionReasons(
  members: readonly PathCollisionMember[],
  policy: VaultPathPolicy,
): PathCollisionReason[] {
  const reasons = new Set<PathCollisionReason>();
  if (new Set(members.map((member) => member.kind)).size > 1) reasons.add("file-folder");
  if (new Set(members.map((member) => member.displayPath)).size < members.length) reasons.add("duplicate");

  for (let leftIndex = 0; leftIndex < members.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < members.length; rightIndex += 1) {
      const left = members[leftIndex].displayPath;
      const right = members[rightIndex].displayPath;
      if (left === right) continue;
      const unicodeEqual = normalizeForComparison(left, policy.unicodeMode) === normalizeForComparison(right, policy.unicodeMode);
      const caseEqual = left.toLowerCase() === right.toLowerCase();
      if (unicodeEqual && !caseEqual) reasons.add("unicode");
      else if (caseEqual && !unicodeEqual) reasons.add("case");
      else if (policy.caseMode === "insensitive" && policy.unicodeMode !== "preserve") reasons.add("case-and-unicode");
      else if (policy.caseMode === "insensitive") reasons.add("case");
      else reasons.add("unicode");
    }
  }

  const order: readonly PathCollisionReason[] = ["file-folder", "duplicate", "case", "unicode", "case-and-unicode"];
  return order.filter((reason) => reasons.has(reason));
}

function normalizeForComparison(value: string, mode: WorkspacePathUnicodeMode): string {
  return mode === "preserve" ? value : value.normalize(mode);
}

function compareCollisionInputs(left: PathCollisionInput, right: PathCollisionInput): number {
  return compareStrings(left.path, right.path)
    || compareStrings(left.kind, right.kind)
    || compareStrings(left.sourceKey ?? "", right.sourceKey ?? "");
}

function compareCollisionMembers(left: PathCollisionMember, right: PathCollisionMember): number {
  return compareStrings(left.displayPath, right.displayPath)
    || compareStrings(left.kind, right.kind)
    || compareStrings(left.sourceKey ?? "", right.sourceKey ?? "");
}

function compareExclusions(left: WorkspacePathExclusion, right: WorkspacePathExclusion): number {
  return compareStrings(left.kind, right.kind)
    || compareStrings("path" in left ? left.path : left.value, "path" in right ? right.path : right.value);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function assertPathPolicyBinding(path: NormalizedWorkspacePath, policy: VaultPathPolicy): void {
  if (path.vaultId !== policy.vaultId || path.policyVersion !== policy.policyVersion) {
    throw new WorkspacePathError("PATH_POLICY_MISMATCH", "Normalized path uses a different policy version.");
  }
}

function assertPolicy(policy: VaultPathPolicy): void {
  if (
    !policy ||
    policy.schemaVersion !== WORKSPACE_PATH_POLICY_SCHEMA_VERSION ||
    !isStableId("vault", policy.vaultId) ||
    !Number.isInteger(policy.policyVersion) ||
    policy.policyVersion < 1 ||
    (policy.caseMode !== "sensitive" && policy.caseMode !== "insensitive") ||
    (policy.unicodeMode !== "preserve" && policy.unicodeMode !== "NFC" && policy.unicodeMode !== "NFD") ||
    !Number.isInteger(policy.maxDepth) ||
    policy.maxDepth < 1 ||
    !Number.isInteger(policy.maxPathBytes) ||
    policy.maxPathBytes < 1 ||
    !Number.isInteger(policy.maxSegmentBytes) ||
    policy.maxSegmentBytes < 1 ||
    policy.maxSegmentBytes > policy.maxPathBytes ||
    !Array.isArray(policy.exclusions) ||
    policy.exclusions.length > 256
  ) {
    throw new WorkspacePathError("PATH_POLICY_INVALID", "Invalid vault path policy.");
  }
}

function freezePolicy(policy: VaultPathPolicy): VaultPathPolicy {
  return Object.freeze({ ...policy, exclusions: Object.freeze([...policy.exclusions]) });
}

function assertPositiveInteger(value: number, name: string, maximum: number): void {
  if (!Number.isInteger(value) || value < 1 || value > maximum) {
    throw new WorkspacePathError("PATH_POLICY_INVALID", `${name} must be an integer from 1 through ${maximum}.`);
  }
}

function invalidPath(path: unknown, message: string): WorkspacePathError {
  return new WorkspacePathError("INVALID_PATH", message, { path: typeof path === "string" ? path : undefined });
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x7f) bytes += 1;
    else if (code <= 0x7ff) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      bytes += 4;
      index += 1;
    } else bytes += 3;
  }
  return bytes;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) return true;
  }
  return false;
}
