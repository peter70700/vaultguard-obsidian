import {
  AgentNoteOperationError,
  isSha256Hash,
  sha256Text,
  type AgentTextHasher,
} from "./agent-note-operations";

/** Stable public classifications for semantic-mutation failures. */
export type SemanticMutationErrorCode =
  | "stale"
  | "cancelled"
  | "unavailable"
  | "invalid"
  | "failed";

export class SemanticMutationError extends Error {
  constructor(
    public readonly code: SemanticMutationErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SemanticMutationError";
  }
}

export interface MutationReceipt {
  operation: string;
  path: string;
  changed: boolean;
  verified: true;
  idempotentReplay: boolean;
  beforeHash: string;
  afterHash: string;
  beforeBytes: number;
  afterBytes: number;
  line?: number;
  section?: string;
  destination?: string;
}

/**
 * Closed structural data a transform may add to its receipt. Arbitrary detail
 * maps are intentionally unsupported so note/property/task text cannot leak by
 * accidental object spreading.
 */
export interface MutationReceiptLocation {
  line?: number;
  section?: string;
  destination?: string;
}

export interface SemanticMutationTransform {
  content: string;
  receipt?: MutationReceiptLocation;
}

export interface SemanticMutationConfirmation {
  operation: string;
  path: string;
  changed: true;
  beforeHash: string;
  afterHash: string;
  beforeBytes: number;
  afterBytes: number;
}

export interface SemanticMutationRequest {
  operation: string;
  path: string;
  /** Required by callers for existing-note property/task changes. */
  expectedContentHash?: string;
  /** Optional process-local retry key, bounded to 1-128 characters. */
  idempotencyKey?: string;
  /**
   * A stable representation or digest of every operation-specific argument.
   * It is hashed again before being retained and is mandatory with a retry key.
   */
  requestFingerprint?: string;
  /** Optional caller/lease namespace; it is hashed before cache retention. */
  idempotencyScope?: string;
  transform:
    | ((currentContent: string) => SemanticMutationTransform)
    | ((currentContent: string) => Promise<SemanticMutationTransform>);
  /** Optional extra semantic postcondition, after exact readback verification. */
  verify?: (readbackContent: string) => boolean | Promise<boolean>;
  /** Request-specific confirmation policy, used instead of the default. */
  confirm?: (
    preview: SemanticMutationConfirmation,
  ) => boolean | Promise<boolean>;
}

export interface AgentSemanticMutationDependencies {
  readText(path: string): Promise<string>;
  writeText(path: string, content: string): Promise<void>;
  confirm?: (
    preview: SemanticMutationConfirmation,
  ) => boolean | Promise<boolean>;
  hashText?: AgentTextHasher;
  /** Defaults to 256 and may not exceed 4,096. */
  maxIdempotencyEntries?: number;
}

interface CachedMutation {
  fingerprintHash: string;
  receipt: Readonly<MutationReceipt>;
}

interface IdempotencyIdentity {
  cacheKeyHash: string;
  fingerprintHash: string;
}

const MAX_IDEMPOTENCY_ENTRIES = 4_096;
const DEFAULT_IDEMPOTENCY_ENTRIES = 256;
const MAX_PATH_CHARS = 1_024;
const MAX_OPERATION_CHARS = 128;
const MAX_IDEMPOTENCY_KEY_CHARS = 128;
const MAX_FINGERPRINT_CHARS = 262_144;
const MAX_SECTION_CHARS = 300;

function mutationFail(code: SemanticMutationErrorCode, message: string): never {
  throw new SemanticMutationError(code, message);
}

function validateRelativePath(path: string): void {
  if (
    typeof path !== "string" ||
    path.length < 1 ||
    path.length > MAX_PATH_CHARS ||
    path.trim() !== path ||
    path.includes("\0") ||
    path.includes("\\") ||
    path.startsWith("/") ||
    /^[A-Za-z]:/u.test(path)
  ) {
    return mutationFail("invalid", "The mutation path is invalid.");
  }
  const segments = path.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    return mutationFail("invalid", "The mutation path is invalid.");
  }
}

function validateRequest(request: SemanticMutationRequest): void {
  validateRelativePath(request.path);
  if (
    typeof request.operation !== "string" ||
    request.operation.length < 1 ||
    request.operation.length > MAX_OPERATION_CHARS ||
    !/^[A-Za-z][A-Za-z0-9._-]*$/u.test(request.operation)
  ) {
    return mutationFail("invalid", "The mutation operation is invalid.");
  }
  if (
    request.expectedContentHash !== undefined &&
    !isSha256Hash(request.expectedContentHash)
  ) {
    return mutationFail("invalid", "The expected content hash is invalid.");
  }
  if (typeof request.transform !== "function") {
    return mutationFail("invalid", "The mutation transform is invalid.");
  }
  if (request.idempotencyKey === undefined) {
    if (request.requestFingerprint !== undefined || request.idempotencyScope !== undefined) {
      return mutationFail(
        "invalid",
        "Idempotency metadata requires an idempotency key.",
      );
    }
    return;
  }
  if (
    typeof request.idempotencyKey !== "string" ||
    request.idempotencyKey.length < 1 ||
    request.idempotencyKey.length > MAX_IDEMPOTENCY_KEY_CHARS ||
    /[\p{Cc}\p{Cs}]/u.test(request.idempotencyKey)
  ) {
    return mutationFail("invalid", "The idempotency key is invalid.");
  }
  if (
    typeof request.requestFingerprint !== "string" ||
    request.requestFingerprint.length < 1 ||
    request.requestFingerprint.length > MAX_FINGERPRINT_CHARS ||
    request.requestFingerprint.includes("\0")
  ) {
    return mutationFail("invalid", "The idempotency fingerprint is invalid.");
  }
  if (
    request.idempotencyScope !== undefined &&
    (typeof request.idempotencyScope !== "string" ||
      request.idempotencyScope.length < 1 ||
      request.idempotencyScope.length > MAX_IDEMPOTENCY_KEY_CHARS ||
      /[\p{Cc}\p{Cs}]/u.test(request.idempotencyScope))
  ) {
    return mutationFail("invalid", "The idempotency scope is invalid.");
  }
}

function sanitizeLocation(
  location: MutationReceiptLocation | undefined,
): MutationReceiptLocation {
  if (!location) return {};
  const sanitized: MutationReceiptLocation = {};
  if (location.line !== undefined) {
    if (!Number.isSafeInteger(location.line) || location.line < 1) {
      return mutationFail("invalid", "The mutation receipt line is invalid.");
    }
    sanitized.line = location.line;
  }
  if (location.section !== undefined) {
    if (
      typeof location.section !== "string" ||
      location.section.length < 1 ||
      location.section.length > MAX_SECTION_CHARS ||
      /[\r\n\0]/u.test(location.section)
    ) {
      return mutationFail("invalid", "The mutation receipt section is invalid.");
    }
    sanitized.section = location.section;
  }
  if (location.destination !== undefined) {
    validateRelativePath(location.destination);
    sanitized.destination = location.destination;
  }
  return sanitized;
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function mapTransformError(error: unknown): never {
  if (error instanceof SemanticMutationError) throw error;
  if (error instanceof AgentNoteOperationError) {
    const code: SemanticMutationErrorCode =
      error.code === "stale"
        ? "stale"
        : error.code === "unavailable"
          ? "unavailable"
          : "invalid";
    throw new SemanticMutationError(code, error.message);
  }
  return mutationFail("invalid", "The semantic mutation could not be applied safely.");
}

/**
 * Canonically hash bounded JSON-like tool arguments for use as an idempotency
 * request fingerprint. Object keys are sorted and non-JSON values fail closed.
 */
export async function hashSemanticRequest(
  value: unknown,
  hashText: AgentTextHasher = sha256Text,
): Promise<string> {
  let nodes = 0;
  const visit = (entry: unknown, depth: number): string => {
    nodes += 1;
    if (nodes > 10_000 || depth > 32) {
      return mutationFail("invalid", "The semantic request exceeds its safe bound.");
    }
    if (entry === null || typeof entry === "string" || typeof entry === "boolean") {
      return JSON.stringify(entry);
    }
    if (typeof entry === "number") {
      if (!Number.isFinite(entry)) {
        return mutationFail("invalid", "The semantic request contains an invalid number.");
      }
      return JSON.stringify(entry);
    }
    if (Array.isArray(entry)) {
      return `[${entry.map((item) => visit(item, depth + 1)).join(",")}]`;
    }
    if (typeof entry !== "object") {
      return mutationFail("invalid", "The semantic request contains an unsupported value.");
    }
    const prototype = Object.getPrototypeOf(entry);
    if (prototype !== Object.prototype && prototype !== null) {
      return mutationFail("invalid", "The semantic request contains an unsupported value.");
    }
    const record = entry as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${visit(record[key], depth + 1)}`)
      .join(",")}}`;
  };
  const canonical = visit(value, 0);
  if (canonical.length > MAX_FINGERPRINT_CHARS) {
    return mutationFail("invalid", "The semantic request exceeds its safe bound.");
  }
  try {
    const hash = await hashText(canonical);
    if (!isSha256Hash(hash)) throw new Error("invalid hash");
    return hash.toLocaleLowerCase("en-US");
  } catch (error) {
    if (error instanceof SemanticMutationError) throw error;
    return mutationFail("unavailable", "SHA-256 is unavailable for semantic mutation.");
  }
}

/**
 * Bridge-owned semantic-write coordinator. It serializes by normalized path,
 * performs a second read after confirmation, verifies exact readback, and only
 * caches content-free verified receipts.
 */
export class AgentSemanticMutationCoordinator {
  private readonly pathQueues = new Map<string, Promise<void>>();
  private readonly idempotency = new Map<string, CachedMutation>();
  private readonly maxIdempotencyEntries: number;
  private readonly hashText: AgentTextHasher;
  private disposed = false;

  constructor(private readonly dependencies: AgentSemanticMutationDependencies) {
    const maximum =
      dependencies.maxIdempotencyEntries ?? DEFAULT_IDEMPOTENCY_ENTRIES;
    if (
      !Number.isInteger(maximum) ||
      maximum < 1 ||
      maximum > MAX_IDEMPOTENCY_ENTRIES
    ) {
      throw new RangeError("maxIdempotencyEntries must be between 1 and 4096.");
    }
    this.maxIdempotencyEntries = maximum;
    this.hashText = dependencies.hashText ?? sha256Text;
  }

  get pendingPathCount(): number {
    return this.pathQueues.size;
  }

  get idempotencyEntryCount(): number {
    return this.idempotency.size;
  }

  /** Clear retained receipts without interrupting already-running writes. */
  clearIdempotency(): void {
    this.idempotency.clear();
  }

  /** Reject new work and release all process-local receipt state. */
  dispose(): void {
    this.disposed = true;
    this.idempotency.clear();
  }

  execute(request: SemanticMutationRequest): Promise<MutationReceipt> {
    if (this.disposed) {
      return Promise.reject(
        new SemanticMutationError(
          "unavailable",
          "The semantic mutation coordinator is unavailable.",
        ),
      );
    }
    try {
      validateRequest(request);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.runExclusive(request.path, () => this.executeQueued(request));
  }

  /**
   * Serialize any bridge-owned filesystem transaction with semantic mutations
   * targeting the same normalized path. Queue entries are retained only while
   * active/queued, so the process-local lock map stays bounded by live work.
   */
  runExclusive<T>(path: string, operation: () => Promise<T>): Promise<T> {
    if (this.disposed) {
      return Promise.reject(
        new SemanticMutationError(
          "unavailable",
          "The semantic mutation coordinator is unavailable.",
        ),
      );
    }
    try {
      validateRelativePath(path);
      if (typeof operation !== "function") {
        return Promise.reject(
          new SemanticMutationError("invalid", "The queued mutation operation is invalid."),
        );
      }
    } catch (error) {
      return Promise.reject(error);
    }
    return this.enqueue(path, operation);
  }

  private enqueue<T>(path: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.pathQueues.get(path) ?? Promise.resolve();
    const running = previous.then(operation, operation);
    const settled = running.then(
      () => undefined,
      () => undefined,
    );
    this.pathQueues.set(path, settled);
    return running.finally(() => {
      if (this.pathQueues.get(path) === settled) this.pathQueues.delete(path);
    });
  }

  private async checkedHash(value: string): Promise<string> {
    try {
      const hash = await this.hashText(value);
      if (!isSha256Hash(hash)) throw new Error("invalid hash");
      return hash.toLocaleLowerCase("en-US");
    } catch (error) {
      if (error instanceof SemanticMutationError) throw error;
      return mutationFail("unavailable", "SHA-256 is unavailable for semantic mutation.");
    }
  }

  private async idempotencyIdentity(
    request: SemanticMutationRequest,
  ): Promise<IdempotencyIdentity | null> {
    if (!request.idempotencyKey || !request.requestFingerprint) return null;
    const identity = [
      request.idempotencyScope ?? "process",
      request.idempotencyKey,
    ].join("\0");
    const fingerprint = [
      request.path,
      request.operation,
      request.requestFingerprint,
    ].join("\0");
    return {
      cacheKeyHash: await this.checkedHash(identity),
      fingerprintHash: await this.checkedHash(fingerprint),
    };
  }

  private replay(identity: IdempotencyIdentity): MutationReceipt | null {
    const cached = this.idempotency.get(identity.cacheKeyHash);
    if (!cached) return null;
    if (cached.fingerprintHash !== identity.fingerprintHash) {
      return mutationFail(
        "invalid",
        "The idempotency key was already used with different arguments.",
      );
    }
    // Refresh insertion order to make the bounded cache least-recently-used.
    this.idempotency.delete(identity.cacheKeyHash);
    this.idempotency.set(identity.cacheKeyHash, cached);
    return { ...cached.receipt, idempotentReplay: true };
  }

  private remember(
    identity: IdempotencyIdentity | null,
    receipt: MutationReceipt,
  ): void {
    if (!identity) return;
    while (this.idempotency.size >= this.maxIdempotencyEntries) {
      const oldest = this.idempotency.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.idempotency.delete(oldest);
    }
    this.idempotency.set(identity.cacheKeyHash, {
      fingerprintHash: identity.fingerprintHash,
      receipt: Object.freeze({ ...receipt }),
    });
  }

  private async read(path: string): Promise<string> {
    try {
      const content = await this.dependencies.readText(path);
      if (typeof content !== "string") throw new Error("invalid content");
      return content;
    } catch (error) {
      if (error instanceof SemanticMutationError) throw error;
      return mutationFail("failed", "The mutation target could not be read.");
    }
  }

  private async executeQueued(
    request: SemanticMutationRequest,
  ): Promise<MutationReceipt> {
    const identity = await this.idempotencyIdentity(request);
    if (identity) {
      const replay = this.replay(identity);
      if (replay) return replay;
    }

    const beforeContent = await this.read(request.path);
    const beforeHash = await this.checkedHash(beforeContent);
    if (
      request.expectedContentHash !== undefined &&
      beforeHash !== request.expectedContentHash.toLocaleLowerCase("en-US")
    ) {
      return mutationFail("stale", "The mutation target changed before it was applied.");
    }

    let transformed: SemanticMutationTransform;
    try {
      transformed = await request.transform(beforeContent);
    } catch (error) {
      return mapTransformError(error);
    }
    if (!transformed || typeof transformed.content !== "string") {
      return mutationFail("invalid", "The semantic mutation result is invalid.");
    }
    const location = sanitizeLocation(transformed.receipt);
    const proposedContent = transformed.content;
    const changed = proposedContent !== beforeContent;
    const afterHash = changed
      ? await this.checkedHash(proposedContent)
      : beforeHash;
    const beforeBytes = utf8Bytes(beforeContent);
    const afterBytes = changed ? utf8Bytes(proposedContent) : beforeBytes;

    if (changed) {
      const confirm = request.confirm ?? this.dependencies.confirm;
      if (confirm) {
        let approved: boolean;
        try {
          approved = await confirm({
            operation: request.operation,
            path: request.path,
            changed: true,
            beforeHash,
            afterHash,
            beforeBytes,
            afterBytes,
          });
        } catch {
          return mutationFail("failed", "Mutation confirmation failed.");
        }
        if (!approved) {
          return mutationFail("cancelled", "The mutation was cancelled.");
        }
      }
    }

    // The second read is mandatory even when confirmation is policy-skipped.
    const immediatelyBeforeWrite = await this.read(request.path);
    const recheckedHash = await this.checkedHash(immediatelyBeforeWrite);
    if (
      recheckedHash !== beforeHash ||
      immediatelyBeforeWrite !== beforeContent
    ) {
      return mutationFail("stale", "The mutation target changed before it was applied.");
    }

    if (changed) {
      try {
        await this.dependencies.writeText(request.path, proposedContent);
      } catch {
        return mutationFail("failed", "The semantic mutation could not be written.");
      }
    }

    const readback = changed ? await this.read(request.path) : immediatelyBeforeWrite;
    const readbackHash = await this.checkedHash(readback);
    if (readbackHash !== afterHash || readback !== proposedContent) {
      return mutationFail("failed", "The semantic mutation could not be verified.");
    }
    if (request.verify) {
      let verified: boolean;
      try {
        verified = await request.verify(readback);
      } catch {
        return mutationFail("failed", "The semantic mutation postcondition failed.");
      }
      if (!verified) {
        return mutationFail("failed", "The semantic mutation postcondition failed.");
      }
    }

    const receipt: MutationReceipt = {
      operation: request.operation,
      path: request.path,
      changed,
      verified: true,
      idempotentReplay: false,
      beforeHash,
      afterHash,
      beforeBytes,
      afterBytes,
      ...location,
    };
    this.remember(identity, receipt);
    return receipt;
  }
}
