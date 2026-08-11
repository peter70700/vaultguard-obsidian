export type AtRestPayloadClassification =
  | { kind: "encrypted" }
  | { kind: "plaintext" }
  | {
      kind: "corrupt-protected";
      reason: "durable-protected-marker" | "truncated-vg1-header" | "unsupported-vg1-version";
    };

const VG1_MAGIC = [0x56, 0x47, 0x31, 0x00] as const;
const VG1_VERSION = 0x01;
const VG1_MIN_BYTES = 8 + 12 + 16;

/**
 * Classify bytes before any plaintext fallback. A durable protected marker is
 * authoritative: a protected path whose bytes no longer carry a complete VG1
 * envelope is corruption, never legacy plaintext. Partial/unsupported VG1
 * headers also fail closed even before a path has been migrated into the index.
 */
export function classifyAtRestPayload(
  data: ArrayBuffer | Uint8Array,
  durablyProtected: boolean,
): AtRestPayloadClassification {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const magicMatches =
    bytes.length >= VG1_MAGIC.length && VG1_MAGIC.every((value, index) => bytes[index] === value);

  if (magicMatches && bytes.length >= VG1_MIN_BYTES && bytes[4] === VG1_VERSION) {
    return { kind: "encrypted" };
  }
  if (durablyProtected) {
    return { kind: "corrupt-protected", reason: "durable-protected-marker" };
  }

  const matchedPrefix = VG1_MAGIC.reduce<number>(
    (count, value, index) => (count === index && bytes[index] === value ? count + 1 : count),
    0,
  );
  if (matchedPrefix >= 3 || magicMatches) {
    return {
      kind: "corrupt-protected",
      reason:
        magicMatches && bytes.length >= 5 && bytes[4] !== VG1_VERSION
          ? "unsupported-vg1-version"
          : "truncated-vg1-header",
    };
  }
  return { kind: "plaintext" };
}

export interface AtRestProtectionStateIo {
  read(): Promise<string | null>;
  write(serialized: string): Promise<void>;
}

interface PersistedProtectionState {
  version: 1;
  protectedPathHashes: Record<string, true>;
  migrationComplete: boolean;
}

const EMPTY_STATE = (): PersistedProtectionState => ({
  version: 1,
  protectedPathHashes: {},
  migrationComplete: false,
});

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/{2,}/g, "/");
}

/**
 * Versioned, path-redacted durable protection index. Only SHA-256 path hashes
 * are stored, so the sidecar cannot become a plaintext filename inventory.
 */
export class AtRestProtectionStateStore {
  private state: PersistedProtectionState | null = null;
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly io: AtRestProtectionStateIo) {}

  private async load(): Promise<PersistedProtectionState> {
    if (this.state) return this.state;
    const raw = await this.io.read();
    if (raw === null || raw.trim() === "") {
      this.state = EMPTY_STATE();
      return this.state;
    }
    const parsed = JSON.parse(raw) as Partial<PersistedProtectionState>;
    if (
      parsed.version !== 1 ||
      !parsed.protectedPathHashes ||
      typeof parsed.protectedPathHashes !== "object" ||
      Array.isArray(parsed.protectedPathHashes) ||
      (parsed.migrationComplete !== undefined && typeof parsed.migrationComplete !== "boolean") ||
      Object.entries(parsed.protectedPathHashes).some(
        ([key, value]) => !/^[a-f0-9]{64}$/.test(key) || value !== true,
      )
    ) {
      throw new Error("VaultGuard at-rest protection state is malformed; protected files cannot be classified safely.");
    }
    this.state = {
      version: 1,
      protectedPathHashes: { ...parsed.protectedPathHashes } as Record<string, true>,
      migrationComplete: parsed.migrationComplete === true,
    };
    return this.state;
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation, operation);
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async key(path: string): Promise<string> {
    return sha256Hex(normalizePath(path));
  }

  async isProtected(path: string): Promise<boolean> {
    await this.queue;
    const state = await this.load();
    return state.protectedPathHashes[await this.key(path)] === true;
  }

  async markProtected(path: string): Promise<void> {
    return this.markProtectedMany([path]);
  }

  async markProtectedMany(paths: readonly string[]): Promise<void> {
    return this.enqueue(async () => {
      const state = await this.load();
      const keys = await Promise.all([...new Set(paths.map(normalizePath))].map((path) => this.key(path)));
      if (keys.every((key) => state.protectedPathHashes[key] === true)) return;
      const protectedPathHashes = { ...state.protectedPathHashes };
      for (const key of keys) protectedPathHashes[key] = true;
      const next: PersistedProtectionState = {
        version: 1,
        protectedPathHashes,
        migrationComplete: state.migrationComplete,
      };
      await this.io.write(JSON.stringify(next));
      this.state = next;
    });
  }

  async clear(path: string): Promise<void> {
    return this.enqueue(async () => {
      const state = await this.load();
      const key = await this.key(path);
      if (state.protectedPathHashes[key] !== true) return;
      const protectedPathHashes = { ...state.protectedPathHashes };
      delete protectedPathHashes[key];
      const next: PersistedProtectionState = {
        version: 1,
        protectedPathHashes,
        migrationComplete: state.migrationComplete,
      };
      await this.io.write(JSON.stringify(next));
      this.state = next;
    });
  }

  async move(oldPath: string, newPath: string): Promise<void> {
    return this.enqueue(async () => {
      const state = await this.load();
      const [oldKey, newKey] = await Promise.all([this.key(oldPath), this.key(newPath)]);
      if (state.protectedPathHashes[oldKey] !== true) return;
      const protectedPathHashes = { ...state.protectedPathHashes };
      delete protectedPathHashes[oldKey];
      protectedPathHashes[newKey] = true;
      const next: PersistedProtectionState = {
        version: 1,
        protectedPathHashes,
        migrationComplete: state.migrationComplete,
      };
      await this.io.write(JSON.stringify(next));
      this.state = next;
    });
  }

  async clearAll(): Promise<void> {
    return this.enqueue(async () => {
      await this.load();
      const next = EMPTY_STATE();
      await this.io.write(JSON.stringify(next));
      this.state = next;
    });
  }

  async isMigrationComplete(): Promise<boolean> {
    await this.queue;
    return (await this.load()).migrationComplete;
  }

  async completeMigration(protectedPaths: readonly string[]): Promise<void> {
    return this.enqueue(async () => {
      const state = await this.load();
      const keys = await Promise.all(
        [...new Set(protectedPaths.map(normalizePath))].map((path) => this.key(path)),
      );
      const protectedPathHashes = { ...state.protectedPathHashes };
      for (const key of keys) protectedPathHashes[key] = true;
      const next: PersistedProtectionState = {
        version: 1,
        protectedPathHashes,
        migrationComplete: true,
      };
      await this.io.write(JSON.stringify(next));
      this.state = next;
    });
  }
}
