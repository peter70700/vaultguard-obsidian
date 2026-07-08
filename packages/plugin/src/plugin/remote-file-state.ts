export type RemoteFileStateKind = "present" | "absent" | "unknown";

export interface RemoteFileStateEntry {
  path: string;
  state: RemoteFileStateKind;
  versionId?: string;
  baseHash?: string;
  checksum?: string;
  lastModified?: string;
  size?: number;
  updatedAt: string;
}

export interface RemoteFileStateUpdate {
  versionId?: string | null;
  baseHash?: string | null;
  checksum?: string | null;
  lastModified?: string | null;
  size?: number | null;
}

export interface RemoteFileStateSnapshot {
  v: 1;
  entries: RemoteFileStateEntry[];
}

function normalizeRemoteStatePath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\/+/, "");
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function optionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export class RemoteFileStateStore {
  private readonly entries = new Map<string, RemoteFileStateEntry>();

  get(path: string): RemoteFileStateEntry | null {
    return this.entries.get(normalizeRemoteStatePath(path)) ?? null;
  }

  getExpectedVersionId(path: string): string | undefined {
    const entry = this.get(path);
    if (!entry || entry.state !== "present") return undefined;
    return entry.versionId;
  }

  recordPresent(path: string, update: RemoteFileStateUpdate = {}): void {
    const normalized = normalizeRemoteStatePath(path);
    if (!normalized) return;
    const previous = this.entries.get(normalized);
    this.entries.set(normalized, {
      path: normalized,
      state: "present",
      versionId: update.versionId ?? previous?.versionId,
      baseHash: update.baseHash ?? previous?.baseHash,
      checksum: update.checksum ?? previous?.checksum,
      lastModified: update.lastModified ?? previous?.lastModified,
      size: update.size ?? previous?.size,
      updatedAt: new Date().toISOString(),
    });
  }

  recordAbsent(path: string): void {
    const normalized = normalizeRemoteStatePath(path);
    if (!normalized) return;
    this.entries.set(normalized, {
      path: normalized,
      state: "absent",
      updatedAt: new Date().toISOString(),
    });
  }

  clear(): void {
    this.entries.clear();
  }

  load(entries: RemoteFileStateEntry[]): void {
    this.entries.clear();
    for (const entry of entries) {
      const normalized = normalizeRemoteStatePath(entry.path);
      if (!normalized) continue;
      if (entry.state !== "present" && entry.state !== "absent") continue;
      this.entries.set(normalized, {
        path: normalized,
        state: entry.state,
        versionId: optionalString(entry.versionId),
        baseHash: optionalString(entry.baseHash),
        checksum: optionalString(entry.checksum),
        lastModified: optionalString(entry.lastModified),
        size: optionalNumber(entry.size),
        updatedAt: optionalString(entry.updatedAt) ?? new Date().toISOString(),
      });
    }
  }

  snapshot(): RemoteFileStateSnapshot {
    return {
      v: 1,
      entries: Array.from(this.entries.values()),
    };
  }

  isEmpty(): boolean {
    return this.entries.size === 0;
  }
}
