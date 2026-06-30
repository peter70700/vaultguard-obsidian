import {
  PermissionsGraphView,
  VAULTGUARD_GRAPH_VIEW_TYPE,
  type PermissionsGraphDataSource,
  type PermissionsGraphDataset,
} from "../ui/graph/permissions-graph-view";
import type { PermissionsGraphRuntimeContext } from "./plugin-runtime-types";

/**
 * On-disk shape of the LAK-encrypted permissions-graph cache envelope. Stamped
 * with the owning userId so it's never surfaced to a different signed-in user.
 */
interface PersistedPermissionsGraphCache {
  // Bumped to 2 when the dataset gained per-folder access summaries; v1 envelopes
  // are rejected so old caches can't mask the folder-permission feature.
  version: 2;
  userId: string;
  entries: Record<string, { fetchedAt: number; data: PermissionsGraphDataset }>;
}

export class PermissionsGraphRuntime {
  // Two layers: a fast in-memory map, and a disk envelope encrypted with the LAK
  // (AtRestCipher) so the cached permissions map survives a restart yet stays
  // opaque to a forensic disk image.
  private readonly cache = new Map<
    string,
    { data: PermissionsGraphDataset; fetchedAt: number }
  >();
  private static readonly CACHE_TTL_MS = 30 * 60_000;

  constructor(private readonly ctx: PermissionsGraphRuntimeContext) {}

  /**
   * Data source for the Permissions graph view. Delegates every call to the
   * authenticated API client (requestUrl underneath) and fails closed if the
   * client is not ready.
   */
  getDataSource(): PermissionsGraphDataSource {
    return {
      listVaultMembers: (vaultId) => {
        if (!this.ctx.apiClient) throw new Error("VaultGuard is not connected.");
        return this.ctx.apiClient.listVaultMembers(vaultId);
      },
      getPermissions: () => {
        if (!this.ctx.apiClient) throw new Error("VaultGuard is not connected.");
        return this.ctx.apiClient.getPermissions();
      },
      getUserPermissions: (userId) => {
        if (!this.ctx.apiClient) throw new Error("VaultGuard is not connected.");
        return this.ctx.apiClient.getUserPermissions(userId);
      },
      getBatchPathAccess: (paths) => {
        if (!this.ctx.apiClient) throw new Error("VaultGuard is not connected.");
        return this.ctx.apiClient.getBatchPathAccess(paths);
      },
      getAllFilePaths: () =>
        this.ctx.app.vault
          .getFiles()
          .map((file) => this.ctx.normalizeVaultPath(file.path)),
    };
  }

  /** In-memory cached dataset for a vault, or null if absent/expired. */
  getCache(vaultId: string): PermissionsGraphDataset | null {
    const entry = this.cache.get(vaultId);
    if (!entry) return null;
    if (!this.isCacheFresh(entry.fetchedAt)) {
      this.cache.delete(vaultId);
      return null;
    }
    return entry.data;
  }

  /**
   * Cached dataset for a vault, checking memory first then the encrypted disk
   * envelope (hydrating memory on a disk hit). Returns null when nothing fresh
   * exists for the current user.
   */
  async loadPersistedCache(vaultId: string): Promise<PermissionsGraphDataset | null> {
    const mem = this.getCache(vaultId);
    if (mem) return mem;

    if (!this.ctx.atRestCipher?.isReady()) return null;
    const readBin = this.ctx.adapterReadBinary;
    if (!readBin) return null;

    const path = this.cachePath();
    try {
      if (!(await this.ctx.app.vault.adapter.exists(path))) return null;
      const cipherBytes = await readBin(path);
      const plaintext = await this.ctx.atRestCipher.decryptString(cipherBytes);
      const env = JSON.parse(plaintext) as PersistedPermissionsGraphCache;
      if (!env || env.version !== 2) return null;
      // Belongs to a different user -> never surface it.
      if (env.userId !== (this.ctx.session?.userId ?? "")) return null;
      const entry = env.entries?.[vaultId];
      if (!entry || !this.isCacheFresh(entry.fetchedAt)) return null;
      this.cache.set(vaultId, { data: entry.data, fetchedAt: entry.fetchedAt });
      return entry.data;
    } catch (err) {
      this.ctx.logError("Failed to read permissions-graph cache", err);
      return null;
    }
  }

  async setCache(vaultId: string, data: PermissionsGraphDataset): Promise<void> {
    this.cache.set(vaultId, { data, fetchedAt: Date.now() });
    await this.persistCache().catch((err) =>
      this.ctx.logError("Failed to persist permissions-graph cache", err),
    );
  }

  /** Drop one vault's cache, or all of it when called with no argument. */
  invalidateCache(vaultId?: string): void {
    if (vaultId) {
      this.cache.delete(vaultId);
      void this.persistCache().catch(() => {});
    } else {
      this.cache.clear();
      void this.deleteCacheFile().catch(() => {});
    }
  }

  /** Re-render every open Permissions graph view (e.g. after coming online). */
  refreshOpenViews(): void {
    const leaves = this.ctx.app.workspace.getLeavesOfType(VAULTGUARD_GRAPH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof PermissionsGraphView) {
        void view.refresh();
      }
    }
  }

  private cachePath(): string {
    const pluginId = this.ctx.manifestId ?? "vaultguard-sync";
    return this.ctx.vaultConfigPath("plugins", pluginId, "permissions-graph.cache");
  }

  private isCacheFresh(fetchedAt: number): boolean {
    return Date.now() - fetchedAt <= PermissionsGraphRuntime.CACHE_TTL_MS;
  }

  /** Write the fresh in-memory entries to the encrypted disk envelope. */
  private async persistCache(): Promise<void> {
    if (!this.ctx.atRestCipher?.isReady()) return;
    const writeBin = this.ctx.adapterWriteBinary;
    if (!writeBin) return;
    const userId = this.ctx.session?.userId ?? "";
    if (!userId) return;

    const entries: PersistedPermissionsGraphCache["entries"] = {};
    for (const [vid, entry] of this.cache.entries()) {
      if (this.isCacheFresh(entry.fetchedAt)) {
        entries[vid] = { fetchedAt: entry.fetchedAt, data: entry.data };
      }
    }

    const env: PersistedPermissionsGraphCache = { version: 2, userId, entries };
    const path = this.cachePath();
    await this.ctx.ensureParentFoldersForPath(path);
    const cipher = await this.ctx.atRestCipher.encryptString(JSON.stringify(env));
    await writeBin(path, cipher);
  }

  private async deleteCacheFile(): Promise<void> {
    try {
      const path = this.cachePath();
      if (await this.ctx.app.vault.adapter.exists(path)) {
        await this.ctx.app.vault.adapter.remove(path);
      }
    } catch (err) {
      this.ctx.logError("Failed to delete permissions-graph cache", err);
    }
  }
}

export function createPermissionsGraphRuntime(
  ctx: PermissionsGraphRuntimeContext,
): PermissionsGraphRuntime {
  return new PermissionsGraphRuntime(ctx);
}
