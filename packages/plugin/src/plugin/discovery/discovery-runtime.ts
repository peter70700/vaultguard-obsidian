import {
  AuthenticationError,
  AuthorizationError,
  NetworkError,
  SubscriptionRequiredError,
  VaultGuardError,
  type VaultFileDecryptedResponse,
  type VaultFileListOptions,
  type VaultFileListPage,
  type VaultRecord,
} from "../../api/client";
import { PermissionLevel } from "../../types";
import type { PermissionDecision } from "../permission-store";
import {
  DISCOVERY_BUDGETS,
  SearchGeneration,
  addPartialReason,
  createEmptyCoverage,
  normalizeVaultRelativePath,
  sanitizeSnippet,
  scorePathMatch,
  sortSecureSearchResults,
  type SearchCoverage,
  type SecureSearchAccess,
  type SecureSearchRequest,
  type SecureSearchResponse,
  type SecureSearchResult,
} from "./search-model";

export interface DiscoveryLocalFile {
  path: string;
  size?: number;
}

export interface DiscoveryRuntimeContext {
  isModuleEnabled(): boolean;
  getSession(): { userId: string } | null;
  getBoundVault(): { id: string; name: string } | null;
  getLocalFiles(): readonly DiscoveryLocalFile[];
  readLocalText(path: string): Promise<string>;
  getPermissionDecision(path: string): Promise<PermissionDecision>;
  isPathExcluded(path: string): boolean;
  isMetadataSuppressed(path: string): boolean;
  listVaults(): Promise<VaultRecord[]>;
  listVaultFilesPage(vaultId: string, options?: VaultFileListOptions): Promise<VaultFileListPage>;
  readVaultFileDecrypted(vaultId: string, path: string): Promise<VaultFileDecryptedResponse>;
  searchSemantic?(request: SecureSearchRequest): Promise<SecureSearchResponse>;
  cancelSemantic?(): void;
  yieldControl(): Promise<void>;
  now(): number;
}

interface ContentBudgetState {
  files: number;
  bytes: number;
}

interface RemoteContentCandidate {
  vaultId: string;
  vaultName: string;
  path: string;
}

interface SearchState {
  generation: number;
  request: SecureSearchRequest;
  coverage: SearchCoverage;
  results: Map<string, SecureSearchResult>;
  content: ContentBudgetState;
  contentCandidates: RemoteContentCandidate[];
  revokedVaults: Set<string>;
  failedVaults: Set<string>;
  truncatedVaults: Set<string>;
  metadataStartedAt: number;
  contentStartedAt: number;
}

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

function resultKey(vaultId: string, path: string): string {
  return `${vaultId}\u0000${path}`;
}

function permissionAccess(decision: PermissionDecision): SecureSearchAccess | null {
  if (decision.kind === "unknown" || decision.level < PermissionLevel.READ) return null;
  if (decision.level >= PermissionLevel.ADMIN) return "admin";
  if (decision.level >= PermissionLevel.WRITE) return "write";
  return "read";
}

function contentScore(index: number, contentLength: number): number {
  const position = Math.max(0, Math.min(contentLength, index));
  const earlyBonus = contentLength > 0 ? 0.09 * (1 - position / contentLength) : 0;
  return Math.min(0.69, 0.6 + earlyBonus);
}

function isMarkdownPath(path: string): boolean {
  return path.toLocaleLowerCase("en-US").endsWith(".md");
}

function isRemoteExcluded(vault: VaultRecord, path: string): boolean {
  const first = path.split("/")[0] ?? "";
  if (first.startsWith(".")) return true;
  for (const raw of vault.excludedPaths ?? []) {
    const excluded = raw.trim().replace(/^\/+/, "").replace(/\/+$/, "");
    if (excluded && (path === excluded || path.startsWith(`${excluded}/`))) return true;
  }
  return false;
}

function errorStatus(error: unknown): number | null {
  if (error instanceof AuthenticationError) return 401;
  if (error instanceof SubscriptionRequiredError) return 402;
  if (error instanceof AuthorizationError) return 403;
  if (error instanceof VaultGuardError && error.apiError?.statusCode) {
    return error.apiError.statusCode;
  }
  return null;
}

function isFatalIdentityError(error: unknown): boolean {
  const status = errorStatus(error);
  return status === 401 || status === 402;
}

async function runWorkerPool<T>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const count = Math.min(Math.max(1, concurrency), items.length);
  await Promise.all(Array.from({ length: count }, async () => {
    while (true) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      await worker(items[index]!);
    }
  }));
}

export class DiscoveryRuntime {
  private readonly generations = new SearchGeneration();

  constructor(private readonly ctx: DiscoveryRuntimeContext) {}

  cancel(): void {
    this.generations.cancel();
    this.ctx.cancelSemantic?.();
  }

  async search(request: SecureSearchRequest): Promise<SecureSearchResponse> {
    if (!this.ctx.isModuleEnabled()) {
      throw new Error("Secure Discovery is disabled.");
    }
    if (!this.ctx.getSession()) {
      throw new AuthenticationError("Sign in before searching VaultGuard knowledge.");
    }
    const boundVault = this.ctx.getBoundVault();
    if (!boundVault) {
      throw new Error("Bind this local folder to a VaultGuard vault before searching.");
    }
    if (request.semantic) {
      if (!this.ctx.searchSemantic) throw new Error("Semantic search runtime is not available.");
      return await this.ctx.searchSemantic(request);
    }

    const state: SearchState = {
      generation: this.generations.start(),
      request,
      coverage: createEmptyCoverage(),
      results: new Map(),
      content: { files: 0, bytes: 0 },
      contentCandidates: [],
      revokedVaults: new Set(),
      failedVaults: new Set(),
      truncatedVaults: new Set(),
      metadataStartedAt: this.ctx.now(),
      contentStartedAt: this.ctx.now(),
    };

    if (request.scope === "current") {
      state.coverage.vaultsConsidered = 1;
      await this.scanLocalVault(state, boundVault);
    } else {
      await this.scanAllVaults(state, boundVault);
    }

    if (!this.isCurrent(state)) {
      return this.cancelledResponse(state);
    }
    const results = sortSecureSearchResults(
      [...state.results.values()].filter((result) => !state.revokedVaults.has(result.vaultId)),
    ).slice(0, request.limit);
    return {
      schemaVersion: 1,
      query: request.query,
      scope: request.scope,
      results,
      coverage: state.coverage,
    };
  }

  private isCurrent(state: SearchState): boolean {
    return this.generations.isCurrent(state.generation);
  }

  private cancelledResponse(state: SearchState): SecureSearchResponse {
    addPartialReason(state.coverage, "cancelled");
    return {
      schemaVersion: 1,
      query: state.request.query,
      scope: state.request.scope,
      results: [],
      coverage: state.coverage,
    };
  }

  private metadataTimedOut(state: SearchState): boolean {
    if (this.ctx.now() - state.metadataStartedAt <= DISCOVERY_BUDGETS.metadataDeadlineMs) {
      return false;
    }
    addPartialReason(state.coverage, "timeout");
    return true;
  }

  private contentTimedOut(state: SearchState): boolean {
    if (this.ctx.now() - state.contentStartedAt <= DISCOVERY_BUDGETS.contentDeadlineMs) {
      return false;
    }
    addPartialReason(state.coverage, "timeout");
    return true;
  }

  private async scanLocalVault(
    state: SearchState,
    boundVault: { id: string; name: string },
  ): Promise<void> {
    state.coverage.vaultsSearched += 1;
    const seen = new Set<string>();
    for (const file of this.ctx.getLocalFiles()) {
      if (!this.isCurrent(state)) return;
      if (state.coverage.metadataFiles >= DISCOVERY_BUDGETS.maxMetadataFiles) {
        addPartialReason(state.coverage, "limit");
        break;
      }
      const path = normalizeVaultRelativePath(file.path);
      if (
        !path ||
        seen.has(path) ||
        !isMarkdownPath(path) ||
        this.ctx.isPathExcluded(path) ||
        this.ctx.isMetadataSuppressed(path)
      ) {
        state.coverage.skippedFiles += 1;
        continue;
      }
      seen.add(path);

      const initialDecision = await this.ctx.getPermissionDecision(path);
      if (!this.isCurrent(state)) return;
      const initialAccess = permissionAccess(initialDecision);
      if (!initialAccess) {
        state.coverage.skippedFiles += 1;
        continue;
      }
      state.coverage.metadataFiles += 1;

      const pathScore = scorePathMatch(path, state.request.query);
      let score = pathScore;
      let matchKind: "path" | "content" = "path";
      let snippet: string | undefined;

      if (state.request.includeContent) {
        if (
          state.content.files >= DISCOVERY_BUDGETS.maxContentFiles ||
          (typeof file.size === "number" && file.size > DISCOVERY_BUDGETS.maxContentBytesPerFile)
        ) {
          state.coverage.skippedFiles += 1;
          addPartialReason(state.coverage, "limit");
        } else if (!this.contentTimedOut(state)) {
          state.content.files += 1;
          let content: string;
          try {
            content = await this.ctx.readLocalText(path);
          } catch (error) {
            state.coverage.skippedFiles += 1;
            addPartialReason(
              state.coverage,
              error instanceof NetworkError ? "offline" : "content-failure",
            );
            continue;
          }
          if (!this.isCurrent(state)) return;
          const byteLength = utf8Encoder.encode(content).byteLength;
          if (
            byteLength > DISCOVERY_BUDGETS.maxContentBytesPerFile ||
            state.content.bytes + byteLength > DISCOVERY_BUDGETS.maxContentBytesTotal
          ) {
            state.coverage.skippedFiles += 1;
            addPartialReason(state.coverage, "limit");
          } else {
            state.content.bytes += byteLength;
            state.coverage.contentFiles += 1;
            const normalizedContent = content.toLocaleLowerCase("en-US");
            const matchIndex = normalizedContent.indexOf(
              state.request.query.toLocaleLowerCase("en-US"),
            );
            if (matchIndex >= 0) {
              score = Math.max(pathScore ?? 0, contentScore(matchIndex, content.length));
              matchKind = "content";
              snippet = sanitizeSnippet(content, matchIndex);
            }
          }
        }
      }

      if (score === null) continue;
      const finalDecision = await this.ctx.getPermissionDecision(path);
      if (!this.isCurrent(state)) return;
      const finalAccess = permissionAccess(finalDecision);
      if (!finalAccess) {
        state.coverage.skippedFiles += 1;
        continue;
      }
      this.mergeResult(state, {
        vaultId: boundVault.id,
        vaultName: boundVault.name,
        path,
        local: true,
        matchKind,
        score,
        access: finalAccess,
        ...(snippet ? { snippet } : {}),
      });
      await this.ctx.yieldControl();
    }
  }

  private async scanAllVaults(
    state: SearchState,
    boundVault: { id: string; name: string },
  ): Promise<void> {
    let vaults: VaultRecord[];
    try {
      vaults = await this.ctx.listVaults();
    } catch (error) {
      if (isFatalIdentityError(error)) throw error;
      addPartialReason(
        state.coverage,
        error instanceof NetworkError ? "offline" : "vault-failure",
      );
      state.coverage.failedVaults += 1;
      return;
    }
    if (!this.isCurrent(state)) return;

    const active: VaultRecord[] = [];
    const seen = new Set<string>();
    for (const vault of vaults) {
      if (
        !vault ||
        vault.archived ||
        typeof vault.vaultId !== "string" ||
        !vault.vaultId ||
        seen.has(vault.vaultId)
      ) {
        continue;
      }
      seen.add(vault.vaultId);
      active.push(vault);
    }
    active.sort((left, right) =>
      left.name.localeCompare(right.name, undefined, { sensitivity: "base" }) ||
      left.vaultId.localeCompare(right.vaultId),
    );
    if (active.length > DISCOVERY_BUDGETS.maxVaults) {
      const totalActive = active.length;
      const boundIndex = active.findIndex((vault) => vault.vaultId === boundVault.id);
      const bounded = active.slice(0, DISCOVERY_BUDGETS.maxVaults);
      if (boundIndex >= DISCOVERY_BUDGETS.maxVaults) {
        // The all-vault contract always searches the current local vault. Keep
        // it in the bounded set even when its display name sorts after the
        // remote-vault cap, replacing the last remote candidate deterministically.
        bounded[bounded.length - 1] = active[boundIndex]!;
      }
      active.splice(0, active.length, ...bounded);
      state.coverage.truncatedVaults += totalActive - active.length;
      addPartialReason(state.coverage, "limit");
    }
    state.coverage.vaultsConsidered = active.length;

    const local = active.find((vault) => vault.vaultId === boundVault.id);
    if (local) {
      await this.scanLocalVault(state, { id: local.vaultId, name: local.name || boundVault.name });
    } else {
      state.coverage.failedVaults += 1;
      addPartialReason(state.coverage, "vault-failure");
    }
    if (!this.isCurrent(state)) return;

    const remoteVaults = active.filter((vault) => vault.vaultId !== boundVault.id);
    await runWorkerPool(remoteVaults, DISCOVERY_BUDGETS.maxListConcurrency, async (vault) => {
      await this.scanRemoteVault(state, vault);
    });
    if (!this.isCurrent(state) || !state.request.includeContent) return;
    await this.scanRemoteContent(state);
  }

  private async scanRemoteVault(state: SearchState, vault: VaultRecord): Promise<void> {
    let cursor: string | undefined;
    let filesForVault = 0;
    let completedPage = false;
    const seenCursors = new Set<string>();
    do {
      if (!this.isCurrent(state) || state.revokedVaults.has(vault.vaultId)) return;
      if (this.metadataTimedOut(state)) {
        this.markVaultTruncated(state, vault.vaultId);
        return;
      }
      if (
        filesForVault >= DISCOVERY_BUDGETS.maxMetadataFilesPerVault ||
        state.coverage.metadataFiles >= DISCOVERY_BUDGETS.maxMetadataFiles
      ) {
        addPartialReason(state.coverage, "limit");
        this.markVaultTruncated(state, vault.vaultId);
        return;
      }

      let response: VaultFileListPage;
      try {
        response = await this.ctx.listVaultFilesPage(vault.vaultId, {
          limit: DISCOVERY_BUDGETS.metadataPageSize,
          ...(cursor ? { continuationToken: cursor } : {}),
        });
      } catch (error) {
        if (isFatalIdentityError(error)) throw error;
        if (errorStatus(error) === 403) {
          state.revokedVaults.add(vault.vaultId);
          this.discardVault(state, vault.vaultId);
        }
        this.markVaultFailed(state, vault.vaultId);
        if (error instanceof NetworkError) addPartialReason(state.coverage, "offline");
        return;
      }
      if (!this.isCurrent(state)) return;
      if (!completedPage) {
        completedPage = true;
        state.coverage.vaultsSearched += 1;
      }

      for (const item of response.files) {
        if (
          filesForVault >= DISCOVERY_BUDGETS.maxMetadataFilesPerVault ||
          state.coverage.metadataFiles >= DISCOVERY_BUDGETS.maxMetadataFiles
        ) {
          addPartialReason(state.coverage, "limit");
          this.markVaultTruncated(state, vault.vaultId);
          break;
        }
        const path = normalizeVaultRelativePath(item.path);
        if (!path || isRemoteExcluded(vault, path)) {
          state.coverage.skippedFiles += 1;
          continue;
        }
        filesForVault += 1;
        state.coverage.metadataFiles += 1;
        const score = scorePathMatch(path, state.request.query);
        if (score !== null) {
          this.mergeResult(state, {
            vaultId: vault.vaultId,
            vaultName: vault.name,
            path,
            local: false,
            matchKind: "path",
            score,
            access: "list",
          });
        }
        if (state.request.includeContent && isMarkdownPath(path)) {
          if (item.size > DISCOVERY_BUDGETS.maxContentBytesPerFile) {
            state.coverage.skippedFiles += 1;
            addPartialReason(state.coverage, "limit");
          } else {
            state.contentCandidates.push({
              vaultId: vault.vaultId,
              vaultName: vault.name,
              path,
            });
          }
        }
      }

      const nextCursor = response.nextContinuationToken ?? undefined;
      if (!nextCursor) break;
      if (nextCursor === cursor || seenCursors.has(nextCursor)) {
        this.markVaultTruncated(state, vault.vaultId);
        addPartialReason(state.coverage, "truncated");
        return;
      }
      seenCursors.add(nextCursor);
      cursor = nextCursor;
      await this.ctx.yieldControl();
    } while (cursor);
  }

  private async scanRemoteContent(state: SearchState): Promise<void> {
    state.contentStartedAt = this.ctx.now();
    const candidates = state.contentCandidates
      .filter((candidate) => !state.revokedVaults.has(candidate.vaultId))
      .sort((left, right) =>
        left.vaultName.localeCompare(right.vaultName, undefined, { sensitivity: "base" }) ||
        left.path.localeCompare(right.path, undefined, { sensitivity: "base" }),
      );
    if (candidates.length > DISCOVERY_BUDGETS.maxContentFiles - state.content.files) {
      addPartialReason(state.coverage, "limit");
    }
    const available = Math.max(0, DISCOVERY_BUDGETS.maxContentFiles - state.content.files);
    const selected = candidates.slice(0, available);

    await runWorkerPool(selected, DISCOVERY_BUDGETS.maxRemoteReadConcurrency, async (candidate) => {
      if (
        !this.isCurrent(state) ||
        state.revokedVaults.has(candidate.vaultId) ||
        this.contentTimedOut(state)
      ) {
        return;
      }
      // Reserve before the await so concurrent workers cannot exceed the cap.
      state.content.files += 1;
      let response: VaultFileDecryptedResponse;
      try {
        response = await this.ctx.readVaultFileDecrypted(candidate.vaultId, candidate.path);
      } catch (error) {
        if (isFatalIdentityError(error)) throw error;
        const status = errorStatus(error);
        if (status === 404) {
          state.coverage.skippedFiles += 1;
          return;
        }
        if (status === 403) {
          state.revokedVaults.add(candidate.vaultId);
          this.discardVault(state, candidate.vaultId);
          this.markVaultFailed(state, candidate.vaultId);
          return;
        }
        state.coverage.skippedFiles += 1;
        addPartialReason(
          state.coverage,
          error instanceof NetworkError ? "offline" : "content-failure",
        );
        return;
      }
      if (!this.isCurrent(state) || state.revokedVaults.has(candidate.vaultId)) return;

      const bytes = new Uint8Array(response.content);
      if (
        bytes.byteLength > DISCOVERY_BUDGETS.maxContentBytesPerFile ||
        state.content.bytes + bytes.byteLength > DISCOVERY_BUDGETS.maxContentBytesTotal
      ) {
        state.coverage.skippedFiles += 1;
        addPartialReason(state.coverage, "limit");
        return;
      }
      state.content.bytes += bytes.byteLength;
      let content: string;
      try {
        content = utf8Decoder.decode(bytes);
      } catch {
        state.coverage.skippedFiles += 1;
        addPartialReason(state.coverage, "content-failure");
        return;
      } finally {
        bytes.fill(0);
      }
      state.coverage.contentFiles += 1;
      const matchIndex = content
        .toLocaleLowerCase("en-US")
        .indexOf(state.request.query.toLocaleLowerCase("en-US"));
      if (matchIndex < 0) return;
      this.mergeResult(state, {
        vaultId: candidate.vaultId,
        vaultName: candidate.vaultName,
        path: candidate.path,
        local: false,
        matchKind: "content",
        score: contentScore(matchIndex, content.length),
        access: "read",
        snippet: sanitizeSnippet(content, matchIndex),
      });
    });
  }

  private mergeResult(state: SearchState, candidate: SecureSearchResult): void {
    const key = resultKey(candidate.vaultId, candidate.path);
    const existing = state.results.get(key);
    if (!existing) {
      state.results.set(key, candidate);
      return;
    }
    const preferContent = candidate.matchKind === "content" && existing.matchKind !== "content";
    const accessRank: Record<SecureSearchAccess, number> = {
      list: 0,
      read: 1,
      write: 2,
      admin: 3,
    };
    state.results.set(key, {
      ...existing,
      ...(preferContent ? { matchKind: candidate.matchKind } : {}),
      score: Math.max(existing.score, candidate.score),
      access: accessRank[candidate.access] > accessRank[existing.access]
        ? candidate.access
        : existing.access,
      ...(candidate.snippet ? { snippet: candidate.snippet } : {}),
    });
  }

  private discardVault(state: SearchState, vaultId: string): void {
    for (const [key, result] of state.results) {
      if (result.vaultId === vaultId) state.results.delete(key);
    }
    state.contentCandidates = state.contentCandidates.filter(
      (candidate) => candidate.vaultId !== vaultId,
    );
  }

  private markVaultFailed(state: SearchState, vaultId: string): void {
    if (state.failedVaults.has(vaultId)) return;
    state.failedVaults.add(vaultId);
    state.coverage.failedVaults += 1;
    addPartialReason(state.coverage, "vault-failure");
  }

  private markVaultTruncated(state: SearchState, vaultId: string): void {
    if (state.truncatedVaults.has(vaultId)) return;
    state.truncatedVaults.add(vaultId);
    state.coverage.truncatedVaults += 1;
  }
}
