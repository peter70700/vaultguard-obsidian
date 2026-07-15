import { PermissionLevel, type SemanticIndexState } from "../../types";
import type { PermissionDecision } from "../permission-store";
import {
  SemanticOperationCancelledError,
  type SemanticEmbeddingProvider,
} from "./ollama-embedding-provider";
import {
  SEMANTIC_CHUNKER_VERSION,
  chunkMarkdown,
} from "./semantic-chunker";
import type {
  SemanticIndexEntry,
  SemanticIndexEnvelope,
  SemanticIndexExpectedIdentity,
} from "./semantic-index-codec";
import {
  addPartialReason,
  createEmptyCoverage,
  normalizeVaultRelativePath,
  sanitizeSnippet,
  sortSecureSearchResults,
  type SecureSearchAccess,
  type SecureSearchRequest,
  type SecureSearchResponse,
} from "./search-model";

const MAX_NOTES = 1_000;
const MAX_CHUNKS = 25_000;
const MAX_DECRYPTED_BYTES = 128 * 1024 * 1024;
const MAX_RESULTS = 50;

export interface SemanticLocalFile {
  path: string;
  size?: number;
}

export interface SemanticIndexRepository {
  load(expected: SemanticIndexExpectedIdentity): Promise<SemanticIndexEnvelope | null>;
  save(envelope: SemanticIndexEnvelope): Promise<void>;
  purge(): Promise<void>;
}

export interface SemanticSearchRuntimeContext {
  isParentEnabled(): boolean;
  isSemanticEnabled(): boolean;
  getSession(): { userId: string } | null;
  getBoundVault(): { id: string; name: string } | null;
  getLocalVaultId(): string;
  getProviderConfig(): { origin: string; model: string };
  createProvider(config: { origin: string; model: string }): SemanticEmbeddingProvider;
  repository: SemanticIndexRepository;
  getLocalFiles(): readonly SemanticLocalFile[];
  readLocalText(path: string): Promise<string>;
  getPermissionDecision(path: string): Promise<PermissionDecision>;
  isPathExcluded(path: string): boolean;
  isMetadataSuppressed(path: string): boolean;
  yieldControl(): Promise<void>;
  now(): number;
}

export interface SemanticRuntimeStatus {
  state: SemanticIndexState;
  indexedFiles: number;
  indexedChunks: number;
  stale: boolean;
  processedFiles?: number;
  totalFiles?: number;
  skippedFiles?: number;
  failedFiles?: number;
  limitedFiles?: number;
  error?: string;
}

export interface SemanticSearchRuntimeLimits {
  maxNotes?: number;
  maxChunks?: number;
  maxDecryptedBytes?: number;
}

export interface SemanticQueryOptions {
  canUsePath?: (path: string) => Promise<boolean>;
}

export type SemanticPurgeReason =
  | "disable"
  | "logout"
  | "lock"
  | "vault-switch"
  | "provider-change"
  | "manual";

function permissionAccess(decision: PermissionDecision): SecureSearchAccess | null {
  if (decision.kind === "unknown" || decision.level < PermissionLevel.READ) return null;
  if (decision.level >= PermissionLevel.ADMIN) return "admin";
  if (decision.level >= PermissionLevel.WRITE) return "write";
  return "read";
}

function uniquePathCount(entries: readonly SemanticIndexEntry[]): number {
  return new Set(entries.map((entry) => entry.path)).size;
}

function boundedLimit(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error("Semantic runtime limits must be positive safe integers.");
  }
  return Math.min(value, fallback);
}

function utf8ByteLength(value: string): number {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x80) {
      bytes += 1;
    } else if (code < 0x800) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        index += 1;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

function identityMatches(
  envelope: SemanticIndexEnvelope,
  expected: SemanticIndexExpectedIdentity,
): boolean {
  return (
    envelope.schemaVersion === expected.schemaVersion &&
    envelope.userId === expected.userId &&
    envelope.localVaultId === expected.localVaultId &&
    envelope.vaultId === expected.vaultId &&
    envelope.provider === expected.provider &&
    envelope.providerOrigin === expected.providerOrigin &&
    envelope.model === expected.model &&
    envelope.chunkerVersion === expected.chunkerVersion &&
    (expected.dimensions === undefined || envelope.dimensions === expected.dimensions)
  );
}

function matchesGlob(path: string, rawPattern: string): boolean {
  const pattern = rawPattern.trim().replace(/^\/+/, "");
  if (!pattern) return true;
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index]!;
    if (char === "*" && pattern[index + 1] === "*") {
      source += ".*";
      index += 1;
    } else if (char === "*") {
      source += "[^/]*";
    } else {
      source += char.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    }
  }
  source += "$";
  return new RegExp(source, "u").test(path);
}

async function fingerprint(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  try {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
  } finally {
    bytes.fill(0);
  }
}

function dot(left: readonly number[], right: readonly number[]): number {
  let score = 0;
  for (let index = 0; index < left.length; index += 1) score += left[index]! * right[index]!;
  return score;
}

export class SemanticSearchRuntime {
  private envelope: SemanticIndexEnvelope | null = null;
  private generation = 0;
  private purgeEpoch = 0;
  private contentEpoch = 0;
  private filterEpoch = 0;
  private building = false;
  private buildIdle: Promise<void> = Promise.resolve();
  private finishBuildIdle: (() => void) | null = null;
  private repositoryTail: Promise<void> = Promise.resolve();
  private readonly limits: Required<SemanticSearchRuntimeLimits>;
  private status: SemanticRuntimeStatus = {
    state: "absent",
    indexedFiles: 0,
    indexedChunks: 0,
    stale: false,
  };
  private readonly listeners = new Set<(status: SemanticRuntimeStatus) => void>();

  constructor(
    private readonly context: SemanticSearchRuntimeContext,
    limits: SemanticSearchRuntimeLimits = {},
  ) {
    this.limits = {
      maxNotes: boundedLimit(limits.maxNotes, MAX_NOTES),
      maxChunks: boundedLimit(limits.maxChunks, MAX_CHUNKS),
      maxDecryptedBytes: boundedLimit(limits.maxDecryptedBytes, MAX_DECRYPTED_BYTES),
    };
  }

  getStatus(): SemanticRuntimeStatus {
    return { ...this.status };
  }

  subscribe(listener: (status: SemanticRuntimeStatus) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  cancel(): void {
    this.generation += 1;
  }

  async cancelAndWait(): Promise<void> {
    this.cancel();
    await this.buildIdle;
    await this.repositoryTail;
  }

  async load(): Promise<SemanticRuntimeStatus> {
    const { provider, expected } = this.requireReady();
    void provider;
    const generation = ++this.generation;
    this.setStatus({ ...this.status, state: "loading", error: undefined });
    try {
      const loaded = await this.withRepository(() => this.context.repository.load(expected));
      this.assertCurrent(generation);
      if (!loaded || !identityMatches(loaded, expected)) {
        this.envelope = null;
        this.setStatus({ state: "absent", indexedFiles: 0, indexedChunks: 0, stale: false });
        return this.getStatus();
      }
      this.envelope = loaded;
      this.setStatus({
        state: "ready",
        indexedFiles: uniquePathCount(loaded.entries),
        indexedChunks: loaded.entries.length,
        stale: false,
      });
    } catch (error) {
      if (error instanceof SemanticOperationCancelledError) throw error;
      this.envelope = null;
      this.setStatus({
        state: "absent",
        indexedFiles: 0,
        indexedChunks: 0,
        stale: false,
        error: "The encrypted semantic index could not be loaded.",
      });
    }
    return this.getStatus();
  }

  async build(): Promise<SemanticRuntimeStatus> {
    if (this.building) throw new Error("A semantic index build is already active.");
    const { provider, expected, vault } = this.requireReady();
    this.building = true;
    this.buildIdle = new Promise<void>((resolve) => {
      this.finishBuildIdle = resolve;
    });
    const generation = ++this.generation;
    const buildPurgeEpoch = this.purgeEpoch;
    const buildContentEpoch = this.contentEpoch;
    const previous = this.envelope;
    const previousStatus = this.getStatus();
    const progress = {
      processedFiles: 0,
      totalFiles: 0,
      skippedFiles: 0,
      failedFiles: 0,
      limitedFiles: 0,
    };
    let activeFile = false;
    this.setStatus({
      ...previousStatus,
      ...progress,
      state: "building",
      error: undefined,
    });

    try {
      let prior = previous && identityMatches(previous, expected) ? previous : null;
      if (!prior) {
        try {
          const loaded = await this.withRepository(() => this.context.repository.load(expected));
          prior = loaded && identityMatches(loaded, expected) ? loaded : null;
        } catch {
          await this.withRepository(() => this.context.repository.purge()).catch(() => {});
          prior = null;
        }
      }
      this.assertCurrent(generation);

      const priorByPath = new Map<string, SemanticIndexEntry[]>();
      for (const entry of prior?.entries ?? []) {
        const entries = priorByPath.get(entry.path) ?? [];
        entries.push(entry);
        priorByPath.set(entry.path, entries);
      }

      const seen = new Set<string>();
      const markdownFiles = this.context.getLocalFiles()
        .map((file) => ({ ...file, normalized: normalizeVaultRelativePath(file.path) }))
        .filter((file): file is SemanticLocalFile & { normalized: string } =>
          Boolean(
            file.normalized &&
            file.normalized.toLocaleLowerCase("en-US").endsWith(".md") &&
            !seen.has(file.normalized) &&
            seen.add(file.normalized),
          ),
        )
        .sort((left, right) => left.normalized.localeCompare(right.normalized, undefined, {
          sensitivity: "base",
        }));
      progress.totalFiles = markdownFiles.length;
      const eligibleFiles = markdownFiles.filter((file) => {
        const allowed =
          !this.context.isPathExcluded(file.normalized) &&
          !this.context.isMetadataSuppressed(file.normalized);
        if (!allowed) {
          progress.processedFiles += 1;
          progress.skippedFiles += 1;
        }
        return allowed;
      });
      const files = eligibleFiles.slice(0, this.limits.maxNotes);
      const noteLimitSkips = eligibleFiles.length - files.length;
      progress.processedFiles += noteLimitSkips;
      progress.skippedFiles += noteLimitSkips;
      progress.limitedFiles += noteLimitSkips;

      const replacement: SemanticIndexEntry[] = [];
      const replacementPaths = new Set<string>();
      let dimensions: number | null = prior?.dimensions ?? null;
      let decryptedBytes = 0;
      const finishFile = (kind: "indexed" | "skipped" | "failed", limited = false): void => {
        progress.processedFiles += 1;
        if (kind === "skipped") progress.skippedFiles += 1;
        if (kind === "failed") progress.failedFiles += 1;
        if (limited) progress.limitedFiles += 1;
        activeFile = false;
        this.publishBuildProgress(progress, replacementPaths.size, replacement.length);
      };
      this.publishBuildProgress(progress, 0, 0);
      for (let fileIndex = 0; fileIndex < files.length; fileIndex += 1) {
        const file = files[fileIndex]!;
        this.assertCurrent(generation);
        if (replacement.length >= this.limits.maxChunks) {
          const remaining = files.length - fileIndex;
          progress.processedFiles += remaining;
          progress.skippedFiles += remaining;
          progress.limitedFiles += remaining;
          this.publishBuildProgress(progress, replacementPaths.size, replacement.length);
          break;
        }
        activeFile = true;
        const remainingBytes = this.limits.maxDecryptedBytes - decryptedBytes;
        if (
          typeof file.size === "number" &&
          Number.isFinite(file.size) &&
          file.size >= 0 &&
          file.size > remainingBytes
        ) {
          finishFile("skipped", true);
          await this.context.yieldControl();
          continue;
        }
        const initial = await this.context.getPermissionDecision(file.normalized);
        this.assertCurrent(generation);
        if (!permissionAccess(initial)) {
          finishFile("skipped");
          await this.context.yieldControl();
          continue;
        }
        const content = await this.context.readLocalText(file.normalized);
        this.assertCurrent(generation);
        const contentBytes = utf8ByteLength(content);
        if (contentBytes > remainingBytes) {
          finishFile("skipped", true);
          await this.context.yieldControl();
          continue;
        }
        decryptedBytes += contentBytes;
        const beforeProvider = await this.context.getPermissionDecision(file.normalized);
        this.assertCurrent(generation);
        if (!permissionAccess(beforeProvider)) {
          finishFile("skipped");
          await this.context.yieldControl();
          continue;
        }
        const sourceFingerprint = await fingerprint(content);
        this.assertCurrent(generation);
        const priorEntries = priorByPath.get(file.normalized) ?? [];
        if (
          priorEntries.length > 0 &&
          priorEntries.every((entry) => entry.fingerprint === sourceFingerprint)
        ) {
          const finalDecision = await this.context.getPermissionDecision(file.normalized);
          this.assertCurrent(generation);
          if (permissionAccess(finalDecision)) {
            replacement.push(...priorEntries.map((entry) => ({
              ...entry,
              vector: [...entry.vector],
            })).slice(0, this.limits.maxChunks - replacement.length));
            replacementPaths.add(file.normalized);
            finishFile("indexed");
          } else {
            finishFile("skipped");
          }
          await this.context.yieldControl();
          continue;
        }

        const chunked = chunkMarkdown(content);
        const availableChunks = this.limits.maxChunks - replacement.length;
        const chunks = chunked.chunks.slice(0, availableChunks);
        const limited = chunked.truncated || chunks.length < chunked.chunks.length;
        if (chunks.length === 0) {
          finishFile("skipped", limited);
          await this.context.yieldControl();
          continue;
        }
        const vectors = await provider.embed(chunks.map((chunk) => chunk.text), {
          isCancelled: () => generation !== this.generation,
        });
        this.assertCurrent(generation);
        if (vectors.length !== chunks.length) {
          throw new Error("The semantic provider returned an unexpected vector count.");
        }
        const returnedDimensions = vectors[0]?.length ?? 0;
        if (returnedDimensions < 1 || vectors.some((vector) => vector.length !== returnedDimensions)) {
          throw new Error("The semantic provider returned inconsistent dimensions.");
        }
        if (dimensions !== null && dimensions !== returnedDimensions) {
          throw new Error("The semantic provider dimension changed; purge and rebuild the index.");
        }
        dimensions = returnedDimensions;
        const finalDecision = await this.context.getPermissionDecision(file.normalized);
        this.assertCurrent(generation);
        if (!permissionAccess(finalDecision)) {
          finishFile("skipped");
          await this.context.yieldControl();
          continue;
        }
        const indexedAt = this.context.now();
        for (let index = 0; index < chunks.length; index += 1) {
          const chunk = chunks[index]!;
          replacement.push({
            path: file.normalized,
            fingerprint: sourceFingerprint,
            chunkIndex: chunk.index,
            start: chunk.start,
            end: chunk.end,
            ...(chunk.heading ? { heading: chunk.heading } : {}),
            vector: [...vectors[index]!],
            indexedAt,
          });
        }
        replacementPaths.add(file.normalized);
        finishFile("indexed", limited);
        await this.context.yieldControl();
      }

      this.assertCurrent(generation);
      if (replacement.length === 0 || dimensions === null) {
        await this.withRepository(() => this.context.repository.purge());
        if (generation !== this.generation) {
          await this.restoreAfterCancelledCommit(previous, buildPurgeEpoch, buildContentEpoch);
          throw new SemanticOperationCancelledError();
        }
        this.envelope = null;
        this.setStatus({
          state: "absent",
          indexedFiles: 0,
          indexedChunks: 0,
          stale: false,
          ...progress,
        });
        return this.getStatus();
      }
      const candidate: SemanticIndexEnvelope = {
        ...expected,
        dimensions,
        generatedAt: this.context.now(),
        entries: replacement,
      };
      await this.withRepository(() => this.context.repository.save(candidate));
      if (generation !== this.generation) {
        await this.restoreAfterCancelledCommit(previous, buildPurgeEpoch, buildContentEpoch);
        throw new SemanticOperationCancelledError();
      }
      this.envelope = candidate;
      this.setStatus({
        state: "ready",
        indexedFiles: uniquePathCount(candidate.entries),
        indexedChunks: candidate.entries.length,
        stale: false,
        ...progress,
      });
      void vault;
      return this.getStatus();
    } catch (error) {
      if (error instanceof SemanticOperationCancelledError) {
        if (buildPurgeEpoch !== this.purgeEpoch) {
          this.envelope = null;
          this.setStatus({ state: "absent", indexedFiles: 0, indexedChunks: 0, stale: false });
        } else if (buildContentEpoch === this.contentEpoch) {
          this.envelope = previous;
          this.setStatus(previous
            ? { ...previousStatus, state: previousStatus.stale ? "stale" : "ready" }
            : { state: "absent", indexedFiles: 0, indexedChunks: 0, stale: false });
        } else if (this.status.state === "building") {
          this.refreshStaleStatus();
        }
        throw error;
      }
      if (activeFile) {
        progress.processedFiles += 1;
        progress.failedFiles += 1;
        activeFile = false;
      }
      this.envelope = previous;
      this.setStatus({
        ...(previous
          ? { ...previousStatus, state: "failed" as const }
          : { state: "failed" as const, indexedFiles: 0, indexedChunks: 0, stale: false }),
        ...progress,
        error: "The semantic index build failed.",
      });
      throw error;
    } finally {
      this.building = false;
      this.finishBuildIdle?.();
      this.finishBuildIdle = null;
    }
  }

  async query(
    request: SecureSearchRequest,
    options: SemanticQueryOptions = {},
  ): Promise<SecureSearchResponse> {
    if (!request.semantic || request.scope !== "current") {
      throw new Error("Semantic search is limited to explicit current-vault requests.");
    }
    if (this.building) throw new Error("Wait for the active semantic build to finish.");
    const { provider, expected, vault } = this.requireReady();
    if (!this.envelope || !identityMatches(this.envelope, expected)) await this.load();
    const active = this.envelope;
    if (!active || !identityMatches(active, expected)) {
      throw new Error("Build the current semantic index before searching.");
    }

    const generation = ++this.generation;
    const queryVector = (await provider.embed([request.query], {
      isCancelled: () => generation !== this.generation,
    }))[0]!;
    this.assertCurrent(generation);
    if (queryVector.length !== active.dimensions) {
      throw new Error("The semantic query dimension does not match the index.");
    }

    const best = new Map<string, { entry: SemanticIndexEntry; score: number }>();
    for (let index = 0; index < active.entries.length; index += 1) {
      this.assertCurrent(generation);
      const entry = active.entries[index]!;
      const cosine = Math.max(-1, Math.min(1, dot(queryVector, entry.vector)));
      const score = (cosine + 1) / 2;
      const prior = best.get(entry.path);
      if (!prior || score > prior.score || (score === prior.score && entry.chunkIndex < prior.entry.chunkIndex)) {
        best.set(entry.path, { entry, score });
      }
      if (index > 0 && index % 500 === 0) await this.context.yieldControl();
    }

    const coverage = createEmptyCoverage();
    coverage.vaultsConsidered = 1;
    coverage.vaultsSearched = 1;
    coverage.metadataFiles = best.size;
    if (this.status.stale) addPartialReason(coverage, "stale-index");
    const results = [];
    const candidates = [...best.values()].sort((left, right) =>
      right.score - left.score ||
      left.entry.path.localeCompare(right.entry.path, undefined, { sensitivity: "base" }),
    );
    for (const candidate of candidates) {
      if (results.length >= Math.min(MAX_RESULTS, request.limit)) break;
      this.assertCurrent(generation);
      if (options.canUsePath && !(await options.canUsePath(candidate.entry.path))) {
        coverage.skippedFiles += 1;
        continue;
      }
      const initial = await this.context.getPermissionDecision(candidate.entry.path);
      this.assertCurrent(generation);
      const initialAccess = permissionAccess(initial);
      if (!initialAccess) {
        coverage.skippedFiles += 1;
        continue;
      }
      let content: string;
      try {
        content = await this.context.readLocalText(candidate.entry.path);
      } catch {
        coverage.skippedFiles += 1;
        addPartialReason(coverage, "content-failure");
        continue;
      }
      this.assertCurrent(generation);
      coverage.contentFiles += 1;
      if (await fingerprint(content) !== candidate.entry.fingerprint) {
        coverage.skippedFiles += 1;
        addPartialReason(coverage, "stale-index");
        this.markFileStale(candidate.entry.path, false);
        continue;
      }
      const finalDecision = await this.context.getPermissionDecision(candidate.entry.path);
      this.assertCurrent(generation);
      const access = permissionAccess(finalDecision);
      if (!access) {
        coverage.skippedFiles += 1;
        continue;
      }
      const excerpt = content.slice(candidate.entry.start, candidate.entry.end);
      results.push({
        vaultId: vault.id,
        vaultName: vault.name,
        path: candidate.entry.path,
        local: true,
        matchKind: "semantic" as const,
        score: candidate.score,
        access,
        snippet: sanitizeSnippet(excerpt),
      });
    }
    return {
      schemaVersion: 1,
      query: request.query,
      scope: "current",
      results: sortSecureSearchResults(results),
      coverage,
    };
  }

  markFileChanged(path: string): void {
    this.markFileStale(path, true);
  }

  removeFile(path: string): void {
    const normalized = normalizeVaultRelativePath(path);
    if (!normalized) return;
    this.contentEpoch += 1;
    this.cancel();
    if (!this.envelope) {
      this.setStatus({ ...this.status, state: "stale", stale: true });
      return;
    }
    this.envelope = {
      ...this.envelope,
      entries: this.envelope.entries.filter((entry) => entry.path !== normalized),
    };
    this.refreshStaleStatus();
    this.persistFilteredEnvelope();
  }

  handlePermissionInvalidation(pattern?: string): void {
    this.contentEpoch += 1;
    this.cancel();
    if (!this.envelope) {
      this.setStatus({ ...this.status, state: "stale", stale: true });
      return;
    }
    this.envelope = {
      ...this.envelope,
      entries: pattern
        ? this.envelope.entries.filter((entry) => !matchesGlob(entry.path, pattern))
        : [],
    };
    this.refreshStaleStatus();
    this.persistFilteredEnvelope();
  }

  async purge(_reason: SemanticPurgeReason = "manual"): Promise<void> {
    this.purgeEpoch += 1;
    this.contentEpoch += 1;
    this.cancel();
    this.envelope = null;
    await this.withRepository(() => this.context.repository.purge());
    this.setStatus({ state: "absent", indexedFiles: 0, indexedChunks: 0, stale: false });
  }

  private publishBuildProgress(
    progress: Pick<
      SemanticRuntimeStatus,
      "processedFiles" | "totalFiles" | "skippedFiles" | "failedFiles" | "limitedFiles"
    >,
    indexedFiles: number,
    indexedChunks: number,
  ): void {
    this.setStatus({
      state: "building",
      indexedFiles,
      indexedChunks,
      stale: false,
      ...progress,
    });
  }

  private markFileStale(path: string, cancelActive: boolean): void {
    if (!normalizeVaultRelativePath(path)) return;
    this.contentEpoch += 1;
    if (cancelActive) this.cancel();
    this.setStatus({ ...this.status, state: "stale", stale: true });
  }

  private persistFilteredEnvelope(): void {
    const filterEpoch = ++this.filterEpoch;
    const purgeEpoch = this.purgeEpoch;
    const envelope = this.envelope;
    void this.withRepository(async () => {
      if (filterEpoch !== this.filterEpoch || purgeEpoch !== this.purgeEpoch) return;
      if (envelope) await this.context.repository.save(envelope);
      else await this.context.repository.purge();
    }).catch(() => {
      if (filterEpoch !== this.filterEpoch || purgeEpoch !== this.purgeEpoch) return;
      this.setStatus({
        ...this.status,
        state: "stale",
        stale: true,
        error: "The encrypted semantic index could not be updated after access changed.",
      });
    });
  }

  private async restoreAfterCancelledCommit(
    previous: SemanticIndexEnvelope | null,
    buildPurgeEpoch: number,
    buildContentEpoch: number,
  ): Promise<void> {
    await this.withRepository(async () => {
      if (buildPurgeEpoch !== this.purgeEpoch) {
        await this.context.repository.purge();
        return;
      }
      const rollback = buildContentEpoch === this.contentEpoch ? previous : this.envelope;
      if (rollback) await this.context.repository.save(rollback);
      else await this.context.repository.purge();
    });
  }

  private withRepository<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.repositoryTail.then(operation, operation);
    this.repositoryTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private refreshStaleStatus(): void {
    const entries = this.envelope?.entries ?? [];
    this.setStatus({
      state: "stale",
      indexedFiles: uniquePathCount(entries),
      indexedChunks: entries.length,
      stale: true,
    });
  }

  private requireReady(): {
    provider: SemanticEmbeddingProvider;
    expected: SemanticIndexExpectedIdentity;
    vault: { id: string; name: string };
  } {
    if (!this.context.isParentEnabled() || !this.context.isSemanticEnabled()) {
      throw new Error("Semantic search consent is disabled.");
    }
    const session = this.context.getSession();
    const vault = this.context.getBoundVault();
    const localVaultId = this.context.getLocalVaultId().trim();
    if (!session?.userId || !vault?.id || !localVaultId) {
      throw new Error("Semantic search requires a signed-in bound vault.");
    }
    const provider = this.context.createProvider(this.context.getProviderConfig());
    return {
      provider,
      vault,
      expected: {
        schemaVersion: 1,
        userId: session.userId,
        localVaultId,
        vaultId: vault.id,
        provider: "ollama",
        providerOrigin: provider.origin,
        model: provider.model,
        chunkerVersion: SEMANTIC_CHUNKER_VERSION,
      },
    };
  }

  private assertCurrent(generation: number): void {
    if (generation !== this.generation) throw new SemanticOperationCancelledError();
  }

  private setStatus(status: SemanticRuntimeStatus): void {
    this.status = { ...status };
    for (const listener of this.listeners) listener(this.getStatus());
  }
}
