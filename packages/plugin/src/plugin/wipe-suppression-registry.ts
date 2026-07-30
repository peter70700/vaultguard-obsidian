/**
 * Cross-instance delete-suppression registry for the local at-rest reset wipe
 * (SD-07-F4).
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 * `resetLocalAtRestAndResync()` raw-removes every VG1 ciphertext file via the
 * captured `originalAdapterMethods.remove`. Obsidian's file watcher still fires
 * `vault.on('delete')` for each removed file, and those events MUST NOT
 * propagate a server DELETE — the server copy is the authoritative one the
 * reset is about to re-download.
 *
 * Suppression used to live entirely in the initiating plugin instance (a
 * `resettingLocalCache` boolean plus a `wipedPathsAwaitingRepull` Set). A hot
 * reload mid-wipe defeated both: `onunload` does not await the wipe, so the
 * wipe promise stayed alive holding a live raw `remove`, while the REPLACEMENT
 * instance booted with `resettingLocalCache === false` and an empty set. The
 * zombie's late watcher deletes were then read by the new instance as genuine
 * user deletes and propagated `DELETE /vaults/{id}/files/{path}` for files that
 * existed only on the server.
 *
 * ── WHY `globalThis` AND NOT MODULE SCOPE ────────────────────────────────────
 * A hot reload re-evaluates `main.js` in a FRESH module scope, so a
 * module-level `Map` would be a brand-new empty `Map` for the replacement
 * instance — exactly the state loss this module exists to prevent.
 * `globalThis` (the Electron renderer's shared global, one per vault window) is
 * the only in-memory scope that survives a plugin reload.
 *
 * ── MEMORY-ONLY, NEVER PERSISTED ─────────────────────────────────────────────
 * This state is NEVER written to disk. A full Obsidian restart kills the zombie
 * wipe promise too, so process lifetime is exactly the right lifetime for the
 * suppression. Persisting it would risk permanently over-suppressing a GENUINE
 * user delete after a crash — a silent, unbounded sync-correctness bug that is
 * strictly worse than the transient window it would close.
 *
 * ── DEGRADED FALLBACK ────────────────────────────────────────────────────────
 * If `globalThis` is unavailable (sandboxed runtimes can throw on the property
 * access itself), the registry degrades to module-local scope — i.e. EXACTLY
 * today's pre-fix per-instance behavior. No worse than before, and no new
 * failure mode: the API can never return `undefined` and never throws, because
 * throwing on a `vault.on('delete')` hot path would be a worse outcome than
 * losing cross-instance protection.
 *
 * ── RESET LEASE STALENESS: 60 s ──────────────────────────────────────────────
 * A single `remove()` on a slow network drive can take seconds but not a
 * minute. After 60 s without a progress beat the wipe is either dead or wedged,
 * and refusing recovery FOREVER would be a worse failure than proceeding. In
 * practice this window is rarely load-bearing: the unload system abort makes
 * the zombie's `finally` — and therefore `releaseResetLease` — run promptly. It
 * only matters when the promise dies without running `finally` (renderer
 * teardown) or is wedged inside `await remove(path)`.
 */

export const WIPE_SUPPRESSION_REGISTRY_GLOBAL_KEY = "__vaultguardWipeSuppressionRegistry_v1";

/** @see the "RESET LEASE STALENESS" note in this module's header. */
export const DEFAULT_RESET_LEASE_STALE_MS = 60_000;

export interface ResetLeaseSnapshot {
  ownerId: string;
  updatedAt: number;
}

export type AcquireResetLeaseResult =
  | { acquired: true; ownerId: string; tookOverStaleLease: boolean }
  | { acquired: false; heldBy: ResetLeaseSnapshot; ageMs: number };

interface VaultSuppressionState {
  wipedPaths: Set<string>;
  lease: ResetLeaseSnapshot | null;
}

interface RegistryRoot {
  version: 1;
  vaults: Map<string, VaultSuppressionState>;
  ownerSeq: number;
}

type RegistryHost = { __vaultguardWipeSuppressionRegistry_v1?: RegistryRoot };

/**
 * Module-local last resort. Only reached when `globalThis` access throws, in
 * which case behavior degrades to today's per-instance semantics (see header).
 */
const fallbackRoot: RegistryRoot = { version: 1, vaults: new Map(), ownerSeq: 0 };

function registryRoot(): RegistryRoot {
  try {
    const host = globalThis as RegistryHost;
    const existing = host.__vaultguardWipeSuppressionRegistry_v1;
    if (existing && existing.version === 1 && existing.vaults instanceof Map) {
      return existing;
    }
    const fresh: RegistryRoot = { version: 1, vaults: new Map(), ownerSeq: 0 };
    host.__vaultguardWipeSuppressionRegistry_v1 = fresh;
    return fresh;
  } catch {
    // Sandboxed runtimes can throw on the property access itself. Degrade to
    // module scope rather than throwing on a delete-event hot path.
    return fallbackRoot;
  }
}

function vaultState(vaultKey: string): VaultSuppressionState {
  const root = registryRoot();
  const existing = root.vaults.get(vaultKey);
  if (existing) return existing;
  const fresh: VaultSuppressionState = { wipedPaths: new Set<string>(), lease: null };
  root.vaults.set(vaultKey, fresh);
  return fresh;
}

function firstNonEmptyString(...candidates: Array<() => unknown>): string | null {
  for (const read of candidates) {
    try {
      const value = read();
      if (typeof value === "string" && value.trim().length > 0) return value.trim();
    } catch {
      // A getter on a partially-constructed app can throw; just try the next one.
    }
  }
  return null;
}

/**
 * Synchronous per-vault key for the shared registry.
 *
 * Deliberately synchronous: the async `computeHash` vault fingerprint used by
 * settings is unusable on a `vault.on('delete')` hot path. The key never leaves
 * memory, so it needs DISTINCTNESS, not collision resistance or privacy
 * hardening.
 *
 * In real Obsidian each vault is its own renderer window, so `globalThis` is
 * ALREADY per-vault — this key is defence in depth, and the mechanism that
 * keeps unit tests isolated from one another.
 *
 * Preference order, first non-empty wins:
 *   1. `app.appId` — Obsidian's per-vault ID (the same identifier
 *      `App.saveLocalStorage` prefixes its keys with).
 *   2. `app.vault.getName()`
 *   3. `app.vault.adapter.getBasePath()` / `.basePath`
 *   4. a constant fallback
 */
export function deriveWipeSuppressionVaultKey(app: unknown): string {
  const host = app as
    | {
        appId?: unknown;
        vault?: {
          getName?: () => unknown;
          adapter?: { getBasePath?: () => unknown; basePath?: unknown };
        };
      }
    | null
    | undefined;

  const chosen = firstNonEmptyString(
    () => host?.appId,
    () => host?.vault?.getName?.(),
    () => host?.vault?.adapter?.getBasePath?.(),
    () => host?.vault?.adapter?.basePath,
  );

  return `vault:${chosen ?? "vaultguard-default-vault"}`;
}

/** Mark `normalizedPath` as wiped-and-awaiting-repull for this vault. */
export function recordWipedPath(vaultKey: string, normalizedPath: string): void {
  vaultState(vaultKey).wipedPaths.add(normalizedPath);
}

/**
 * The path is back on disk (reconcile re-pulled it, or the user created a new
 * file there), so a future delete of it is a GENUINE user action and must
 * propagate. The lifetime of an entry is "until its path is back" — never a
 * fixed timer.
 */
export function clearWipedPath(vaultKey: string, normalizedPath: string): void {
  const state = vaultState(vaultKey);
  if (state.wipedPaths.size === 0) return;
  state.wipedPaths.delete(normalizedPath);
}

/** Drop every suppression entry for ONE vault key. Never touches other vaults. */
export function clearAllWipedPaths(vaultKey: string): void {
  vaultState(vaultKey).wipedPaths.clear();
}

/**
 * True when a `vault.on('delete')` for `normalizedPath` is a wipe artifact.
 *
 * For a FOLDER delete we also suppress when the folder still CONTAINS a
 * wiped-awaiting-repull descendant: a folder emptied by the wipe and removed
 * late by Obsidian would otherwise prefix-DELETE its (server-authoritative)
 * children. Once reconcile re-pulls those children their entries self-clear,
 * and a later user delete of the re-created folder propagates normally.
 */
export function isPathWipeSuppressed(
  vaultKey: string,
  normalizedPath: string,
  isFolder: boolean,
): boolean {
  const state = vaultState(vaultKey);
  if (state.wipedPaths.size === 0) return false;
  if (state.wipedPaths.has(normalizedPath)) return true;
  if (isFolder) {
    const prefix = normalizedPath + "/";
    for (const wiped of state.wipedPaths) {
      if (wiped.startsWith(prefix)) return true;
    }
  }
  return false;
}

/** Diagnostics / tests: how many paths this vault currently suppresses. */
export function countWipedPaths(vaultKey: string): number {
  return vaultState(vaultKey).wipedPaths.size;
}

/**
 * Take cross-instance ownership of the local at-rest reset for this vault.
 *
 * The owner token is minted HERE, never by the plugin: `lifecycleGeneration` is
 * a PER-INSTANCE counter that restarts at 0 in a replacement instance, so two
 * instances would collide on it. The shared `ownerSeq` guarantees uniqueness
 * between instances; the random suffix covers the degraded module-local
 * fallback branch where two scopes could each hold their own `ownerSeq`.
 */
export function acquireResetLease(
  vaultKey: string,
  options: { staleAfterMs?: number; now?: () => number } = {},
): AcquireResetLeaseResult {
  const root = registryRoot();
  const state = vaultState(vaultKey);
  const now = options.now ?? Date.now;
  const staleAfterMs = options.staleAfterMs ?? DEFAULT_RESET_LEASE_STALE_MS;
  const nowMs = now();

  const existing = state.lease;
  if (existing) {
    const ageMs = nowMs - existing.updatedAt;
    if (ageMs < staleAfterMs) {
      return { acquired: false, heldBy: { ...existing }, ageMs };
    }
  }

  const seq = ++root.ownerSeq;
  const ownerId = `reset-${seq}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  state.lease = { ownerId, updatedAt: nowMs };
  return { acquired: true, ownerId, tookOverStaleLease: existing !== null };
}

/**
 * Progress IS the heartbeat: the wipe bumps this after every successful raw
 * remove, so no timer is needed and the beat can never outlive the work it
 * measures. A non-owner beat is a no-op — a superseded instance must not keep
 * a newer reset's lease looking fresh.
 */
export function heartbeatResetLease(
  vaultKey: string,
  ownerId: string,
  now: () => number = Date.now,
): void {
  const state = vaultState(vaultKey);
  if (!state.lease || state.lease.ownerId !== ownerId) return;
  state.lease = { ownerId, updatedAt: now() };
}

/**
 * Release the lease ONLY if `ownerId` still owns it, so a late `finally` from a
 * superseded instance can never clobber a newer reset's marker. Returns whether
 * it actually released. Never touches `wipedPaths` — suppression entries
 * outlive the reset window by design.
 */
export function releaseResetLease(vaultKey: string, ownerId: string): boolean {
  const state = vaultState(vaultKey);
  if (!state.lease || state.lease.ownerId !== ownerId) return false;
  state.lease = null;
  return true;
}

/** Tests / diagnostics only. */
export function peekResetLease(vaultKey: string): ResetLeaseSnapshot | null {
  const lease = vaultState(vaultKey).lease;
  return lease ? { ...lease } : null;
}

/**
 * TEST-ONLY. The registry is `globalThis`-scoped and therefore shared by every
 * test in a vitest worker; call this in `beforeEach` to isolate cases.
 */
export function __resetWipeSuppressionRegistryForTests(): void {
  const root = registryRoot();
  root.vaults.clear();
  root.ownerSeq = 0;
  fallbackRoot.vaults.clear();
  fallbackRoot.ownerSeq = 0;
}
