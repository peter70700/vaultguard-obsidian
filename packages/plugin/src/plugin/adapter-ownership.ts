/**
 * SD-07-F5 — cross-generation ownership of the Obsidian vault adapter.
 *
 * Obsidian's `unloadPlugin` does not await `plugin.unload()`, so a superseded
 * VaultGuard runtime's async unload tail overlaps the next runtime's boot. The
 * replacement therefore captures whatever is installed on the adapter at that
 * instant — which is the superseded runtime's wrappers. When the old runtime
 * later clears its own delegates, the new runtime's "raw disk boundary" is a
 * chain of dead functions.
 *
 * Every wrapper this plugin installs carries the base function it delegates to,
 * so a later generation can unwrap to the REAL adapter method instead of
 * chaining onto a doomed wrapper.
 *
 * The marker is a plain STRING property, not a Symbol. A hot reload re-evaluates
 * main.js in a fresh module scope, so a module-level `Symbol(...)` in the new
 * bundle would not be the same symbol the old bundle wrote — the marker would be
 * unreadable in exactly the case it exists for. A string also matches the
 * existing `__vaultguard` diagnostic tag on the getResourcePath override and is
 * greppable from the console.
 */

/**
 * Any vault-adapter method this plugin wraps. `never[]` params keep every
 * concrete adapter signature assignable without reaching for `any`.
 */
export type AdapterMethodLike = (...args: never[]) => unknown;

export const ADAPTER_BASE_MARKER = "__vaultguardAdapterBase" as const;

/** Defensive cap on wrapper-chain traversal. Real chains are 1 deep per generation. */
export const MAX_ADAPTER_WRAPPER_DEPTH = 32;

/** A function this plugin installed on the adapter, carrying its delegate. */
export type MarkedAdapterMethod = {
  __vaultguardAdapterBase?: AdapterMethodLike;
};

/** Tag `wrapper` with the base function it delegates to. Returns `wrapper`. */
export function markAdapterWrapper<TWrapper extends AdapterMethodLike>(
  wrapper: TWrapper,
  base: AdapterMethodLike,
): TWrapper {
  (wrapper as TWrapper & MarkedAdapterMethod)[ADAPTER_BASE_MARKER] = base;
  return wrapper;
}

/**
 * Follow the marker chain from `fn` to the deepest recorded base and return it,
 * or `null` when `fn` is not a VaultGuard wrapper (i.e. it IS the base).
 *
 * A LOOP, not a single step: A→B→C hot reloads in rapid succession stack
 * generations, and a single dereference would still land on a doomed wrapper.
 */
export function resolveAdapterMethodBase<TFn extends AdapterMethodLike>(fn: TFn): TFn | null {
  let current: AdapterMethodLike = fn;
  let found: AdapterMethodLike | null = null;
  const seen = new Set<AdapterMethodLike>([fn]);
  for (let depth = 0; depth < MAX_ADAPTER_WRAPPER_DEPTH; depth += 1) {
    const base = (current as MarkedAdapterMethod)[ADAPTER_BASE_MARKER];
    if (typeof base !== "function" || seen.has(base)) break; // end of chain, or a cycle
    seen.add(base);
    found = base;
    current = base;
  }
  // Confined, documented cast: the marker is only ever written by
  // markAdapterWrapper with a same-signature base for that exact adapter slot,
  // and the typeof guard above proves it is callable.
  return found as TFn | null;
}

/** Thrown when a torn-down runtime is asked to mutate the vault it no longer owns. */
export class AtRestAdapterDetachedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AtRestAdapterDetachedError";
  }
}
