/**
 * VaultGuard - Shared Electron safeStorage probe.
 *
 * Both the at-rest cipher and the session-persistence layer need OS-keystore
 * encryption (DPAPI / Keychain / libsecret) to protect their respective key
 * material on disk. Modern Electron exposes this only in the main process,
 * but Obsidian still bundles `@electron/remote` which forwards safeStorage
 * to the renderer over IPC. This module is the single source of truth for
 * locating that API.
 *
 * Returns `null` when:
 *  - Not running inside an Electron context that exposes CommonJS `require`
 *  - `@electron/remote` is unavailable AND `electron.safeStorage` is unset
 *  - `safeStorage.isEncryptionAvailable()` returns false (e.g. Linux without
 *    a working keyring)
 *
 * Callers MUST treat a `null` result as "OS keystore not available — never
 * persist sensitive material in plaintext as a fallback."
 */

export interface SafeStorageLike {
  isEncryptionAvailable(): boolean;
  encryptString(plaintext: string): Buffer | Uint8Array;
  decryptString(ciphertext: Buffer | Uint8Array): string;
}

export function probeSafeStorage(): SafeStorageLike | null {
  const req = getElectronRequire();
  if (typeof req !== "function") return null;

  const candidates: Array<() => SafeStorageLike | null> = [
    () => {
      try {
        const remote = req("@electron/remote") as { safeStorage?: SafeStorageLike };
        return remote?.safeStorage ?? null;
      } catch {
        return null;
      }
    },
    () => {
      try {
        const electron = req("electron") as {
          remote?: { safeStorage?: SafeStorageLike };
          safeStorage?: SafeStorageLike;
        };
        return electron?.remote?.safeStorage ?? electron?.safeStorage ?? null;
      } catch {
        return null;
      }
    },
  ];

  for (const probe of candidates) {
    const ss = probe();
    if (!ss || typeof ss.isEncryptionAvailable !== "function") continue;
    try {
      if (ss.isEncryptionAvailable()) return ss;
    } catch {
      // Some platforms throw if the keychain is locked — treat as unavailable
      // and fall through to the next candidate.
    }
  }
  return null;
}

function getElectronRequire(): ((id: string) => unknown) | null {
  const w = (typeof window !== "undefined" ? (window as unknown) : undefined) as
    | { require?: unknown }
    | undefined;
  if (typeof w?.require === "function") {
    return w.require as (id: string) => unknown;
  }

  // Electron's renderer exposes CommonJS `require` as a global, not on `window`.
  // Keep this fallback so the safeStorage probe works (and stays unit-testable
  // via a globalThis.require shim).
  const g = globalThis as unknown as { require?: unknown };
  if (typeof g.require === "function") {
    return g.require as (id: string) => unknown;
  }

  try {
    const scopedRequire = require;
    if (typeof scopedRequire === "function") {
      return scopedRequire as (id: string) => unknown;
    }
  } catch {
    // Browser-only hosts simply do not have CommonJS require.
  }

  return null;
}
