/**
 * VaultGuard — Local device folder picker + read-only source-fs provider
 * (desktop-only).
 *
 * The ONLY part of the import pipeline that touches the device: it opens the
 * Electron folder dialog (`pickSourceFolder`) and exposes a read-only Node `fs`
 * surface (`makeImportSourceFs`) that backs the chat-only, sandboxed
 * `vaultguard_import_*` agent tools (sd4). Conversion (converters/) is pure and
 * lives elsewhere; the SANDBOX policy (realpath + prefix check) lives in the
 * agent bridge, not here — this module only performs raw, absolute-path reads.
 *
 * Networking: NONE. No `requestUrl`, no `fetch` — this reads the local filesystem
 * only and returns bytes. No Obsidian vault writes happen here either.
 *
 * Desktop gate (HARD): every exported function bails cleanly when
 * `Platform.isMobileApp` is true OR a CommonJS `require` isn't available. On
 * mobile we NEVER attempt the Electron/`fs` require — `pickSourceFolder` returns
 * `null` and `makeImportSourceFs` returns `null`. The `getElectronRequire()`
 * helper mirrors `src/crypto/safe-storage.ts`.
 */

import { Platform } from "obsidian";

/** Minimal shape of Electron's `dialog` we rely on. */
interface ElectronDialogLike {
  showOpenDialog(opts: {
    properties: string[];
    title?: string;
  }): Promise<{ canceled: boolean; filePaths: string[] }>;
}

/** Minimal shape of Node `fs.promises` we rely on. */
interface FsPromisesLike {
  readdir(
    path: string,
    opts: { withFileTypes: true },
  ): Promise<Array<{ name: string; isDirectory(): boolean; isFile(): boolean }>>;
  stat(path: string): Promise<{ size: number; isFile(): boolean; isDirectory(): boolean }>;
  readFile(path: string): Promise<Uint8Array>;
  /** Canonicalizes a path, resolving every symlink — the sandbox-escape gate. */
  realpath(path: string): Promise<string>;
}

/**
 * Locate a CommonJS `require` from inside Obsidian's Electron renderer.
 * Mirrors `getElectronRequire()` in `src/crypto/safe-storage.ts`. Returns `null`
 * on non-Electron hosts (mobile), which is the hard desktop gate.
 */
function getElectronRequire(): ((id: string) => unknown) | null {
  const w = (typeof window !== "undefined" ? (window as unknown) : undefined) as
    | { require?: unknown }
    | undefined;
  if (typeof w?.require === "function") {
    return w.require as (id: string) => unknown;
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

/** Resolve Electron's `dialog` across the @electron/remote / electron shapes. */
function resolveDialog(req: (id: string) => unknown): ElectronDialogLike | null {
  const candidates: Array<() => ElectronDialogLike | null> = [
    () => {
      try {
        const remote = req("@electron/remote") as { dialog?: ElectronDialogLike };
        return remote?.dialog ?? null;
      } catch {
        return null;
      }
    },
    () => {
      try {
        const electron = req("electron") as {
          remote?: { dialog?: ElectronDialogLike };
          dialog?: ElectronDialogLike;
        };
        return electron?.remote?.dialog ?? electron?.dialog ?? null;
      } catch {
        return null;
      }
    },
  ];
  for (const probe of candidates) {
    const dialog = probe();
    if (dialog && typeof dialog.showOpenDialog === "function") return dialog;
  }
  return null;
}

/** Resolve Node `fs.promises`. */
function resolveFsPromises(req: (id: string) => unknown): FsPromisesLike | null {
  try {
    const fs = req("fs") as { promises?: FsPromisesLike };
    if (fs?.promises && typeof fs.promises.readdir === "function") {
      return fs.promises;
    }
  } catch {
    // fall through
  }
  return null;
}

/** Resolve the Node `path` module's `join`/`basename`/`extname`. */
interface NodePathLike {
  join(...parts: string[]): string;
  basename(p: string): string;
  extname(p: string): string;
  relative(from: string, to: string): string;
  resolve(...parts: string[]): string;
  sep: string;
}
function resolvePath(req: (id: string) => unknown): NodePathLike | null {
  try {
    const p = req("path") as NodePathLike;
    if (p && typeof p.join === "function") return p;
  } catch {
    // fall through
  }
  return null;
}

/** True when the host can read the device filesystem (desktop Electron). */
export function isLocalImportAvailable(): boolean {
  if (Platform.isMobileApp) return false;
  return getElectronRequire() !== null;
}

/**
 * Open the native folder picker and return the chosen absolute path, or `null`
 * if cancelled / unavailable. NEVER attempts the require on mobile.
 */
export async function pickSourceFolder(): Promise<string | null> {
  if (Platform.isMobileApp) return null;
  const req = getElectronRequire();
  if (!req) return null;

  const dialog = resolveDialog(req);
  if (!dialog) return null;

  try {
    const result = await dialog.showOpenDialog({
      properties: ["openDirectory"],
      title: "Select a folder to import into VaultGuard",
    });
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
  } catch {
    return null;
  }
}

// ─── Gated source-read provider (backs the chat-only import tool, sd4) ────────
//
// The agent bridge's `vaultguard_import_*` tools read external source bytes
// through THIS provider. It is the only fs surface the bridge ever touches for
// imports — desktop-gated here (Electron `require`), so on mobile the factory
// returns null and the bridge tool fails closed. The bridge owns the sandbox
// guard (realpath + prefix check) and all the policy; this provider is a thin,
// dependency-free shim over Node `fs.promises` + `path` so the bridge stays
// unit-testable by injecting a `node:fs`-backed equivalent.
//
// READ-ONLY by construction: it exposes readdir/stat/readFile/realpath/path
// helpers only — no write, no delete, no rename.

/** A directory entry returned by {@link ImportSourceFs.readdir}. */
export interface ImportDirEntry {
  name: string;
  isDirectory: boolean;
  isFile: boolean;
}

/**
 * Minimal, read-only filesystem surface the bridge's gated import tool calls.
 * All methods are absolute-path based; the bridge resolves + sandbox-checks
 * every path against the active import-session root BEFORE calling these.
 */
export interface ImportSourceFs {
  /** Canonicalize a path (resolves symlinks). The bridge's escape gate. */
  realpath(absPath: string): Promise<string>;
  /** List a directory's entries (kind flags pre-resolved to booleans). */
  readdir(absDir: string): Promise<ImportDirEntry[]>;
  /** Stat a path for size + kind. */
  stat(absPath: string): Promise<{ size: number; isFile: boolean; isDirectory: boolean }>;
  /** Read a file's raw bytes. */
  readFile(absPath: string): Promise<Uint8Array>;
  /** Join path segments using the host separator. */
  join(...parts: string[]): string;
  /** Resolve to an absolute path. */
  resolve(...parts: string[]): string;
  /** Compute a relative path from `from` to `to` (forward-slashed by the bridge). */
  relative(from: string, to: string): string;
  /** Lower-cased extension without the leading dot, e.g. `"docx"`. */
  extname(absPath: string): string;
  /** Base name (with extension). */
  basename(absPath: string): string;
}

/**
 * Build the gated import-source fs provider, or return `null` when the device
 * filesystem is unreachable (mobile / non-Electron host). NEVER attempts the
 * Electron `require` on mobile — `Platform.isMobileApp` short-circuits first,
 * matching {@link isLocalImportAvailable}.
 */
export function makeImportSourceFs(): ImportSourceFs | null {
  if (Platform.isMobileApp) return null;
  const req = getElectronRequire();
  if (!req) return null;

  const fsp = resolveFsPromises(req);
  const nodePath = resolvePath(req);
  if (!fsp || typeof fsp.realpath !== "function" || !nodePath) return null;

  return {
    realpath: (absPath) => fsp.realpath(absPath),
    readdir: async (absDir) => {
      const entries = await fsp.readdir(absDir, { withFileTypes: true });
      return entries.map((e) => ({
        name: e.name,
        isDirectory: e.isDirectory(),
        isFile: e.isFile(),
      }));
    },
    stat: async (absPath) => {
      const st = await fsp.stat(absPath);
      return { size: st.size, isFile: st.isFile(), isDirectory: st.isDirectory() };
    },
    readFile: async (absPath) => {
      const bytes = await fsp.readFile(absPath);
      return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    },
    join: (...parts) => nodePath.join(...parts),
    resolve: (...parts) => nodePath.resolve(...parts),
    relative: (from, to) => nodePath.relative(from, to),
    extname: (absPath) => nodePath.extname(absPath).replace(/^\.+/, "").toLowerCase(),
    basename: (absPath) => nodePath.basename(absPath),
  };
}
