import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Menu, Notice, TFile, requestUrl } from "obsidian";

import VaultGuardPlugin from "../src/plugin/main";
import { DEFAULT_EXCLUDED_PATHS, DEFAULT_SETTINGS, SAAS_DEFAULTS } from "../src/plugin/settings";
import { ConflictResolutionStrategy, PermissionLevel } from "../src/types";
import { BINARY_SYNC_MAX_BYTES } from "../src/plugin/binary-content";

const mockNotice = vi.mocked(Notice);
const mockRequestUrl = vi.mocked(requestUrl);

/**
 * Test-only minimal PermissionStore stand-in. Phase 9 replaced the
 * permissionCache: Map field in main.ts with a unified PermissionStore.
 * Existing tests still poke at the cache via `.permissionCache.size/get/set/has`;
 * this stand-in backs those reads with a real Map and forwards
 * emit('changed') events to four registered listeners (matching the
 * production fan-out: file-explorer, sidebar, header, read-only-guard).
 */
function installTestPermissionStore(plugin: any): Map<string, number> {
  const cache = new Map<string, number>();
  const listeners: Array<(payload: { path?: string; serverConfirmed?: boolean }) => void> = [];
  // Wave 2 Fix 2 (1.0.31): track the lifecycle state in the fixture so
  // tests can assert state transitions via getStoreState().
  let storeState: any = { kind: "cold" };

  plugin.permissionStore = {
    getCachedPermission: (path: string) => cache.get(path),
    getPermission: async (path: string) => cache.get(path) ?? 0,
    warm: vi.fn(async () => {
      storeState = { kind: "warmed", warmedAt: Date.now() };
    }),
    sweepLeavesAfterWarm: vi.fn(async () => undefined),
    markWarming: vi.fn(() => {
      storeState = { kind: "warming" };
    }),
    markFetchFailed: vi.fn((statusCode: number | null) => {
      storeState = { kind: "fetch-failed", statusCode, failedAt: Date.now() };
    }),
    getStoreState: () => storeState,
    emit: (_name: string, payload: { path?: string; serverConfirmed?: boolean } = {}) => {
      if (payload.path !== undefined) {
        cache.delete(payload.path);
      } else {
        cache.clear();
      }
      // Fan out so the four production subscribers (when wired) still fire.
      for (const cb of listeners) cb(payload);
    },
    invalidate: (path?: string) => {
      if (path === undefined) cache.clear();
      else cache.delete(path);
    },
    on: (_name: string, cb: (...args: unknown[]) => unknown) => {
      listeners.push(cb as (payload: { path?: string; serverConfirmed?: boolean }) => void);
      return { name: _name, cb };
    },
  };
  // Phase 9 back-compat: expose `permissionCache` as a getter onto the
  // store's backing Map so legacy tests that read .size/.get/.has/.set
  // keep working. New tests should use `permissionStore.getCachedPermission`.
  Object.defineProperty(plugin, "permissionCache", {
    configurable: true,
    get: () => cache,
    set: (newMap: Map<string, number>) => {
      cache.clear();
      for (const [k, v] of newMap) cache.set(k, v);
    },
  });
  // Phase 9 back-compat: legacy tests reference `runPermissionWarmup` to
  // execute warm-up logic. The new main.ts method drives the store; for
  // tests we route through the test-only seed helpers.
  plugin.warmPermissionCache = vi.fn(async () => undefined);
  return cache;
}

function makePlugin() {
  const plugin = new VaultGuardPlugin() as any;

  plugin.app = {
    appId: "test-app-id",
    vault: {
      configDir: ".obsidian",
      adapter: {
        getBasePath: () => "/Users/test/VaultGuard Test Vault",
        exists: vi.fn().mockResolvedValue(false),
        remove: vi.fn().mockResolvedValue(undefined),
      },
      getName: () => "VaultGuard Test Vault",
    },
    workspace: {
      on: vi.fn(() => ({ unload: vi.fn() })),
      getLeavesOfType: vi.fn(() => []),
    },
    metadataCache: {},
    loadLocalStorage: vi.fn((key: string) => {
      const raw = localStorage.getItem(key);
      if (raw === null) return null;
      try {
        return JSON.parse(raw);
      } catch {
        return raw;
      }
    }),
    saveLocalStorage: vi.fn((key: string, data: unknown | null) => {
      if (data === null) {
        localStorage.removeItem(key);
      } else {
        localStorage.setItem(key, JSON.stringify(data));
      }
    }),
  };
  plugin.settings = {
    ...DEFAULT_SETTINGS,
    vaultBindingId: "test-vault-binding",
    serverVaultId: "vault-abc",
    cognitoUserPoolId: "test-pool",       // Phase 4 hardening (D-42a item 2): avoid SAAS_DEFAULTS env drift
    cognitoClientId: "test-client",        // Phase 4 hardening (D-42a item 2): avoid SAAS_DEFAULTS env drift
    maxRetryAttempts: 2,
    showStatusBar: false,
    debugLogging: false,
  };
  plugin.connectionState = {
    status: "offline",
    lastConnected: null,
    failedAttempts: 0,
    nextRetryAt: null,
    latencyMs: null,
  };
  plugin.offlineQueue = [];
  plugin.updateStatusBar = vi.fn();
  plugin.log = vi.fn();
  plugin.logError = vi.fn();
  plugin.scheduleConnectionRetry = vi.fn();
  plugin.stopConnectionRetry = vi.fn();
  plugin.derivedBindingId = "test-vault-binding";

  installTestPermissionStore(plugin);

  return plugin;
}

function makeSession() {
  return {
    sessionId: "session-1",
    userId: "user-1",
    organizationId: "org-1",
    displayName: "Test User",
    email: "test@example.com",
    accessToken: "access-token",
    idToken: "id-token",
    refreshToken: "refresh-token",
    tokenExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    role: "admin" as const,
    roles: ["admin"],
    createdAt: new Date().toISOString(),
  };
}

function jsonResponse(
  status: number,
  json: unknown,
  headers: Record<string, string> = {
    "content-type": "application/json",
    "x-request-id": "req-test",
  }
) {
  return {
    status,
    json,
    text: JSON.stringify(json),
    headers,
  } as any;
}

function awsSigV4GatewayResponse(message = "Authorization header requires 'Credential' parameter.") {
  return {
    status: 403,
    json: { message },
    text: JSON.stringify({ message }),
    headers: { "content-type": "application/json" },
  } as any;
}

function makeMemoryStorage(): Storage {
  const items = new Map<string, string>();

  return {
    get length() {
      return items.size;
    },
    clear: vi.fn(() => items.clear()),
    getItem: vi.fn((key: string) => items.get(key) ?? null),
    key: vi.fn((index: number) => Array.from(items.keys())[index] ?? null),
    removeItem: vi.fn((key: string) => {
      items.delete(key);
    }),
    setItem: vi.fn((key: string, value: string) => {
      items.set(key, value);
    }),
  };
}

function installFakeSafeStorage() {
  const testWindow = ensureTestWindow();
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const safeStorage = {
    isEncryptionAvailable: vi.fn(() => true),
    encryptString: vi.fn((plaintext: string) => encoder.encode(`safe:${plaintext}`)),
    decryptString: vi.fn((ciphertext: Uint8Array) => {
      const decoded = decoder.decode(ciphertext);
      if (!decoded.startsWith("safe:")) {
        throw new Error("Invalid test safeStorage payload");
      }
      return decoded.slice("safe:".length);
    }),
  };

  Object.defineProperty(testWindow, "require", {
    configurable: true,
    value: vi.fn((id: string) => {
      if (id === "@electron/remote") {
        return { safeStorage };
      }
      if (id === "electron") {
        return { safeStorage };
      }
      throw new Error(`Unexpected require(${id})`);
    }),
  });

  return safeStorage;
}

function protectSessionForTest(plugin: any, session: ReturnType<typeof makeSession>) {
  const envelope = plugin.protectSessionForStorage(session);
  expect(envelope).toEqual(expect.objectContaining({
    v: 1,
    storage: "electron-safe-storage",
    ciphertext: expect.any(String),
  }));
  return envelope;
}

function storeProtectedSession(
  plugin: any,
  bindingId: string,
  session: ReturnType<typeof makeSession>
) {
  const envelope = protectSessionForTest(plugin, session);
  localStorage.setItem(`vaultguard-session:${bindingId}`, JSON.stringify(envelope));
  return envelope;
}

function ensureTestWindow(): Record<string, unknown> {
  if (typeof globalThis.window === "undefined") {
    vi.stubGlobal("window", {});
  }
  const testWindow = globalThis.window as unknown as Record<string, unknown>;
  testWindow.setTimeout = (...args: Parameters<typeof setTimeout>) => setTimeout(...args);
  testWindow.clearTimeout = (...args: Parameters<typeof clearTimeout>) => clearTimeout(...args);
  testWindow.setInterval = (...args: Parameters<typeof setInterval>) => setInterval(...args);
  testWindow.clearInterval = (...args: Parameters<typeof clearInterval>) => clearInterval(...args);
  return testWindow;
}

function makeKeyLease() {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  return {
    key: Buffer.from(rawKey).toString("base64"),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    refreshToken: "refresh-token",
    leaseId: "lease-1",
    algorithm: "AES-256-GCM" as const,
    offlineCapable: true,
    scope: "/**",
    vaultId: "vault-abc",
  };
}

describe("VaultGuardPlugin byte crypto (BIN-A)", () => {
  // PNG magic bytes + 0x80/0xff/0xfe invalid-UTF-8 continuation bytes: a payload
  // a lossy TextDecoder would mangle (U+FFFD) — exactly the AR1 failure class the
  // byte variants avoid by never UTF-8-decoding.
  const BINARY_FIXTURE = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00,
  ]);

  beforeEach(() => {
    mockNotice.mockReset();
    mockRequestUrl.mockReset();
    vi.stubGlobal("localStorage", makeMemoryStorage());
  });

  it("round-trips raw binary bytes through encrypt/decrypt without loss", async () => {
    const plugin = makePlugin();
    plugin.keyLease = makeKeyLease();

    const encrypted = await plugin.encryptContentBytes(BINARY_FIXTURE.buffer);
    expect(typeof encrypted).toBe("string");

    const decrypted = await plugin.decryptContentBytes(encrypted);
    expect(new Uint8Array(decrypted)).toEqual(BINARY_FIXTURE);
  });

  it("produces an envelope identical to the string crypto (server sees no difference)", async () => {
    const plugin = makePlugin();
    plugin.keyLease = makeKeyLease();

    // Byte-encrypt of UTF-8 "hello" is decryptable by the STRING decryptContent.
    const byteEncrypted = await plugin.encryptContentBytes(
      new TextEncoder().encode("hello").buffer
    );
    await expect(plugin.decryptContent(byteEncrypted)).resolves.toBe("hello");

    // String-encrypt of "hello" is decryptable by the BYTE decryptContentBytes.
    const stringEncrypted = await plugin.encryptContent("hello");
    const decryptedBytes = await plugin.decryptContentBytes(stringEncrypted);
    expect(new TextDecoder().decode(decryptedBytes)).toBe("hello");
  });

  it("computeHashBytes matches computeHash for the same UTF-8 content", async () => {
    const plugin = makePlugin();

    // Include a multi-byte-UTF-8 string so the parity is not an ASCII accident.
    for (const s of ["hello", "žlutý kůň", ""]) {
      const bytesHash = await plugin.computeHashBytes(
        new TextEncoder().encode(s).buffer
      );
      const stringHash = await plugin.computeHash(s);
      expect(bytesHash).toBe(stringHash);
    }
  });

  it("both byte variants reject when the key lease is missing", async () => {
    const plugin = makePlugin();
    plugin.keyLease = null;

    await expect(
      plugin.encryptContentBytes(BINARY_FIXTURE.buffer)
    ).rejects.toThrow(/no valid key lease/);
    await expect(plugin.decryptContentBytes("AAAA")).rejects.toThrow(
      /no valid key lease/
    );
  });

  it("both byte variants reject when the key lease is expired", async () => {
    const plugin = makePlugin();
    plugin.keyLease = makeKeyLease();
    plugin.isKeyLeaseExpired = vi.fn(() => true);

    await expect(
      plugin.encryptContentBytes(BINARY_FIXTURE.buffer)
    ).rejects.toThrow(/no valid key lease/);
    await expect(plugin.decryptContentBytes("AAAA")).rejects.toThrow(
      /no valid key lease/
    );
  });

  it("bytesToBase64 chunking is byte-identical to a per-byte reference", () => {
    const plugin = makePlugin();
    // 70_000 bytes crosses two 0x8000 (32_768) chunks plus an odd remainder.
    // Deterministic fill covering the full 0-255 byte range (crypto.getRandomValues
    // caps at 65_536 bytes/call, and a reproducible pattern is a better parity fixture).
    const bytes = new Uint8Array(70_000);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = (i * 31 + 7) & 0xff;
    }

    let reference = "";
    for (let i = 0; i < bytes.length; i++) {
      reference += String.fromCharCode(bytes[i]);
    }
    const expected = btoa(reference);

    expect(plugin.bytesToBase64(bytes)).toBe(expected);
  });
});

describe("VaultGuardPlugin requestWithTimeout override (BIN-A / L2)", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("rejects with the default 30 s timeout when the request is slow", async () => {
    const plugin = makePlugin();
    // A request that would resolve only after 60 s — longer than the 30 s default.
    const slow = new Promise((resolve) =>
      setTimeout(() => resolve("late"), 60_000)
    );

    const raced = (plugin as any).requestWithTimeout(slow);
    const expectation = expect(raced).rejects.toThrow("Request timeout");

    // Advance past the 30 s default; the internal timeout fires before the request.
    await vi.advanceTimersByTimeAsync(30_000);
    await expectation;
  });

  it("resolves when a longer per-request timeoutMs override is supplied", async () => {
    const plugin = makePlugin();
    const slow = new Promise((resolve) =>
      setTimeout(() => resolve("late"), 60_000)
    );

    const raced = (plugin as any).requestWithTimeout(slow, 120_000);

    // Advance past the request's 60 s but before the 120 s override → it resolves.
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(raced).resolves.toBe("late");
  });
});

describe("VaultGuardPlugin readForSync classifier (BIN-A / D-10)", () => {
  // PNG magic + 0x80/0xff/0xfe invalid-UTF-8 bytes: never survives a strict
  // UTF-8 probe, so it must classify as binary.
  const BINARY_BYTES = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00,
  ]);

  beforeEach(() => {
    mockNotice.mockReset();
  });

  it("classifies UTF-8 content as text from a single binary read (capable adapter)", async () => {
    const plugin = makePlugin();
    const readBinary = vi
      .fn()
      .mockResolvedValue(new TextEncoder().encode("# hello world").buffer);
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary,
      write: null,
      list: null,
      remove: null,
      rename: null,
    };

    const runtime = plugin.ensureSyncRuntime();
    const result = await runtime.readForSync("notes/a.md");

    expect(result).toEqual({ kind: "text", text: "# hello world" });
    // One disk read, no double-read (no readPlainFromDisk fallback path).
    expect(readBinary).toHaveBeenCalledTimes(1);
  });

  it("strips a leading UTF-8 BOM to match readPlainFromDisk text semantics", async () => {
    const plugin = makePlugin();
    // EF BB BF is the UTF-8 BOM; TextDecoder('utf-8') consumes it, matching
    // readPlainFromDisk's own TextDecoder.
    const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69]); // BOM + "hi"
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(withBom.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };

    const runtime = plugin.ensureSyncRuntime();
    const result = await runtime.readForSync("notes/bom.md");

    expect(result).toEqual({ kind: "text", text: "hi" });
  });

  it("classifies invalid-UTF-8 bytes as binary, returning the exact bytes read once", async () => {
    const plugin = makePlugin();
    const readBinary = vi.fn().mockResolvedValue(BINARY_BYTES.buffer);
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary,
      write: null,
      list: null,
      remove: null,
      rename: null,
    };

    const runtime = plugin.ensureSyncRuntime();
    const result = await runtime.readForSync("attachments/photo.png");

    expect(result.kind).toBe("binary");
    if (result.kind === "binary") {
      expect(new Uint8Array(result.bytes)).toEqual(BINARY_BYTES);
    }
    expect(readBinary).toHaveBeenCalledTimes(1);
  });

  it("always classifies as text via readPlainFromDisk on a legacy adapter, never touching readBinary (AR2/D-10)", async () => {
    const plugin = makePlugin();
    // Legacy adapter: no readBinary capability.
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: null,
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("legacy string content");
    plugin.readPlainBinaryFromDisk = vi.fn(); // must NOT be called

    const runtime = plugin.ensureSyncRuntime();
    const result = await runtime.readForSync("attachments/photo.png");

    expect(result).toEqual({ kind: "text", text: "legacy string content" });
    expect(plugin.readPlainBinaryFromDisk).not.toHaveBeenCalled();
    expect(plugin.readPlainFromDisk).toHaveBeenCalledWith("attachments/photo.png");
  });
});

describe("VaultGuardPlugin uploadReconciledBinaryFile (BIN-A / D-07)", () => {
  const BINARY_BYTES = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00,
  ]);

  function makeBinaryUploadPlugin() {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);
    return plugin;
  }

  beforeEach(() => {
    mockNotice.mockReset();
  });

  it("uploads bytes via encryptContentBytes with a byte hash, real contentType, and 120 s timeout", async () => {
    const plugin = makeBinaryUploadPlugin();
    let put: any = null;
    plugin.apiRequest = vi.fn(
      async (method: string, path: string, body: any, _idT: unknown, options: unknown) => {
        if (method === "PUT") {
          put = { path, body, options };
          return { success: true, data: {}, error: null, requestId: "req-put" };
        }
        throw new Error(`Unexpected API call: ${method} ${path}`);
      }
    );

    const runtime = plugin.ensureSyncRuntime();
    const outcome = await runtime.uploadReconciledBinaryFile(
      "attachments/photo.png",
      BINARY_BYTES.buffer
    );

    expect(outcome).toBe("uploaded");
    // Vault-scoped path, body extended with contentType only.
    expect(put.path).toContain("/files/");
    expect(Object.keys(put.body).sort()).toEqual(["content", "contentType", "hash"]);
    expect(put.body.contentType).toBe("image/png");
    expect(put.options).toEqual({ timeoutMs: 120000 });
    // The ciphertext round-trips to the original bytes; hash matches computeHashBytes.
    const decrypted = await plugin.decryptContentBytes(put.body.content);
    expect(new Uint8Array(decrypted)).toEqual(BINARY_BYTES);
    expect(put.body.hash).toBe(await plugin.computeHashBytes(BINARY_BYTES.buffer));
    expect(plugin.emitAuditEvent).toHaveBeenCalledWith(
      "file.write",
      "attachments/photo.png",
      { reconciliation: true }
    );
  });

  it("records an upload.binary-push diagnostics breadcrumb on a successful byte upload (D-11 coverage, dev-only)", async () => {
    const plugin = makeBinaryUploadPlugin();
    plugin.apiRequest = vi.fn(async () => ({
      success: true,
      data: {},
      error: null,
      requestId: "req-put",
    }));

    const runtime = plugin.ensureSyncRuntime();
    await runtime.uploadReconciledBinaryFile("attachments/photo.png", BINARY_BYTES.buffer);

    // Completes the binary breadcrumb family (pull / oversize-skip / size-gate
    // already covered by 11-04/05) with the push-success event.
    const pushCrumb = plugin.syncDiagnostics
      .snapshot()
      .find((entry: any) => entry.event === "upload.binary-push");
    expect(pushCrumb).toBeDefined();
    expect(pushCrumb.detail).toEqual({
      path: "attachments/photo.png",
      bytes: BINARY_BYTES.byteLength,
    });
  });

  it("returns skipped-too-large with NO network call and a limit+BIN-B Notice for oversize bytes", async () => {
    const plugin = makeBinaryUploadPlugin();
    plugin.apiRequest = vi.fn();
    const oversize = new Uint8Array(BINARY_SYNC_MAX_BYTES + 1);
    oversize[8] = 0xff;

    const runtime = plugin.ensureSyncRuntime();
    const outcome = await runtime.uploadReconciledBinaryFile("attachments/huge.png", oversize.buffer);

    expect(outcome).toBe("skipped-too-large");
    expect(plugin.apiRequest).not.toHaveBeenCalled();
    // Notice names the file, the 7 MiB limit, and BIN-B.
    const noticed = mockNotice.mock.calls.some(
      ([message]) =>
        typeof message === "string" &&
        message.includes("attachments/huge.png") &&
        message.includes("7 MiB") &&
        message.includes("BIN-B")
    );
    expect(noticed).toBe(true);
  });

  it("returns skipped-no-lease without a PUT when no key lease is available", async () => {
    const plugin = makeBinaryUploadPlugin();
    plugin.keyLease = null;
    plugin.apiRequest = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    const outcome = await runtime.uploadReconciledBinaryFile("a.png", BINARY_BYTES.buffer);

    expect(outcome).toBe("skipped-no-lease");
    expect(plugin.apiRequest).not.toHaveBeenCalled();
  });

  it("returns skipped-no-permission without a PUT when the user lacks WRITE", async () => {
    const plugin = makeBinaryUploadPlugin();
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.NONE);
    plugin.apiRequest = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    const outcome = await runtime.uploadReconciledBinaryFile("a.png", BINARY_BYTES.buffer);

    expect(outcome).toBe("skipped-no-permission");
    expect(plugin.apiRequest).not.toHaveBeenCalled();
  });

  it("throws when the PUT fails (caller requeue discipline unchanged)", async () => {
    const plugin = makeBinaryUploadPlugin();
    plugin.apiRequest = vi.fn(async () => ({
      success: false,
      data: null,
      error: { statusCode: 500, message: "server boom" },
      requestId: "req-put",
    }));

    const runtime = plugin.ensureSyncRuntime();
    await expect(
      runtime.uploadReconciledBinaryFile("a.png", BINARY_BYTES.buffer)
    ).rejects.toThrow("server boom");
  });
});

describe("VaultGuardPlugin handleShareLink (BIN-A / D-11 — local-open-only, no download; T-11-25)", () => {
  // A share token is a POINTER, never a capability token. The handler resolves
  // the token to a (vaultId, relPath) and OPENS the local file via Obsidian's own
  // pipeline (interceptedReadBinary decrypts a synced binary at rest). It NEVER
  // downloads content. Verify-only: no production change — these lock the two
  // branches (synced-open, not-yet-synced Notice) so BIN-A can't regress them.
  function makeShareLinkPlugin(resolvedRelPath: string) {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.apiClient = {
      resolveShare: vi.fn(async () => ({ vaultId: "vault-abc", relPath: resolvedRelPath })),
    };
    // Tripwire: the handler must never issue a content download. Any apiRequest
    // call (e.g. a /files/ GET) would mean the pointer became a capability.
    plugin.apiRequest = vi.fn(async () => ({ success: true, data: {}, error: null, requestId: "x" }));
    return plugin;
  }

  beforeEach(() => {
    mockNotice.mockReset();
  });

  it("opens a locally-present synced binary via workspace.openFile (Obsidian's own pipeline) without downloading", async () => {
    const plugin = makeShareLinkPlugin("attachments/photo.png");
    const file = Object.assign(new TFile(), { path: "attachments/photo.png" });
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => file);
    const openFile = vi.fn().mockResolvedValue(undefined);
    plugin.app.workspace.getLeaf = vi.fn(() => ({ openFile }));

    await plugin.handleShareLink({ token: "tok-1", vaultId: "vault-abc" });

    expect(plugin.apiClient.resolveShare).toHaveBeenCalledWith("vault-abc", "tok-1");
    // Opened via Obsidian's binary pipeline (→ interceptedReadBinary decrypts);
    // the plugin itself fetches no bytes.
    expect(openFile).toHaveBeenCalledWith(file);
    expect(plugin.apiRequest).not.toHaveBeenCalled();
  });

  it("shows the existing \"isn't available in this vault\" Notice for a not-yet-synced binary and downloads nothing", async () => {
    const plugin = makeShareLinkPlugin("attachments/not-synced.png");
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => null);
    const openFile = vi.fn();
    plugin.app.workspace.getLeaf = vi.fn(() => ({ openFile }));

    await plugin.handleShareLink({ token: "tok-2", vaultId: "vault-abc" });

    expect(openFile).not.toHaveBeenCalled();
    const noticed = mockNotice.mock.calls.some(
      ([message]) =>
        typeof message === "string" &&
        message.includes("attachments/not-synced.png") &&
        message.includes("isn't available in this vault")
    );
    expect(noticed).toBe(true);
    expect(plugin.apiRequest).not.toHaveBeenCalled();
  });
});

describe("VaultGuardPlugin writeLocalBinaryFileFromRemote (BIN-A / D-06 pull)", () => {
  function makeBinaryPullPlugin() {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.applyingRemoteWrite = false;
    // Capable adapter: writeBinary present → L13 gate passes.
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn(),
      write: vi.fn(),
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
    plugin.writePlainBinaryToDisk = vi.fn().mockResolvedValue(undefined);
    return plugin;
  }

  beforeEach(() => {
    mockNotice.mockReset();
  });

  it("writes a new binary via vault.createBinary inside the applyingRemoteWrite bracket, ensuring parent folders", async () => {
    const plugin = makeBinaryPullPlugin();
    let appliedDuringWrite: boolean | null = null;
    const createBinary = vi.fn(async () => {
      appliedDuringWrite = plugin.applyingRemoteWrite;
    });
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => null);
    plugin.app.vault.createBinary = createBinary;
    plugin.app.vault.modifyBinary = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]).buffer;
    await runtime.writeLocalBinaryFileFromRemote("attachments/nested/photo.png", bytes);

    // Parent folders ensured for the nested path.
    expect(plugin.ensureParentFoldersForPath).toHaveBeenCalledWith(
      "attachments/nested/photo.png"
    );
    expect(createBinary).toHaveBeenCalledWith("attachments/nested/photo.png", bytes);
    expect(plugin.app.vault.modifyBinary).not.toHaveBeenCalled();
    // The string writers are never used for binary content.
    expect(plugin.writePlainBinaryToDisk).not.toHaveBeenCalled();
    // Bracket: applyingRemoteWrite is TRUE during the write, reset to false after.
    expect(appliedDuringWrite).toBe(true);
    expect(plugin.applyingRemoteWrite).toBe(false);
  });

  it("modifies an existing binary via vault.modifyBinary when a TFile already exists", async () => {
    const plugin = makeBinaryPullPlugin();
    const existing = Object.assign(new TFile(), { path: "attachments/photo.png" });
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => existing);
    plugin.app.vault.createBinary = vi.fn();
    plugin.app.vault.modifyBinary = vi.fn().mockResolvedValue(undefined);

    const runtime = plugin.ensureSyncRuntime();
    const bytes = new Uint8Array([0x89, 0x50, 0x80, 0xff]).buffer;
    await runtime.writeLocalBinaryFileFromRemote("attachments/photo.png", bytes);

    expect(plugin.app.vault.modifyBinary).toHaveBeenCalledWith(existing, bytes);
    expect(plugin.app.vault.createBinary).not.toHaveBeenCalled();
    expect(plugin.applyingRemoteWrite).toBe(false);
  });

  it("falls back to writePlainBinaryToDisk when vault.createBinary throws", async () => {
    const plugin = makeBinaryPullPlugin();
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => null);
    plugin.app.vault.createBinary = vi.fn(async () => {
      throw new Error("vault index stale");
    });
    plugin.app.vault.modifyBinary = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    const bytes = new Uint8Array([0x89, 0x50, 0x80, 0xff]).buffer;
    await runtime.writeLocalBinaryFileFromRemote("a.png", bytes);

    expect(plugin.writePlainBinaryToDisk).toHaveBeenCalledWith("a.png", bytes);
    expect(plugin.applyingRemoteWrite).toBe(false);
  });

  it("skips with a log and no write on a legacy adapter without writeBinary (L13 — never silently drops content)", async () => {
    const plugin = makeBinaryPullPlugin();
    plugin.originalAdapterMethods.writeBinary = null; // legacy adapter
    plugin.app.vault.getAbstractFileByPath = vi.fn();
    plugin.app.vault.createBinary = vi.fn();
    plugin.app.vault.modifyBinary = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    const bytes = new Uint8Array([0x89, 0x50]).buffer;
    await expect(
      runtime.writeLocalBinaryFileFromRemote("a.png", bytes)
    ).resolves.toBeUndefined();

    expect(plugin.app.vault.createBinary).not.toHaveBeenCalled();
    expect(plugin.app.vault.modifyBinary).not.toHaveBeenCalled();
    expect(plugin.writePlainBinaryToDisk).not.toHaveBeenCalled();
    expect(plugin.ensureParentFoldersForPath).not.toHaveBeenCalled();
    expect(plugin.log).toHaveBeenCalled();
  });

  it("resets applyingRemoteWrite even when the write fails entirely (finally-block discipline)", async () => {
    const plugin = makeBinaryPullPlugin();
    plugin.app.vault.getAbstractFileByPath = vi.fn(() => null);
    plugin.app.vault.createBinary = vi.fn(async () => {
      throw new Error("disk full");
    });
    plugin.app.vault.modifyBinary = vi.fn();
    plugin.writePlainBinaryToDisk = vi.fn(async () => {
      throw new Error("cipher not ready");
    });

    const runtime = plugin.ensureSyncRuntime();
    const bytes = new Uint8Array([0x89, 0x50]).buffer;
    await expect(
      runtime.writeLocalBinaryFileFromRemote("a.png", bytes)
    ).rejects.toThrow("cipher not ready");

    expect(plugin.applyingRemoteWrite).toBe(false);
  });
});

describe("VaultGuardPlugin applyRemoteChange binary fork (BIN-A / D-06)", () => {
  function makeApplyRemotePlugin() {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.settings.deletionTombstones = {};
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn(),
      write: vi.fn(),
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    return plugin;
  }

  beforeEach(() => {
    mockNotice.mockReset();
  });

  it("routes a binary GET response (contentType image/png) to the byte writer, never the string writer", async () => {
    const plugin = makeApplyRemotePlugin();
    const fixture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff, 0xfe, 0x00]);
    const encrypted = await plugin.encryptContentBytes(fixture.buffer);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: encrypted, encoding: "base64", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    plugin.writeLocalFileFromRemote = vi.fn(); // string writer — must NOT be called

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn().mockResolvedValue(undefined);

    await runtime.applyRemoteChange({ path: "attachments/photo.png", size: 8 });

    expect(runtime.writeLocalBinaryFileFromRemote).toHaveBeenCalledTimes(1);
    const [calledPath, calledBytes] =
      runtime.writeLocalBinaryFileFromRemote.mock.calls[0];
    expect(calledPath).toBe("attachments/photo.png");
    expect(new Uint8Array(calledBytes)).toEqual(fixture);
    expect(plugin.writeLocalFileFromRemote).not.toHaveBeenCalled();
  });

  it("routes a text GET response (contentType text/markdown) through the string path unchanged", async () => {
    const plugin = makeApplyRemotePlugin();
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: "ignored-ciphertext", contentType: "text/markdown" },
      error: null,
      requestId: "req-get",
    });
    plugin.decodeRemoteFileContent = vi.fn().mockResolvedValue("# hello");
    plugin.writeLocalFileFromRemote = vi.fn().mockResolvedValue(undefined);

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn();

    await runtime.applyRemoteChange({ path: "notes/a.md", size: 7 });

    expect(plugin.writeLocalFileFromRemote).toHaveBeenCalledWith("notes/a.md", "# hello");
    expect(runtime.writeLocalBinaryFileFromRemote).not.toHaveBeenCalled();
  });

  it("treats an undefined contentType as text (fail-safe = today's behavior)", async () => {
    const plugin = makeApplyRemotePlugin();
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: "ignored-ciphertext" }, // no contentType field
      error: null,
      requestId: "req-get",
    });
    plugin.decodeRemoteFileContent = vi.fn().mockResolvedValue("body");
    plugin.writeLocalFileFromRemote = vi.fn().mockResolvedValue(undefined);

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn();

    await runtime.applyRemoteChange({ path: "notes/a.md", size: 4 });

    expect(plugin.writeLocalFileFromRemote).toHaveBeenCalledWith("notes/a.md", "body");
    expect(runtime.writeLocalBinaryFileFromRemote).not.toHaveBeenCalled();
  });

  it("base64-decodes a decrypted:true binary response DIRECTLY, never through a UTF-8 decode (L5)", async () => {
    const plugin = makeApplyRemotePlugin();
    // Bytes that are NOT valid UTF-8: a TextDecoder round-trip would corrupt them.
    const rawBytes = new Uint8Array([0x89, 0x50, 0x80, 0xff, 0xfe, 0x00, 0xc0, 0xc1]);
    const b64 = Buffer.from(rawBytes).toString("base64");
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: {
        content: b64,
        encoding: "base64",
        decrypted: true,
        contentType: "image/png",
      },
      error: null,
      requestId: "req-dec",
    });
    // The string decode path must NOT be used for the binary branch.
    plugin.decodeRemoteFileContent = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn().mockResolvedValue(undefined);

    await runtime.applyRemoteChange({ path: "attachments/photo.png", size: 8 });

    const [, calledBytes] = runtime.writeLocalBinaryFileFromRemote.mock.calls[0];
    expect(new Uint8Array(calledBytes)).toEqual(rawBytes);
    expect(plugin.decodeRemoteFileContent).not.toHaveBeenCalled();
  });

  it("skips with a notice and no write when a binary decrypt fails (OD-2 fail-open, never wipes)", async () => {
    const plugin = makeApplyRemotePlugin();
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: "not-decryptable", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    plugin.decryptContentBytes = vi.fn().mockRejectedValue(new Error("bad tag"));
    plugin.notifyCloudDecryptFallback = vi.fn();

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn();

    await expect(
      runtime.applyRemoteChange({ path: "attachments/photo.png", size: 8 })
    ).resolves.toBeUndefined();

    expect(plugin.notifyCloudDecryptFallback).toHaveBeenCalledWith("attachments/photo.png");
    expect(runtime.writeLocalBinaryFileFromRemote).not.toHaveBeenCalled();
  });

  it("does not decrypt previously cached cloud ciphertext outside lease-authorized paths", async () => {
    const plugin = makeApplyRemotePlugin();
    plugin.keyLease = {
      ...plugin.keyLease,
      deniedPaths: [{ pathPattern: "/secret/**", ruleId: "deny-secret" }],
    };
    plugin.decryptContent = vi.fn().mockResolvedValue("should-not-decrypt");
    const runtime = plugin.ensureSyncRuntime();

    await expect(runtime.decodeRemoteFileContent("secret/cached.md", {
      content: "cached-cloud-ciphertext",
      contentType: "text/markdown",
    })).rejects.toThrow("key lease explicitly denies this path");
    expect(plugin.decryptContent).not.toHaveBeenCalled();

    plugin.fetchRemoteFileContent = vi.fn();
    await runtime.applyRemoteChange({ path: "secret/cached.md", size: 42 });
    expect(plugin.fetchRemoteFileContent).not.toHaveBeenCalled();
  });

  it("returns server-decrypted plaintext for a carve-out path the server authorized (SD-03-F8/F2 allow-override, no over-block)", async () => {
    // A deniedPaths carve-out is a RAW deny rule (the backend does not resolve
    // allow-overrides), so a path whose deny is beaten by a higher-priority
    // allow is still listed. When the server returns already-decrypted bytes it
    // has run its own authoritative per-file gate and allowed the read — the
    // client must honor that instead of over-blocking a readable file.
    const plugin = makeApplyRemotePlugin();
    plugin.keyLease = {
      ...plugin.keyLease,
      deniedPaths: [{ pathPattern: "/secret/**", ruleId: "deny-secret" }],
    };
    plugin.decryptContent = vi.fn().mockResolvedValue("should-not-local-decrypt");
    const runtime = plugin.ensureSyncRuntime();

    const plaintext = "server-authorized body";
    await expect(
      runtime.decodeRemoteFileContent("secret/allowed-by-override.md", {
        content: Buffer.from(plaintext, "utf8").toString("base64"),
        decrypted: true,
        contentType: "text/markdown",
      })
    ).resolves.toBe(plaintext);
    // Server already decrypted it — the local vault DEK must NOT be used.
    expect(plugin.decryptContent).not.toHaveBeenCalled();
  });

  it("still decrypts a non-denied path's raw ciphertext with the vault DEK (normal path intact)", async () => {
    const plugin = makeApplyRemotePlugin();
    plugin.keyLease = {
      ...plugin.keyLease,
      deniedPaths: [{ pathPattern: "/secret/**", ruleId: "deny-secret" }],
    };
    plugin.decryptContent = vi.fn().mockResolvedValue("decrypted body");
    const runtime = plugin.ensureSyncRuntime();

    await expect(
      runtime.decodeRemoteFileContent("notes/ok.md", {
        content: "raw-ciphertext",
        contentType: "text/markdown",
      })
    ).resolves.toBe("decrypted body");
    expect(plugin.decryptContent).toHaveBeenCalledWith("raw-ciphertext");
  });

  it("materializes a serverOnly binary through the SAME applyRemoteChange fork during reconciliation", async () => {
    // Proves the chokepoint covers the reconciliation download surface (and, by
    // construction, the delta-loop and repair surfaces that call the identical
    // this.ctx.applyRemoteChange). Real applyRemoteChange runs (not stubbed).
    const plugin = makeApplyRemotePlugin();
    plugin.connectionState.status = "online";
    plugin.isOnline = vi.fn(() => true);
    plugin.vaultLeaseDenied = false;
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.uploadReconciledFile = vi.fn().mockResolvedValue("uploaded");
    plugin.askReconciliationPlan = vi
      .fn()
      .mockResolvedValue({ proceed: true, conflictStrategy: "keep-local" });

    const fixture = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
    const encrypted = await plugin.encryptContentBytes(fixture.buffer);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: encrypted, encoding: "base64", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            deltas: [
              {
                path: "/attachments/photo.png",
                action: "created",
                lastModified: "x",
                checksum: "c",
                size: 6,
              },
            ],
            syncTimestamp: "2026-07-03T00:00:00.000Z",
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn().mockResolvedValue(undefined);

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    expect(runtime.writeLocalBinaryFileFromRemote).toHaveBeenCalledTimes(1);
    const [p, b] = runtime.writeLocalBinaryFileFromRemote.mock.calls[0];
    expect(p).toBe("attachments/photo.png");
    expect(new Uint8Array(b)).toEqual(fixture);
  });
});

describe("VaultGuardPlugin connection and crypto helpers", () => {
  beforeEach(() => {
    mockNotice.mockReset();
    mockRequestUrl.mockReset();
    ((Menu as unknown as { instances: unknown[] }).instances ?? []).length = 0;
    vi.stubGlobal("localStorage", makeMemoryStorage());
    Object.defineProperty(ensureTestWindow(), "require", {
      configurable: true,
      value: undefined,
    });
  });

  it("roundtrips encrypted content with the active key lease", async () => {
    const plugin = makePlugin();
    plugin.keyLease = makeKeyLease();

    const encrypted = await plugin.encryptContent("hello vaultguard");

    expect(encrypted).not.toBe("hello vaultguard");
    await expect(plugin.decryptContent(encrypted)).resolves.toBe("hello vaultguard");
  });

  it("sends the current lease ID when renewing a key lease", async () => {
    const plugin = makePlugin();
    const currentLease = makeKeyLease();
    const nextLease = {
      ...makeKeyLease(),
      leaseId: "lease-2",
      refreshToken: "refresh-token-2",
    };
    plugin.session = makeSession();
    plugin.keyLease = currentLease;
    plugin.applyOrgSettings = vi.fn();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: {
        sessionId: "session-1",
        expiresAt: nextLease.expiresAt,
        keyLease: nextLease,
      },
      error: null,
      requestId: "req-1",
    });

    await plugin.renewKeyLease();

    expect(plugin.apiRequest).toHaveBeenCalledWith(
      "POST",
      "/auth/refresh",
      {
        sessionId: "session-1",
        leaseId: "lease-1",
        refreshToken: "refresh-token",
      }
    );
    expect(plugin.keyLease.leaseId).toBe("lease-2");
  });

  it("merges lease and response deniedPaths deterministically and rejects malformed carve-outs", () => {
    const plugin = makePlugin();
    const normalized = plugin.normalizeKeyLease(
      {
        ...makeKeyLease(),
        deniedPaths: [{ pathPattern: "/z/**", ruleId: "z" }],
      },
      [{ pathPattern: "/a/**", ruleId: "a" }]
    );
    expect(normalized.deniedPaths).toEqual([
      { pathPattern: "/a/**", ruleId: "a" },
      { pathPattern: "/z/**", ruleId: "z" },
    ]);

    expect(() => plugin.normalizeKeyLease({
      ...makeKeyLease(),
      deniedPaths: [{ pathPattern: "relative/**", ruleId: "bad" }],
    })).toThrow("malformed key-lease denied paths");
  });

  it("recovers an expired key lease without clearing the stored login", async () => {
    const plugin = makePlugin();
    const currentLease = makeKeyLease();
    const replacementLease = {
      ...makeKeyLease(),
      leaseId: "lease-2",
      refreshToken: "refresh-token-2",
    };
    plugin.session = makeSession();
    plugin.keyLease = currentLease;
    plugin.applyOrgSettings = vi.fn();
    plugin.forceLogout = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn(async (_method: string, endpoint: string) => {
      if (endpoint === "/auth/refresh") {
        return {
          success: false,
          data: null,
          error: {
            code: "AUTH_ERROR",
            message: "Lease has expired",
            details: null,
            statusCode: 401,
          },
          requestId: "req-1",
        };
      }
      if (endpoint === "/auth/key-lease/scoped") {
        return {
          success: true,
          data: { keyLease: replacementLease },
          error: null,
          requestId: "req-2",
        };
      }
      throw new Error(`Unexpected endpoint ${endpoint}`);
    });

    await plugin.renewKeyLease();

    expect(plugin.forceLogout).not.toHaveBeenCalled();
    expect(plugin.session).toMatchObject({ sessionId: "session-1" });
    expect(plugin.keyLease).toMatchObject({ leaseId: "lease-2" });
    expect(plugin.apiRequest.mock.calls.map((call: any[]) => call[1])).toEqual([
      "/auth/refresh",
      "/auth/key-lease/scoped",
    ]);
  });

  it("degrades to limited access instead of logging out when a revoked lease cannot be reissued", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.forceLogout = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn(async (_method: string, endpoint: string) => {
      if (endpoint === "/auth/refresh") {
        return {
          success: false,
          data: null,
          error: {
            code: "AUTH_ERROR",
            message: "Lease has been revoked",
            details: null,
            statusCode: 403,
          },
          requestId: "req-1",
        };
      }
      if (endpoint === "/auth/key-lease/scoped") {
        return {
          success: false,
          data: null,
          error: {
            code: "AUTH_ERROR",
            message: "Access denied: insufficient permissions for requested key scope",
            details: null,
            statusCode: 403,
          },
          requestId: "req-2",
        };
      }
      throw new Error(`Unexpected endpoint ${endpoint}`);
    });

    await plugin.renewKeyLease();

    expect(plugin.forceLogout).not.toHaveBeenCalled();
    expect(plugin.session).toMatchObject({ sessionId: "session-1" });
    expect(plugin.keyLease).toBeNull();
    expect(plugin.vaultLeaseDenied).toBe(true);
  });

  it("flushes the offline queue when reconnecting transitions back online", () => {
    const plugin = makePlugin();
    plugin.connectionState.status = "reconnecting";
    plugin.flushOfflineQueue = vi.fn().mockResolvedValue(undefined);

    plugin.setConnectionStatus("online");

    expect(plugin.flushOfflineQueue).toHaveBeenCalledOnce();
  });

  it("refreshes the file permission header on the offline→online edge", () => {
    const plugin = makePlugin();
    plugin.connectionState.status = "reconnecting";
    plugin.flushOfflineQueue = vi.fn().mockResolvedValue(undefined);
    plugin.refreshFilePermissionHeader = vi.fn();

    plugin.setConnectionStatus("online");

    // The header rendered its offline/unavailable state on launch (the online
    // flip is deferred until first sync); refresh it on the edge so it
    // self-corrects without the user switching files.
    expect(plugin.refreshFilePermissionHeader).toHaveBeenCalledOnce();
  });

  it("does not refresh the file permission header when already online (edge-only)", () => {
    const plugin = makePlugin();
    plugin.connectionState.status = "online";
    plugin.flushOfflineQueue = vi.fn().mockResolvedValue(undefined);
    plugin.refreshFilePermissionHeader = vi.fn();

    plugin.setConnectionStatus("online");

    expect(plugin.refreshFilePermissionHeader).not.toHaveBeenCalled();
  });

  it("counts a failed reconnection attempt only once", async () => {
    const plugin = makePlugin();
    plugin.session = {
      ...makeSession(),
      tokenExpiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    };
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: {
        code: "REQUEST_FAILED",
        message: "still offline",
        details: null,
        statusCode: 503,
      },
      requestId: "req-123",
    });

    await plugin.attemptReconnection();

    expect(plugin.connectionState.status).toBe("offline");
    expect(plugin.connectionState.failedAttempts).toBe(1);
    expect(plugin.scheduleConnectionRetry).toHaveBeenCalledOnce();
    expect(
      mockNotice.mock.calls.some(([message]) =>
        String(message).includes("Connection lost")
      )
    ).toBe(false);
  });

  it("marks the plugin offline when an API request exhausts network retries, then surfaces the debounced notice after the grace window", async () => {
    vi.useFakeTimers();
    try {
      const plugin = makePlugin();
      plugin.session = {
        ...makeSession(),
        tokenExpiresAt: new Date(Date.now() + 10 * 60_000).toISOString(),
      };
      plugin.connectionState.status = "online";
      plugin.settings.apiEndpoint = "https://api.vaultguard.test";
      plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
      plugin.settings.maxRetryAttempts = 1;
      mockRequestUrl.mockResolvedValueOnce({
        status: 0,
        json: null,
        text: "net::ERR_INTERNET_DISCONNECTED",
        headers: {},
      } as any);

      const response = await plugin.apiRequest("GET", "/vaults");

      expect(response).toMatchObject({
        success: false,
        error: {
          code: "NETWORK_ERROR",
          statusCode: 0,
        },
      });
      expect(plugin.connectionState.status).toBe("offline");
      expect(plugin.scheduleConnectionRetry).toHaveBeenCalledOnce();

      // Debounced: the alarming toast must NOT fire immediately — a transient
      // blip might still recover within the grace window.
      expect(
        mockNotice.mock.calls.some(([message]) =>
          String(message).includes("Connection lost")
        )
      ).toBe(false);

      // Still offline when the grace window elapses → the toast fires once.
      await vi.advanceTimersByTimeAsync(8_000);
      expect(
        mockNotice.mock.calls.some(([message]) =>
          String(message).includes("Connection lost")
        )
      ).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("suppresses the connection-lost notice when connectivity returns within the grace window", async () => {
    vi.useFakeTimers();
    try {
      const plugin = makePlugin();
      plugin.session = makeSession();
      plugin.flushOfflineQueue = vi.fn().mockResolvedValue(undefined);
      plugin.connectionState.status = "online";

      // A transient blip flips the status offline...
      plugin.setConnectionStatus("offline");
      expect(plugin.connectionState.status).toBe("offline");

      // ...then recovers before the 8s grace window elapses.
      await vi.advanceTimersByTimeAsync(3_000);
      plugin.setConnectionStatus("online");
      await vi.advanceTimersByTimeAsync(10_000);

      // No alarming toast for a blip that self-healed.
      expect(
        mockNotice.mock.calls.some(([message]) =>
          String(message).includes("Connection lost")
        )
      ).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not send a stale ID token to the backend when Cognito refresh fails", async () => {
    const plugin = makePlugin();
    plugin.session = {
      ...makeSession(),
      idToken: "expired-id-token",
      tokenExpiresAt: new Date(Date.now() - 60_000).toISOString(),
    };
    plugin.connectionState.status = "online";
    plugin.settings.apiEndpoint = "https://api.vaultguard.test";
    plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
    plugin.settings.maxRetryAttempts = 1;
    mockRequestUrl.mockResolvedValueOnce({
      status: 0,
      json: { message: "Cognito temporarily unavailable" },
      text: "net::ERR_INTERNET_DISCONNECTED",
      headers: {},
    } as any);

    const response = await plugin.apiRequest("GET", "/auth/heartbeat?sessionId=session-1");

    expect(response).toMatchObject({
      success: false,
      error: {
        code: "TOKEN_REFRESH_FAILED",
        statusCode: 0,
      },
    });
    expect(plugin.session).toMatchObject({ idToken: "expired-id-token" });
    expect(mockRequestUrl).toHaveBeenCalledOnce();
    expect(mockRequestUrl.mock.calls[0][0].url).toContain("cognito-idp");
  });

  it("escalates a terminal Cognito refresh rejection to a revocation logout (PL4)", async () => {
    const plugin = makePlugin();
    plugin.session = {
      ...makeSession(),
      idToken: "expired-id-token",
      tokenExpiresAt: new Date(Date.now() - 60_000).toISOString(),
    };
    plugin.connectionState.status = "online";
    plugin.settings.apiEndpoint = "https://api.vaultguard.test";
    plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
    plugin.settings.maxRetryAttempts = 1;
    plugin.handleServerRevocation = vi.fn().mockResolvedValue(undefined);
    // Cognito rejects the refresh TERMINALLY (revoked token / disabled user).
    mockRequestUrl.mockResolvedValueOnce({
      status: 400,
      json: { __type: "NotAuthorizedException", message: "Refresh Token has been revoked" },
      text: "",
      headers: {},
    } as any);

    const response = await plugin.apiRequest("GET", "/auth/heartbeat?sessionId=session-1");

    expect(response).toMatchObject({
      success: false,
      error: { code: "SESSION_REVOKED", statusCode: 401 },
    });
    expect(plugin.handleServerRevocation).toHaveBeenCalledWith("session expired or revoked");
    // Only the Cognito call went out — the dead token never reached the backend
    // and the pre-fix perpetual statusCode-0 "offline" parking did not happen.
    expect(mockRequestUrl).toHaveBeenCalledOnce();
    expect(mockRequestUrl.mock.calls[0][0].url).toContain("cognito-idp");
  });

  it("recovers from an expired MFA challenge session by minting a fresh challenge (PL5)", async () => {
    const plugin = makePlugin();
    plugin.pendingChallengeSession = "dead-challenge-session";
    mockRequestUrl
      // RespondToAuthChallenge with the ~3-minute-old session → expired.
      .mockResolvedValueOnce({
        status: 400,
        json: {
          __type: "NotAuthorizedException",
          message: "Invalid session for the user, session is expired.",
        },
        text: "",
        headers: {},
      } as any)
      // Automatic re-login mints a FRESH MFA challenge.
      .mockResolvedValueOnce({
        status: 200,
        json: { ChallengeName: "SOFTWARE_TOKEN_MFA", Session: "fresh-challenge-session" },
        text: "",
        headers: {},
      } as any);

    await expect(
      plugin.performLogin({
        email: "user@test.com",
        password: "pw-123456",
        mfaCode: "000000",
      })
    ).rejects.toThrow(/MFA code expired/i);

    // The dead session is gone and the fresh one is armed — the next submit
    // responds to the NEW challenge instead of replaying the dead one forever.
    expect(plugin.pendingChallengeSession).toBe("fresh-challenge-session");
    expect(mockRequestUrl).toHaveBeenCalledTimes(2);
    const targets = mockRequestUrl.mock.calls.map(
      (c) => (c[0].headers as Record<string, string>)["X-Amz-Target"]
    );
    expect(targets[0]).toContain("RespondToAuthChallenge");
    expect(targets[1]).toContain("InitiateAuth");
  });

  it("returns the REAL status for permanent HTTP failures without retrying (AC-API1)", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.isSessionTokenExpiring = vi.fn(() => false);
    plugin.connectionState.status = "online";
    plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
    plugin.settings.maxRetryAttempts = 3;
    mockRequestUrl.mockResolvedValue({
      status: 404,
      json: { message: "File not found", code: "NOT_FOUND" },
      text: JSON.stringify({ message: "File not found" }),
      headers: { "x-request-id": "req-404" },
    } as any);

    const response = await plugin.apiRequest("DELETE", "/vaults/vault-abc/files/x.md");

    expect(response).toMatchObject({
      success: false,
      error: { statusCode: 404, code: "NOT_FOUND", message: "File not found" },
    });
    // Permanent failure: exactly ONE request — no retry storm, and the
    // pre-fix collapse to statusCode 0 (offline + endless requeue) is gone.
    expect(mockRequestUrl).toHaveBeenCalledTimes(1);
    expect(plugin.connectionState.status).toBe("online");
  });

  it("retries 5xx and then returns the real status instead of statusCode 0 (AC-API1)", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.isSessionTokenExpiring = vi.fn(() => false);
    plugin.connectionState.status = "online";
    plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
    plugin.settings.maxRetryAttempts = 2;
    plugin.delay = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockResolvedValue({
      status: 503,
      json: { message: "Service unavailable" },
      text: JSON.stringify({ message: "Service unavailable" }),
      headers: {},
    } as any);

    const response = await plugin.apiRequest("GET", "/vaults/vault-abc/files");

    expect(mockRequestUrl).toHaveBeenCalledTimes(2);
    expect(response).toMatchObject({
      success: false,
      error: { statusCode: 503 },
    });
    // A server-side failure is NOT a network outage.
    expect(plugin.connectionState.status).toBe("online");
  });

  it("re-resolves a stale cached API endpoint when server-session login hits an AWS SigV4 gateway error", async () => {
    const plugin = makePlugin();
    plugin.settings.apiEndpoint = "https://api.vaultguard.test";
    plugin.resolvedApiEndpoint = "https://stale.vaultguard.test";
    plugin.settings.maxRetryAttempts = 2;
    const sessionEnvelope = {
      sessionId: "server-session-1",
      userId: "user-1",
      email: "user@example.com",
      roles: ["admin"],
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    mockRequestUrl
      .mockResolvedValueOnce(awsSigV4GatewayResponse())
      .mockResolvedValueOnce(jsonResponse(200, { vaults: [] }))
      .mockResolvedValueOnce(jsonResponse(200, sessionEnvelope));

    await expect(plugin.openServerSession("provider-id-token")).resolves.toEqual(
      sessionEnvelope
    );

    expect(mockRequestUrl.mock.calls.map((call) => call[0].url)).toEqual([
      "https://stale.vaultguard.test/auth/session",
      "https://api.vaultguard.test/vaults",
      "https://api.vaultguard.test/auth/session",
    ]);
    expect(mockRequestUrl.mock.calls[0][0].headers).toMatchObject({
      Authorization: "provider-id-token",
    });
    expect(mockRequestUrl.mock.calls[2][0].headers).toMatchObject({
      Authorization: "provider-id-token",
    });
  });

  it("sanitizes unrecoverable AWS SigV4 gateway errors during server-session login", async () => {
    const plugin = makePlugin();
    plugin.settings.apiEndpoint = "https://api.vaultguard.test";
    plugin.resolvedApiEndpoint = "https://api.vaultguard.test";
    plugin.settings.maxRetryAttempts = 2;
    const rawAwsMessage =
      "Authorization header requires 'Credential' parameter. " +
      "Authorization header requires 'Signature' parameter. " +
      "Authorization header requires 'SignedHeaders' parameter. " +
      "Authorization=W1OMEyBH/FmQL+YPOaLvOX/mWkhUnVBCMQ7";

    mockRequestUrl
      .mockResolvedValueOnce(awsSigV4GatewayResponse(rawAwsMessage))
      .mockResolvedValueOnce(awsSigV4GatewayResponse(rawAwsMessage));

    let thrown: unknown;
    try {
      await plugin.openServerSession("provider-id-token");
    } catch (error) {
      thrown = error;
    }
    const message = thrown instanceof Error ? thrown.message : String(thrown);
    expect(message).toContain("VaultGuard API endpoint rejected the request");
    expect(message).not.toMatch(/Credential|Signature|SignedHeaders|Authorization=/i);
    expect(message).not.toContain("<Error");
    expect(mockRequestUrl.mock.calls[0][0].url).toBe(
      "https://api.vaultguard.test/auth/session"
    );
    expect(mockRequestUrl.mock.calls.slice(1).map((call) => call[0].url)).toContain(
      "https://api.vaultguard.test/vaults"
    );
  });

  it("keeps the user logged in but skips vault binding and sync in Local Project Memory Mode", async () => {
    const plugin = makePlugin();
    plugin.settings.localProjectMemoryMode = true;
    plugin.settings.manualConfig = true;
    plugin.settings.serverVaultId = "";
    plugin.openServerSession = vi.fn().mockResolvedValue({
      sessionId: "server-session-1",
      userId: "user-1",
      email: "test@example.com",
      roles: ["member"],
      orgSettings: null,
    });
    plugin.decodeJwtPayload = vi.fn(() => ({
      sub: "user-1",
      email: "test@example.com",
      name: "Test User",
      "custom:org": "org-1",
    }));
    plugin.syncSettingsFromTokenPayload = vi.fn(() => false);
    plugin.rebuildApiClient = vi.fn();
    plugin.initializeApiClientFromSession = vi.fn();
    plugin.persistSession = vi.fn().mockResolvedValue(undefined);
    plugin.promptVaultBinding = vi.fn().mockResolvedValue(true);
    plugin.initializeSyncEngine = vi.fn().mockResolvedValue(undefined);
    plugin.startKeyRenewalMonitor = vi.fn();
    plugin.startHeartbeatMonitor = vi.fn();
    plugin.stopSyncTimer = vi.fn();
    plugin.stopKeyRenewalMonitor = vi.fn();
    plugin.stopHeartbeatMonitor = vi.fn();

    await plugin.completeLogin(
      {
        tokens: {
          idToken: "provider-id-token",
          accessToken: "access-token",
          refreshToken: "refresh-token",
          expiresIn: 3600,
        },
      },
      "test@example.com",
    );

    expect(plugin.session).toMatchObject({
      sessionId: "server-session-1",
      email: "test@example.com",
    });
    expect(plugin.persistSession).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: "server-session-1" }),
    );
    expect(plugin.promptVaultBinding).not.toHaveBeenCalled();
    expect(plugin.initializeSyncEngine).not.toHaveBeenCalled();
    expect(plugin.startKeyRenewalMonitor).not.toHaveBeenCalled();
    expect(plugin.startHeartbeatMonitor).not.toHaveBeenCalled();
    expect(plugin.stopSyncTimer).toHaveBeenCalled();
    expect(plugin.stopKeyRenewalMonitor).toHaveBeenCalled();
    expect(plugin.stopHeartbeatMonitor).toHaveBeenCalled();
    expect(plugin.connectionState.status).toBe("offline");
    expect(mockNotice).toHaveBeenCalledWith(
      expect.stringContaining("Logged in as Test User"),
      8000,
    );
  });

  it("does not schedule retry timers while the browser reports offline", () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.connectionState.status = "online";
    plugin.pauseSyncLoop = vi.fn();

    plugin.handleBrowserOffline();

    expect(plugin.connectionState.status).toBe("offline");
    expect(plugin.scheduleConnectionRetry).not.toHaveBeenCalled();
    expect(plugin.pauseSyncLoop).toHaveBeenCalledWith("network offline");
  });

  it("re-queues an offline flush batch in order after a network failure", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [
      {
        operation: "write",
        path: "a.md",
        data: "A",
        timestamp: "2026-01-01T00:00:00.000Z",
      },
      {
        operation: "write",
        path: "b.md",
        data: "B",
        timestamp: "2026-01-01T00:00:01.000Z",
      },
    ];
    plugin.apiRequest = vi.fn().mockRejectedValue(new Error("net::ERR_CONNECTION_REFUSED"));

    await plugin.flushOfflineQueue();

    expect(plugin.offlineQueue.map((op: any) => op.path)).toEqual(["a.md", "b.md"]);
    expect(plugin.connectionState.status).toBe("offline");
  });

  describe("offline-queue v2 flush — binary fork (BIN-A / L8)", () => {
    const ok = { success: true, data: {}, error: null, requestId: "r" };
    const failWith = (statusCode: number, message: string) => ({
      success: false,
      data: null,
      error: { code: "ERR", message, details: null, statusCode },
      requestId: "r",
    });

    it("flushes a queued binary op through the byte path with contentType + 120 s timeout", async () => {
      const plugin = makePlugin();
      plugin.session = makeSession();
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = "online";

      // PNG magic + invalid-UTF-8 bytes: a lossy string flush would corrupt this.
      const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff, 0xfe, 0x00]);
      plugin.offlineQueue = [
        {
          operation: "write",
          path: "img/pic.png",
          data: Buffer.from(PNG).toString("base64"),
          timestamp: "2026-07-03T00:00:00.000Z",
          encoding: "base64",
          contentType: "image/png",
        },
      ];
      plugin.apiRequest = vi.fn().mockResolvedValue(ok);

      await plugin.flushOfflineQueue();

      expect(plugin.apiRequest).toHaveBeenCalledTimes(1);
      const [method, endpoint, body, idToken, options] = plugin.apiRequest.mock.calls[0];
      expect(method).toBe("PUT");
      expect(endpoint).toContain("img%2Fpic.png");
      expect(body.contentType).toBe("image/png");
      expect(idToken).toBeUndefined();
      expect(options).toEqual({ timeoutMs: 120_000 });
      // hash is the BYTE hash of the plain bytes…
      expect(body.hash).toBe(await plugin.computeHashBytes(PNG.buffer));
      // …and content decrypts back to the exact original bytes (no lossy decode).
      const decrypted = await plugin.decryptContentBytes(body.content);
      expect(new Uint8Array(decrypted)).toEqual(PNG);
      expect(plugin.offlineQueue).toHaveLength(0);
    });

    it("leaves the text flush body byte-identical ({ content, hash }, no contentType, no timeout)", async () => {
      const plugin = makePlugin();
      plugin.session = makeSession();
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = "online";
      plugin.offlineQueue = [
        {
          operation: "write",
          path: "notes/a.md",
          data: "hello",
          timestamp: "2026-07-03T00:00:00.000Z",
        },
      ];
      plugin.apiRequest = vi.fn().mockResolvedValue(ok);

      await plugin.flushOfflineQueue();

      const [method, , body, , options] = plugin.apiRequest.mock.calls[0];
      expect(method).toBe("PUT");
      expect(body).toEqual({ content: expect.any(String), hash: expect.any(String) });
      expect(body).not.toHaveProperty("contentType");
      expect(options).toBeUndefined();
    });

    it("drops a binary op on a permanent 413 with a Notice naming the path; text stays console-only", async () => {
      // Binary + 413 → dropped (not requeued) + Notice.
      const plugin = makePlugin();
      plugin.session = makeSession();
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = "online";
      plugin.offlineQueue = [
        {
          operation: "write",
          path: "img/big.png",
          data: Buffer.from(new Uint8Array([0x89, 0x50, 0xff])).toString("base64"),
          timestamp: "2026-07-03T00:00:00.000Z",
          encoding: "base64",
          contentType: "image/png",
        },
      ];
      plugin.apiRequest = vi.fn().mockResolvedValue(failWith(413, "Payload too large"));
      mockNotice.mockClear();

      await plugin.flushOfflineQueue();

      expect(plugin.offlineQueue).toHaveLength(0);
      expect(mockNotice).toHaveBeenCalledWith(expect.stringContaining("img/big.png"), 10_000);

      // Text + 413 → dropped, NO Notice (today's semantics preserved).
      const plugin2 = makePlugin();
      plugin2.session = makeSession();
      plugin2.keyLease = makeKeyLease();
      plugin2.connectionState.status = "online";
      plugin2.offlineQueue = [
        {
          operation: "write",
          path: "notes/big.md",
          data: "x",
          timestamp: "2026-07-03T00:00:00.000Z",
        },
      ];
      plugin2.apiRequest = vi.fn().mockResolvedValue(failWith(413, "Payload too large"));
      mockNotice.mockClear();

      await plugin2.flushOfflineQueue();

      expect(plugin2.offlineQueue).toHaveLength(0);
      expect(mockNotice).not.toHaveBeenCalled();
    });

    it("requeues a binary op on a transient statusCode 0 (AC-API1 discipline intact)", async () => {
      const plugin = makePlugin();
      plugin.session = makeSession();
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = "online";
      plugin.offlineQueue = [
        {
          operation: "write",
          path: "img/x.png",
          data: Buffer.from(new Uint8Array([0x89, 0xff])).toString("base64"),
          timestamp: "2026-07-03T00:00:00.000Z",
          encoding: "base64",
          contentType: "image/png",
        },
      ];
      plugin.apiRequest = vi.fn().mockResolvedValue(failWith(0, "Network request failed"));
      mockNotice.mockClear();

      await plugin.flushOfflineQueue();

      // Transient → requeued (never dropped), offline flip, and NO drop Notice.
      expect(plugin.offlineQueue.map((op: any) => op.path)).toEqual(["img/x.png"]);
      expect(plugin.connectionState.status).toBe("offline");
      expect(mockNotice).not.toHaveBeenCalled();
    });
  });

  it("flushes queued writes with the captured expectedVersionId and stores the returned version", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [
      {
        operation: "write",
        path: "a.md",
        data: "A",
        baseVersionId: "v1",
        timestamp: "2026-01-01T00:00:00.000Z",
      },
    ];
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: {
        path: "/a.md",
        versionId: "v2",
        checksum: '"etag-2"',
        size: 1,
        lastModified: "2026-07-03T00:00:00.000Z",
      },
      error: null,
      requestId: "req-write",
    });

    await plugin.flushOfflineQueue();

    expect(plugin.offlineQueue).toHaveLength(0);
    expect(plugin.apiRequest).toHaveBeenCalledWith(
      "PUT",
      "/vaults/vault-abc/files/a.md",
      expect.objectContaining({ expectedVersionId: "v1" })
    );
    expect(plugin.remoteFileState.getExpectedVersionId("a.md")).toBe("v2");
  });

  it("keeps an offline queued write pending when replay hits a version conflict requiring user resolution", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.settings.defaultConflictResolution = "ask_user";
    plugin.offlineQueue = [
      {
        operation: "write",
        path: "a.md",
        data: "local edit",
        baseVersionId: "v1",
        timestamp: "2026-01-01T00:00:00.000Z",
      },
    ];
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: {
        content: Buffer.from("remote edit").toString("base64"),
        decrypted: true,
        versionId: "v2",
        lastModified: "2026-07-03T00:00:00.000Z",
      },
      error: null,
      requestId: "req-read",
    });
    plugin.decodeRemoteFileContent = vi.fn().mockResolvedValue("remote edit");
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: {
        code: "CONFLICT",
        message: "stale version",
        details: null,
        statusCode: 409,
      },
      requestId: "req-conflict",
    });

    await plugin.flushOfflineQueue();

    expect(plugin.offlineQueue).toHaveLength(1);
    expect(plugin.offlineQueue[0]).toMatchObject({
      operation: "write",
      path: "a.md",
      data: "local edit",
      baseVersionId: "v1",
    });
    expect(plugin.syncState.conflicts).toHaveLength(1);
    expect(plugin.syncState.conflicts[0]).toMatchObject({
      path: "a.md",
      localHash: expect.any(String),
      remoteHash: expect.any(String),
      resolution: null,
    });
  });

  it("keeps an offline queued write pending when replay discovers the remote file was deleted", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.settings.defaultConflictResolution = "ask_user";
    plugin.remoteFileState.recordPresent("a.md", {
      versionId: "v1",
      baseHash: "base-hash",
    });
    plugin.offlineQueue = [
      {
        operation: "write",
        path: "a.md",
        data: "local edit after remote delete",
        baseVersionId: "v1",
        timestamp: "2026-01-01T00:00:00.000Z",
      },
    ];
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: {
        code: "NOT_FOUND",
        message: "File not found",
        details: null,
        statusCode: 404,
      },
      requestId: "req-read-missing",
    });
    plugin.decodeRemoteFileContent = vi.fn();
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: {
        code: "CONFLICT",
        message: "current version is missing",
        details: null,
        statusCode: 409,
      },
      requestId: "req-conflict",
    });

    await plugin.flushOfflineQueue();

    expect(plugin.fetchRemoteFileContent).toHaveBeenCalledWith("a.md");
    expect(plugin.decodeRemoteFileContent).not.toHaveBeenCalled();
    expect(plugin.offlineQueue).toHaveLength(1);
    expect(plugin.remoteFileState.get("a.md")).toMatchObject({ state: "absent" });
    expect(plugin.syncState.conflicts[0]).toMatchObject({
      path: "a.md",
      localHash: expect.any(String),
      remoteHash: "remote-deleted",
      baseHash: "base-hash",
      remoteDeleted: true,
      resolution: null,
    });
  });

  it("keeps an offline queued delete pending when replay hits a version conflict", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.settings.deletionTombstones = { "a.md": "2026-01-01T00:00:00.000Z" };
    plugin.offlineQueue = [
      {
        operation: "delete",
        path: "a.md",
        baseVersionId: "v1",
        timestamp: "2026-01-01T00:00:00.000Z",
      },
    ];
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: {
        code: "CONFLICT",
        message: "stale delete",
        details: null,
        statusCode: 409,
      },
      requestId: "req-delete-conflict",
    });

    await plugin.flushOfflineQueue();

    expect(plugin.apiRequest).toHaveBeenCalledWith(
      "DELETE",
      "/vaults/vault-abc/files/a.md",
      { expectedVersionId: "v1" }
    );
    expect(plugin.offlineQueue).toHaveLength(1);
    expect(plugin.offlineQueue[0]).toMatchObject({
      operation: "delete",
      path: "a.md",
      baseVersionId: "v1",
    });
    expect(plugin.settings.deletionTombstones["a.md"]).toBe("2026-01-01T00:00:00.000Z");
  });

  it("resolves a pending remote-deleted conflict by keeping the remote deletion", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.settings.defaultConflictResolution = "keep_remote";
    plugin.originalAdapterMethods = {
      ...(plugin.originalAdapterMethods ?? {}),
      remove: vi.fn().mockResolvedValue(undefined),
    };
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);
    const conflict = {
      path: "a.md",
      localHash: "local-hash",
      remoteHash: "remote-deleted",
      baseHash: "base-hash",
      detectedAt: "2026-01-01T00:00:00.000Z",
      resolution: null,
      localModified: "2026-01-01T00:00:00.000Z",
      remoteModified: "2026-01-01T00:00:01.000Z",
      remoteDeleted: true,
    };

    await plugin.handleConflict(conflict);

    expect(plugin.originalAdapterMethods.remove).toHaveBeenCalledWith("a.md");
    expect(plugin.remoteFileState.get("a.md")).toMatchObject({ state: "absent" });
    expect(conflict.resolution).toBe("keep_remote");
  });

  it("does not fail startup when Obsidian protocol handlers are unavailable", () => {
    const plugin = makePlugin();

    expect(() => plugin.registerInviteProtocolHandler()).not.toThrow();
    expect(plugin.log).toHaveBeenCalledWith(
      "Obsidian protocol handlers are not available in this Obsidian version; invite links can still be pasted in settings."
    );
  });

  it("registers the invite protocol handler when Obsidian exposes the API", () => {
    const plugin = makePlugin();
    plugin.registerObsidianProtocolHandler = vi.fn();

    plugin.registerInviteProtocolHandler();

    expect(plugin.registerObsidianProtocolHandler).toHaveBeenCalledWith(
      "vaultguard-invite",
      expect.any(Function)
    );
  });

  it("opens the VaultGuard settings tab through Obsidian settings", () => {
    const plugin = makePlugin();
    const open = vi.fn();
    const openTabById = vi.fn();
    plugin.app = {
      setting: {
        open,
        openTabById,
      },
    };
    plugin.manifest = { id: "vaultguard" };

    plugin.openVaultGuardSettings();

    expect(open).toHaveBeenCalledOnce();
    expect(openTabById).toHaveBeenCalledWith("vaultguard");
  });

  it("registers menu and settings command palette entries", () => {
    const plugin = makePlugin();
    plugin.addCommand = vi.fn();
    plugin.registerEvent = vi.fn();
    plugin.app = {
      workspace: {
        on: vi.fn(() => ({ unload: vi.fn() })),
      },
    };

    plugin.registerCommands();

    expect(plugin.addCommand.mock.calls.map((call: any[]) => call[0].id)).toEqual(
      expect.arrayContaining(["open-menu", "open-settings", "pick-vault"])
    );
  });

  it("shows a VaultGuard ribbon menu with settings and vault actions", () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.apiClient = {};
    plugin.settings.serverVaultName = "Engineering";

    plugin.showVaultGuardMenu({} as MouseEvent);

    const [menu] = (Menu as unknown as { instances: Array<{ items: Array<{ title: string }>; showAtMouseEvent: ReturnType<typeof vi.fn> }> }).instances;
    expect(menu.showAtMouseEvent).toHaveBeenCalledOnce();
    expect(menu.items.map((item) => item.title)).toEqual(
      expect.arrayContaining([
        "Vault settings",
        "Pick or switch server vault",
        "Open files panel",
        "View my permissions",
        "Manage organization",
        "Logout",
      ])
    );
  });

  it("derives a stable path-scoped vault binding without persisting a UUID fallback", async () => {
    const plugin = makePlugin();
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      vaultBindingId: undefined,
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.derivedBindingId).toMatch(/^[0-9a-f]{32}$/);
    expect(plugin.settings.vaultBindingId).toBeUndefined();
    expect(plugin.saveData).not.toHaveBeenCalled();
  });

  it("adds required local-only exclusions when loading older settings", async () => {
    const plugin = makePlugin();
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      excludedPaths: [".trash", "custom/local-only"],
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.excludedPaths).toEqual(
      expect.arrayContaining([...DEFAULT_EXCLUDED_PATHS, "custom/local-only"])
    );
    expect(
      plugin.settings.excludedPaths.filter((path: string) => path === ".trash")
    ).toHaveLength(1);
  });

  it("migrates the removed 'merge' conflict strategy to DUPLICATE on load", async () => {
    const plugin = makePlugin();
    // A user who previously selected the (now-removed) "Attempt auto-merge"
    // option has "merge" persisted. It was never implemented in either
    // conflict path, so coerce it to the safest automatic strategy.
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      defaultConflictResolution: "merge",
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.defaultConflictResolution).toBe("duplicate");
  });

  it("preserves a valid persisted conflict strategy on load", async () => {
    const plugin = makePlugin();
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      defaultConflictResolution: "keep_local",
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.defaultConflictResolution).toBe("keep_local");
  });

  it("migrates a legacy showPermissionIndicators=false into the granular display toggles", async () => {
    const plugin = makePlugin();
    // A user who turned the old single toggle OFF must keep the explorer dots
    // and avatars off after the split; the note-header banner (always on
    // before) stays on.
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      showPermissionIndicators: false,
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.showMyPermissionLevel).toBe(false);
    expect(plugin.settings.showOthersAccess).toBe(false);
    expect(plugin.settings.showPermissionBanner).toBe(true);
  });

  it("migrates a legacy showPermissionIndicators=true into all three display toggles on", async () => {
    const plugin = makePlugin();
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      showPermissionIndicators: true,
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.showMyPermissionLevel).toBe(true);
    expect(plugin.settings.showOthersAccess).toBe(true);
    expect(plugin.settings.showPermissionBanner).toBe(true);
  });

  it("does not let the legacy toggle override already-persisted granular keys", async () => {
    const plugin = makePlugin();
    // Once the granular keys exist in data.json the legacy field is inert: the
    // migration reads the RAW data and detects the new keys' presence, so a
    // stale showPermissionIndicators=false must not clobber them.
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      showPermissionIndicators: false,
      showMyPermissionLevel: true,
      showOthersAccess: false,
      showPermissionBanner: false,
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.showMyPermissionLevel).toBe(true);
    expect(plugin.settings.showOthersAccess).toBe(false);
    expect(plugin.settings.showPermissionBanner).toBe(false);
  });

  it("leaves the granular display toggles at their defaults when no legacy key is present", async () => {
    const plugin = makePlugin();
    // Fresh install / data.json with neither the legacy nor the new keys: the
    // DEFAULT_SETTINGS seed (all true) stands, migration is a no-op.
    plugin.loadData = vi.fn().mockResolvedValue({ orgSlug: "acme" });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.settings.showMyPermissionLevel).toBe(true);
    expect(plugin.settings.showOthersAccess).toBe(true);
    expect(plugin.settings.showPermissionBanner).toBe(true);
  });

  it("restores persisted Community Edition feature flags on load", async () => {
    const plugin = makePlugin();
    plugin.loadData = vi.fn().mockResolvedValue({
      orgSlug: "acme",
      serverEdition: "community",
      serverFeatures: {
        shareLinks: false,
        advancedAudit: false,
        billing: false,
        webAdmin: false,
      },
    });
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.loadSettings();

    expect(plugin.serverEdition).toBe("community");
    expect(plugin.featureEnabled("shareLinks")).toBe(false);
    expect(plugin.featureEnabled("billing")).toBe(false);
  });

  it("discovers and persists Community Edition flags for manual self-hosted config", async () => {
    const plugin = makePlugin();
    plugin.settings.manualConfig = true;
    plugin.settings.apiEndpoint = "https://api.ce.test/dev";
    plugin.settings.organizationId = "org-1";
    plugin.settings.orgSlug = "";
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: {
        orgSlug: "acme",
        edition: "community",
        features: {
          shareLinks: false,
          advancedAudit: false,
          billing: false,
          webAdmin: false,
        },
      },
      text: "{}",
      headers: {},
    } as any);

    const changed = await plugin.refreshServerCapabilitiesFromConfiguredEndpoint();

    expect(changed).toBe(true);
    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://api.ce.test/dev/orgs/org-1/config",
        method: "GET",
      })
    );
    expect(plugin.settings.orgSlug).toBe("acme");
    expect(plugin.featureEnabled("shareLinks")).toBe(false);
    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({
        serverEdition: "community",
        serverFeatures: expect.objectContaining({ shareLinks: false, billing: false }),
      })
    );
  });

  it("treats forbidden capability discovery as an unavailable optional endpoint", async () => {
    const plugin = makePlugin();
    plugin.settings.manualConfig = true;
    plugin.settings.apiEndpoint = "https://api.ce.test/dev";
    plugin.settings.organizationId = "org-1";
    plugin.settings.orgSlug = "";
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const logErrorSpy = vi.spyOn(plugin, "logError");
    mockRequestUrl.mockResolvedValueOnce({
      status: 403,
      json: { message: "Forbidden" },
      text: "{\"message\":\"Forbidden\"}",
      headers: {},
    } as any);

    await expect(plugin.refreshServerCapabilitiesFromConfiguredEndpoint()).resolves.toBe(false);

    expect(logErrorSpy).not.toHaveBeenCalledWith(
      "Server capability discovery failed",
      expect.anything()
    );
    expect(plugin.saveData).not.toHaveBeenCalled();
  });

  it("uses bundled Cloud defaults in auto mode without persisting them as settings defaults", () => {
    const plugin = makePlugin();
    plugin.settings.manualConfig = false;
    plugin.settings.apiEndpoint = "";
    plugin.settings.cognitoUserPoolId = "";
    plugin.settings.cognitoClientId = "";

    expect(plugin.getEffectiveConfig()).toMatchObject({
      apiEndpoint: SAAS_DEFAULTS.apiEndpoint,
      cognitoUserPoolId: SAAS_DEFAULTS.cognitoUserPoolId,
      cognitoClientId: SAAS_DEFAULTS.cognitoClientId,
    });
    expect(DEFAULT_SETTINGS.apiEndpoint).toBe("");
    expect(DEFAULT_SETTINGS.cognitoUserPoolId).toBe("");
    expect(DEFAULT_SETTINGS.cognitoClientId).toBe("");
  });

  it("does not fall back to Cloud defaults in manual mode", () => {
    const plugin = makePlugin();
    plugin.settings.manualConfig = true;
    plugin.settings.apiEndpoint = "";
    plugin.settings.cognitoUserPoolId = "";
    plugin.settings.cognitoClientId = "";

    expect(plugin.getEffectiveConfig()).toMatchObject({
      apiEndpoint: "",
      cognitoUserPoolId: "",
      cognitoClientId: "",
    });
  });

  it("clears stale manual connection fields when switching back to Cloud mode", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    plugin.settings.manualConfig = true;
    plugin.settings.orgSlug = "self-hosted";
    plugin.settings.apiEndpoint = "https://self-hosted.example.com";
    plugin.settings.organizationId = "org-self";
    plugin.settings.cognitoUserPoolId = "eu-central-1_SELF";
    plugin.settings.cognitoClientId = "self-client";
    plugin.settings.serverEdition = "community";
    plugin.settings.serverFeatures = {
      shareLinks: false,
      advancedAudit: false,
      billing: false,
      webAdmin: false,
    };

    await plugin.setManualConfigurationMode(false);

    expect(plugin.settings.manualConfig).not.toBe(true);
    expect(plugin.settings.orgSlug).toBe("");
    expect(plugin.settings.apiEndpoint).toBe("");
    expect(plugin.settings.organizationId).toBe("");
    expect(plugin.settings.cognitoUserPoolId).toBe("");
    expect(plugin.settings.cognitoClientId).toBe("");
    expect(plugin.getEffectiveConfig().apiEndpoint).toBe(SAAS_DEFAULTS.apiEndpoint);
  });

  it("does not use the Cloud org-config fallback while manual mode is enabled", async () => {
    const plugin = makePlugin();
    plugin.settings.manualConfig = true;
    plugin.settings.apiEndpoint = "";

    await expect(plugin.resolveOrgConfig("acme")).rejects.toThrow("No API endpoint configured");
    expect(mockRequestUrl).not.toHaveBeenCalled();
  });

  it("allows org config resolution in Local Project Memory Mode for sign-in", async () => {
    const plugin = makePlugin();
    plugin.settings.localProjectMemoryMode = true;
    plugin.settings.manualConfig = false;
    plugin.settings.apiEndpoint = "https://api.vaultguard.test";
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const body = {
      orgSlug: "acme",
      organizationId: "org-1",
      apiEndpoint: "https://api.vaultguard.test",
      cognitoUserPoolId: "eu-central-1_ACMEpool9",
      cognitoClientId: "acmeclient0123456789ab",
      edition: "pro",
      features: {
        shareLinks: true,
        advancedAudit: true,
        billing: true,
        webAdmin: true,
      },
    };
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, body));

    await plugin.resolveOrgConfig("acme");

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://api.vaultguard.test/orgs/acme/config",
        method: "GET",
      }),
    );
    expect(plugin.settings.orgSlug).toBe("acme");
    expect(plugin.settings.organizationId).toBe("org-1");
    expect(plugin.settings.cognitoUserPoolId).toBe("eu-central-1_ACMEpool9");
    expect(plugin.settings.cognitoClientId).toBe("acmeclient0123456789ab");
  });

  it("applies a self-hosted server config URL in manual mode", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const body = {
      orgSlug: "acme",
      apiEndpoint: "https://acme.example.com",
      cognitoUserPoolId: "eu-central-1_ACMEpool9",
      cognitoClientId: "acmeclient0123456789ab",
      edition: "community",
      features: {
        shareLinks: false,
        advancedAudit: false,
        billing: false,
        webAdmin: false,
      },
    };
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: body,
      text: JSON.stringify(body),
      headers: {},
    } as any);

    await plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json");

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://acme.example.com/.well-known/vaultguard.json",
        method: "GET",
      })
    );
    expect(plugin.settings.manualConfig).toBe(true);
    expect(plugin.settings.apiEndpoint).toBe("https://acme.example.com");
    expect(plugin.settings.cognitoUserPoolId).toBe("eu-central-1_ACMEpool9");
    expect(plugin.featureEnabled("billing")).toBe(false);
  });

  it("rejects non-HTTPS self-hosted server config URLs except localhost", async () => {
    const plugin = makePlugin();

    await expect(
      plugin.applyManualServerConfigUrl("http://api.acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow("HTTPS");
    expect(mockRequestUrl).not.toHaveBeenCalled();
  });

  // CR-01 / WR-06: the response body must not be allowed to silently redirect
  // the user to a different host than the one they pasted. A malicious
  // .well-known doc on attacker.example.com whose body claims
  // apiEndpoint=https://api.real-service.com would otherwise capture credentials.
  it("rejects a server config whose apiEndpoint host differs from the pasted URL host", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const body = {
      orgSlug: "acme",
      apiEndpoint: "https://api.attacker.example.com",
      cognitoUserPoolId: "eu-central-1_EVILpoolA",
      cognitoClientId: "evilclient0123456789ab",
      edition: "community",
      features: { shareLinks: false, advancedAudit: false, billing: false, webAdmin: false },
    };
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: body,
      text: JSON.stringify(body),
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/apiEndpoint host/);
    // The plugin must not switch to manual mode or apply the attacker's
    // Cognito identifiers when rejecting an SSRF response.
    expect(plugin.settings.manualConfig).not.toBe(true);
    expect(plugin.settings.cognitoUserPoolId).not.toBe("eu-central-1_EVILpoolA");
    expect(plugin.settings.cognitoClientId).not.toBe("evilclient0123456789ab");
    expect(plugin.settings.apiEndpoint).not.toBe("https://api.attacker.example.com");
  });

  // WR-05: malformed Cognito identifiers (e.g. an HTML error page parsed as JSON
  // with stringy fields) must be rejected, not partial-applied.
  it("rejects a server config whose cognitoUserPoolId is not a valid Cognito pool identifier", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const body = {
      orgSlug: "acme",
      cognitoUserPoolId: "<html><body>500 Internal Server Error</body></html>",
      cognitoClientId: "acmeclient0123456789ab",
    };
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: body,
      text: JSON.stringify(body),
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/cognitoUserPoolId/);
    expect(plugin.settings.manualConfig).not.toBe(true);
  });

  it("rejects a server config whose cognitoClientId is not a valid Cognito client identifier", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    const body = {
      orgSlug: "acme",
      cognitoUserPoolId: "eu-central-1_ACMEpool9",
      cognitoClientId: "BAD-CLIENT-ID-WITH-HYPHENS",
    };
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: body,
      text: JSON.stringify(body),
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/cognitoClientId/);
    expect(plugin.settings.manualConfig).not.toBe(true);
  });

  // WR-07: non-object response bodies (array, primitive, null) must be rejected.
  it("rejects a server config whose body is an array, not an object", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: [],
      text: "[]",
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/JSON object/);
    expect(plugin.settings.manualConfig).not.toBe(true);
  });

  it("rejects a server config whose body is a primitive, not an object", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: 42,
      text: "42",
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/JSON object/);
    expect(plugin.settings.manualConfig).not.toBe(true);
  });

  // WR-04: a malicious server returning a multi-megabyte body must be rejected
  // before the plugin spends any further work parsing it.
  it("rejects a server config response that exceeds the size cap", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    // 128 KB of padding — twice the 64 KB cap.
    const oversizedBody = JSON.stringify({
      orgSlug: "acme",
      cognitoUserPoolId: "eu-central-1_ACMEpool9",
      cognitoClientId: "acmeclient0123456789ab",
      padding: "x".repeat(128 * 1024),
    });
    mockRequestUrl.mockResolvedValueOnce({
      status: 200,
      json: JSON.parse(oversizedBody),
      text: oversizedBody,
      headers: {},
    } as any);

    await expect(
      plugin.applyManualServerConfigUrl("https://acme.example.com/.well-known/vaultguard.json")
    ).rejects.toThrow(/unexpectedly large/);
    expect(plugin.settings.manualConfig).not.toBe(true);
  });

  it("rejects invite API overrides unless the user has switched to manual mode", async () => {
    const plugin = makePlugin();

    await expect(
      plugin.redeemInvite({
        org: "acme",
        email: "invitee@example.com",
        api: "https://evil.example.com",
      })
    ).rejects.toThrow("cannot override");
    expect(mockRequestUrl).not.toHaveBeenCalled();
  });

  it("skips plugin allowlist entries whose ids are not safe path segments", async () => {
    const plugin = makePlugin();
    const adapterExists = vi.fn().mockResolvedValue(true);
    const enablePluginAndSave = vi.fn();
    plugin.app.vault.adapter.exists = adapterExists;
    plugin.app.plugins = {
      enabledPlugins: new Set<string>(),
      loadManifests: vi.fn(),
      enablePluginAndSave,
    };
    plugin.settings.serverPluginAllowlist = [
      {
        pluginId: "../secrets",
        displayName: "Bad Plugin",
        addedAt: "2026-07-10T00:00:00.000Z",
        addedBy: "admin@example.com",
      },
    ];
    plugin.promptPluginAllowlistDecision = vi.fn().mockResolvedValue("install");
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);

    await plugin.runPluginAllowlistReconciliation();

    expect(adapterExists).not.toHaveBeenCalled();
    expect(plugin.promptPluginAllowlistDecision).not.toHaveBeenCalled();
    expect(enablePluginAndSave).not.toHaveBeenCalled();
    expect(plugin.emitAuditEvent).toHaveBeenCalledWith(
      "plugin.allowlist_skip",
      "../secrets",
      expect.objectContaining({ reason: "invalid-plugin-id" }),
    );
    expect(plugin.logError).toHaveBeenCalledWith(
      expect.stringContaining('Allowlist: refused unsafe plugin id "../secrets"'),
      expect.any(Error),
    );
  });

  it("derives different session bindings for different vault filesystem paths", async () => {
    const first = makePlugin();
    const second = makePlugin();
    first.loadData = vi.fn().mockResolvedValue({});
    second.loadData = vi.fn().mockResolvedValue({});
    first.saveData = vi.fn().mockResolvedValue(undefined);
    second.saveData = vi.fn().mockResolvedValue(undefined);
    second.app.vault.adapter.getBasePath = () => "/Users/test/Another VaultGuard Vault";

    await first.loadSettings();
    await second.loadSettings();

    expect(first.derivedBindingId).toMatch(/^[0-9a-f]{32}$/);
    expect(second.derivedBindingId).toMatch(/^[0-9a-f]{32}$/);
    expect(first.derivedBindingId).not.toBe(second.derivedBindingId);
  });

  it("persists the session under the vault-scoped key as a sealed envelope", async () => {
    const plugin = makePlugin();
    const session = makeSession();
    const safeStorage = installFakeSafeStorage();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.persistSession(session);

    const rawStored = localStorage.getItem("vaultguard-session:test-vault-binding");
    const stored = JSON.parse(rawStored ?? "null");

    expect(stored).toEqual(expect.objectContaining({
      v: 1,
      storage: "electron-safe-storage",
      ciphertext: expect.any(String),
    }));
    expect(rawStored).not.toContain("refresh-token");
    expect(rawStored).not.toContain("access-token");
    expect(plugin.loadSessionFromStore()).toMatchObject({
      userId: "user-1",
      refreshToken: "refresh-token",
    });
    expect(safeStorage.encryptString).toHaveBeenCalledOnce();
    expect(safeStorage.decryptString).toHaveBeenCalledOnce();
    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({
        storedSessions: {
          "test-vault-binding": stored,
        },
      })
    );
  });

  it("rejects unsealed values stored under the scoped key", () => {
    const plugin = makePlugin();
    const session = makeSession();

    // A previous (envelope-less) blob — or anything an attacker writes to
    // localStorage by hand — must not be trusted as a valid session.
    localStorage.setItem(
      "vaultguard-session:test-vault-binding",
      JSON.stringify(session)
    );

    expect(plugin.loadSessionFromStore()).toBeNull();
  });

  it("only restores the session stored for the current vault binding", () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const currentVaultSession = makeSession();
    const otherVaultSession = {
      ...makeSession(),
      userId: "other-user",
      displayName: "Other User",
    };

    storeProtectedSession(plugin, "other-vault-binding", otherVaultSession);
    storeProtectedSession(plugin, "test-vault-binding", currentVaultSession);

    expect(plugin.loadSessionFromStore()).toMatchObject({
      userId: "user-1",
      displayName: "Test User",
    });
  });

  it("restores from Obsidian plugin data when localStorage has no session", () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const envelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = {
      "test-vault-binding": envelope,
    };

    expect(plugin.loadSessionFromStore()).toMatchObject({
      userId: "user-1",
      displayName: "Test User",
    });
  });

  it("keeps data-store sessions when saving settings", async () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const envelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = {
      "test-vault-binding": envelope,
    };
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.saveSettings();

    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({
        storedSessions: {
          "test-vault-binding": envelope,
        },
      })
    );
  });

  it("keeps the previous encrypted session if safeStorage disappears during persistence", async () => {
    const plugin = makePlugin();
    const session = makeSession();
    installFakeSafeStorage();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.persistSession(session);
    const originalLocal = localStorage.getItem("vaultguard-session:test-vault-binding");
    const originalPersisted = plugin.persistedSessions["test-vault-binding"];
    plugin.saveData.mockClear();

    Object.defineProperty(ensureTestWindow(), "require", {
      configurable: true,
      value: undefined,
    });

    await plugin.persistSession({
      ...session,
      displayName: "Renamed User",
      accessToken: "new-access-token",
    });

    expect(localStorage.getItem("vaultguard-session:test-vault-binding")).toBe(originalLocal);
    expect(plugin.persistedSessions["test-vault-binding"]).toBe(originalPersisted);
    expect(plugin.saveData).not.toHaveBeenCalled();
    expect(mockNotice).toHaveBeenCalledWith(
      expect.stringContaining("secure credential storage"),
      10000
    );
  });

  it("warns the user only once when safeStorage stays unavailable across calls", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.persistSession(makeSession());
    await plugin.persistSession(makeSession());
    plugin.loadSessionFromStore();

    const credentialNotices = mockNotice.mock.calls.filter(([msg]) =>
      typeof msg === "string" && msg.includes("secure credential storage")
    );
    expect(credentialNotices).toHaveLength(1);
  });

  it("warns the user when a sealed envelope cannot be unwrapped because safeStorage is gone", async () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    await plugin.persistSession(makeSession());

    Object.defineProperty(ensureTestWindow(), "require", {
      configurable: true,
      value: undefined,
    });
    mockNotice.mockReset();

    expect(plugin.loadSessionFromStore()).toBeNull();
    expect(mockNotice).toHaveBeenCalledWith(
      expect.stringContaining("secure credential storage"),
      10000
    );
  });

  it("falls back to data.json when the localStorage envelope is corrupt", async () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const envelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = { "test-vault-binding": envelope };

    localStorage.setItem("vaultguard-session:test-vault-binding", "{not valid json");

    expect(plugin.loadSessionFromStore()).toMatchObject({ userId: "user-1" });
  });

  it("falls back to data.json when the localStorage entry is not a sealed envelope", () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const envelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = { "test-vault-binding": envelope };

    localStorage.setItem(
      "vaultguard-session:test-vault-binding",
      JSON.stringify({ v: 99, storage: "future-format", ciphertext: "x" })
    );

    expect(plugin.loadSessionFromStore()).toMatchObject({ userId: "user-1" });
  });

  it("filters out malformed envelopes from data.json on load", () => {
    const plugin = makePlugin();

    plugin.persistedSessions = plugin.normalizePersistedSessions({
      "good-binding": {
        v: 1,
        storage: "electron-safe-storage",
        ciphertext: "abc",
      },
      "wrong-version": {
        v: 2,
        storage: "electron-safe-storage",
        ciphertext: "abc",
      },
      "wrong-storage": {
        v: 1,
        storage: "future",
        ciphertext: "abc",
      },
      "missing-ciphertext": {
        v: 1,
        storage: "electron-safe-storage",
      },
      "empty-ciphertext": {
        v: 1,
        storage: "electron-safe-storage",
        ciphertext: "",
      },
      "plain-blob": { userId: "u", refreshToken: "r" },
      "non-object": "string",
      "null-entry": null,
    });

    expect(Object.keys(plugin.persistedSessions)).toEqual(["good-binding"]);
  });

  it("keeps at-rest-cipher envelopes through normalization", () => {
    const plugin = makePlugin();

    plugin.persistedSessions = plugin.normalizePersistedSessions({
      "safe-storage-binding": {
        v: 1,
        storage: "electron-safe-storage",
        ciphertext: "abc",
      },
      "at-rest-binding": {
        v: 1,
        storage: "at-rest-cipher",
        ciphertext: "def",
      },
    });

    expect(Object.keys(plugin.persistedSessions).sort()).toEqual([
      "at-rest-binding",
      "safe-storage-binding",
    ]);
  });

  it("falls back to AtRestCipher when safeStorage is unavailable", async () => {
    const plugin = makePlugin();
    const session = makeSession();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    // No safeStorage, but a ready at-rest cipher. Round-trip through the
    // mocked cipher: encryptString returns deterministic bytes we can
    // decrypt back via decryptString.
    const cipherStore = new Map<string, string>();
    plugin.atRestCipher = {
      isReady: () => true,
      encryptString: vi.fn(async (plaintext: string) => {
        const id = `cipher-${cipherStore.size + 1}`;
        cipherStore.set(id, plaintext);
        return new TextEncoder().encode(id).buffer;
      }),
      decryptString: vi.fn(async (bytes: ArrayBuffer | Uint8Array) => {
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        const id = new TextDecoder().decode(view);
        const plaintext = cipherStore.get(id);
        if (!plaintext) throw new Error(`Unknown cipher id: ${id}`);
        return plaintext;
      }),
    };

    await plugin.persistSession(session);

    const rawStored = localStorage.getItem("vaultguard-session:test-vault-binding");
    const stored = JSON.parse(rawStored ?? "null");

    expect(stored).toEqual(expect.objectContaining({
      v: 1,
      storage: "at-rest-cipher",
      ciphertext: expect.any(String),
    }));
    // Tokens must not leak into the envelope.
    expect(rawStored).not.toContain("refresh-token");
    expect(rawStored).not.toContain("access-token");

    // Sync path returns null (envelope is at-rest, not safeStorage), async path resolves it.
    expect(plugin.loadSessionFromStore()).toBeNull();
    await expect(plugin.loadAtRestSessionFromStore()).resolves.toMatchObject({
      userId: "user-1",
      refreshToken: "refresh-token",
    });
    expect(plugin.atRestCipher.encryptString).toHaveBeenCalledOnce();
    expect(plugin.atRestCipher.decryptString).toHaveBeenCalledOnce();

    // The Notice must NOT fire when at-rest fallback succeeded.
    const credentialNotices = mockNotice.mock.calls.filter(([msg]) =>
      typeof msg === "string" && msg.includes("secure credential storage")
    );
    expect(credentialNotices).toHaveLength(0);
  });

  it("notifies only when both safeStorage AND the at-rest cipher are unavailable", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    // No safeStorage; no cipher.
    plugin.atRestCipher = null;

    await plugin.persistSession(makeSession());

    const credentialNotices = mockNotice.mock.calls.filter(([msg]) =>
      typeof msg === "string" && msg.includes("secure credential storage")
    );
    expect(credentialNotices).toHaveLength(1);
    expect(plugin.saveData).not.toHaveBeenCalled();
  });

  it("restoreSession resolves an at-rest envelope when safeStorage is gone", async () => {
    const plugin = makePlugin();
    const session = makeSession();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);
    plugin.initializeApiClientFromSession = vi.fn();
    plugin.decodeJwtPayload = vi.fn(() => ({}));
    plugin.syncSettingsFromTokenPayload = vi.fn(() => false);

    const cipherStore = new Map<string, string>();
    plugin.atRestCipher = {
      isReady: () => true,
      encryptString: vi.fn(async (plaintext: string) => {
        const id = `cipher-${cipherStore.size + 1}`;
        cipherStore.set(id, plaintext);
        return new TextEncoder().encode(id).buffer;
      }),
      decryptString: vi.fn(async (bytes: ArrayBuffer | Uint8Array) => {
        const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        const id = new TextDecoder().decode(view);
        const plaintext = cipherStore.get(id);
        if (!plaintext) throw new Error(`Unknown cipher id: ${id}`);
        return plaintext;
      }),
    };

    await plugin.persistSession(session);
    plugin.session = null; // simulate plugin reload

    await plugin.restoreSession();

    expect(plugin.session).toMatchObject({
      userId: "user-1",
      displayName: "Test User",
    });
  });

  it("rejects decrypted sessions missing required fields", () => {
    const plugin = makePlugin();
    const valid = makeSession();

    expect(plugin.materializeSession(null)).toBeNull();
    expect(plugin.materializeSession({})).toBeNull();
    expect(plugin.materializeSession({ ...valid, refreshToken: "" })).toBeNull();
    expect(plugin.materializeSession({ ...valid, role: "stranger" })).toBeNull();
    expect(plugin.materializeSession({ ...valid, email: undefined })).toBeNull();
    expect(plugin.materializeSession(valid)).toMatchObject({
      userId: "user-1",
      role: "admin",
    });
  });

  it("preserves a session with no roles array by deriving it from the role field", () => {
    const plugin = makePlugin();
    const { roles: _drop, ...withoutRoles } = makeSession();

    const materialized = plugin.materializeSession(withoutRoles);

    expect(materialized?.roles).toEqual(["admin"]);
  });

  it("does not warn the user about safeStorage when explicitly logging out", async () => {
    const plugin = makePlugin();
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    await plugin.clearStoredSession();

    expect(mockNotice).not.toHaveBeenCalledWith(
      expect.stringContaining("secure credential storage"),
      expect.anything()
    );
  });

  it("binds a server vault and resets first-sync reconciliation state", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-old";
    plugin.settings.serverVaultName = "Old Vault";
    plugin.settings.serverVaultSlug = "old-vault";
    plugin.settings.bindingReconciledVaultId = "vault-old";
    plugin.settings.lastSyncTimestamp = "2026-01-01T00:00:00.000Z";
    plugin.syncState.lastSync = "2026-01-01T00:00:00.000Z";
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    const changed = await plugin.bindServerVault({
      vaultId: "vault-new",
      name: "New Vault",
      slug: "new-vault",
    });

    expect(changed).toBe(true);
    expect(plugin.settings.serverVaultId).toBe("vault-new");
    expect(plugin.settings.serverVaultName).toBe("New Vault");
    expect(plugin.settings.serverVaultSlug).toBe("new-vault");
    expect(plugin.settings.bindingReconciledVaultId).toBeUndefined();
    expect(plugin.settings.lastSyncTimestamp).toBeUndefined();
    expect(plugin.syncState.lastSync).toBeNull();
    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({
        serverVaultId: "vault-new",
        serverVaultName: "New Vault",
        serverVaultSlug: "new-vault",
      })
    );
  });

  it("creates parent folders before applying a remote file", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.keyLease = makeKeyLease();

    const existingPaths = new Set<string>();
    const createFolder = vi.fn(async (path: string) => {
      existingPaths.add(path);
    });
    const create = vi.fn(async (path: string) => {
      existingPaths.add(path);
    });
    const modify = vi.fn();
    const write = vi.fn();

    plugin.app = {
      vault: {
        configDir: ".obsidian",
        adapter: {
          exists: vi.fn(async (path: string) => existingPaths.has(path)),
        },
        createFolder,
        create,
        modify,
        getAbstractFileByPath: vi.fn((path: string) => (existingPaths.has(path) ? {} : null)),
      },
    };
    plugin.originalAdapterMethods.write = write;
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: { content: "encrypted-content" },
      error: null,
      requestId: "req-1",
    });
    plugin.decryptContent = vi.fn().mockResolvedValue("remote body");

    await plugin.applyRemoteChange({ path: "/test1/nested/remote.md", size: 11 });

    expect(createFolder).toHaveBeenCalledWith("test1");
    expect(createFolder).toHaveBeenCalledWith("test1/nested");
    expect(create).toHaveBeenCalledWith("test1/nested/remote.md", "remote body");
    expect(write).not.toHaveBeenCalled();
    expect(modify).not.toHaveBeenCalled();
  });

  it("repairs missing remote folders and files from the full server inventory", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.settings.serverVaultId = "vault-abc";

    const existingPaths = new Set<string>();
    const createFolder = vi.fn(async (path: string) => {
      existingPaths.add(path);
    });
    const create = vi.fn(async (path: string) => {
      existingPaths.add(path);
    });
    const modify = vi.fn();
    const write = vi.fn();

    plugin.app = {
      vault: {
        configDir: ".obsidian",
        adapter: {
          exists: vi.fn(async (path: string) => existingPaths.has(path)),
        },
        createFolder,
        create,
        modify,
        getAbstractFileByPath: vi.fn((path: string) => (existingPaths.has(path) ? {} : null)),
      },
    };
    plugin.originalAdapterMethods.write = write;
    plugin.apiRequest = vi.fn(async (method: string) => {
      if (method === "POST") {
        return {
          success: true,
          data: {
            deltas: [
              { path: "/test1/remote.md", action: "created", size: 12 },
              { path: "/empty/.vaultguard-folder", action: "created", size: 0 },
            ],
          },
          error: null,
          requestId: "req-sync",
        };
      }

      return {
        success: true,
        data: { content: "encrypted-remote" },
        error: null,
        requestId: "req-read",
      };
    });
    plugin.decryptContent = vi.fn().mockResolvedValue("remote body");

    const result = await plugin.repairMissingRemoteItems();

    expect(result).toMatchObject({
      downloadedFiles: 1,
      downloadedFolders: 2,
      failedFiles: 0,
      failedFolders: 0,
    });
    expect(createFolder).toHaveBeenCalledWith("test1");
    expect(createFolder).toHaveBeenCalledWith("empty");
    expect(create).toHaveBeenCalledWith("test1/remote.md", "remote body");
    expect(write).not.toHaveBeenCalled();
    expect(modify).not.toHaveBeenCalled();
  });

  it("bootstraps accessible server files as placeholders when the vault-wide key lease is denied (Phase 8 limited-access)", async () => {
    // Phase 8 (plan 08-03) changed limited-access reconciliation: instead of
    // calling ?decrypt=true per file to materialize plaintext immediately, we
    // write 36-byte VG1 placeholders via writePlainToDisk(path, '') and add
    // each path to placeholderPaths. The first interceptedRead per file then
    // hydrates via the new /files-decrypted endpoint.
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = null;
    plugin.vaultLeaseDenied = true;
    plugin.placeholderPaths = new Set<string>();
    plugin.connectionState.status = "online";
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    // Modal must NOT be shown in limited-access mode.
    plugin.askReconciliationPlan = vi.fn();

    plugin.app = {
      vault: {
        configDir: ".obsidian",
        adapter: {
          exists: vi.fn(async () => false),
        },
        getFiles: vi.fn(() => []),
        getRoot: vi.fn(() => ({ children: [] })),
      },
    };
    plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
    plugin.ensureLocalFolderPath = vi.fn().mockResolvedValue(true);
    plugin.writePlainToDisk = vi.fn().mockResolvedValue(undefined);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.decryptContent = vi.fn();
    plugin.apiRequest = vi.fn(async (method: string, endpoint: string) => {
      if (method === "POST" && endpoint === "/vaults/vault-abc/files/sync") {
        return {
          success: true,
          data: {
            deltas: [
              { path: "/docs/welcome.md", action: "created", checksum: "etag", size: 12 },
            ],
            syncTimestamp: "2026-05-21T12:00:00.000Z",
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${endpoint}`);
    });

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // The modal must NOT be shown in limited-access mode.
    expect(plugin.askReconciliationPlan).not.toHaveBeenCalled();
    // No per-file ?decrypt=true fetch — placeholders only.
    expect(plugin.apiRequest).not.toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining("?decrypt=true")
    );
    // No client-side decrypt — there is no lease.
    expect(plugin.decryptContent).not.toHaveBeenCalled();
    // Placeholder write + set membership.
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("docs/welcome.md", "");
    expect(plugin.placeholderPaths.has("docs/welcome.md")).toBe(true);
    expect(plugin.settings.bindingReconciledVaultId).toBe("vault-abc");
  });

  it("routes vault settings helpers through the bound vault API", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.serverVaultName = "Engineering";
    plugin.settings.serverVaultSlug = "engineering";
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    const vault = {
      orgId: "org-1",
      vaultId: "vault-abc",
      name: "Engineering",
      slug: "engineering",
      kind: "team" as const,
      defaultRole: "editor" as const,
      createdAt: "2026-01-01T00:00:00.000Z",
      createdBy: "user-1",
      archived: false,
    };
    const apiClient = {
      listVaults: vi.fn().mockResolvedValue([vault]),
      createVault: vi.fn().mockResolvedValue(vault),
      updateVault: vi.fn().mockResolvedValue({ ...vault, archived: true }),
      listVaultMembers: vi.fn().mockResolvedValue([{ vaultId: "vault-abc", userId: "user-1", role: "admin" }]),
      listUsers: vi.fn().mockResolvedValue([{ id: "user-1", email: "user@example.com", displayName: "User One" }]),
      addVaultMember: vi.fn().mockResolvedValue({ vaultId: "vault-abc", userId: "user-2", role: "viewer" }),
      updateVaultMember: vi.fn().mockResolvedValue({ vaultId: "vault-abc", userId: "user-2", role: "editor" }),
      removeVaultMember: vi.fn().mockResolvedValue(undefined),
    };
    plugin.apiClient = apiClient;

    await expect(plugin.listServerVaults()).resolves.toEqual([vault]);
    await plugin.createServerVault({
      name: "Docs",
      description: "Team docs",
      kind: "shared",
      defaultRole: "viewer",
    });
    await plugin.updateCurrentVault({ archived: true });
    await plugin.listCurrentVaultMembers();
    await plugin.listOrganizationUsers();
    await plugin.addCurrentVaultMember("user-2", "viewer");
    await plugin.updateCurrentVaultMember("user-2", "editor");
    await plugin.removeCurrentVaultMember("user-2");

    expect(apiClient.createVault).toHaveBeenCalledWith({
      name: "Docs",
      description: "Team docs",
      kind: "shared",
      defaultRole: "viewer",
    });
    expect(apiClient.updateVault).toHaveBeenCalledWith("vault-abc", { archived: true });
    expect(apiClient.listVaultMembers).toHaveBeenCalledWith("vault-abc");
    expect(apiClient.addVaultMember).toHaveBeenCalledWith("vault-abc", "user-2", "viewer");
    expect(apiClient.updateVaultMember).toHaveBeenCalledWith("vault-abc", "user-2", "editor");
    expect(apiClient.removeVaultMember).toHaveBeenCalledWith("vault-abc", "user-2");
  });

  it("refreshes live permission surfaces after vault membership changes", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.apiClient = {
      addVaultMember: vi.fn().mockResolvedValue({ vaultId: "vault-abc", userId: "user-2", role: "viewer" }),
      updateVaultMember: vi.fn().mockResolvedValue({ vaultId: "vault-abc", userId: "user-2", role: "editor" }),
      removeVaultMember: vi.fn().mockResolvedValue(undefined),
    };
    plugin.readOnlyGuard = {
      refreshAll: vi.fn(),
    };
    plugin.filePermissionHeader = {
      invalidateCache: vi.fn(),
      update: vi.fn().mockResolvedValue(undefined),
    };
    plugin.fileExplorerDecorations = {
      invalidate: vi.fn(),
    };

    // Phase 9: production wires subscribers inside init* methods. Tests
    // bypass init* so wire them explicitly here to mirror the four
    // production listeners (decorations + sidebar + header + readOnlyGuard).
    plugin.permissionStore.on("changed", (payload: { path?: string } = {}) => {
      plugin.fileExplorerDecorations.invalidate(payload.path);
    });
    plugin.permissionStore.on("changed", (payload: { path?: string } = {}) => {
      plugin.filePermissionHeader.invalidateCache(payload.path);
      void plugin.filePermissionHeader.update();
    });
    plugin.permissionStore.on("changed", () => {
      plugin.readOnlyGuard.refreshAll();
    });

    await plugin.addCurrentVaultMember("user-2", "viewer");
    await plugin.updateCurrentVaultMember("user-2", "editor");
    await plugin.removeCurrentVaultMember("user-2");

    expect(plugin.permissionCache.size).toBe(0);
    expect(plugin.readOnlyGuard.refreshAll).toHaveBeenCalledTimes(3);
    expect(plugin.fileExplorerDecorations.invalidate).toHaveBeenCalledTimes(3);
    expect(plugin.filePermissionHeader.invalidateCache).toHaveBeenCalledTimes(3);
    // After Phase 9 the header receives both a bus-driven update() and
    // the explicit force-refresh update({ force: true }) inside
    // refreshPermissionUiAfterMembershipChange. 3 membership changes ×
    // 2 update calls = 6.
    expect(plugin.filePermissionHeader.update).toHaveBeenCalledTimes(6);
    expect(plugin.filePermissionHeader.update).toHaveBeenCalledWith({ force: true });
  });

  it("re-enables file explorer decorations when a permission indicator toggle is turned back on", () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.apiClient = {
      isAuthenticated: vi.fn(() => true),
    };
    plugin.fileExplorerDecorations = {
      enable: vi.fn(),
      refresh: vi.fn(),
      disable: vi.fn(),
      setDisplayOptions: vi.fn(),
    };

    plugin.settings.showMyPermissionLevel = true;
    plugin.settings.showOthersAccess = true;
    plugin.refreshFileExplorerDecorations();

    expect(plugin.fileExplorerDecorations.setDisplayOptions).toHaveBeenCalledWith({
      showMyLevel: true,
      showOthersAccess: true,
    });
    expect(plugin.fileExplorerDecorations.enable).toHaveBeenCalledOnce();
    expect(plugin.fileExplorerDecorations.refresh).toHaveBeenCalledOnce();
    expect(plugin.fileExplorerDecorations.disable).not.toHaveBeenCalled();
  });

  it("disables file explorer decorations only when both indicator toggles are off", () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.apiClient = {
      isAuthenticated: vi.fn(() => true),
    };
    plugin.fileExplorerDecorations = {
      enable: vi.fn(),
      refresh: vi.fn(),
      disable: vi.fn(),
      setDisplayOptions: vi.fn(),
    };

    plugin.settings.showMyPermissionLevel = false;
    plugin.settings.showOthersAccess = false;
    plugin.refreshFileExplorerDecorations();

    expect(plugin.fileExplorerDecorations.disable).toHaveBeenCalledOnce();
    expect(plugin.fileExplorerDecorations.enable).not.toHaveBeenCalled();
  });

  it("propagates a vault admin membership into live UI context for an org member", async () => {
    const plugin = makePlugin();
    plugin.session = { ...makeSession(), role: "member", roles: ["member"] };
    plugin.settings.serverVaultId = "vault-abc";
    plugin.permissionCache.set("docs/readme.md", 1);
    plugin.apiClient = {
      listVaultMembers: vi.fn().mockResolvedValue([
        { vaultId: "vault-abc", userId: "user-1", role: "admin" },
      ]),
    };
    plugin.filePermissionHeader = {
      setContext: vi.fn(),
      invalidateCache: vi.fn(),
      update: vi.fn(),
    };
    plugin.fileExplorerDecorations = {
      setConfig: vi.fn(),
    };

    await plugin.refreshVaultMemberRole();

    expect(plugin.vaultMemberRole).toBe("admin");
    // Stale per-path entries from before the role change must be dropped;
    // the warm-up may seed the root key ("") with the new default level.
    expect(plugin.permissionCache.has("docs/readme.md")).toBe(false);
    expect(plugin.filePermissionHeader.setContext).toHaveBeenCalledWith(expect.objectContaining({
      currentUserId: "user-1",
      currentUserRole: "admin",
      isAdmin: true,
    }));
    expect(plugin.fileExplorerDecorations.setConfig).toHaveBeenCalledWith({
      currentUserId: "user-1",
      currentUserRole: "admin",
    });
  });

  it("propagates a vault viewer membership as non-admin UI context", async () => {
    const plugin = makePlugin();
    plugin.session = { ...makeSession(), role: "member", roles: ["member"] };
    plugin.settings.serverVaultId = "vault-abc";
    plugin.apiClient = {
      listVaultMembers: vi.fn().mockResolvedValue([
        { vaultId: "vault-abc", userId: "user-1", role: "viewer" },
      ]),
    };
    plugin.filePermissionHeader = {
      setContext: vi.fn(),
      invalidateCache: vi.fn(),
      update: vi.fn(),
    };
    plugin.fileExplorerDecorations = {
      setConfig: vi.fn(),
    };

    await plugin.refreshVaultMemberRole();

    expect(plugin.vaultMemberRole).toBe("viewer");
    expect(plugin.filePermissionHeader.setContext).toHaveBeenCalledWith(expect.objectContaining({
      currentUserId: "user-1",
      currentUserRole: "viewer",
      isAdmin: false,
    }));
    expect(plugin.fileExplorerDecorations.setConfig).toHaveBeenCalledWith({
      currentUserId: "user-1",
      currentUserRole: "viewer",
    });
  });

  // Phase 9 (Plan 09-02): warm-up logic moved from main.ts into
  // PermissionStore. Three former `runPermissionWarmup` tests (glob-deny
  // bypass, glob-write grant, literal-deny-over-allow) were removed from
  // here when ownership shifted. Canonical coverage now lives in
  // `tests/permission-store.test.ts` — search for "R-09-08 warm-up
  // sentinel" and the cache walk-up tests around `runWarm()`. (IN-04)

  it("clears EVERY stored session envelope on logout, including orphaned bindings (PL6)", async () => {
    // Both stores (data.json + app.saveLocalStorage) are per-vault, so an
    // "other" binding id in them is THIS vault's own orphan from a folder
    // rename/move — an envelope still holding a valid refresh token. Logout
    // must not leave it behind.
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const currentEnvelope = protectSessionForTest(plugin, session);
    const orphanEnvelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = {
      "test-vault-binding": currentEnvelope,
      "other-vault-binding": orphanEnvelope,
    };
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    localStorage.setItem("vaultguard-session:test-vault-binding", JSON.stringify(currentEnvelope));
    localStorage.setItem("vaultguard-session:other-vault-binding", JSON.stringify(orphanEnvelope));

    await plugin.clearStoredSession();

    expect(localStorage.getItem("vaultguard-session:test-vault-binding")).toBeNull();
    expect(localStorage.getItem("vaultguard-session:other-vault-binding")).toBeNull();
    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({ storedSessions: {} })
    );
  });

  it("clears stale sidebar auth config and keeps the logout reason visible", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: null,
      error: null,
      requestId: "req-1",
    });
    plugin.clearStoredSession = vi.fn().mockResolvedValue(undefined);
    plugin.revokeAgentBridgeLeasesForSessionEnd = vi.fn().mockResolvedValue(undefined);
    const sidebarView = {
      configure: vi.fn(),
      reload: vi.fn().mockResolvedValue(undefined),
    };
    plugin.app.workspace.getLeavesOfType = vi.fn(() => [{ view: sidebarView }]);

    await plugin.forceLogout("VaultGuard Sync: Session expired. Please log in again.");

    expect(plugin.session).toBeNull();
    expect(plugin.lastLogoutAuthState).toMatchObject({
      title: "Logged out",
      detail: "Session expired. Please log in again.",
      actionLabel: "Log in again",
    });
    expect(plugin.sidebarViewConfig).toBeNull();
    expect(sidebarView.configure).toHaveBeenCalledWith(null);
    expect(sidebarView.reload).toHaveBeenCalled();
    expect(mockNotice).toHaveBeenCalledWith(
      "VaultGuard Sync: Session expired. Please log in again."
    );
  });

  it("revokes the Cognito refresh token during logout, best-effort (PL6)", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    const refreshToken = plugin.session.refreshToken;
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: null,
      error: null,
      requestId: "req-1",
    });
    plugin.clearStoredSession = vi.fn().mockResolvedValue(undefined);
    plugin.revokeAgentBridgeLeasesForSessionEnd = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockResolvedValueOnce({ status: 200, json: {}, text: "", headers: {} } as any);

    await plugin.forceLogout("bye");

    // Without RevokeToken, any backup of data.json keeps a working refresh
    // token after "logout".
    const revokeCall = mockRequestUrl.mock.calls.find((c) =>
      String((c[0].headers as Record<string, string>)?.["X-Amz-Target"] ?? "").includes(
        "RevokeToken"
      )
    );
    expect(revokeCall).toBeTruthy();
    const body = JSON.parse(revokeCall![0].body as string);
    expect(body).toMatchObject({ ClientId: "test-client", Token: refreshToken });
    expect(plugin.session).toBeNull();
  });

  it("finishes local logout even when Cognito RevokeToken fails (PL6 best-effort)", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: null,
      error: null,
      requestId: "req-1",
    });
    plugin.clearStoredSession = vi.fn().mockResolvedValue(undefined);
    plugin.revokeAgentBridgeLeasesForSessionEnd = vi.fn().mockResolvedValue(undefined);
    mockRequestUrl.mockRejectedValueOnce(new Error("network down"));

    await plugin.forceLogout("bye");

    expect(plugin.session).toBeNull();
    expect(plugin.clearStoredSession).toHaveBeenCalled();
  });

  it("uses the status bar to show durable logged-out feedback", () => {
    const plugin = makePlugin();
    const statusBarEl = {
      setText: vi.fn(),
      setAttr: vi.fn(),
    };
    plugin.statusBarEl = statusBarEl;
    plugin.updateStatusBar = Object.getPrototypeOf(plugin).updateStatusBar.bind(plugin);
    plugin.rememberLogoutAuthState(
      "VaultGuard Sync: Session locked after 15 minutes of inactivity."
    );

    plugin.updateStatusBar();

    expect(statusBarEl.setText).toHaveBeenCalledWith("VaultGuard Sync: Logged out");
    expect(statusBarEl.setAttr).toHaveBeenCalledWith(
      "title",
      expect.stringContaining("Session locked after 15 minutes of inactivity.")
    );
  });

  it("marks the shield when logged out and all VaultGuard ribbon icons when signed in", () => {
    const plugin = makePlugin();
    const priorDocument = globalThis.document;
    const bodyToggleClass = vi.fn();
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { body: { toggleClass: bodyToggleClass } },
    });
    const makeRibbonEl = () => ({
      addClass: vi.fn(),
      removeClass: vi.fn(),
      setAttr: vi.fn(),
    });
    const shieldRibbonEl = makeRibbonEl();
    const chatRibbonEl = makeRibbonEl();
    const graphRibbonEl = makeRibbonEl();
    plugin.vaultGuardRibbonEl = shieldRibbonEl;
    plugin.vaultGuardChatRibbonEl = chatRibbonEl;
    plugin.vaultGuardGraphRibbonEl = graphRibbonEl;
    plugin.lastLogoutAuthState = {
      title: "Logged out",
      message: "VaultGuard is no longer connected.",
      detail: "Session expired. Please log in again.",
      icon: "log-out",
      tone: "warning",
      actionLabel: "Log in again",
    };

    try {
      plugin.updateRibbonAuthIndicator();

      expect(bodyToggleClass).toHaveBeenCalledWith("vaultguard-auth-logged-in", false);
      expect(shieldRibbonEl.addClass).toHaveBeenCalledWith("vaultguard-ribbon-auth-logged-out");
      expect(chatRibbonEl.addClass).not.toHaveBeenCalledWith("vaultguard-ribbon-auth-logged-out");
      expect(graphRibbonEl.addClass).not.toHaveBeenCalledWith("vaultguard-ribbon-auth-logged-out");
      expect(shieldRibbonEl.setAttr).toHaveBeenCalledWith(
        "title",
        expect.stringContaining("Session expired. Please log in again.")
      );

      plugin.session = makeSession();
      plugin.updateRibbonAuthIndicator();

      expect(bodyToggleClass).toHaveBeenCalledWith("vaultguard-auth-logged-in", true);
      for (const el of [shieldRibbonEl, chatRibbonEl, graphRibbonEl]) {
        expect(el.addClass).toHaveBeenCalledWith("vaultguard-ribbon-auth-logged-in");
        expect(el.removeClass).toHaveBeenCalledWith("vaultguard-ribbon-auth-logged-out");
      }
      expect(shieldRibbonEl.setAttr).toHaveBeenCalledWith(
        "title",
        expect.stringContaining("connected as test@example.com")
      );
    } finally {
      Object.defineProperty(globalThis, "document", {
        configurable: true,
        value: priorDocument,
      });
    }
  });

  it("short-circuits performSync when the cursor matches the last seen revision", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.localOnlyCatchupCompleted = true;
    plugin.remoteInventoryRepairCompleted = true;
    plugin.syncState.lastSeenRevision = 42;

    const apiCalls: Array<{ method: string; path: string }> = [];
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      apiCalls.push({ method, path });
      if (path.endsWith("/sync-cursor")) {
        return {
          success: true,
          data: { revision: 42, lastChangedAt: "2026-04-30T12:00:00.000Z", serverTime: "2026-04-30T12:34:56.000Z" },
          error: null,
          requestId: "req-cursor",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    await plugin.performSync();

    const cursorCalls = apiCalls.filter((c) => c.path.endsWith("/sync-cursor"));
    const fullSyncCalls = apiCalls.filter((c) => c.path.endsWith("/files/sync"));
    expect(cursorCalls).toHaveLength(1);
    expect(fullSyncCalls).toHaveLength(0);
    expect(plugin.syncState.status).toBe("idle");
  });

  it("falls through to a full sync when the server revision differs from the last seen one", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.localOnlyCatchupCompleted = true;
    plugin.remoteInventoryRepairCompleted = true;
    plugin.syncState.lastSeenRevision = 5;
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);

    let fullSyncCalled = false;
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (path.endsWith("/sync-cursor")) {
        return {
          success: true,
          data: { revision: 6, lastChangedAt: "2026-04-30T12:00:00.000Z", serverTime: "2026-04-30T12:00:01.000Z" },
          error: null,
          requestId: "req-cursor",
        };
      }
      if (path.endsWith("/files/sync")) {
        fullSyncCalled = true;
        return {
          success: true,
          data: {
            deltas: [],
            syncTimestamp: "2026-04-30T12:00:02.000Z",
            revision: 6,
            mode: "activity-log",
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    await plugin.performSync();

    expect(fullSyncCalled).toBe(true);
    expect(plugin.syncState.lastSeenRevision).toBe(6);
  });

  it("clears the local permission cache when the sync response signals permissionsChanged", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.localOnlyCatchupCompleted = true;
    plugin.remoteInventoryRepairCompleted = true;
    plugin.syncState.lastSeenRevision = 5;
    plugin.permissionCache = new Map([
      ["docs/file.md", 1],
      ["secret/private.md", 0],
    ]);
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);

    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (path.endsWith("/sync-cursor")) {
        return {
          success: true,
          data: { revision: 6, lastChangedAt: "2026-04-30T12:00:00.000Z", serverTime: "2026-04-30T12:00:01.000Z" },
          error: null,
          requestId: "req-cursor",
        };
      }
      if (path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            deltas: [],
            syncTimestamp: "2026-04-30T12:00:02.000Z",
            revision: 6,
            mode: "full-scan",
            permissionsChanged: true,
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    expect(plugin.permissionCache.size).toBe(2);
    await plugin.performSync();
    expect(plugin.permissionCache.size).toBe(0);
  });

  it("removes server-missing local files when the user cannot upload them (permission store warmed)", async () => {
    const plugin = makePlugin();
    const localOnlyPath = "Welcome (conflict 2026-04-29T15-16-30-016Z).md";
    const remove = vi.fn().mockResolvedValue(undefined);

    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = { ...makeSession(), role: "member", roles: ["member"] };
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.originalAdapterMethods = {
      read: vi.fn().mockResolvedValue("local conflict content"),
      write: null,
      list: null,
      remove,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: localOnlyPath }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.apiRequest = vi.fn(async (method: string, path: string, body?: { action?: string }) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: { deltas: [] },
          error: null,
          requestId: "req-sync",
        };
      }
      if (method === "POST" && path.endsWith("/permissions/check")) {
        return {
          success: true,
          data: { allowed: body?.action === "read" },
          error: null,
          requestId: "req-perm",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    // SY2: removal of a never-uploaded local file only happens on a CONFIRMED
    // (warmed) permission baseline.
    await plugin.permissionStore.warm();

    const result = await plugin.uploadLocalOnlyFiles();

    expect(result?.skippedFiles).toBe(1);
    expect(result?.removedLocalFiles).toBe(1);
    expect(remove).toHaveBeenCalledWith(localOnlyPath);
    expect(plugin.apiRequest).not.toHaveBeenCalledWith(
      "PUT",
      expect.any(String),
      expect.anything()
    );
  });

  it("does NOT remove a server-missing local file when the permission store has not warmed (SY2)", async () => {
    const plugin = makePlugin();
    const localOnlyPath = "Welcome (conflict 2026-04-29T15-16-30-016Z).md";
    const remove = vi.fn().mockResolvedValue(undefined);

    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = { ...makeSession(), role: "member", roles: ["member"] };
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.originalAdapterMethods = {
      read: vi.fn().mockResolvedValue("local conflict content"),
      write: null,
      list: null,
      remove,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: localOnlyPath }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.apiRequest = vi.fn(async (method: string, path: string, body?: { action?: string }) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return { success: true, data: { deltas: [] }, error: null, requestId: "req-sync" };
      }
      if (method === "POST" && path.endsWith("/permissions/check")) {
        return { success: true, data: { allowed: body?.action === "read" }, error: null, requestId: "req-perm" };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    // Permission store stays "cold" (fetch never landed). A NONE baseline here
    // is unconfirmed and must NOT trigger a permanent local delete.
    plugin.permissionStore.markFetchFailed(503);

    const result = await plugin.uploadLocalOnlyFiles();

    expect(result?.skippedFiles).toBe(1);
    expect(result?.removedLocalFiles).toBe(0);
    expect(remove).not.toHaveBeenCalled();
  });

  // AR1: 0x80–0xFF bytes are invalid as a UTF-8 lead sequence, so a real
  // attachment (PNG header + high bytes) can never survive the *string* sync
  // pipeline losslessly. Post-BIN-A these bytes ride the dedicated BYTE path
  // (encryptContentBytes / computeHashBytes); this fixture proves the byte
  // path is taken and the lossy string decode never happens.
  const AR1_BINARY_BYTES = new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00,
  ]);

  it("uploadLocalOnlyFiles uploads an in-size binary via the byte path and counts it as an upload (BIN-A / D-07)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.ensureAtRestEncryptedInPlace = vi.fn(async () => true);
    let put: any = null;
    plugin.apiRequest = vi.fn(
      async (method: string, path: string, body: any, _idT: unknown, options: unknown) => {
        if (method === "POST" && path.endsWith("/files/sync")) {
          return { success: true, data: { deltas: [] }, error: null, requestId: "req-sync" };
        }
        if (method === "PUT") {
          put = { path, body, options };
          return { success: true, data: {}, error: null, requestId: "req-put" };
        }
        throw new Error(`Unexpected API call: ${method} ${path}`);
      }
    );

    const result = await plugin.uploadLocalOnlyFiles();

    // Counted as an UPLOAD, not skipped (D-11 truthfulness).
    expect(result?.uploadedFiles).toBe(1);
    expect(result?.skippedFiles).toBe(0);
    expect(result?.removedLocalFiles).toBe(0);
    // The byte PUT fired with a real contentType + the large-body timeout, and
    // the ciphertext round-trips to the original bytes.
    expect(put).not.toBeNull();
    expect(put.body.contentType).toBe("image/png");
    expect(put.options).toEqual({ timeoutMs: 120000 });
    const decrypted = await plugin.decryptContentBytes(put.body.content);
    expect(new Uint8Array(decrypted)).toEqual(AR1_BINARY_BYTES);
    // Post-upload at-rest hygiene fires ONLY after "uploaded" (CR-1/D-01).
    expect(plugin.ensureAtRestEncryptedInPlace).toHaveBeenCalledWith("attachments/photo.png");
  });

  it("uploadLocalOnlyFiles on a legacy adapter (no readBinary) keeps a binary-extension file on the text path, never the byte path (AR2/D-10)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: null, // legacy: capability gate closed
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    // Legacy classification reads via readPlainFromDisk (string).
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("legacy text");
    plugin.readPlainBinaryFromDisk = vi.fn(); // must NOT be called
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.uploadReconciledFile = vi.fn(async () => "uploaded");
    plugin.ensureAtRestEncryptedInPlace = vi.fn(async () => true);
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return { success: true, data: { deltas: [] }, error: null, requestId: "req-sync" };
      }
      // A byte PUT would be a regression — legacy adapters must not reach it.
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const result = await plugin.uploadLocalOnlyFiles();

    expect(result?.uploadedFiles).toBe(1);
    // The STRING sibling handled it (byte-identical to pre-BIN-A behavior); the
    // byte path (direct PUT) was never taken.
    expect(plugin.uploadReconciledFile).toHaveBeenCalledWith(
      "attachments/photo.png",
      "legacy text",
      expect.anything()
    );
    expect(plugin.readPlainBinaryFromDisk).not.toHaveBeenCalled();
  });

  it("uploadLocalOnlyFiles skips an oversize binary (no PUT, no hygiene) and counts it skipped (L10)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    const oversize = new Uint8Array(BINARY_SYNC_MAX_BYTES + 1);
    oversize[8] = 0xff; // ensure the content probe classifies it binary
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(oversize.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/huge.png" }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.ensureAtRestEncryptedInPlace = vi.fn(async () => true);
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return { success: true, data: { deltas: [] }, error: null, requestId: "req-sync" };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const result = await plugin.uploadLocalOnlyFiles();

    expect(result?.skippedFiles).toBe(1);
    expect(result?.uploadedFiles).toBe(0);
    // CR-1/L10: no PUT and no LAK-encrypt path for an unsendable file.
    expect(plugin.apiRequest).not.toHaveBeenCalledWith(
      "PUT",
      expect.any(String),
      expect.anything(),
      undefined,
      expect.anything()
    );
    expect(plugin.ensureAtRestEncryptedInPlace).not.toHaveBeenCalled();
  });

  it("uploadLocalOnlyFiles re-encrypts an uploaded local-only text file in place (external-add hygiene)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(new TextEncoder().encode("# dropped in Finder").buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "dropped/note.md" }]);
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.uploadReconciledFile = vi.fn(async () => "uploaded");
    plugin.ensureAtRestEncryptedInPlace = vi.fn(async () => true);
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return { success: true, data: { deltas: [] }, error: null, requestId: "req-sync" };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const result = await plugin.uploadLocalOnlyFiles();

    expect(result?.uploadedFiles).toBe(1);
    expect(plugin.ensureAtRestEncryptedInPlace).toHaveBeenCalledWith("dropped/note.md");
  });

  // BIN-A / wave 5: the former AR1 "binaries are invisible to reconciliation"
  // test is replaced by these — binaries now participate as first-class,
  // byte-hashed manifest entries, with the L7 lossy-artifact healing rule.
  function makeBinaryReconcilePlugin() {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.vaultLeaseDenied = false;
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.applyRemoteChange = vi.fn();
    plugin.uploadReconciledFile = vi.fn().mockResolvedValue("uploaded");
    plugin.askReconciliationPlan = vi
      .fn()
      .mockResolvedValue({ proceed: true, conflictStrategy: "keep_local" });
    return plugin;
  }

  function stubSyncInventory(plugin: any) {
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            deltas: [
              {
                path: "/attachments/photo.png",
                action: "created",
                lastModified: "2026-07-01T00:00:00.000Z",
                checksum: "c",
                size: 12,
              },
            ],
            syncTimestamp: "2026-07-02T00:00:00.000Z",
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });
  }

  it("heals a pre-BIN-A lossy server copy (text/markdown) of a local binary by uploading local bytes, never downloading (AR1/L7)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    stubSyncInventory(plugin);
    // The server copy is a lossy text/markdown artifact of the pre-fix pipeline.
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: "lossy-artifact", contentType: "text/markdown" },
      error: null,
      requestId: "req-get",
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // Healed: intact local bytes uploaded via the byte path.
    expect(runtime.uploadReconciledBinaryFile).toHaveBeenCalledTimes(1);
    const [healedPath, healedBytes] =
      runtime.uploadReconciledBinaryFile.mock.calls[0];
    expect(healedPath).toBe("attachments/photo.png");
    expect(new Uint8Array(healedBytes)).toEqual(AR1_BINARY_BYTES);
    // The lossy artifact was NEVER downloaded over local content (T-11-16).
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
    expect(plugin.uploadReconciledFile).not.toHaveBeenCalled();
    // A silent integrity heal — invisible to the plan buckets.
    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: [],
    });
  });

  it("treats a byte-identical server binary as already in sync — no upload, no download (BIN-A)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    stubSyncInventory(plugin);
    // A genuine server BINARY whose bytes match the local file exactly.
    const encrypted = await plugin.encryptContentBytes(AR1_BINARY_BYTES.buffer);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: encrypted, encoding: "base64", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn();

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: [],
    });
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
  });

  it("CR-1 closure: an interceptedWriteBinary push is in-sync on the next catch-up — no echo re-upload (BIN-A / D-08)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    // Isolate the push from permission-warmup + at-rest-cipher internals so the
    // test asserts only the hash-stability loop.
    plugin.awaitPermissionReadiness = vi.fn().mockResolvedValue(undefined);
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.writePlainBinaryToDisk = vi.fn().mockResolvedValue(undefined);

    // ── Device-A drag-drop: interceptedWriteBinary pushes the in-size binary.
    let pushedContent: string | null = null;
    let pushedHash: string | null = null;
    plugin.apiRequest = vi.fn(async (method: string, endpoint: string, body: any) => {
      if (method === "PUT" && endpoint.includes("/files/")) {
        pushedContent = body.content;
        pushedHash = body.hash;
      }
      return { success: true, data: {}, error: null, requestId: "r" };
    });

    await plugin.interceptedWriteBinary("attachments/photo.png", AR1_BINARY_BYTES.buffer);

    // The push hashed the PLAINTEXT bytes — the exact hash reconciliation's
    // byte-hashed manifest entry computes for the identical local plaintext.
    expect(pushedHash).toBe(await plugin.computeHashBytes(AR1_BINARY_BYTES.buffer));
    // A local VG1 copy landed (never a server-only push with no local trace).
    expect(plugin.writePlainBinaryToDisk).toHaveBeenCalledWith(
      "attachments/photo.png",
      AR1_BINARY_BYTES.buffer
    );

    // ── Device-A catch-up: the server now holds exactly what we pushed. The
    // both-exist byte compare decrypts the server copy, hashes its bytes, and
    // finds them equal to the local manifest hash → in-sync. No re-upload
    // (echo storm), no download.
    stubSyncInventory(plugin);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: pushedContent, encoding: "base64", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn();

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: [],
    });
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
  });

  it("routes a differing server binary to a conflict resolved via the byte path (BIN-A / L4)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    stubSyncInventory(plugin);
    // A genuine server BINARY whose bytes DIFFER from the local file.
    const differentBytes = new Uint8Array([0x89, 0x50, 0x00, 0x01, 0x80, 0xfe]);
    const encrypted = await plugin.encryptContentBytes(differentBytes.buffer);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: true,
      data: { content: encrypted, encoding: "base64", contentType: "image/png" },
      error: null,
      requestId: "req-get",
    });
    const runtime = plugin.ensureSyncRuntime();
    // keep_local (the plan default) → the binary conflict resolves via byte upload.
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // Differing hash → routed to the conflict bucket...
    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: ["/attachments/photo.png"],
    });
    // ...and resolved losslessly via the byte uploader (KEEP_LOCAL).
    expect(runtime.uploadReconciledBinaryFile).toHaveBeenCalledTimes(1);
    expect(plugin.uploadReconciledFile).not.toHaveBeenCalled();
  });

  it("skips a binary whose server copy cannot be fetched — never a conflict, never a wipe (OD-2)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    stubSyncInventory(plugin);
    plugin.fetchRemoteFileContent = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: { message: "server unreachable" },
      requestId: "req-get",
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn();

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // Neither same, conflict, nor heal — just skipped. Local bytes untouched.
    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: [],
    });
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
  });

  it("on a legacy adapter (no readBinary) keeps a binary-extension file on the string path, never the byte path (AR2/D-10)", async () => {
    const plugin = makeBinaryReconcilePlugin();
    // Legacy: capability gate closed → readForSync string-reads everything.
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: null,
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("legacy text");
    plugin.readPlainBinaryFromDisk = vi.fn(); // must NOT be called
    plugin.fetchRemoteFileContent = vi.fn(); // no byte fetch on legacy
    // photo.png is local-only here (empty server inventory).
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: { deltas: [], syncTimestamp: "2026-07-02T00:00:00.000Z" },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn(); // byte path must NOT be taken

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // The STRING sibling handled it (byte-identical to pre-BIN-A legacy behavior).
    expect(plugin.uploadReconciledFile).toHaveBeenCalledWith(
      "attachments/photo.png",
      "legacy text",
      undefined
    );
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(plugin.readPlainBinaryFromDisk).not.toHaveBeenCalled();
  });

  it("performInitialReconciliation uploads a local-only in-size binary as a first-class byte upload (BIN-A / D-05, D-11)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.vaultLeaseDenied = false;
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.applyRemoteChange = vi.fn();
    // The STRING uploader must NOT be used for a binary.
    plugin.uploadReconciledFile = vi.fn().mockResolvedValue("uploaded");
    plugin.askReconciliationPlan = vi
      .fn()
      .mockResolvedValue({ proceed: true, conflictStrategy: "keep-local" });
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: { deltas: [], syncTimestamp: "2026-07-03T00:00:00.000Z" },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // The binary is a first-class localOnly entry, uploaded via the BYTE path.
    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: ["/attachments/photo.png"],
      conflicts: [],
    });
    expect(runtime.uploadReconciledBinaryFile).toHaveBeenCalledTimes(1);
    const [uploadedPath, uploadedBytes] =
      runtime.uploadReconciledBinaryFile.mock.calls[0];
    expect(uploadedPath).toBe("attachments/photo.png");
    expect(new Uint8Array(uploadedBytes)).toEqual(AR1_BINARY_BYTES);
    expect(plugin.uploadReconciledFile).not.toHaveBeenCalled();
  });

  it("performInitialReconciliation excludes an oversize local binary — never uploaded, serverOnly, or overwritten (L10)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.vaultLeaseDenied = false;
    const oversize = new Uint8Array(BINARY_SYNC_MAX_BYTES + 1);
    oversize[8] = 0xff; // ensure the content probe classifies it binary
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(oversize.buffer),
      write: null,
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/huge.png" }]);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.applyRemoteChange = vi.fn();
    plugin.uploadReconciledFile = vi.fn().mockResolvedValue("uploaded");
    plugin.askReconciliationPlan = vi
      .fn()
      .mockResolvedValue({ proceed: true, conflictStrategy: "keep-local" });
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            // A server copy of the SAME oversize path: it must NOT be classified
            // serverOnly and written over the intact local (only) copy.
            deltas: [
              {
                path: "/attachments/huge.png",
                action: "created",
                lastModified: "x",
                checksum: "c",
                size: 99,
              },
            ],
            syncTimestamp: "2026-07-03T00:00:00.000Z",
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");
    mockNotice.mockClear();

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // Invisible to the plan: not serverOnly (no overwrite), not localOnly (no
    // upload), not a conflict.
    expect(plugin.askReconciliationPlan).toHaveBeenCalledWith({
      serverOnly: [],
      localOnly: [],
      conflicts: [],
    });
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
    // A throttled size Notice named the ~7 MiB limit + BIN-B.
    const sizedNotice = mockNotice.mock.calls.some(
      ([message]) =>
        typeof message === "string" &&
        message.includes("7 MiB") &&
        message.includes("BIN-B")
    );
    expect(sizedNotice).toBe(true);
  });

  it("resolveReconciliationConflict KEEP_LOCAL byte-uploads a binary entry, never the string uploader (BIN-A / L4)", async () => {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.uploadReconciledFile = vi.fn(); // string uploader must NOT be used
    plugin.applyRemoteChange = vi.fn();
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");
    const manifest = new Map([
      [
        "/attachments/photo.png",
        { kind: "binary", bytes: AR1_BINARY_BYTES.buffer, hash: "h" },
      ],
    ]);

    await runtime.resolveReconciliationConflict(
      "/attachments/photo.png",
      ConflictResolutionStrategy.KEEP_LOCAL,
      manifest
    );

    expect(runtime.uploadReconciledBinaryFile).toHaveBeenCalledTimes(1);
    const [p, b] = runtime.uploadReconciledBinaryFile.mock.calls[0];
    expect(p).toBe("attachments/photo.png");
    expect(new Uint8Array(b)).toEqual(AR1_BINARY_BYTES);
    expect(plugin.uploadReconciledFile).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
  });

  it("resolveReconciliationConflict KEEP_REMOTE byte-pulls a binary via the applyRemoteChange chokepoint (BIN-A / L4)", async () => {
    const plugin = makePlugin();
    plugin.applyRemoteChange = vi.fn().mockResolvedValue(undefined);
    plugin.uploadReconciledFile = vi.fn();
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn();
    runtime.writeLocalBinaryFileFromRemote = vi.fn();
    const manifest = new Map([
      [
        "/attachments/photo.png",
        { kind: "binary", bytes: AR1_BINARY_BYTES.buffer, hash: "h" },
      ],
    ]);

    await runtime.resolveReconciliationConflict(
      "/attachments/photo.png",
      ConflictResolutionStrategy.KEEP_REMOTE,
      manifest
    );

    // The single chokepoint pulls the remote; byte-vs-string is decided INSIDE
    // applyRemoteChange on the GET-response contentType (D-06). No local upload.
    expect(plugin.applyRemoteChange).toHaveBeenCalledWith({
      path: "attachments/photo.png",
      size: 0,
    });
    expect(runtime.uploadReconciledBinaryFile).not.toHaveBeenCalled();
    expect(runtime.writeLocalBinaryFileFromRemote).not.toHaveBeenCalled();
  });

  it("resolveReconciliationConflict DUPLICATE byte-writes local to the conflict path then byte-pulls the remote (BIN-A / L4)", async () => {
    const plugin = makePlugin();
    plugin.writeLocalFileFromRemote = vi.fn(); // string writer must NOT be used
    plugin.applyRemoteChange = vi.fn().mockResolvedValue(undefined);
    const runtime = plugin.ensureSyncRuntime();
    runtime.writeLocalBinaryFileFromRemote = vi.fn().mockResolvedValue(undefined);
    const manifest = new Map([
      [
        "/attachments/photo.png",
        { kind: "binary", bytes: AR1_BINARY_BYTES.buffer, hash: "h" },
      ],
    ]);

    await runtime.resolveReconciliationConflict(
      "/attachments/photo.png",
      ConflictResolutionStrategy.DUPLICATE,
      manifest
    );

    // Local bytes written to a conflict-named path via the reused byte writer...
    expect(runtime.writeLocalBinaryFileFromRemote).toHaveBeenCalledTimes(1);
    const [conflictPath, bytes] =
      runtime.writeLocalBinaryFileFromRemote.mock.calls[0];
    expect(conflictPath).toMatch(/^attachments\/photo \(conflict .*\)\.png$/);
    expect(new Uint8Array(bytes)).toEqual(AR1_BINARY_BYTES);
    // ...and the remote byte-pulled into the ORIGINAL path.
    expect(plugin.applyRemoteChange).toHaveBeenCalledWith({
      path: "attachments/photo.png",
      size: 0,
    });
    expect(plugin.writeLocalFileFromRemote).not.toHaveBeenCalled();
  });

  it("counts a reconciled binary upload as an upload (not a skip) in the summary (BIN-A / D-11)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.settings.bindingReconciledVaultId = undefined;
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.vaultLeaseDenied = false;
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.applyRemoteChange = vi.fn();
    plugin.askReconciliationPlan = vi
      .fn()
      .mockResolvedValue({ proceed: true, conflictStrategy: "keep_local" });
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (method === "POST" && path.endsWith("/files/sync")) {
        return {
          success: true,
          data: { deltas: [], syncTimestamp: "2026-07-03T00:00:00.000Z" },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });
    const runtime = plugin.ensureSyncRuntime();
    runtime.uploadReconciledBinaryFile = vi.fn().mockResolvedValue("uploaded");
    mockNotice.mockClear();

    await expect(plugin.performInitialReconciliation()).resolves.toBe(true);

    // The completion summary counts the binary in the UPLOAD bucket (D-11), not
    // as a skip.
    const completeNotice = mockNotice.mock.calls.find(
      ([message]) =>
        typeof message === "string" && message.includes("Reconciliation complete")
    );
    expect(completeNotice?.[0]).toContain("1 uploaded");
    expect(completeNotice?.[0]).not.toContain("skipped");
  });

  it("queues both rename halves and tombstones the old path when offline/lease-less (SY4)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = null; // lease-less: folder-rename children used to be silently dropped
    plugin.connectionState.status = "offline";
    plugin.settings.deletionTombstones = {};
    plugin.offlineQueue = [];
    const textBytes = new TextEncoder().encode("note body");
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(textBytes.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.apiRequest = vi.fn();

    await plugin.syncFileRenameToServer("folder-a/note.md", "folder-b/note.md");

    expect(plugin.apiRequest).not.toHaveBeenCalled();
    expect(plugin.offlineQueue).toEqual([
      expect.objectContaining({
        operation: "write",
        path: "folder-b/note.md",
        data: "note body",
      }),
      expect.objectContaining({ operation: "delete", path: "folder-a/note.md" }),
    ]);
    // The tombstone stops repair from resurrecting the old server copy
    // before the queued delete lands.
    expect(typeof plugin.settings.deletionTombstones["folder-a/note.md"]).toBe("string");
  });

  it("syncFileRenameToServer renames an online binary via a byte PUT + old-path DELETE (BIN-A / L1)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.emitPermissionChanged = vi.fn();
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    const calls: any[] = [];
    plugin.apiRequest = vi.fn(
      async (method: string, path: string, body: any, _idT: unknown, options: unknown) => {
        calls.push({ method, path, body, options });
        return { success: true, data: {}, error: null, requestId: "r" };
      }
    );

    await plugin.syncFileRenameToServer("attachments/old.png", "attachments/new.png");

    const put = calls.find((c) => c.method === "PUT");
    const del = calls.find((c) => c.method === "DELETE");
    // Byte PUT of the NEW path: contentType + large-body timeout, ciphertext
    // round-trips to the original bytes.
    expect(put).toBeDefined();
    expect(put.path).toContain("new.png");
    expect(put.body.contentType).toBe("image/png");
    expect(put.options).toEqual({ timeoutMs: 120000 });
    const decrypted = await plugin.decryptContentBytes(put.body.content);
    expect(new Uint8Array(decrypted)).toEqual(AR1_BINARY_BYTES);
    // OLD path still DELETEd (the rename completes on the server).
    expect(del).toBeDefined();
    expect(del.path).toContain("old.png");
  });

  it("syncFileRenameToServer queues an offline binary rename as a base64 write + delete (BIN-A / L1)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = null; // lease-less → offline branch
    plugin.connectionState.status = "offline";
    plugin.settings.deletionTombstones = {};
    plugin.offlineQueue = [];
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(AR1_BINARY_BYTES.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.apiRequest = vi.fn();

    await plugin.syncFileRenameToServer("attachments/old.png", "attachments/new.png");

    expect(plugin.apiRequest).not.toHaveBeenCalled();
    const writeOp = plugin.offlineQueue.find((o: any) => o.operation === "write");
    const deleteOp = plugin.offlineQueue.find((o: any) => o.operation === "delete");
    // Queued write carries encoding "base64" + contentType; data is base64 of
    // the PLAIN bytes so the flush replays it through the byte crypto path.
    expect(writeOp).toMatchObject({
      operation: "write",
      path: "attachments/new.png",
      encoding: "base64",
      contentType: "image/png",
    });
    expect(writeOp.data).toBe(Buffer.from(AR1_BINARY_BYTES).toString("base64"));
    expect(deleteOp).toMatchObject({ operation: "delete", path: "attachments/old.png" });
    expect(typeof plugin.settings.deletionTombstones["attachments/old.png"]).toBe("string");
  });

  it("syncFileRenameToServer skips ALL server ops for an oversize binary rename (no PUT/queue/delete + Notice, L10)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.settings.deletionTombstones = {};
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    const oversize = new Uint8Array(BINARY_SYNC_MAX_BYTES + 1);
    oversize[8] = 0xff; // ensure the content probe classifies it binary
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn().mockResolvedValue(oversize.buffer),
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.apiRequest = vi.fn();
    mockNotice.mockClear();

    await plugin.syncFileRenameToServer("attachments/huge-old.png", "attachments/huge-new.png");

    // Same conservative rule as interceptedRename (11-02): never a PUT, never a
    // queued write, never a delete of the old server copy we can't replace.
    expect(plugin.apiRequest).not.toHaveBeenCalled();
    expect(plugin.offlineQueue).toHaveLength(0);
    expect(plugin.settings.deletionTombstones).toEqual({});
    const noticed = mockNotice.mock.calls.some(
      ([message]) =>
        typeof message === "string" &&
        message.includes("7 MiB") &&
        message.includes("BIN-B")
    );
    expect(noticed).toBe(true);
  });

  it("syncFileRenameToServer on a legacy adapter (no readBinary) keeps the string PUT path (AR2/D-10)", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(PermissionLevel.WRITE);
    plugin.emitPermissionChanged = vi.fn();
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: null, // legacy: capability gate closed
      write: null,
      list: null,
      remove: null,
      rename: null,
    };
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("legacy note text");
    plugin.readPlainBinaryFromDisk = vi.fn(); // must NOT be called
    const calls: any[] = [];
    plugin.apiRequest = vi.fn(async (method: string, path: string, body: any) => {
      calls.push({ method, path, body });
      return { success: true, data: {}, error: null, requestId: "r" };
    });

    await plugin.syncFileRenameToServer("attachments/old.png", "attachments/new.png");

    const put = calls.find((c) => c.method === "PUT");
    // String PUT body (no contentType) — byte-identical to pre-BIN-A behavior.
    expect(put).toBeDefined();
    expect(Object.keys(put.body).sort()).toEqual(["content", "hash"]);
    expect(put.body.contentType).toBeUndefined();
    expect(plugin.readPlainBinaryFromDisk).not.toHaveBeenCalled();
  });

  // Regression: cold-path (full-scan) deletions are INFERRED from manifest-vs-S3
  // absence and can wrongly target never-uploaded local files, so they must go
  // to recoverable trash — never a permanent wipe. Warm-path (activity-log)
  // deletions are real events and delete permanently.
  function setupDeletionSyncPlugin(mode: "full-scan" | "activity-log") {
    const plugin = makePlugin();
    const remove = vi.fn().mockResolvedValue(undefined);
    const trashLocal = vi.fn().mockResolvedValue(undefined);
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.localOnlyCatchupCompleted = true;
    plugin.remoteInventoryRepairCompleted = true;
    plugin.syncState.lastSeenRevision = 5;
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.originalAdapterMethods = {
      read: null,
      write: null,
      list: null,
      remove,
      rename: null,
    };
    plugin.app.vault.adapter = { ...(plugin.app.vault.adapter ?? {}), trashLocal };
    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (path.endsWith("/sync-cursor")) {
        return {
          success: true,
          data: { revision: 6, lastChangedAt: "2026-05-01T00:00:00.000Z", serverTime: "2026-05-01T00:00:01.000Z" },
          error: null,
          requestId: "req-cursor",
        };
      }
      if (path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            deltas: [
              {
                path: "/notes/todo.md",
                action: "deleted",
                lastModified: "2026-05-01T00:00:00.000Z",
                checksum: "",
                size: 0,
              },
            ],
            syncTimestamp: "2026-05-01T00:00:02.000Z",
            revision: 6,
            mode,
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });
    return { plugin, remove, trashLocal };
  }

  it("moves cold-path (full-scan) inferred deletions to trash instead of permanently deleting", async () => {
    const { plugin, remove, trashLocal } = setupDeletionSyncPlugin("full-scan");

    await plugin.performSync();

    expect(trashLocal).toHaveBeenCalledWith("notes/todo.md");
    expect(remove).not.toHaveBeenCalled();
  });

  it("permanently deletes warm-path (activity-log) deletions", async () => {
    const { plugin, remove, trashLocal } = setupDeletionSyncPlugin("activity-log");

    await plugin.performSync();

    expect(remove).toHaveBeenCalledWith("notes/todo.md");
    expect(trashLocal).not.toHaveBeenCalled();
  });

  it("does not apply a remote delta over a path with a pending offline operation (SY5)", async () => {
    const { plugin, remove, trashLocal } = setupDeletionSyncPlugin("activity-log");
    // Limited access: no lease, so the Phase-1 flush is skipped and the
    // queued local edit of notes/todo.md has NOT reached the server.
    plugin.keyLease = null;
    plugin.offlineQueue = [
      {
        operation: "write",
        path: "notes/todo.md",
        data: "local edit made while limited",
        timestamp: "2026-05-01T00:00:00.000Z",
      },
    ];
    plugin.applyRemoteChange = vi.fn();

    await plugin.performSync();

    // The remote "deleted" delta must NOT run over the locally-dirty file —
    // pre-fix it deleted (or overwrote) the user's unsynced edit.
    expect(remove).not.toHaveBeenCalled();
    expect(trashLocal).not.toHaveBeenCalled();
    expect(plugin.applyRemoteChange).not.toHaveBeenCalled();
    expect(plugin.offlineQueue).toHaveLength(1);
  });

  it("persists the offline queue as a LAK envelope and restores it on load (SY5)", async () => {
    const envelopeFiles = new Map<string, ArrayBuffer>();
    const envelopePath = ".obsidian/plugins/vaultguard-sync/offline-queue.envelope";

    function wireEnvelopePlugin() {
      const plugin = makePlugin();
      plugin.manifest = { id: "vaultguard-sync" };
      plugin.app.vault.configDir = ".obsidian";
      plugin.app.vault.adapter = {
        exists: vi.fn(async (p: string) => envelopeFiles.has(p)),
        remove: vi.fn(async (p: string) => {
          envelopeFiles.delete(p);
        }),
      };
      plugin.originalAdapterMethods = {
        read: null,
        write: null,
        list: null,
        remove: null,
        rename: null,
        readBinary: vi.fn(async (p: string) => envelopeFiles.get(p)!),
        writeBinary: vi.fn(async (p: string, bytes: ArrayBuffer) => {
          envelopeFiles.set(p, bytes);
        }),
      };
      plugin.atRestCipher = {
        isReady: () => true,
        encryptString: vi.fn(async (s: string) => new TextEncoder().encode(s).buffer),
        decryptString: vi.fn(async (b: ArrayBuffer) => new TextDecoder().decode(b)),
      };
      plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
      plugin.waitForCipherInit = vi.fn().mockResolvedValue(true);
      return plugin;
    }

    // Session 1: queue an op and persist.
    const plugin1 = wireEnvelopePlugin();
    plugin1.offlineQueue = [
      {
        operation: "write",
        path: "notes/limited-edit.md",
        data: "edited while limited-access",
        timestamp: "2026-07-02T00:00:00.000Z",
      },
    ];
    await plugin1.persistOfflineQueue();
    expect(envelopeFiles.has(envelopePath)).toBe(true);

    // Session 2 (restart): the queue restores from the envelope.
    const plugin2 = wireEnvelopePlugin();
    plugin2.offlineQueue = [];
    await plugin2.loadPersistedOfflineQueue();
    expect(plugin2.offlineQueue).toEqual([
      expect.objectContaining({
        operation: "write",
        path: "notes/limited-edit.md",
        data: "edited while limited-access",
      }),
    ]);

    // Draining the queue removes the envelope (logout leaves nothing behind).
    plugin2.offlineQueue = [];
    await plugin2.persistOfflineQueue();
    expect(envelopeFiles.has(envelopePath)).toBe(false);
  });

  describe("offline-queue v2 envelope (BIN-A / D-09)", () => {
    const envelopePath = ".obsidian/plugins/vaultguard-sync/offline-queue.envelope";
    let envelopeFiles: Map<string, ArrayBuffer>;

    beforeEach(() => {
      envelopeFiles = new Map<string, ArrayBuffer>();
      vi.stubGlobal("localStorage", makeMemoryStorage());
    });

    function wireEnvelopePlugin() {
      const plugin = makePlugin();
      plugin.manifest = { id: "vaultguard-sync" };
      plugin.app.vault.configDir = ".obsidian";
      plugin.app.vault.adapter = {
        exists: vi.fn(async (p: string) => envelopeFiles.has(p)),
        remove: vi.fn(async (p: string) => {
          envelopeFiles.delete(p);
        }),
      };
      plugin.originalAdapterMethods = {
        read: null,
        write: null,
        list: null,
        remove: null,
        rename: null,
        readBinary: vi.fn(async (p: string) => envelopeFiles.get(p)!),
        writeBinary: vi.fn(async (p: string, bytes: ArrayBuffer) => {
          envelopeFiles.set(p, bytes);
        }),
      };
      // Identity cipher: the persisted "ciphertext" is the UTF-8 bytes of the
      // JSON plaintext, so a test can decode the stored envelope to assert its
      // shape (and the version tag).
      plugin.atRestCipher = {
        isReady: () => true,
        encryptString: vi.fn(async (s: string) => new TextEncoder().encode(s).buffer),
        decryptString: vi.fn(async (b: ArrayBuffer) => new TextDecoder().decode(b)),
      };
      plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
      plugin.waitForCipherInit = vi.fn().mockResolvedValue(true);
      return plugin;
    }

    it("round-trips a v2 envelope with a text op and a binary op across restart", async () => {
      const plugin1 = wireEnvelopePlugin();
      plugin1.offlineQueue = [
        {
          operation: "write",
          path: "notes/a.md",
          data: "hello",
          timestamp: "2026-07-03T00:00:00.000Z",
        },
        {
          operation: "write",
          path: "img/pic.png",
          data: "iVBORw0KGgo=",
          timestamp: "2026-07-03T00:00:01.000Z",
          encoding: "base64",
          contentType: "image/png",
        },
      ];
      await plugin1.persistOfflineQueue();

      // The on-disk envelope is v2 (identity cipher ⇒ plaintext is the UTF-8 JSON).
      const stored = envelopeFiles.get(envelopePath)!;
      expect(JSON.parse(new TextDecoder().decode(stored)).v).toBe(2);

      // Restart: a fresh instance restores both ops with their fields intact.
      const plugin2 = wireEnvelopePlugin();
      plugin2.offlineQueue = [];
      await plugin2.loadPersistedOfflineQueue();

      expect(plugin2.offlineQueue).toEqual([
        expect.objectContaining({ operation: "write", path: "notes/a.md", data: "hello" }),
        expect.objectContaining({
          operation: "write",
          path: "img/pic.png",
          data: "iVBORw0KGgo=",
          encoding: "base64",
          contentType: "image/png",
        }),
      ]);
      // The text op restored WITHOUT a spurious binary marker.
      expect(plugin2.offlineQueue[0].encoding).toBeUndefined();
      expect(plugin2.offlineQueue[0].contentType).toBeUndefined();
    });

    it("still restores a legacy v1 envelope written by an older build", async () => {
      const plugin = wireEnvelopePlugin();
      // Hand-write a v1 envelope through the same identity cipher (persist now
      // always writes v2, so v1 can only arrive from an older build on disk).
      const v1Json = JSON.stringify({
        v: 1,
        ops: [
          {
            operation: "write",
            path: "notes/old.md",
            data: "legacy",
            timestamp: "2026-07-01T00:00:00.000Z",
          },
        ],
      });
      envelopeFiles.set(envelopePath, new TextEncoder().encode(v1Json).buffer);

      plugin.offlineQueue = [];
      await plugin.loadPersistedOfflineQueue();

      expect(plugin.offlineQueue).toEqual([
        expect.objectContaining({ operation: "write", path: "notes/old.md", data: "legacy" }),
      ]);
    });

    it("drops a v2 entry with an unknown encoding but keeps valid siblings", async () => {
      const plugin = wireEnvelopePlugin();
      const v2Json = JSON.stringify({
        v: 2,
        ops: [
          {
            operation: "write",
            path: "img/ok.png",
            data: "AAAA",
            timestamp: "2026-07-03T00:00:00.000Z",
            encoding: "base64",
            contentType: "image/png",
          },
          {
            operation: "write",
            path: "img/bad.bin",
            data: "ffff",
            timestamp: "2026-07-03T00:00:01.000Z",
            encoding: "hex",
          },
          {
            operation: "write",
            path: "notes/ok.md",
            data: "text",
            timestamp: "2026-07-03T00:00:02.000Z",
          },
        ],
      });
      envelopeFiles.set(envelopePath, new TextEncoder().encode(v2Json).buffer);

      plugin.offlineQueue = [];
      await plugin.loadPersistedOfflineQueue();

      const paths = plugin.offlineQueue.map((op: any) => op.path);
      expect(paths).toEqual(["img/ok.png", "notes/ok.md"]);
      expect(paths).not.toContain("img/bad.bin");
      expect(plugin.logError).toHaveBeenCalledWith(
        expect.stringContaining("unknown queue encoding"),
        expect.any(Error)
      );
    });

    it("persists the envelope as v2 (plaintext handed to the cipher)", async () => {
      const plugin = wireEnvelopePlugin();
      const encryptSpy = plugin.atRestCipher.encryptString;
      plugin.offlineQueue = [
        {
          operation: "write",
          path: "notes/a.md",
          data: "hi",
          timestamp: "2026-07-03T00:00:00.000Z",
        },
      ];
      await plugin.persistOfflineQueue();
      expect(encryptSpy).toHaveBeenCalledTimes(1);
      const plaintext = encryptSpy.mock.calls[0][0] as string;
      expect(JSON.parse(plaintext).v).toBe(2);
    });
  });

  it("preserves the local permission cache when the sync response does not signal permissionsChanged", async () => {
    const plugin = makePlugin();
    plugin.settings.serverVaultId = "vault-abc";
    plugin.session = makeSession();
    plugin.keyLease = makeKeyLease();
    plugin.connectionState.status = "online";
    plugin.offlineQueue = [];
    plugin.localOnlyCatchupCompleted = true;
    plugin.remoteInventoryRepairCompleted = true;
    plugin.syncState.lastSeenRevision = 5;
    plugin.permissionCache = new Map([["docs/file.md", 1]]);
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);

    plugin.apiRequest = vi.fn(async (method: string, path: string) => {
      if (path.endsWith("/sync-cursor")) {
        return {
          success: true,
          data: { revision: 6, lastChangedAt: "2026-04-30T12:00:00.000Z", serverTime: "2026-04-30T12:00:01.000Z" },
          error: null,
          requestId: "req-cursor",
        };
      }
      if (path.endsWith("/files/sync")) {
        return {
          success: true,
          data: {
            deltas: [],
            syncTimestamp: "2026-04-30T12:00:02.000Z",
            revision: 6,
            mode: "activity-log",
            permissionsChanged: false,
          },
          error: null,
          requestId: "req-sync",
        };
      }
      throw new Error(`Unexpected API call: ${method} ${path}`);
    });

    await plugin.performSync();
    expect(plugin.permissionCache.size).toBe(1);
  });

  it("computes adaptive sync delay based on observed activity recency", () => {
    const plugin = makePlugin();
    plugin.orgSettings = { syncMode: "periodic", syncIntervalMinutes: 0.5 };

    plugin.syncState.lastObservedActivityAt = null;
    expect(plugin.computeNextSyncDelayMs()).toBe(30_000);

    plugin.syncState.lastObservedActivityAt = Date.now() - 1_000;
    expect(plugin.computeNextSyncDelayMs()).toBe(30_000);

    plugin.syncState.lastObservedActivityAt = Date.now() - 10 * 60_000;
    const tenMinIdle = plugin.computeNextSyncDelayMs();
    expect(tenMinIdle).toBeGreaterThanOrEqual(60_000);

    plugin.syncState.lastObservedActivityAt = Date.now() - 60 * 60_000;
    const oneHourIdle = plugin.computeNextSyncDelayMs();
    expect(oneHourIdle).toBeGreaterThanOrEqual(120_000);
    expect(oneHourIdle).toBeLessThanOrEqual(5 * 60_000);
  });

  it("builds a sync manifest with every local file path so the server can detect deletions", () => {
    const plugin = makePlugin();
    plugin.settings.excludedPaths = ["secret"];

    const files = [
      { path: "Welcome.md" },
      { path: "notes/idea.md" },
      // BIN-A: binaries flow in presence-only via vault.getFiles() — no byte
      // hash goes on the wire here (the manifest is deletion-detection only).
      { path: "attachments/photo.png" },
      { path: ".obsidian/plugins/vaultguard-sync/data.json" },
      { path: "secret/private.md" },
    ];
    const folders = ["notes", "empty"];

    plugin.app.vault.getFiles = vi.fn(() => files);
    plugin.app.vault.getRoot = vi.fn(() => ({
      children: [
        { path: "notes", children: [], constructor: { name: "TFolder" } },
        { path: "empty", children: [], constructor: { name: "TFolder" } },
        { path: "secret", children: [], constructor: { name: "TFolder" } },
      ],
    }));
    plugin.collectLocalFolderPaths = vi.fn(() => folders);

    const manifest = plugin.buildLocalSyncManifest();

    expect(manifest["/Welcome.md"]).toBe("");
    expect(manifest["/notes/idea.md"]).toBe("");
    // BIN-A: a binary path appears presence-only (empty value), exactly like text.
    expect(manifest["/attachments/photo.png"]).toBe("");
    expect(manifest).not.toHaveProperty("/.obsidian/plugins/vaultguard-sync/data.json");
    expect(manifest).not.toHaveProperty("/secret/private.md");
    expect(manifest["/notes/.vaultguard-folder"]).toBe("");
    expect(manifest["/empty/.vaultguard-folder"]).toBe("");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Phase 8 (plan 08-03): Limited-access placeholder flow + sweep
// ─────────────────────────────────────────────────────────────────────────────

describe("VaultGuardPlugin limited-access placeholder flow", () => {
  beforeEach(() => {
    mockNotice.mockReset();
    mockRequestUrl.mockReset();
    vi.stubGlobal("localStorage", makeMemoryStorage());
  });

  function makeLimitedPlugin() {
    const plugin = makePlugin();
    // Default to limited-access state for most tests in this block.
    plugin.vaultLeaseDenied = true;
    plugin.placeholderPaths = new Set<string>();
    plugin.session = makeSession();
    plugin.permissionCache = new Map<string, number>();
    // interceptedRead deps — make all the gates a pass-through.
    plugin.isPathExcluded = vi.fn(() => false);
    plugin.awaitPermissionReadiness = vi.fn().mockResolvedValue(undefined);
    plugin.getEffectivePermission = vi.fn().mockResolvedValue(3); // READ-or-better
    plugin.emitAuditEvent = vi.fn().mockResolvedValue(undefined);
    plugin.writePlainToDisk = vi.fn().mockResolvedValue(undefined);
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("");
    plugin.notifyDeniedLocalWipe = vi.fn();
    plugin.notifyCloudDecryptFallback = vi.fn();
    plugin.isOnline = vi.fn(() => true);
    plugin.isNetworkError = vi.fn(() => false);
    plugin.setConnectionStatus = vi.fn();
    // base64 -> utf8 helper used by the hydration path.
    plugin.decodeBase64Utf8 = vi.fn((b64: string) =>
      Buffer.from(b64, "base64").toString("utf8")
    );
    plugin.normalizeVaultPath = vi.fn((p: string) => p.replace(/^\/+/, ""));
    return plugin;
  }

  it("interceptedRead in limited-access mode with placeholder hit fetches via readFileDecrypted and writes plaintext", async () => {
    const plugin = makeLimitedPlugin();
    plugin.placeholderPaths.add("notes/welcome.md");
    plugin.readFileDecrypted = vi.fn().mockResolvedValue({
      success: true,
      data: {
        path: "/notes/welcome.md",
        content: Buffer.from("hello world", "utf8").toString("base64"),
        encoding: "base64",
        decrypted: true,
      },
      error: null,
      requestId: "req-1",
    });

    const result = await plugin.interceptedRead("notes/welcome.md");

    expect(result).toBe("hello world");
    expect(plugin.readFileDecrypted).toHaveBeenCalledWith("notes/welcome.md");
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith(
      "notes/welcome.md",
      "hello world"
    );
    expect(plugin.placeholderPaths.has("notes/welcome.md")).toBe(false);
  });

  it("interceptedRead on 404 fails open: returns on-disk content, drops the placeholder, does not wipe (Fix A, 2026-05-31)", async () => {
    // 2026-05-31 Pete incident: the previous behavior here wiped local
    // content and threw. That was the data-loss vector — any user with a
    // read-deny rule overlapping /** got a 403 on the scoped lease,
    // forcing vaultLeaseDenied=true, after which every read of a read-
    // only file hit this branch and erased the local copy. The new
    // contract mirrors the post-1.0.17 fail-open principle for the main
    // read path: emit a denial audit event, return readPlainFromDisk,
    // never throw, never wipe.
    const plugin = makeLimitedPlugin();
    plugin.placeholderPaths.add("secret/locked.md");
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("on-disk fallback content");
    plugin.readFileDecrypted = vi.fn().mockResolvedValue({
      success: false,
      data: null,
      error: { statusCode: 404, message: "File not found" },
      requestId: "req-2",
    });

    const result = await plugin.interceptedRead("secret/locked.md");

    expect(result).toBe("on-disk fallback content");
    expect(plugin.placeholderPaths.has("secret/locked.md")).toBe(false);
    expect(plugin.readPlainFromDisk).toHaveBeenCalledWith("secret/locked.md");
    expect(plugin.emitAuditEvent).toHaveBeenCalledWith(
      "file.read",
      "secret/locked.md",
      expect.objectContaining({
        outcome: "denied",
        reason: "limited-access-placeholder-404-fail-open",
      })
    );
  });

  it("performInitialReconciliation in limited-access mode writes placeholders for serverOnly paths AND does not show the modal", async () => {
    const plugin = makeLimitedPlugin();
    plugin.connectionState.status = "online";
    plugin.isOnline = vi.fn(() => true);

    // Existing methods used inside performInitialReconciliation.
    plugin.computeHash = vi.fn(async (s: string) => "h-" + s);
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
    plugin.ensureLocalFolderPath = vi.fn().mockResolvedValue(true);
    plugin.isFolderMarkerPath = vi.fn((p: string) => p.endsWith(".vaultguard-folder"));
    plugin.askReconciliationPlan = vi.fn(); // Must NOT be called
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: {
        deltas: [
          { path: "/permitted/a.md", action: "created", lastModified: "x", checksum: "c1", size: 1 },
          { path: "/permitted/b.md", action: "created", lastModified: "x", checksum: "c2", size: 1 },
        ],
        syncTimestamp: "2026-05-21T00:00:00.000Z",
      },
      error: null,
      requestId: "req-recon",
    });

    const ok = await plugin.performInitialReconciliation();

    expect(ok).toBe(true);
    expect(plugin.askReconciliationPlan).not.toHaveBeenCalled();
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("permitted/a.md", "");
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("permitted/b.md", "");
    expect(plugin.placeholderPaths.has("permitted/a.md")).toBe(true);
    expect(plugin.placeholderPaths.has("permitted/b.md")).toBe(true);
  });

  it("skips empty placeholders for known-binary-extension serverOnly paths (BIN-A/L6 option b), keeping text + extensionless placeholders", async () => {
    const plugin = makeLimitedPlugin();
    plugin.connectionState.status = "online";
    plugin.isOnline = vi.fn(() => true);
    plugin.computeHash = vi.fn(async (s: string) => "h-" + s);
    plugin.app.vault.getFiles = vi.fn(() => []);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
    plugin.ensureLocalFolderPath = vi.fn().mockResolvedValue(true);
    plugin.isFolderMarkerPath = vi.fn((p: string) => p.endsWith(".vaultguard-folder"));
    plugin.askReconciliationPlan = vi.fn(); // must NOT be called in limited mode
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: {
        deltas: [
          { path: "/notes/note.md", action: "created", lastModified: "x", checksum: "c1", size: 1 },
          { path: "/attachments/photo.png", action: "created", lastModified: "x", checksum: "c2", size: 2 },
          { path: "/data/export", action: "created", lastModified: "x", checksum: "c3", size: 3 },
        ],
        syncTimestamp: "2026-07-03T00:00:00.000Z",
      },
      error: null,
      requestId: "req-recon",
    });

    const ok = await plugin.performInitialReconciliation();

    expect(ok).toBe(true);
    // Text note + extension-less path get placeholders...
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("notes/note.md", "");
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("data/export", "");
    expect(plugin.placeholderPaths.has("notes/note.md")).toBe(true);
    expect(plugin.placeholderPaths.has("data/export")).toBe(true);
    // ...but the binary attachment is never placeholdered (would be a broken image).
    expect(plugin.writePlainToDisk).not.toHaveBeenCalledWith("attachments/photo.png", "");
    expect(plugin.placeholderPaths.has("attachments/photo.png")).toBe(false);
  });

  it("never overwrites a locally-existing binary via the lease-denied placeholder branch (OD-2 regression guard)", async () => {
    const plugin = makeLimitedPlugin();
    plugin.connectionState.status = "online";
    plugin.isOnline = vi.fn(() => true);
    plugin.computeHash = vi.fn(async (s: string) => "h-" + s);
    // A local binary that ALSO exists on the server (same path).
    plugin.originalAdapterMethods = {
      read: vi.fn(),
      readBinary: vi.fn(),
      write: null,
      writeBinary: vi.fn(),
      list: null,
      remove: null,
      rename: null,
    };
    plugin.readPlainBinaryFromDisk = vi
      .fn()
      .mockResolvedValue(new Uint8Array([0x89, 0x50, 0x80, 0xff]).buffer);
    plugin.app.vault.getFiles = vi.fn(() => [{ path: "attachments/photo.png" }]);
    plugin.app.vault.getRoot = vi.fn(() => ({ children: [] }));
    plugin.collectLocalFolderPaths = vi.fn(() => []);
    plugin.ensureParentFoldersForPath = vi.fn().mockResolvedValue(undefined);
    plugin.ensureLocalFolderPath = vi.fn().mockResolvedValue(true);
    plugin.isFolderMarkerPath = vi.fn((p: string) => p.endsWith(".vaultguard-folder"));
    plugin.saveSettings = vi.fn().mockResolvedValue(undefined);
    plugin.apiRequest = vi.fn().mockResolvedValue({
      success: true,
      data: {
        deltas: [
          { path: "/attachments/photo.png", action: "created", lastModified: "x", checksum: "c", size: 2 },
        ],
        syncTimestamp: "2026-07-03T00:00:00.000Z",
      },
      error: null,
      requestId: "req-recon",
    });

    const ok = await plugin.performInitialReconciliation();

    expect(ok).toBe(true);
    // The on-disk binary is never overwritten with an empty placeholder (it is a
    // local file, excluded from serverOnly; the placeholder branch never sees it).
    expect(plugin.writePlainToDisk).not.toHaveBeenCalledWith("attachments/photo.png", "");
    expect(plugin.placeholderPaths.has("attachments/photo.png")).toBe(false);
  });

  it("placeholderPaths is cleared when checkKeyLeaseRenewal recovers from limited -> ok", async () => {
    const plugin = makeLimitedPlugin();
    plugin.placeholderPaths.add("a.md");
    plugin.placeholderPaths.add("b.md");
    plugin.keyLease = null;
    plugin.settings.serverVaultId = "vault-abc";
    plugin.ensureVaultScopedKeyLease = vi.fn().mockImplementation(async () => {
      plugin.vaultLeaseDenied = false;
      plugin.keyLease = makeKeyLease();
      return "ok";
    });
    plugin.readOnlyGuard = { refreshAll: vi.fn() };
    plugin.fileExplorerDecorations = { invalidate: vi.fn() };
    plugin.filePermissionHeader = { invalidateCache: vi.fn(), update: vi.fn() };

    await plugin.checkKeyLeaseRenewal();

    expect(plugin.placeholderPaths.size).toBe(0);
    expect(plugin.permissionCache.size).toBe(0);
  });

  it("checkKeyLeaseRenewal retries a lease that failed TRANSIENTLY, not only a 403 denial (PL2)", async () => {
    const plugin = makeLimitedPlugin();
    plugin.keyLease = null;
    // Transient-failure state: NOT a 403 denial, but a retry is owed.
    plugin.vaultLeaseDenied = false;
    plugin.leaseRetryNeeded = true;
    plugin.settings.serverVaultId = "vault-abc";
    const ensure = vi.fn().mockImplementation(async () => {
      plugin.leaseRetryNeeded = false;
      plugin.keyLease = makeKeyLease();
      return "ok";
    });
    plugin.ensureVaultScopedKeyLease = ensure;

    await plugin.checkKeyLeaseRenewal();

    expect(ensure).toHaveBeenCalledTimes(1);
    expect(plugin.keyLease).not.toBeNull();
  });

  it("checkKeyLeaseRenewal does NOT retry when neither denied nor retry-needed (no vault binding yet)", async () => {
    const plugin = makeLimitedPlugin();
    plugin.keyLease = null;
    plugin.vaultLeaseDenied = false;
    plugin.leaseRetryNeeded = false;
    plugin.settings.serverVaultId = "vault-abc";
    const ensure = vi.fn();
    plugin.ensureVaultScopedKeyLease = ensure;

    await plugin.checkKeyLeaseRenewal();

    expect(ensure).not.toHaveBeenCalled();
  });

  it("placeholderPaths is not persisted to data.json (saveData payload never contains the set)", async () => {
    const plugin = makeLimitedPlugin();
    plugin.placeholderPaths.add("a.md");
    plugin.placeholderPaths.add("b.md");
    const saveSpy = vi.fn().mockResolvedValue(undefined);
    plugin.saveData = saveSpy;

    await plugin.saveSettings();

    expect(saveSpy).toHaveBeenCalled();
    for (const call of saveSpy.mock.calls) {
      const payload = call[0];
      expect(JSON.stringify(payload)).not.toContain("placeholderPaths");
    }
  });

  it("secondary heuristic: empty decrypted plaintext + vaultLeaseDenied triggers a fetch (legacy placeholder fallback)", async () => {
    const plugin = makeLimitedPlugin();
    // Path NOT in placeholderPaths (legacy on-disk file written by older
    // plugin version before placeholderPaths existed). Use the offline
    // fallback branch to specifically exercise the secondary heuristic; the
    // primary online branch would fire readFileDecrypted via the normal
    // fetchRemoteFileContent path otherwise.
    plugin.isOnline = vi.fn(() => false);
    plugin.readPlainFromDisk = vi.fn().mockResolvedValue("");
    plugin.readFileDecrypted = vi.fn().mockResolvedValue({
      success: true,
      data: {
        path: "/legacy/old.md",
        content: Buffer.from("hydrated", "utf8").toString("base64"),
        encoding: "base64",
        decrypted: true,
      },
      error: null,
      requestId: "req-fallback",
    });

    const result = await plugin.interceptedRead("legacy/old.md");

    expect(result).toBe("hydrated");
    expect(plugin.readFileDecrypted).toHaveBeenCalledWith("legacy/old.md");
    expect(plugin.writePlainToDisk).toHaveBeenCalledWith("legacy/old.md", "hydrated");
  });

  it("sweepPlaceholderPaths only adds 36-byte files whose first 4 bytes are VG1 magic", async () => {
    const plugin = makeLimitedPlugin();
    plugin.originalAdapterMethods.list = vi
      .fn()
      .mockResolvedValueOnce({ files: ["a.md", "b.md", "c.md"], folders: [] });
    plugin.app.vault.adapter.stat = vi
      .fn()
      .mockResolvedValueOnce({ size: 36, type: "file" }) // a.md
      .mockResolvedValueOnce({ size: 36, type: "file" }) // b.md
      .mockResolvedValueOnce({ size: 100, type: "file" }); // c.md
    const vg1 = new Uint8Array([0x56, 0x47, 0x31, 0x00, ...new Array(32).fill(0)]).buffer;
    const notVg1 = new Uint8Array([0xff, 0xff, 0xff, 0xff, ...new Array(32).fill(0)]).buffer;
    plugin.originalAdapterMethods.readBinary = vi
      .fn()
      .mockResolvedValueOnce(vg1)
      .mockResolvedValueOnce(notVg1);

    await plugin.sweepPlaceholderPaths();

    expect(plugin.placeholderPaths.has("a.md")).toBe(true);
    expect(plugin.placeholderPaths.has("b.md")).toBe(false);
    expect(plugin.placeholderPaths.has("c.md")).toBe(false);
  });

  it("sweepPlaceholderPaths aborts at MAX_SWEEP_ENTRIES (5000) and emits one console.warn", async () => {
    const plugin = makeLimitedPlugin();
    // Manufacture 5500 file paths to exceed the cap.
    const files = Array.from({ length: 5500 }, (_, i) => `f${i}.md`);
    plugin.originalAdapterMethods.list = vi
      .fn()
      .mockResolvedValueOnce({ files, folders: [] });
    plugin.app.vault.adapter.stat = vi
      .fn()
      .mockResolvedValue({ size: 100, type: "file" }); // none are 36-byte
    plugin.originalAdapterMethods.readBinary = vi.fn();
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    await plugin.sweepPlaceholderPaths();

    expect(warnSpy).toHaveBeenCalled();
    const firstCallMsg = String(warnSpy.mock.calls[0][0]);
    expect(firstCallMsg).toContain("sweepPlaceholderPaths");
    warnSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 1.0.30 (Fix 1 + Fix 4): resumeStoredSession warm-up retry + degraded Notice
//
// Root cause behind the 2026-05-31 Pete incident: restoreSession()'s early
// runPermissionWarmup() ran with the stale stored access token; on mobile
// (background-killed for hours = expired token), the warm-up's HTTP call
// 401'd and collectRulesForWarmup's catch returned []. PermissionStore.warm
// seeded the cache with the vault-role baseline, so every per-file lookup
// resolved to view-only. The state stuck because the only re-fire path
// runs inside restoreServerSession → refreshVaultMemberRole, and any
// earlier failure in resumeStoredSession killed the chain silently.
//
// Fix 1: re-fire runPermissionWarmup after a successful token refresh in
// resumeStoredSession AND after a restoreServerSession failure (tokens are
// fresh by then).
// Fix 4: surface the degraded state via notifySessionRestoreDegraded so
// users know to re-login if it doesn't self-heal.
// ─────────────────────────────────────────────────────────────────────────────

describe("VaultGuardPlugin resumeStoredSession — 1.0.30 Fix 1 + Fix 4", () => {
  beforeEach(() => {
    mockNotice.mockReset();
    vi.stubGlobal("localStorage", makeMemoryStorage());
  });

  function makeResumePlugin(opts: {
    tokenExpiring: boolean;
    refreshOk: boolean;
    restoreServerThrows: boolean;
  }) {
    const plugin = makePlugin();
    plugin.session = makeSession();
    plugin.runPermissionWarmup = vi.fn().mockResolvedValue(undefined);
    plugin.restoreServerSession = opts.restoreServerThrows
      ? vi.fn().mockRejectedValue(new Error("simulated openServerSession 500"))
      : vi.fn().mockResolvedValue(undefined);
    plugin.isSessionTokenExpiring = vi.fn(() => opts.tokenExpiring);
    plugin.refreshAccessToken = vi.fn().mockResolvedValue(
      opts.refreshOk
        ? { ok: true }
        : { ok: false, message: "simulated cognito timeout" }
    );
    return plugin;
  }

  it("re-fires runPermissionWarmup after a successful token refresh (Fix 1)", async () => {
    const plugin = makeResumePlugin({
      tokenExpiring: true,
      refreshOk: true,
      restoreServerThrows: false,
    });

    await plugin.resumeStoredSession();

    expect(plugin.refreshAccessToken).toHaveBeenCalledTimes(1);
    // The retry fires non-blockingly via `void`; the call itself is
    // synchronous from the assertion's perspective because the mock
    // resolves on the next microtask. Flush microtasks before asserting.
    await Promise.resolve();
    expect(plugin.runPermissionWarmup).toHaveBeenCalledTimes(1);
    expect(plugin.restoreServerSession).toHaveBeenCalledTimes(1);
    // No degraded Notice on the happy path.
    expect(mockNotice).not.toHaveBeenCalled();
  });

  it("does NOT re-fire warmup when the stored token was still fresh (Fix 1: only triggered by refresh)", async () => {
    const plugin = makeResumePlugin({
      tokenExpiring: false,
      refreshOk: true,
      restoreServerThrows: false,
    });

    await plugin.resumeStoredSession();

    expect(plugin.refreshAccessToken).not.toHaveBeenCalled();
    // Fresh tokens means the original restoreSession-time warmup landed
    // correctly — no retry needed and we don't want to double-warm.
    expect(plugin.runPermissionWarmup).not.toHaveBeenCalled();
    expect(plugin.restoreServerSession).toHaveBeenCalledTimes(1);
  });

  it("surfaces a Notice and returns when token refresh fails (Fix 4)", async () => {
    const plugin = makeResumePlugin({
      tokenExpiring: true,
      refreshOk: false,
      restoreServerThrows: false,
    });

    await plugin.resumeStoredSession();

    expect(plugin.refreshAccessToken).toHaveBeenCalledTimes(1);
    // Refresh failed → must not proceed to restoreServerSession.
    expect(plugin.restoreServerSession).not.toHaveBeenCalled();
    // Notice fires so the user knows the session is degraded.
    expect(mockNotice).toHaveBeenCalledTimes(1);
    const message = String(mockNotice.mock.calls[0][0]);
    expect(message).toContain("session refresh deferred");
    expect(message).toContain("simulated cognito timeout");
    // No warmup retry: we couldn't get a fresh token so a re-warm would
    // 401 just like the original one.
    expect(plugin.runPermissionWarmup).not.toHaveBeenCalled();
  });

  it("surfaces a Notice AND re-fires warmup when restoreServerSession throws (Fix 1 + Fix 4)", async () => {
    const plugin = makeResumePlugin({
      tokenExpiring: true,
      refreshOk: true,
      restoreServerThrows: true,
    });

    await expect(plugin.resumeStoredSession()).rejects.toThrow(
      /openServerSession 500/
    );

    expect(plugin.refreshAccessToken).toHaveBeenCalledTimes(1);
    expect(plugin.restoreServerSession).toHaveBeenCalledTimes(1);
    await Promise.resolve();
    // Two warmup fires: post-refresh (Fix 1) + post-failure (Fix 1).
    expect(plugin.runPermissionWarmup).toHaveBeenCalledTimes(2);
    // Degraded Notice — see notifySessionRestoreDegraded.
    expect(mockNotice).toHaveBeenCalledTimes(1);
    expect(String(mockNotice.mock.calls[0][0])).toContain(
      "openServerSession 500"
    );
  });

  it("throttles the degraded Notice to one per 60s window (Fix 4)", async () => {
    const plugin = makeResumePlugin({
      tokenExpiring: true,
      refreshOk: false,
      restoreServerThrows: false,
    });

    await plugin.resumeStoredSession();
    expect(mockNotice).toHaveBeenCalledTimes(1);

    // Immediate second attempt — should NOT fire another Notice.
    await plugin.resumeStoredSession();
    expect(mockNotice).toHaveBeenCalledTimes(1);

    // 61s later — Notice may fire again.
    plugin.lastSessionDegradedNoticeAt = Date.now() - 61_000;
    await plugin.resumeStoredSession();
    expect(mockNotice).toHaveBeenCalledTimes(2);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// 1.0.31 (Fix 2 + Issue A + Issue D): warmup discriminated result, retry
// scheduling, vaultMemberRole persistence, focus re-warm
// ─────────────────────────────────────────────────────────────────────────────

describe("VaultGuardPlugin runPermissionWarmup — 1.0.31 Fix 2", () => {
  beforeEach(() => {
    mockNotice.mockReset();
    vi.stubGlobal("localStorage", makeMemoryStorage());
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function makeWarmupPlugin(opts: {
    fetchOutcome: "ok" | "401" | "500" | "network";
    sessionRole?: "member" | "editor" | "admin" | "owner";
  }) {
    const plugin = makePlugin();
    plugin.session = { ...makeSession(), role: opts.sessionRole ?? "member", roles: [opts.sessionRole ?? "member"] };
    plugin.vaultMemberRole = "viewer";

    const apiClient = {
      getUserPermissions: vi.fn(async () => {
        if (opts.fetchOutcome === "ok") return [];
        if (opts.fetchOutcome === "401") {
          const err: Error & { statusCode?: number } = new Error("unauth");
          err.statusCode = 401;
          throw err;
        }
        if (opts.fetchOutcome === "500") {
          const err: Error & { statusCode?: number } = new Error("server");
          err.statusCode = 503;
          throw err;
        }
        // network error — no statusCode
        throw new Error("network blew up");
      }),
      getPermissions: vi.fn(async () => []),
    };
    plugin.apiClient = apiClient;
    plugin.isEffectiveAdmin = vi.fn(() => false);
    return { plugin, apiClient };
  }

  it("on successful fetch: store flips to warmed, retry counter resets", async () => {
    const { plugin } = makeWarmupPlugin({ fetchOutcome: "ok" });

    await plugin.runPermissionWarmup();

    expect(plugin.permissionStore.getStoreState().kind).toBe("warmed");
    expect(plugin.warmupRetryCount).toBe(0);
  });

  it("on 401 fetch failure: store flips to fetch-failed, retry scheduled with 5s backoff", async () => {
    const { plugin, apiClient } = makeWarmupPlugin({ fetchOutcome: "401" });

    await plugin.runPermissionWarmup();

    const state = plugin.permissionStore.getStoreState();
    expect(state.kind).toBe("fetch-failed");
    expect(state.statusCode).toBe(401);
    expect(plugin.warmupRetryCount).toBe(1);
    expect(plugin.warmupRetryTimer).not.toBeNull();

    // Advance 5s → retry fires.
    apiClient.getUserPermissions.mockResolvedValueOnce([]);
    await vi.advanceTimersByTimeAsync(5_000);
    // After the retry's warmup resolves, the timer is cleared and the
    // counter reset on success.
    await Promise.resolve();
    expect(plugin.permissionStore.getStoreState().kind).toBe("warmed");
    expect(plugin.warmupRetryCount).toBe(0);
  });

  it("on 5xx fetch failure: retry uses 30s backoff", async () => {
    const { plugin } = makeWarmupPlugin({ fetchOutcome: "500" });
    await plugin.runPermissionWarmup();
    expect(plugin.warmupRetryCount).toBe(1);

    // 29s isn't enough.
    await vi.advanceTimersByTimeAsync(29_000);
    expect(plugin.warmupRetryCount).toBe(1);
    // 30s lands the retry.
    await vi.advanceTimersByTimeAsync(2_000);
    expect(plugin.warmupRetryCount).toBe(2);
  });

  it("on network error (no statusCode): retry uses 60s backoff", async () => {
    const { plugin } = makeWarmupPlugin({ fetchOutcome: "network" });
    await plugin.runPermissionWarmup();
    expect(plugin.warmupRetryCount).toBe(1);

    await vi.advanceTimersByTimeAsync(59_000);
    expect(plugin.warmupRetryCount).toBe(1);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(plugin.warmupRetryCount).toBe(2);
  });

  it("retry caps at MAX_WARMUP_RETRIES (3) per session", async () => {
    const { plugin } = makeWarmupPlugin({ fetchOutcome: "401" });
    // First attempt + 3 retries = 4 total scheduling attempts; the 4th
    // attempt to schedule is the no-op.
    await plugin.runPermissionWarmup();
    expect(plugin.warmupRetryCount).toBe(1);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(plugin.warmupRetryCount).toBe(2);
    await vi.advanceTimersByTimeAsync(5_000);
    expect(plugin.warmupRetryCount).toBe(3);
    // 4th retry attempt — should be capped.
    await vi.advanceTimersByTimeAsync(5_000);
    expect(plugin.warmupRetryCount).toBe(3);
    expect(plugin.warmupRetryTimer).toBeNull();
  });

  it("maybeRewarmOnFocus resets retry state and forces a re-fire even after the cap", async () => {
    const { plugin } = makeWarmupPlugin({ fetchOutcome: "401" });
    await plugin.runPermissionWarmup();
    plugin.warmupRetryCount = 3; // simulate already capped

    // Focus signal — user-visible intent, bypasses the cap.
    plugin.maybeRewarmOnFocus();

    expect(plugin.warmupRetryCount).toBe(0);
  });
});

describe("VaultGuardPlugin vaultMemberRole persistence — 1.0.31 Issue A", () => {
  beforeEach(() => {
    mockNotice.mockReset();
    vi.stubGlobal("localStorage", makeMemoryStorage());
  });

  it("persistSession stamps current vaultMemberRole onto the protected envelope", async () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    plugin.session = makeSession();
    plugin.vaultMemberRole = "editor";
    plugin.derivedBindingId = "test-binding";

    let capturedPlaintext = "";
    plugin.protectSessionForStorage = vi.fn((session: unknown) => {
      capturedPlaintext = JSON.stringify(session);
      return { v: 1, storage: "electron-safe-storage", ciphertext: "x" };
    });
    plugin.savePluginData = vi.fn().mockResolvedValue(undefined);

    await plugin.persistSession(plugin.session);

    const parsed = JSON.parse(capturedPlaintext);
    expect(parsed.vaultMemberRole).toBe("editor");
  });

  it("materializeSession round-trips vaultMemberRole when present and absent", () => {
    const plugin = makePlugin();
    const withRole = plugin.materializeSession({
      ...makeSession(),
      vaultMemberRole: "admin",
    });
    expect(withRole?.vaultMemberRole).toBe("admin");

    const withoutRole = plugin.materializeSession({ ...makeSession() });
    expect(withoutRole?.vaultMemberRole).toBeNull();
  });
});
