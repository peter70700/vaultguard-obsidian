import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Menu, Notice, requestUrl } from "obsidian";

import VaultGuardPlugin from "../src/plugin/main";
import { DEFAULT_EXCLUDED_PATHS, DEFAULT_SETTINGS, SAAS_DEFAULTS } from "../src/plugin/settings";
import { PermissionLevel } from "../src/types";

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

  it("re-enables file explorer decorations when permission indicators are turned back on", () => {
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
    };

    plugin.settings.showPermissionIndicators = true;
    plugin.refreshFileExplorerDecorations();

    expect(plugin.fileExplorerDecorations.enable).toHaveBeenCalledOnce();
    expect(plugin.fileExplorerDecorations.refresh).toHaveBeenCalledOnce();
    expect(plugin.fileExplorerDecorations.disable).not.toHaveBeenCalled();
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

  it("clears only the current vault session on logout", async () => {
    const plugin = makePlugin();
    installFakeSafeStorage();
    const session = makeSession();
    const currentEnvelope = protectSessionForTest(plugin, session);
    const otherEnvelope = protectSessionForTest(plugin, session);
    plugin.persistedSessions = {
      "test-vault-binding": currentEnvelope,
      "other-vault-binding": otherEnvelope,
    };
    plugin.saveData = vi.fn().mockResolvedValue(undefined);

    localStorage.setItem("vaultguard-session:test-vault-binding", JSON.stringify(currentEnvelope));
    localStorage.setItem("vaultguard-session:other-vault-binding", JSON.stringify(otherEnvelope));

    await plugin.clearStoredSession();

    expect(localStorage.getItem("vaultguard-session:test-vault-binding")).toBeNull();
    expect(localStorage.getItem("vaultguard-session:other-vault-binding")).toBe(
      JSON.stringify(otherEnvelope)
    );
    expect(plugin.saveData).toHaveBeenCalledWith(
      expect.objectContaining({
        storedSessions: {
          "other-vault-binding": otherEnvelope,
        },
      })
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

  it("removes server-missing local files when the user cannot upload them", async () => {
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
