import { beforeEach, describe, expect, it, vi } from "vitest";

import { Menu, Notice, requestUrl } from "obsidian";

import VaultGuardPlugin from "../src/plugin/main";
import { DEFAULT_EXCLUDED_PATHS, DEFAULT_SETTINGS } from "../src/plugin/settings";

const mockNotice = vi.mocked(Notice);
const mockRequestUrl = vi.mocked(requestUrl);

function makePlugin() {
  const plugin = new VaultGuardPlugin() as any;

  plugin.app = {
    appId: "test-app-id",
    vault: {
      adapter: {
        getBasePath: () => "/Users/test/VaultGuard Test Vault",
      },
      getName: () => "VaultGuard Test Vault",
    },
    workspace: {
      on: vi.fn(() => ({ unload: vi.fn() })),
      getLeavesOfType: vi.fn(() => []),
    },
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
  return globalThis.window as unknown as Record<string, unknown>;
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

  it("marks the plugin offline when an API request exhausts network retries", async () => {
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
    expect(
      mockNotice.mock.calls.some(([message]) =>
        String(message).includes("Connection lost")
      )
    ).toBe(true);
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

    await plugin.addCurrentVaultMember("user-2", "viewer");
    await plugin.updateCurrentVaultMember("user-2", "editor");
    await plugin.removeCurrentVaultMember("user-2");

    expect(plugin.permissionCache.size).toBe(0);
    expect(plugin.readOnlyGuard.refreshAll).toHaveBeenCalledTimes(3);
    expect(plugin.fileExplorerDecorations.invalidate).toHaveBeenCalledTimes(3);
    expect(plugin.filePermissionHeader.invalidateCache).toHaveBeenCalledTimes(3);
    expect(plugin.filePermissionHeader.update).toHaveBeenCalledTimes(3);
    expect(plugin.filePermissionHeader.update).toHaveBeenCalledWith({ force: true });
  });

  it("re-enables file explorer decorations when permission indicators are turned back on", () => {
    const plugin = makePlugin();
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
    expect(plugin.filePermissionHeader.setContext).toHaveBeenCalledWith({
      currentUserId: "user-1",
      currentUserRole: "admin",
      isAdmin: true,
    });
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
    expect(plugin.filePermissionHeader.setContext).toHaveBeenCalledWith({
      currentUserId: "user-1",
      currentUserRole: "viewer",
      isAdmin: false,
    });
    expect(plugin.fileExplorerDecorations.setConfig).toHaveBeenCalledWith({
      currentUserId: "user-1",
      currentUserRole: "viewer",
    });
  });

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
