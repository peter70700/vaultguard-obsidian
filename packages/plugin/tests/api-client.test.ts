import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("obsidian", () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from "obsidian";

import { AuthorizationError, VaultGuardApiClient } from "../src/api/client";

const mockRequestUrl = vi.mocked(requestUrl);

function toBase64Url(value: string): string {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makeJwt(payload: Record<string, unknown>): string {
  return [
    toBase64Url(JSON.stringify({ alg: "none", typ: "JWT" })),
    toBase64Url(JSON.stringify(payload)),
    "signature",
  ].join(".");
}

function jsonResponse(status: number, json: unknown) {
  return {
    status,
    headers: { "content-type": "application/json" },
    json,
    text: JSON.stringify(json),
  } as any;
}

function awsSignatureErrorResponse() {
  return {
    status: 403,
    headers: { "content-type": "application/xml" },
    json: null,
    text:
      "<Error><Code>InvalidArgument</Code><Message>Authorization header requires 'Credential' parameter.</Message></Error>",
  } as any;
}

describe("VaultGuardApiClient", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("falls back to a stage-prefixed API base when settings misroute on the cached base URL", async () => {
    const idToken = makeJwt({ sub: "user-123" });
    const client = new VaultGuardApiClient({
      baseUrl: "https://d1234567890.cloudfront.net",
      orgId: "org-123",
      getAuthTokens: async () => ({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken,
        expiresAt: Date.now() + 60_000,
      }),
    });

    const settingsPayload = {
      orgId: "org-123",
      orgName: "VaultGuard",
      syncMode: "periodic",
      syncIntervalMinutes: 30,
      enforceEncryption: true,
      maxSessionDurationHours: 24,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
    };

    mockRequestUrl
      .mockResolvedValueOnce(awsSignatureErrorResponse())
      .mockResolvedValueOnce(jsonResponse(200, settingsPayload))
      .mockResolvedValueOnce(jsonResponse(200, settingsPayload));

    const result = await client.getOrgSettings();

    expect(result).toEqual(settingsPayload);
    expect(mockRequestUrl).toHaveBeenCalledTimes(3);
    expect(mockRequestUrl.mock.calls.map((call) => call[0].url)).toEqual([
      "https://d1234567890.cloudfront.net/vaults",
      "https://d1234567890.cloudfront.net/dev/vaults",
      "https://d1234567890.cloudfront.net/dev/orgs/org-123/settings",
    ]);
  });

  it("surfaces a friendly message when no candidate supports the settings route", async () => {
    const idToken = makeJwt({ sub: "user-123" });
    const client = new VaultGuardApiClient({
      baseUrl: "https://d1234567890.cloudfront.net",
      orgId: "org-123",
      getAuthTokens: async () => ({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken,
        expiresAt: Date.now() + 60_000,
      }),
    });

    mockRequestUrl.mockResolvedValue(awsSignatureErrorResponse());

    let thrown: unknown;
    try {
      await client.getOrgSettings();
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(AuthorizationError);
    expect((thrown as Error).message).toContain(
      "API endpoint appears to be pointing at a website or routed page"
    );
    expect(mockRequestUrl.mock.calls.length).toBeGreaterThan(2);
  });
});

describe("VaultGuardApiClient server sessions", () => {
  const sessionEnvelope = {
    sessionId: "server-session-1",
    userId: "user-123",
    email: "user@example.com",
    roles: ["editor"],
    expiresAt: "2026-06-29T12:00:00.000Z",
    orgSettings: {
      orgId: "org-123",
      orgName: "VaultGuard",
      syncMode: "periodic",
      syncIntervalMinutes: 30,
      enforceEncryption: true,
      maxSessionDurationHours: 24,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
    },
  };

  function makeSessionClient(
    getSessionId?: () => string | null
  ): VaultGuardApiClient {
    const client = new VaultGuardApiClient({
      baseUrl: "https://api.example.com",
      orgId: "org-123",
      getAuthTokens: vi.fn(async () => ({
        accessToken: "provider-access-token",
        refreshToken: "provider-refresh-token",
        idToken: "provider-id-token",
        expiresAt: Date.now() + 60_000,
      })),
      getSessionId,
    });
    (client as any).resolvedBaseUrl = "https://api.example.com";
    return client;
  }

  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("opens authenticated server sessions with optional vault audit context", async () => {
    const client = makeSessionClient(() => "existing-session-id");
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, sessionEnvelope));

    await expect(client.openServerSession({ vaultId: "vault-abc" })).resolves.toEqual(
      sessionEnvelope
    );

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://api.example.com/auth/session",
        method: "POST",
        headers: {
          Authorization: "provider-id-token",
          "X-VaultGuard-Session-Id": "existing-session-id",
        },
        body: JSON.stringify({ vaultId: "vault-abc" }),
        contentType: "application/json",
        throw: false,
      })
    );
  });

  it("omits session header and body when neither value is configured", async () => {
    const client = makeSessionClient(() => null);
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, sessionEnvelope));

    await client.openServerSession();

    const request = mockRequestUrl.mock.calls[0]![0];
    expect(request.headers).toEqual({ Authorization: "provider-id-token" });
    expect(request.body).toBeUndefined();
    expect(request.contentType).toBeUndefined();
  });

  it("does not expose the stale production email/password login method", () => {
    const client = makeSessionClient();

    expect("login" in client).toBe(false);
    expect((client as any).login).toBeUndefined();
  });
});

// ─── Agent-bridge context propagation ──────────────────────────────────────
//
// These tests pin down the contract between the plugin's agent-bridge layer
// and the API client: when an agent-originated call is wrapped in
// `withAgentContext`, the outbound HTTP request MUST carry
// `X-VG-Agent-Name` and `X-VG-Lease-Id` headers. User-initiated calls
// outside the wrapper MUST NOT carry those headers (otherwise audit
// attribution leaks across requests).

describe("VaultGuardApiClient agent-bridge context", () => {
  function makeClient(): VaultGuardApiClient {
    const idToken = makeJwt({ sub: "user-123" });
    return new VaultGuardApiClient({
      baseUrl: "https://api.example.com",
      orgId: "org-123",
      vaultId: "vault-1",
      getAuthTokens: async () => ({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken,
        expiresAt: Date.now() + 60_000,
      }),
    });
  }

  function lastHeaders(): Record<string, string> {
    const calls = mockRequestUrl.mock.calls;
    const last = calls[calls.length - 1]?.[0] as { headers?: Record<string, string> } | undefined;
    return last?.headers ?? {};
  }

  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("(a) omits agent headers when withAgentContext is NOT active", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    await client.getFiles();

    const headers = lastHeaders();
    expect(headers["X-VG-Agent-Name"]).toBeUndefined();
    expect(headers["X-VG-Lease-Id"]).toBeUndefined();
  });

  it("(b) injects agent headers into outbound request when wrapped", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    await client.withAgentContext("Agent X", "lse_1", () => client.getFiles());

    const headers = lastHeaders();
    expect(headers["X-VG-Agent-Name"]).toBe("Agent X");
    expect(headers["X-VG-Lease-Id"]).toBe("lse_1");
  });

  it("(c) restores stack after wrapped fn returns — next call has no agent headers", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    await client.withAgentContext("Agent X", "lse_1", () => client.getFiles());
    await client.getFiles();

    const headers = lastHeaders();
    expect(headers["X-VG-Agent-Name"]).toBeUndefined();
    expect(headers["X-VG-Lease-Id"]).toBeUndefined();
  });

  it("(d) restores stack even when wrapped fn throws", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    await expect(
      client.withAgentContext("Agent X", "lse_1", async () => {
        throw new Error("boom");
      })
    ).rejects.toThrow("boom");

    // Subsequent call should be clean.
    await client.getFiles();
    const headers = lastHeaders();
    expect(headers["X-VG-Agent-Name"]).toBeUndefined();
    expect(headers["X-VG-Lease-Id"]).toBeUndefined();
  });

  it("(e) postBridgeAudit POSTs to /vaults/{vaultId}/audit/bridge with correct body", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { logged: true }));

    await client.postBridgeAudit("bridge.lease_created", null, { leaseId: "lse_1" });

    const calls = mockRequestUrl.mock.calls;
    const last = calls[calls.length - 1]?.[0] as { url: string; method: string; body?: string };
    expect(last.method).toBe("POST");
    expect(last.url).toBe("https://api.example.com/vaults/vault-1/audit/bridge");
    const parsed = JSON.parse(last.body ?? "{}");
    expect(parsed).toEqual({
      action: "bridge.lease_created",
      resourcePath: null,
      metadata: { leaseId: "lse_1" },
    });
  });

  it("(f) sanitizes agent name (strips CR/LF) and caps length at 128 chars", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    const longLeaseId = "X".repeat(200);
    await client.withAgentContext("a\nb\r\nc", longLeaseId, () => client.getFiles());

    const headers = lastHeaders();
    expect(headers["X-VG-Agent-Name"]).toBe("abc");
    expect(headers["X-VG-Lease-Id"]).toBe("X".repeat(128));
    expect(headers["X-VG-Lease-Id"]!.length).toBe(128);
  });

  it("nested withAgentContext restores outer context (LIFO stack)", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValue(jsonResponse(200, { files: [] }));

    let innerHeaders: Record<string, string> = {};
    let outerHeadersAfter: Record<string, string> = {};

    await client.withAgentContext("Outer", "lse_outer", async () => {
      await client.withAgentContext("Inner", "lse_inner", async () => {
        await client.getFiles();
        innerHeaders = { ...lastHeaders() };
      });
      await client.getFiles();
      outerHeadersAfter = { ...lastHeaders() };
    });

    expect(innerHeaders["X-VG-Agent-Name"]).toBe("Inner");
    expect(innerHeaders["X-VG-Lease-Id"]).toBe("lse_inner");
    expect(outerHeadersAfter["X-VG-Agent-Name"]).toBe("Outer");
    expect(outerHeadersAfter["X-VG-Lease-Id"]).toBe("lse_outer");
  });

  it("postBridgeAudit rejects when no vault is bound", async () => {
    const idToken = makeJwt({ sub: "user-123" });
    const client = new VaultGuardApiClient({
      baseUrl: "https://api.example.com",
      orgId: "org-123",
      // No vaultId
      getAuthTokens: async () => ({
        accessToken: "access-token",
        refreshToken: "refresh-token",
        idToken,
        expiresAt: Date.now() + 60_000,
      }),
    });

    await expect(
      client.postBridgeAudit("bridge.lease_created", null, {})
    ).rejects.toThrow(/not bound to a server vault/);
  });
});
