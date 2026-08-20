import { beforeEach, describe, expect, it, vi } from "vitest";

import { requestUrl } from "obsidian";

import { NetworkError, VaultGuardApiClient, VaultGuardError } from "../src/api/client";

const mockRequestUrl = vi.mocked(requestUrl);

function jsonResponse(status: number, json: unknown) {
  return {
    status,
    json,
    text: JSON.stringify(json),
    headers: {
      "content-type": "application/json",
      "content-length": String(JSON.stringify(json).length),
      "x-request-id": "req-123",
    },
  } as any;
}

function emptyResponse(status = 204) {
  return {
    status,
    json: null,
    text: "",
    headers: {
      "content-type": "application/json",
      "content-length": "0",
      "x-request-id": "req-123",
    },
  } as any;
}

function networkResponse(text = "net::ERR_INTERNET_DISCONNECTED") {
  return {
    status: 0,
    json: null,
    text,
    headers: {},
  } as any;
}

function csvResponse(csv: string) {
  return {
    status: 200,
    json: null,
    text: csv,
    arrayBuffer: new TextEncoder().encode(csv).buffer,
    headers: {
      "content-type": "text/csv",
      "content-length": String(csv.length),
      "x-request-id": "req-123",
    },
  } as any;
}

function makeClient(
  overrides: ConstructorParameters<typeof VaultGuardApiClient>[0] = {}
) {
  const client = new VaultGuardApiClient({
    baseUrl: "https://api.vaultguard.test",
    orgId: "org-123",
    vaultId: "vault-abc",
    maxRetries: 2,
    baseRetryDelayMs: 1,
    maxRetryDelayMs: 1,
    requestTimeoutMs: 1_000,
    ...overrides,
  });

  client.initialize({
    accessToken: "access-token",
    refreshToken: "refresh-token",
    idToken: "id-token",
    expiresAt: Date.now() + 5 * 60_000,
  });

  (client as any).resolvedBaseUrl = "https://api.vaultguard.test";
  return client;
}

describe("VaultGuardApiClient surface", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("maps file endpoints to the expected methods, URLs, and payloads", async () => {
    const client = makeClient();
    const fileBytes = new TextEncoder().encode("hello");

    mockRequestUrl
      .mockResolvedValueOnce(jsonResponse(200, { files: [{ path: "/docs/a.md" }] }))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          content: Buffer.from(fileBytes).toString("base64"),
        })
      )
      .mockResolvedValueOnce(jsonResponse(200, { path: "/docs/a.md", hash: "abc" }))
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(
        jsonResponse(200, [{ version: "v1", timestamp: "2026-01-01T00:00:00Z", userId: "user-1" }])
      );

    await expect(client.getFiles("/docs")).resolves.toEqual([{ path: "/docs/a.md" }]);
    await expect(client.getFile("/docs/a.md")).resolves.toEqual(
      fileBytes.buffer.slice(fileBytes.byteOffset, fileBytes.byteOffset + fileBytes.byteLength)
    );
    await expect(
      client.putFile("/docs/a.md", fileBytes.buffer, { encryptedKey: "wrapped-key" })
    ).resolves.toEqual({ path: "/docs/a.md", hash: "abc" });
    await expect(client.deleteFile("/docs/a.md")).resolves.toBeUndefined();
    await expect(client.getFileHistory("/docs/a.md")).resolves.toEqual([
      { version: "v1", timestamp: "2026-01-01T00:00:00Z", userId: "user-1" },
    ]);

    expect(mockRequestUrl.mock.calls.map((call) => [call[0].method, call[0].url])).toEqual([
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/files?prefix=%2Fdocs"],
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/files/%2Fdocs%2Fa.md"],
      ["PUT", "https://api.vaultguard.test/vaults/vault-abc/files/%2Fdocs%2Fa.md"],
      ["DELETE", "https://api.vaultguard.test/vaults/vault-abc/files/%2Fdocs%2Fa.md"],
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/files/%2Fdocs%2Fa.md/history"],
    ]);

    expect(JSON.parse(mockRequestUrl.mock.calls[2]![0].body as string)).toEqual({
      content: Buffer.from(fileBytes).toString("base64"),
      contentType: "application/octet-stream",
    });
  });

  it("uses the deleted-file read operation for a root file literally named deleted", async () => {
    const client = makeClient();
    const fileBytes = new TextEncoder().encode("root deleted");

    mockRequestUrl
      .mockResolvedValueOnce(
        jsonResponse(200, {
          content: Buffer.from(fileBytes).toString("base64"),
        })
      )
      .mockResolvedValueOnce(jsonResponse(200, { path: "/deleted", hash: "deleted-hash" }))
      .mockResolvedValueOnce(emptyResponse());

    await expect(client.getFile("deleted")).resolves.toEqual(
      fileBytes.buffer.slice(fileBytes.byteOffset, fileBytes.byteOffset + fileBytes.byteLength)
    );
    await expect(
      client.putFile("deleted", fileBytes.buffer, { encryptedKey: "wrapped-key" })
    ).resolves.toEqual({ path: "/deleted", hash: "deleted-hash" });
    await expect(client.deleteFile("deleted")).resolves.toBeUndefined();

    expect(mockRequestUrl.mock.calls.map((call) => [call[0].method, call[0].url])).toEqual([
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/files/deleted?operation=read"],
      ["PUT", "https://api.vaultguard.test/vaults/vault-abc/files/deleted"],
      ["DELETE", "https://api.vaultguard.test/vaults/vault-abc/files/deleted"],
    ]);
  });

  it("sends expectedVersionId for guarded file writes and preserves returned version metadata", async () => {
    const client = makeClient();
    const fileBytes = new TextEncoder().encode("guarded");

    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        path: "/docs/a.md",
        hash: "abc",
        versionId: "v2",
        checksum: '"etag-2"',
      })
    );

    await expect(
      client.putFile(
        "/docs/a.md",
        fileBytes.buffer,
        { encryptedKey: "wrapped-key" },
        { expectedVersionId: "v1" }
      )
    ).resolves.toMatchObject({
      path: "/docs/a.md",
      versionId: "v2",
      checksum: '"etag-2"',
    });

    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      content: Buffer.from(fileBytes).toString("base64"),
      contentType: "application/octet-stream",
      expectedVersionId: "v1",
    });
  });

  it("sends mustBeAbsent for guarded file creates and rejects mixed intent locally", async () => {
    const client = makeClient();
    const fileBytes = new TextEncoder().encode("new file");

    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        path: "/docs/new.md",
        hash: "abc",
        versionId: "v-created",
      })
    );

    await expect(
      client.putFile(
        "/docs/new.md",
        fileBytes.buffer,
        { encryptedKey: "wrapped-key" },
        { mustBeAbsent: true }
      )
    ).resolves.toMatchObject({ versionId: "v-created" });

    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      content: Buffer.from(fileBytes).toString("base64"),
      contentType: "application/octet-stream",
      mustBeAbsent: true,
    });

    await expect(
      client.putFile(
        "/docs/new.md",
        fileBytes.buffer,
        { encryptedKey: "wrapped-key" },
        { expectedVersionId: "v1", mustBeAbsent: true }
      )
    ).rejects.toThrow("mutually exclusive");
    expect(mockRequestUrl).toHaveBeenCalledTimes(1);
  });

  it("sends expectedVersionId for guarded file deletes", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(emptyResponse());

    await expect(client.deleteFile("/docs/a.md", { expectedVersionId: "v1" })).resolves.toBeUndefined();

    expect(mockRequestUrl.mock.calls[0]![0].method).toBe("DELETE");
    expect(mockRequestUrl.mock.calls[0]![0].url).toBe(
      "https://api.vaultguard.test/vaults/vault-abc/files/%2Fdocs%2Fa.md"
    );
    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      expectedVersionId: "v1",
    });
  });

  it("maps permission and user-management endpoints to the expected routes", async () => {
    const client = makeClient();
    const rule = {
      id: "rule-1",
      userId: "user-1",
      role: null,
      pathPattern: "/docs/**",
      actions: ["read"],
      effect: "allow",
      priority: 1,
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      createdBy: "admin-1",
    } as const;

    mockRequestUrl
      .mockResolvedValueOnce(jsonResponse(200, { rules: [rule] }))
      .mockResolvedValueOnce(jsonResponse(200, { rule }))
      .mockResolvedValueOnce(jsonResponse(200, { rule: { ...rule, priority: 2 } }))
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(jsonResponse(200, { rules: [rule] }))
      .mockResolvedValueOnce(jsonResponse(200, {
        path: "/docs/a.md",
        currentUserLevel: "read",
        principals: [{ userId: "user-1", level: "read" }],
      }))
      .mockResolvedValueOnce(jsonResponse(200, {
        summaries: [
          { path: "/docs/a.md", currentUserLevel: "read", principals: [] },
          { path: "/docs/b.md", currentUserLevel: "none", principals: [] },
        ],
      }))
      .mockResolvedValueOnce(
        jsonResponse(200, [
          {
            id: "user-1",
            email: "user@example.com",
            displayName: "User One",
            name: "User One",
            role: "admin",
            status: "active",
            lastActive: "2026-01-01T00:00:00Z",
            createdAt: "2026-01-01T00:00:00Z",
            mfaEnabled: true,
            deviceCount: 1,
            type: "user",
          },
        ])
      )
      .mockResolvedValueOnce(jsonResponse(200, [{ id: "role-admin", name: "admin", type: "role" }]))
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(
        jsonResponse(200, [{ timestamp: "2026-01-01T00:00:00Z", action: "file.read", resourcePath: "/docs/a.md" }])
      );

    await client.getPermissions("/docs");
    await client.createPermission({
      userId: "user-1",
      pathPattern: "/docs/**",
      actions: ["read"],
      effect: "allow",
    });
    await client.updatePermission("rule-1", { priority: 2 });
    await client.deletePermission("rule-1");
    await client.getUserPermissions("user-1");
    await client.getPathAccess("docs/a.md");
    await client.getBatchPathAccess(["docs/a.md", "docs/b.md"]);
    await client.listUsers();
    await client.listRoles();
    await client.inviteUser({
      email: "user@example.com",
      role: "viewer",
      sendWelcomeEmail: true,
      givenName: "User",
      familyName: "One",
    });
    await client.updateUserRole("user-1", "admin");
    await client.revokeUser("user-1");
    await client.reactivateUser("user-1");
    await client.resendInvitation("user-1");
    await client.getUserActivity("user-1", 25);

    expect(mockRequestUrl.mock.calls.map((call) => [call[0].method, call[0].url])).toEqual([
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/permissions?pathFilter=%2Fdocs&limit=500"],
      ["POST", "https://api.vaultguard.test/vaults/vault-abc/permissions"],
      ["PUT", "https://api.vaultguard.test/vaults/vault-abc/permissions/rule-1"],
      ["DELETE", "https://api.vaultguard.test/vaults/vault-abc/permissions/rule-1"],
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/permissions/user/user-1"],
      ["POST", "https://api.vaultguard.test/vaults/vault-abc/permissions/access"],
      ["POST", "https://api.vaultguard.test/vaults/vault-abc/permissions/access/batch"],
      ["GET", "https://api.vaultguard.test/users"],
      ["GET", "https://api.vaultguard.test/users/roles"],
      ["POST", "https://api.vaultguard.test/users/invite"],
      ["PUT", "https://api.vaultguard.test/users/user-1/role"],
      ["POST", "https://api.vaultguard.test/users/user-1/revoke"],
      ["POST", "https://api.vaultguard.test/users/user-1/reactivate"],
      ["POST", "https://api.vaultguard.test/users/user-1/resend-invite"],
      ["GET", "https://api.vaultguard.test/users/user-1/activity?limit=25"],
    ]);
    expect(JSON.parse(mockRequestUrl.mock.calls[5]![0].body as string)).toEqual({
      path: "/docs/a.md",
    });
    expect(JSON.parse(mockRequestUrl.mock.calls[6]![0].body as string)).toEqual({
      paths: ["/docs/a.md", "/docs/b.md"],
    });
    expect(JSON.parse(mockRequestUrl.mock.calls[9]![0].body as string)).toEqual({
      email: "user@example.com",
      role: "viewer",
      sendWelcomeEmail: true,
      givenName: "User",
      familyName: "One",
    });
  });

  it("forwards expiresAt in the createPermission request body for time-bound grants", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, { rule: { id: "rule-1" } }));

    const expiresAt = "2026-12-31T23:59:59.000Z";
    await client.createPermission({
      userId: "grantee-1",
      role: null,
      pathPattern: "/docs/**",
      actions: ["read", "write", "list"],
      effect: "allow",
      expiresAt,
      upsert: true,
    });

    expect(mockRequestUrl.mock.calls[0]![0].url).toBe(
      "https://api.vaultguard.test/vaults/vault-abc/permissions"
    );
    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toMatchObject({
      userId: "grantee-1",
      pathPattern: "/docs/**",
      effect: "allow",
      expiresAt,
      upsert: true,
    });
  });

  it("forwards priority in the setPermissionLevel request body", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, {
      decision: "create",
      level: "read",
      inheritedLevel: "write",
      rule: null,
    }));

    await client.setPermissionLevel({
      userId: "user-1",
      pathPattern: "/docs/a.md",
      level: "read",
      priority: 77,
    });

    expect(mockRequestUrl.mock.calls[0]![0].url).toBe(
      "https://api.vaultguard.test/vaults/vault-abc/permissions"
    );
    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toMatchObject({
      userId: "user-1",
      pathPattern: "/docs/a.md",
      level: "read",
      priority: 77,
    });
  });

  it("maps audit, org settings, and recovery endpoints correctly", async () => {
    const client = makeClient();

    mockRequestUrl
      .mockResolvedValueOnce(
        jsonResponse(200, {
          entries: [{ id: "audit-1", action: "file.read" }],
          count: 1,
          nextCursor: "cursor-2",
        })
      )
      .mockResolvedValueOnce(csvResponse("timestamp,action\n2026-01-01,file.read\n"))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          orgId: "org-123",
          orgName: "VaultGuard",
          syncMode: "periodic",
          syncIntervalMinutes: 30,
          enforceEncryption: true,
          maxSessionDurationHours: 24,
          requireMfa: true,
          allowedDomains: ["example.com"],
          retentionDays: 365,
          autoLockMinutes: 30,
        })
      )
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(emptyResponse())
      .mockResolvedValueOnce(jsonResponse(200, { jobId: "job-1" }))
      .mockResolvedValueOnce(jsonResponse(200, { job: { id: "job-1", status: "running" } }))
      .mockResolvedValueOnce(jsonResponse(200, { wrappedUMK_org: "wrapped-key" }));

    await expect(
      client.getAuditLogPage({
        search: "alice",
        action: "file.read",
        dateFrom: "2026-01-01",
        dateTo: "2026-01-31",
        cursor: "cursor-1",
        limit: 25,
      })
    ).resolves.toEqual({
      entries: [{ id: "audit-1", action: "file.read" }],
      count: 1,
      nextCursor: "cursor-2",
      lastEvaluatedKey: null,
    });

    const blob = await client.exportAuditLogCsv({
      search: "alice",
      action: "file.read",
      dateFrom: "2026-01-01",
      dateTo: "2026-01-31",
      outcome: "success",
    });

    await expect(blob.text()).resolves.toBe("timestamp,action\n2026-01-01,file.read\n");
    await client.getOrgSettings();
    await client.updateOrgSettings({ requireMfa: false });
    await client.resetOrgSettings();
    await client.triggerReEncryption("user-2");
    await client.getReEncryptionJobStatus("job-1");
    await client.recoverUserKey("user-2");

    expect(mockRequestUrl.mock.calls.map((call) => [call[0].method, call[0].url])).toEqual([
      [
        "GET",
        "https://api.vaultguard.test/vaults/vault-abc/audit?search=alice&action=file.read&startDate=2026-01-01&endDate=2026-01-31&cursor=cursor-1&limit=25",
      ],
      ["POST", "https://api.vaultguard.test/vaults/vault-abc/audit/export"],
      ["GET", "https://api.vaultguard.test/orgs/org-123/settings"],
      ["PUT", "https://api.vaultguard.test/orgs/org-123/settings"],
      ["DELETE", "https://api.vaultguard.test/orgs/org-123/settings"],
      ["POST", "https://api.vaultguard.test/re-encryption/trigger"],
      ["GET", "https://api.vaultguard.test/re-encryption/job-1"],
      ["POST", "https://api.vaultguard.test/auth/recover"],
    ]);
  });

  it("refreshes auth tokens after a 401 and retries the request with the new ID token", async () => {
    const getAuthTokens = vi
      .fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        accessToken: "new-access-token",
        refreshToken: "refresh-token",
        idToken: "new-id-token",
        expiresAt: Date.now() + 5 * 60_000,
      });

    const client = makeClient({ getAuthTokens });

    mockRequestUrl
      .mockResolvedValueOnce(
        jsonResponse(401, {
          statusCode: 401,
          code: "TOKEN_EXPIRED",
          message: "Expired",
        })
      )
      .mockResolvedValueOnce(jsonResponse(200, { files: [{ path: "/docs/retried.md" }] }));

    await expect(client.getFiles()).resolves.toEqual([{ path: "/docs/retried.md" }]);

    expect(getAuthTokens).toHaveBeenNthCalledWith(1, false);
    expect(getAuthTokens).toHaveBeenNthCalledWith(2, true);
    expect(mockRequestUrl.mock.calls[1]![0].headers).toEqual({
      Authorization: "new-id-token",
    });
  });

  it("maps share endpoints to the expected methods, URLs, and payloads", async () => {
    const client = makeClient();

    mockRequestUrl
      .mockResolvedValueOnce(
        jsonResponse(201, {
          share: {
            shareId: "abc123",
            vaultId: "vault-abc",
            relPath: "Notes/Welcome.md",
            createdAt: "2026-04-01T00:00:00.000Z",
            createdBy: "user-1",
          },
          url: "https://share.vaultguard.test/s/abc123?v=vault-abc",
        })
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          shares: [
            {
              shareId: "abc123",
              vaultId: "vault-abc",
              relPath: "Notes/Welcome.md",
              createdAt: "2026-04-01T00:00:00.000Z",
              createdBy: "user-1",
              url: "https://share.vaultguard.test/s/abc123?v=vault-abc",
            },
          ],
          count: 1,
        })
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          shareId: "abc123",
          vaultId: "vault-abc",
          vaultName: "Engineering",
          vaultSlug: "engineering",
          relPath: "Notes/Welcome.md",
          createdBy: "user-1",
          createdAt: "2026-04-01T00:00:00.000Z",
          expiresAt: null,
        })
      )
      .mockResolvedValueOnce(emptyResponse());

    const created = await client.createShare({ relPath: "Notes/Welcome.md" });
    expect(created.url).toBe("https://share.vaultguard.test/s/abc123?v=vault-abc");
    expect(created.shareId).toBe("abc123");

    const list = await client.listShares();
    expect(list).toHaveLength(1);

    const resolved = await client.resolveShare("vault-abc", "abc123");
    expect(resolved.relPath).toBe("Notes/Welcome.md");

    await client.revokeShare("abc123");

    expect(mockRequestUrl.mock.calls.map((call) => [call[0].method, call[0].url])).toEqual([
      ["POST", "https://api.vaultguard.test/vaults/vault-abc/shares"],
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/shares"],
      ["GET", "https://api.vaultguard.test/vaults/vault-abc/shares/abc123"],
      ["DELETE", "https://api.vaultguard.test/vaults/vault-abc/shares/abc123"],
    ]);
  });

  it("threads share-list limit/cursor options and preserves the next opaque cursor", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        shares: [{
          shareId: "older-share",
          vaultId: "vault-abc",
          relPath: "Archive/old.md",
          createdAt: "2025-01-01T00:00:00.000Z",
          createdBy: "user-1",
          url: "https://share.vaultguard.test/s/older-share?v=vault-abc",
        }],
        count: 1,
        nextCursor: "next-cursor-token",
        hasMore: true,
      }),
    );

    const page = await client.listSharesPage({ limit: 25, cursor: "current+cursor" });

    expect(page).toMatchObject({ count: 1, nextCursor: "next-cursor-token", hasMore: true });
    expect(page.shares[0].shareId).toBe("older-share");
    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "GET",
        url:
          "https://api.vaultguard.test/vaults/vault-abc/shares?limit=25&cursor=current%2Bcursor",
      }),
    );
  });

  it("flushes queued requests when the client comes back online", async () => {
    const client = makeClient();

    (client as any).setConnectionStatus("offline");
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, { ok: true }));

    const queued = client.queueRequest("POST", "/permissions", { pathPattern: "/docs/**" });
    (client as any).setConnectionStatus("online");

    await expect(queued).resolves.toEqual({ ok: true });
    expect(client.getQueueSize()).toBe(0);
    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        method: "POST",
        url: "https://api.vaultguard.test/permissions",
        body: JSON.stringify({ pathPattern: "/docs/**" }),
      })
    );
  });

  it("sends selected-vault guest fields and returns explicit provisioning status", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(201, {
      message: "Guest invited",
      userId: "guest-1",
      role: "viewer",
      accessKind: "guest",
      vaultIds: ["vault-abc"],
      expiresAt: "2026-08-13T12:00:00.000Z",
      provisioningStatus: "partial",
      vaultsJoined: 0,
      vaultProvisioningFailures: 1,
    }));

    const result = await client.inviteUser({
      email: "guest@example.com",
      role: "viewer",
      accessKind: "guest",
      vaultIds: ["vault-abc"],
      expiresInDays: 30,
      sendWelcomeEmail: true,
    });

    expect(result).toMatchObject({
      accessKind: "guest",
      provisioningStatus: "partial",
      vaultProvisioningFailures: 1,
    });
    expect(mockRequestUrl).toHaveBeenCalledWith(expect.objectContaining({
      method: "POST",
      url: "https://api.vaultguard.test/users/invite",
      body: JSON.stringify({
        email: "guest@example.com",
        role: "viewer",
        accessKind: "guest",
        vaultIds: ["vault-abc"],
        expiresInDays: 30,
        sendWelcomeEmail: true,
      }),
    }));
  });

  // ─── extendGuestAccess (DR-6) ─────────────────────────────────────────
  //
  // The extend rides the SAME `PATCH /vaults/{vaultId}/members/{userId}`
  // resource the membership update has always used. The server reads the two
  // mutations apart by which field arrives, so the single most important thing
  // these cases pin is the SHAPE of the body: `expiresInDays` alone. A payload
  // that also carried the membership's other mutable field would be a 400.

  it("extends a temporary member through the existing vault-scoped member resource", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, {
      membership: {
        vaultId: "vault-abc",
        userId: "user-guest",
        role: "viewer",
        joinedAt: "2026-08-01T09:00:00.000Z",
        invitedBy: "user-admin",
        accessKind: "guest",
        expiresAt: "2026-09-18T12:00:00.000Z",
      },
      permissionRuleUpdated: true,
    }));

    const result = await client.extendGuestAccess("vault-abc", "user-guest", 30);

    expect(result.membership.expiresAt).toBe("2026-09-18T12:00:00.000Z");
    expect(result.permissionRuleUpdated).toBe(true);

    const call = mockRequestUrl.mock.calls[0]![0];
    expect(call.method).toBe("PATCH");
    expect(call.url).toContain("/vaults/vault-abc/members/user-guest");

    // Exactly one key. Asserted with toEqual rather than toMatchObject so an
    // extra field cannot pass, and re-asserted by name because sending the
    // membership's other mutable field alongside the duration is the specific
    // request the server rejects with a 400.
    const body = JSON.parse(call.body as string);
    expect(body).toEqual({ expiresInDays: 30 });
    expect(Object.keys(body)).not.toContain("role");
  });

  it("reports the server's permission-rule half-state instead of hiding it", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, {
      membership: {
        vaultId: "vault-abc",
        userId: "user-guest",
        role: "viewer",
        joinedAt: "2026-08-01T09:00:00.000Z",
        invitedBy: "user-admin",
        accessKind: "guest",
        expiresAt: "2026-09-18T12:00:00.000Z",
      },
      permissionRuleUpdated: false,
    }));

    // The server moved the row but found no rule to move with it, and
    // deliberately did not mint one. That is a member inside the vault with
    // nothing to read through, so the flag has to reach the caller.
    await expect(client.extendGuestAccess("vault-abc", "user-guest", 7))
      .resolves.toMatchObject({ permissionRuleUpdated: false });
  });

  it("surfaces the extend 409 as the client's normal error type", async () => {
    const client = makeClient();
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(409, {
      message: "Only temporary access carries an expiry date.",
      code: "conflict",
    }));

    await expect(client.extendGuestAccess("vault-abc", "user-permanent", 30))
      .rejects.toBeInstanceOf(VaultGuardError);
  });

  it("refuses to extend when the client is bound to no server vault", async () => {
    // The vault-scoping rule, at the one place it can still be broken: an
    // unbound client whose empty vault id would otherwise interpolate into
    // `/vaults//members/...` — a vault-unscoped call wearing a vault-scoped
    // shape. The guard has to fire BEFORE the request, so nothing is sent.
    const client = makeClient({ vaultId: "" });

    expect(client.getVaultId()).toBe("");
    await expect(client.extendGuestAccess(client.getVaultId(), "user-guest", 30))
      .rejects.toThrow(/not bound to a server vault/);
    expect(mockRequestUrl).not.toHaveBeenCalled();
  });

  it("rejects a non-whole-day extension locally without calling the server", async () => {
    const client = makeClient();

    await expect(client.extendGuestAccess("vault-abc", "user-guest", 2.5))
      .rejects.toThrow(/whole number of days/);
    await expect(client.extendGuestAccess("vault-abc", "user-guest", 0))
      .rejects.toThrow(/whole number of days/);
    expect(mockRequestUrl).not.toHaveBeenCalled();

    // Deliberately NOT asserted here: an upper bound. 1-90 is the server's to
    // enforce in `guestAccessExpiresAt`; a second copy in the client would be
    // free to drift away from the one the invite path applies.
  });

  it("retries status-0 network responses before marking the client offline", async () => {
    const client = makeClient({ maxRetries: 1 });
    const statuses: string[] = [];
    client.onConnectionStatusChange((status) => statuses.push(status));
    mockRequestUrl.mockResolvedValue(networkResponse());

    await expect(client.listVaults()).rejects.toBeInstanceOf(NetworkError);

    expect(mockRequestUrl).toHaveBeenCalledTimes(2);
    expect(client.getConnectionStatus()).toBe("offline");
    expect(statuses).toContain("offline");
  });

  it("health checks downgrade an authenticated client on network loss", async () => {
    const client = makeClient();
    mockRequestUrl.mockRejectedValueOnce(new Error("net::ERR_NETWORK_CHANGED"));

    await (client as any).checkHealth();

    expect(client.getConnectionStatus()).toBe("offline");
  });
});
