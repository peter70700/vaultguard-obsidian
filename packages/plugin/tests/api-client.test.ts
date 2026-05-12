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
