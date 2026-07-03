import { describe, expect, it } from "vitest";

import type { RequestUrlResponse } from "obsidian";

import {
  looksLikeAwsSignatureError,
  looksLikeVaultGuardApiResponse,
  normalizeVaultGuardApiBaseUrl,
} from "../src/api/endpoint-resolver";
import { SAAS_DEFAULTS } from "../src/config/saas-defaults";

describe("normalizeVaultGuardApiBaseUrl", () => {
  it("keeps a plain API base URL unchanged", () => {
    expect(normalizeVaultGuardApiBaseUrl("https://api.example.com/")).toBe(
      "https://api.example.com"
    );
  });

  it("trims pasted admin route URLs back to the CloudFront base", () => {
    expect(
      normalizeVaultGuardApiBaseUrl("https://d1234567890.cloudfront.net/settings")
    ).toBe("https://d1234567890.cloudfront.net");
  });

  it("preserves stage prefixes while trimming pasted UI routes", () => {
    expect(
      normalizeVaultGuardApiBaseUrl("https://d1234567890.cloudfront.net/dev/settings")
    ).toBe("https://d1234567890.cloudfront.net/dev");
  });

  it("trims pasted org config URLs back to the API base", () => {
    expect(
      normalizeVaultGuardApiBaseUrl(
        "https://d1234567890.cloudfront.net/dev/orgs/acme-corp/config"
      )
    ).toBe("https://d1234567890.cloudfront.net/dev");
  });

  it("trims pasted vault-scoped URLs back to the API base", () => {
    expect(
      normalizeVaultGuardApiBaseUrl(
        "https://d1234567890.cloudfront.net/dev/vaults/vault-123/permissions"
      )
    ).toBe("https://d1234567890.cloudfront.net/dev");
  });

  it("rewrites hosted URLs only when SaaS host defaults are populated", () => {
    expect(
      normalizeVaultGuardApiBaseUrl("https://admin.example.com/#/settings")
    ).toBe("https://api.example.com");

    const hostedLandingUrl = "https://example.com/pricing";
    const expectedLandingBase =
      SAAS_DEFAULTS.apiHostname &&
      SAAS_DEFAULTS.websiteHostnames.includes("example.com")
        ? `https://${SAAS_DEFAULTS.apiHostname}`
        : hostedLandingUrl;

    expect(normalizeVaultGuardApiBaseUrl(hostedLandingUrl)).toBe(expectedLandingBase);
  });

  it("rewrites self-hosted admin subdomains to matching API subdomains", () => {
    expect(normalizeVaultGuardApiBaseUrl("https://admin.example.com/settings")).toBe(
      "https://api.example.com"
    );
  });
});

describe("looksLikeAwsSignatureError", () => {
  it("does not classify generic malformed Authorization errors as endpoint misroutes", () => {
    expect(
      looksLikeAwsSignatureError(
        "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter.",
        "",
        "application/json"
      )
    ).toBe(true);

    expect(
      looksLikeAwsSignatureError(
        "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with sha-256 and encoded with base64)",
        "",
        "application/json"
      )
    ).toBe(false);
  });
});

// AC-API2: probing a candidate base must require a POSITIVE VaultGuard
// signal. API Gateway's stock JSON errors ({"message":"Forbidden"} with
// x-amzn-errortype) used to pass the old "any application/json" check,
// resolving the plugin onto a wrong stage/base.
describe("looksLikeVaultGuardApiResponse", () => {
  function makeResponse(overrides: {
    status: number;
    headers?: Record<string, string>;
    json?: unknown;
    text?: string;
  }): RequestUrlResponse {
    return {
      status: overrides.status,
      headers: overrides.headers ?? {},
      json: overrides.json,
      text: overrides.text ?? (overrides.json ? JSON.stringify(overrides.json) : ""),
      arrayBuffer: new ArrayBuffer(0),
    } as unknown as RequestUrlResponse;
  }

  it("rejects API Gateway's stock Forbidden JSON (wrong stage/base)", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 403,
          headers: {
            "content-type": "application/json",
            "x-amzn-requestid": "abc-123",
            "x-amzn-errortype": "ForbiddenException",
          },
          json: { message: "Forbidden" },
        })
      )
    ).toBe(false);
  });

  it("rejects Missing Authentication Token (wrong path on a real gateway)", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 403,
          headers: {
            "content-type": "application/json",
            "x-amzn-errortype": "MissingAuthenticationTokenException",
          },
          json: { message: "Missing Authentication Token" },
        })
      )
    ).toBe(false);
  });

  it("rejects generic JSON without any VaultGuard signal", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 200,
          headers: { "content-type": "application/json" },
          json: { hello: "world" },
        })
      )
    ).toBe(false);
  });

  it("accepts a Lambda response carrying the X-Request-Id security header", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 200,
          headers: { "content-type": "application/json", "X-Request-Id": "req-1" },
          json: { vault: {} },
        })
      )
    ).toBe(true);
    // Presence is the signal — SECURITY_HEADERS may stamp an empty value.
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 403,
          headers: { "content-type": "application/json", "x-request-id": "" },
          json: { statusCode: 403, error: "Forbidden", message: "Access denied" },
        })
      )
    ).toBe(true);
  });

  it("accepts the formatError envelope even without headers", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 401,
          headers: { "content-type": "application/json" },
          json: { statusCode: 401, error: "Unauthorized", message: "Token expired" },
        })
      )
    ).toBe(true);
  });

  it("accepts probe-route success shapes (vaults / rules arrays)", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 200,
          headers: { "content-type": "application/json" },
          json: { vaults: [] },
        })
      )
    ).toBe(true);
  });

  it("still rejects 5xx, 404, and HTML bodies", () => {
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 200,
          headers: { "content-type": "text/html" },
          text: "<html><body>welcome</body></html>",
        })
      )
    ).toBe(false);
    expect(
      looksLikeVaultGuardApiResponse(
        makeResponse({
          status: 404,
          headers: { "content-type": "application/json", "x-request-id": "req-2" },
          json: { statusCode: 404, error: "Not Found", message: "nope" },
        })
      )
    ).toBe(false);
  });
});
