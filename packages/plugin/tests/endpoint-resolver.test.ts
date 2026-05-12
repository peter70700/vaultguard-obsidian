import { describe, expect, it } from "vitest";

import { normalizeVaultGuardApiBaseUrl } from "../src/api/endpoint-resolver";
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
