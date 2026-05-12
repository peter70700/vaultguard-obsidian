import { describe, expect, it } from "vitest";

import {
  buildFallbackOrgSettings,
  shouldUseFallbackOrgSettings,
} from "../src/admin/settings-support";

describe("settings-support", () => {
  it("detects missing settings endpoint style errors", () => {
    expect(
      shouldUseFallbackOrgSettings(
        new Error(
          "The API endpoint appears to be pointing at a website or routed page instead of the VaultGuard REST API."
        )
      )
    ).toBe(true);
    expect(
      shouldUseFallbackOrgSettings(new Error("Missing Authentication Token"))
    ).toBe(true);
    expect(
      shouldUseFallbackOrgSettings(new Error("Internal server error"))
    ).toBe(true);
    expect(
      shouldUseFallbackOrgSettings({
        name: "ServerError",
        message: "Something blew up",
        apiError: { statusCode: 500 },
      })
    ).toBe(true);
    expect(
      shouldUseFallbackOrgSettings(new Error("Network unavailable"))
    ).toBe(false);
  });

  it("builds a readable fallback settings model", () => {
    expect(buildFallbackOrgSettings("org-123", "dropie2")).toEqual({
      orgId: "org-123",
      orgName: "Dropie2",
      syncMode: "periodic",
      syncIntervalMinutes: 1,
      enforceEncryption: true,
      maxSessionDurationHours: 24,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
    });
  });
});
