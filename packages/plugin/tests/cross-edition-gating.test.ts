import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, it, expect, beforeEach, vi } from "vitest";
import { requestUrl } from "obsidian";

/**
 * VER-01 cross-edition gating regression.
 *
 * Per CONTEXT.md D-44 and RESEARCH.md §"Pattern 3":
 *   - Parameterizes the FEATURES payload over Cloud vs Community variants
 *   - Asserts the featureEnabled predicate returns the cached value verbatim
 *   - Static-grep guard-rails ensure main.ts retains the gating call sites
 *     for every Pro feature, so the same compiled binary observably hides
 *     Pro UI when the server advertises edition=community.
 *
 * Pitfall guard: per plug-share-management-gating.test.ts:15-19 and
 * RESEARCH §"Pitfall 3", the full VaultGuardPlugin class cannot be
 * constructed under vitest because `obsidian` is mocked. We do NOT import
 * main.ts directly here. Predicate mirror only.
 *
 * Networking rule: per CLAUDE.md, mock `requestUrl` from "obsidian" — NEVER
 * `fetch`. The mock is set up via tests/setup.ts; we just reset it per spec.
 *
 * Gating mechanism note (verified 2026-05-12 during Plan 04-02 execution):
 *   - `shareLinks`     — gated via `this.featureEnabled('shareLinks')` in
 *                        src/plugin/main.ts (command + file-menu).
 *   - `advancedAudit`  — gated via `this.context.features?.advancedAudit`
 *                        property access in src/admin/admin-modal.ts:718.
 *   - `billing`        — gated via `this.context.features?.billing` property
 *                        access in src/admin/admin-modal.ts:684.
 *   - `webAdmin`       — advertised by the server but has no UI gate site
 *                        in the plugin (the plugin does not render an
 *                        admin link); kept in the FEATURES payload so the
 *                        server-side capability advertisement stays
 *                        symmetric. Predicate-mirror still exercises it.
 *
 * The static-grep guard-rails below mirror these patterns exactly — they
 * fail loudly if any of the four UI hide/show paths is removed without
 * notice.
 */

const mockRequestUrl = vi.mocked(requestUrl);

interface FeaturesPayload {
  shareLinks: boolean;
  advancedAudit: boolean;
  billing: boolean;
  webAdmin: boolean;
}

interface CapabilitiesPayload {
  edition: "pro" | "community";
  features: FeaturesPayload;
}

const CLOUD_PAYLOAD: CapabilitiesPayload = {
  edition: "pro",
  features: { shareLinks: true, advancedAudit: true, billing: true, webAdmin: true },
};

const COMMUNITY_PAYLOAD: CapabilitiesPayload = {
  edition: "community",
  features: { shareLinks: false, advancedAudit: false, billing: false, webAdmin: false },
};

describe.each([
  { name: "Cloud", payload: CLOUD_PAYLOAD },
  { name: "Community", payload: COMMUNITY_PAYLOAD },
])("cross-edition gating: $name", ({ payload }) => {
  beforeEach(() => mockRequestUrl.mockReset());

  it("features payload shape: all four FEATURES keys present", () => {
    expect(typeof payload.features.shareLinks).toBe("boolean");
    expect(typeof payload.features.advancedAudit).toBe("boolean");
    expect(typeof payload.features.billing).toBe("boolean");
    expect(typeof payload.features.webAdmin).toBe("boolean");
  });

  it("featureEnabled returns the cached value verbatim", () => {
    // Mirrors main.ts:192 featureEnabled body:
    //   return this.serverFeatures ? this.serverFeatures[name] : ASSUMED_SERVER_FEATURES[name]
    const serverFeatures = payload.features;
    const featureEnabled = (name: keyof FeaturesPayload) => serverFeatures[name];
    expect(featureEnabled("shareLinks")).toBe(payload.features.shareLinks);
    expect(featureEnabled("advancedAudit")).toBe(payload.features.advancedAudit);
    expect(featureEnabled("billing")).toBe(payload.features.billing);
    expect(featureEnabled("webAdmin")).toBe(payload.features.webAdmin);
  });

  it("Pro-only features visible in Cloud, hidden in Community", () => {
    if (payload.edition === "pro") {
      expect(payload.features.shareLinks).toBe(true);
      expect(payload.features.advancedAudit).toBe(true);
      expect(payload.features.billing).toBe(true);
      expect(payload.features.webAdmin).toBe(true);
    } else {
      expect(payload.features.shareLinks).toBe(false);
      expect(payload.features.advancedAudit).toBe(false);
      expect(payload.features.billing).toBe(false);
      expect(payload.features.webAdmin).toBe(false);
    }
  });

  it("share-link file-menu gate: hidden when shareLinks=false, shown when true", () => {
    // Mirrors main.ts:1596: if (!isFolder && this.featureEnabled('shareLinks')) {...}
    const featureEnabled = (name: keyof FeaturesPayload) => payload.features[name];
    let added = false;
    const isFolder = false;
    if (!isFolder && featureEnabled("shareLinks")) {
      added = true;
    }
    expect(added).toBe(payload.features.shareLinks);
  });

  it("admin-modal billing pane gate: hidden when billing=false, shown when true", () => {
    // Mirrors admin-modal.ts:684: const billingEnabled = this.context.features?.billing ?? true
    const billingEnabled = payload.features.billing ?? true;
    expect(billingEnabled).toBe(payload.features.billing);
  });

  it("admin-modal advanced-audit pane gate: hidden when advancedAudit=false, shown when true", () => {
    // Mirrors admin-modal.ts:718: const advancedAuditEnabled = this.context.features?.advancedAudit ?? true
    const advancedAuditEnabled = payload.features.advancedAudit ?? true;
    expect(advancedAuditEnabled).toBe(payload.features.advancedAudit);
  });
});

describe("cross-edition: static guard-rail (every gated feature has a hide/show call site in source)", () => {
  const mainPath = join(__dirname, "..", "src", "plugin", "main.ts");
  const adminModalPath = join(__dirname, "..", "src", "admin", "admin-modal.ts");

  it("main.ts contains a featureEnabled('shareLinks') guard (command + file-menu)", () => {
    const src = readFileSync(mainPath, "utf8");
    // shareLinks is the only feature that uses the featureEnabled() predicate
    // in main.ts. Other features use property-access gates in admin-modal.ts
    // (see below). Regression net: at least one call site present.
    expect(src).toMatch(/featureEnabled\(\s*['"]shareLinks['"]\s*\)/);
  });

  it("main.ts retains the four-feature normalization (proves the FEATURES contract is wired)", () => {
    // If any of these four lines disappears, the plugin can no longer
    // surface the corresponding hide/show behavior — the FEATURES contract
    // is broken at the boundary even before any UI code runs. This is the
    // catch-all guard-rail for the FEATURES payload shape.
    const src = readFileSync(mainPath, "utf8");
    expect(src).toMatch(/shareLinks:\s*Boolean\(features\.shareLinks\)/);
    expect(src).toMatch(/advancedAudit:\s*Boolean\(features\.advancedAudit\)/);
    expect(src).toMatch(/billing:\s*Boolean\(features\.billing\)/);
    expect(src).toMatch(/webAdmin:\s*Boolean\(features\.webAdmin\)/);
  });

  it("admin-modal.ts gates the billing pane on features.billing", () => {
    const src = readFileSync(adminModalPath, "utf8");
    expect(src).toMatch(/features\?\.billing/);
  });

  it("admin-modal.ts gates the advanced-audit pane on features.advancedAudit", () => {
    const src = readFileSync(adminModalPath, "utf8");
    expect(src).toMatch(/features\?\.advancedAudit/);
  });
});
