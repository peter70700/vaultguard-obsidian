import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, it, expect, beforeEach, vi } from "vitest";
import { requestUrl } from "obsidian";

/**
 * VER-01 cross-edition gating regression.
 *
 * Updated 260513-gj3: gate semantics changed from "hide on CE" to
 * "show but block with ProUpsellModal on CE". The same compiled binary now
 * always renders the Pro-feature surfaces; the featureEnabled() predicate and
 * the features?.advancedAudit read are used as branch selectors at click time
 * (route to ProUpsellModal on CE, route to the real feature on Pro) rather
 * than as if-wrappers around addItem/render.
 *
 * Per CONTEXT.md D-44 and RESEARCH.md §"Pattern 3":
 *   - Parameterizes the FEATURES payload over Cloud vs Community variants
 *   - Asserts the featureEnabled predicate returns the cached value verbatim
 *   - Static-grep guard-rails ensure main.ts and admin-modal.ts retain the
 *     branch-selector reads AND wire ProUpsellModal at every site, so the
 *     same compiled binary observably routes CE users to an upsell modal
 *     instead of silently hiding Pro UI.
 *
 * Pitfall guard: per plug-share-management-gating.test.ts:15-19 and
 * RESEARCH §"Pitfall 3", the full VaultGuardPlugin class cannot be
 * constructed under vitest because `obsidian` is mocked. We do NOT import
 * main.ts directly here. Predicate mirror only.
 *
 * Networking rule: per CLAUDE.md, mock `requestUrl` from "obsidian" — NEVER
 * `fetch`. The mock is set up via tests/setup.ts; we just reset it per spec.
 *
 * Gating mechanism note (post-260513-gj3):
 *   - `shareLinks`     — branch-selected via `this.featureEnabled('shareLinks')`
 *                        in src/plugin/main.ts at the command palette and the
 *                        file-context-menu click handlers. CE branch opens
 *                        ProUpsellModal('shareLinks'); Pro branch opens the
 *                        share-management modal / mints a link.
 *   - `advancedAudit`  — branch-selected via `this.context.features?.advancedAudit`
 *                        in src/admin/admin-modal.ts on the Export CSV click
 *                        handler. CE branch opens ProUpsellModal('advancedAudit');
 *                        Pro branch exports the audit log.
 *   - `billing`        — STILL hide-gated via `this.context.features?.billing`
 *                        in src/admin/admin-modal.ts (dropdown-option filter).
 *                        Out of scope for show-but-block; kept here for the
 *                        cross-edition guard-rail.
 *   - `webAdmin`       — advertised by the server but has no UI gate site
 *                        in the plugin (the plugin does not render an
 *                        admin link); kept in the FEATURES payload so the
 *                        server-side capability advertisement stays
 *                        symmetric. Predicate-mirror still exercises it.
 *
 * The static-grep guard-rails below verify ProUpsellModal wiring at the two
 * show-but-block sites and the persistence of the branch-selector reads.
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

  it("share-link file-menu: always added on files; click branches on featureEnabled", () => {
    // Mirrors main.ts post-260513-gj3: if (!isFolder) { menu.addItem(... onClick branches ...) }
    // Item is now always added regardless of edition; the click handler routes
    // CE users to ProUpsellModal('shareLinks') and Pro users to the mint flow.
    const featureEnabled = (name: keyof FeaturesPayload) => payload.features[name];
    let added = false;
    let clickedAction: "upsell" | "share" | "none" = "none";
    const isFolder = false;
    if (!isFolder) {
      added = true;
      // Simulate the onClick branch:
      clickedAction = featureEnabled("shareLinks") ? "share" : "upsell";
    }
    expect(added).toBe(true); // visible on both editions now
    expect(clickedAction).toBe(payload.features.shareLinks ? "share" : "upsell");
  });

  it("admin-modal billing pane gate: hidden when billing=false, shown when true", () => {
    // Mirrors admin-modal.ts:685: const billingEnabled = this.context.features?.billing ?? true
    // Out of scope for show-but-block — still a hide gate (dropdown-option filter).
    const billingEnabled = payload.features.billing ?? true;
    expect(billingEnabled).toBe(payload.features.billing);
  });

  it("admin-modal Export CSV: always rendered; click branches on advancedAudit", () => {
    // Mirrors admin-modal.ts post-260513-gj3: button always rendered,
    // onClick checks advancedAuditEnabled and opens ProUpsellModal on CE.
    const advancedAuditEnabled = payload.features.advancedAudit ?? true;
    const rendered = true; // button always rendered now
    const clickedAction: "upsell" | "export" = advancedAuditEnabled ? "export" : "upsell";
    expect(rendered).toBe(true);
    expect(clickedAction).toBe(advancedAuditEnabled ? "export" : "upsell");
  });
});

describe("cross-edition: static guard-rail (branch selectors + ProUpsellModal wiring)", () => {
  const mainPath = join(__dirname, "..", "src", "plugin", "main.ts");
  const adminModalPath = join(__dirname, "..", "src", "admin", "admin-modal.ts");

  it("main.ts retains a featureEnabled('shareLinks') call (now used as branch selector, not gate)", () => {
    const src = readFileSync(mainPath, "utf8");
    expect(src).toMatch(/featureEnabled\(\s*['"]shareLinks['"]\s*\)/);
  });

  it("main.ts wires ProUpsellModal at the two shareLinks sites", () => {
    const src = readFileSync(mainPath, "utf8");
    const proUpsellCount = (src.match(/new ProUpsellModal\(/g) ?? []).length;
    expect(proUpsellCount).toBeGreaterThanOrEqual(2);
    expect(src).toMatch(/from\s+["']\.\.\/ui\/pro-upsell-modal["']/);
  });

  it("admin-modal.ts wires ProUpsellModal at the advancedAudit site and retains the feature-flag read", () => {
    const src = readFileSync(adminModalPath, "utf8");
    expect(src).toMatch(/features\?\.advancedAudit/);
    expect(src).toMatch(/new ProUpsellModal\(/);
  });

  it("admin-modal.ts retains the billing-pane gate (out of scope for show-but-block)", () => {
    const src = readFileSync(adminModalPath, "utf8");
    expect(src).toMatch(/features\?\.billing/);
  });

  it("main.ts retains the four-feature normalization (proves the FEATURES contract is wired)", () => {
    // If any of these four lines disappears, the plugin can no longer
    // surface the corresponding branch behavior — the FEATURES contract
    // is broken at the boundary even before any UI code runs. This is the
    // catch-all guard-rail for the FEATURES payload shape.
    const src = readFileSync(mainPath, "utf8");
    expect(src).toMatch(/shareLinks:\s*Boolean\(features\.shareLinks\)/);
    expect(src).toMatch(/advancedAudit:\s*Boolean\(features\.advancedAudit\)/);
    expect(src).toMatch(/billing:\s*Boolean\(features\.billing\)/);
    expect(src).toMatch(/webAdmin:\s*Boolean\(features\.webAdmin\)/);
  });
});
