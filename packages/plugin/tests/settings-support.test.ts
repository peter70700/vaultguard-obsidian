import { readFileSync } from "node:fs";
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
      maxSessionDurationHours: 720,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
      idleAction: "lock",
    });
  });

  it("defaults idleAction to 'lock' in the fallback (260711-l2e)", () => {
    // Offline / unknown-org fallback mirrors the server default
    // (DEFAULT_ORG_SETTINGS = "lock") so an idle vault locks instead of forcing a
    // re-login. Safe offline: no PIN -> the plugin keeps the session (never logs
    // out on idle); with a PIN the lock is offline-unlockable.
    expect(buildFallbackOrgSettings("org-123").idleAction).toBe("lock");
  });

  it("renders both plaintext settings as explicit red encryption warnings", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");
    const styles = readFileSync("styles.css", "utf8");

    expect(settingsSource).toContain('.setName("Plaintext local-only vault")');
    expect(settingsSource).toContain('.setName("Detect Git repo folder")');
    expect(settingsSource).not.toContain(
      '.setName("Automatically use this mode for Git repository vaults")',
    );
    expect(
      settingsSource.match(/settingEl\.addClass\("vaultguard-plaintext-warning-setting"\)/g),
    ).toHaveLength(2);
    expect(styles).toContain(".vaultguard-plaintext-warning-setting .setting-item-name");
    expect(styles).toContain("color: var(--text-error);");
    expect(styles).toContain("border-inline-start: 3px solid var(--text-error);");
  });

  it("states the detected repository boundary without disabling cloud protections", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");

    expect(settingsSource).toContain(
      "Cloud encryption, sync, permissions, and sharing remain active.",
    );
    expect(settingsSource).toContain("refreshDetectedGitRepositoryRoots");
    expect(settingsSource).toContain("convertDetectedGitRepositoryCiphertext");
    expect(settingsSource).toContain("Git repository detection complete:");
    expect(settingsSource).toContain("Cloud protections remain active.");
  });

  it("groups both plaintext exceptions in Protection and gates Git detection off desktop", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");

    const protectionBody = settingsSource.indexOf("private renderProtectionScopeBody");
    const gitSetting = settingsSource.indexOf("this.renderGitRepositoryDetectionSetting", protectionBody);
    const wholeVaultSetting = settingsSource.indexOf("this.renderPlaintextVaultModeSetting", gitSetting);

    expect(settingsSource).toContain('this.renderCollapsibleSection(containerEl, "protection"');
    expect(gitSetting).toBeGreaterThan(protectionBody);
    expect(wholeVaultSetting).toBeGreaterThan(gitSetting);
    expect(settingsSource).toContain(".setDisabled(desktopUnavailable)");
    expect(settingsSource).toContain("the plaintext local-only vault setting currently supersedes it");
  });

  it("keeps origin's searchable single-page shell instead of the incompatible category shell", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");

    expect(settingsSource).toContain("private renderSettingsSearch");
    expect(settingsSource).toContain("private applySettingsFilter");
    expect(settingsSource).toContain("builder(bodyEl);");
    expect(settingsSource).not.toContain('from "./settings-navigation"');
    expect(settingsSource).not.toContain("activeSettingsCategory");
    expect(settingsSource).not.toContain("buildBodyOnce");
  });

  it("does not expose unimplemented security controls and describes the real reset", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");

    expect(settingsSource).not.toContain('.setName("Cache encryption strength")');
    expect(settingsSource).not.toContain('.setName("Offline key lease duration")');
    expect(settingsSource).not.toContain('.setName("Auto-wipe on auth failure")');
    expect(settingsSource).toContain('.setName("Reset local sync state")');
    expect(settingsSource).toContain("This does not delete vault files.");
    const discoverySection = settingsSource.indexOf(
      "private renderSemanticDiscoverySection",
    );
    const resultLimit = settingsSource.indexOf(
      '.setName("Default search result limit")',
      discoverySection,
    );
    const desktopBoundary = settingsSource.indexOf(
      "if (Platform.isDesktopApp !== true)",
      resultLimit,
    );
    expect(resultLimit).toBeGreaterThan(discoverySection);
    expect(desktopBoundary).toBeGreaterThan(resultLimit);
  });

  it("retains settings feedback across rerenders with timeout ownership", () => {
    const settingsSource = readFileSync("src/plugin/settings.ts", "utf8");

    expect(settingsSource).toContain("private latestSettingsStatus");
    expect(settingsSource).toContain("this.renderSettingsStatus(statusHost)");
    expect(settingsSource).toContain("this.latestSettingsStatus?.id !== status.id");
    expect(settingsSource).toContain('status.isError ? "alert" : "status"');
  });
});
