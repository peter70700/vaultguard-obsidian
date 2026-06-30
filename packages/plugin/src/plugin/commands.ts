import { Notice, Platform, TFolder } from "obsidian";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import { PermissionLevel } from "../types";
import type { VaultGuardCommandContext } from "./plugin-runtime-types";

export function registerVaultGuardCommands(ctx: VaultGuardCommandContext): void {
  ctx.addCommand({
    id: "login",
    name: "Login",
    callback: () => ctx.handleLogin(),
  });

  ctx.addCommand({
    id: "logout",
    name: "Logout",
    checkCallback: (checking: boolean) => {
      if (checking) {
        return !!ctx.session;
      }
      void ctx.forceLogout();
    },
  });

  ctx.addCommand({
    id: "sync-now",
    name: "Sync now",
    callback: () => ctx.performSync({ userInitiated: true, forceCatchup: true }),
  });

  if (process.env.NODE_ENV !== "production") {
    ctx.addCommand({
      id: "vaultguard-debug-import-permission-state",
      name: "VaultGuard (debug): Show import permission state",
      callback: async () => {
        const levelName = (l: PermissionLevel | undefined): string =>
          l === undefined ? "<uncached>" : `${PermissionLevel[l] ?? "?"} (${l})`;

        const rootSeed = ctx.permissionStore.getCachedPermission("");
        const probePaths = ["test-notes-1/probe.md", "Clients/probe.md"];
        const probed: string[] = [];
        for (const p of probePaths) {
          try {
            const lvl = await ctx.getEffectivePermission(p);
            probed.push(
              `  ${p} → ${levelName(lvl)}${lvl >= PermissionLevel.WRITE ? " ✅ can create" : " ❌ create blocked"}`
            );
          } catch (err) {
            probed.push(`  ${p} → ERROR ${String(err)}`);
          }
        }

        const isAdminOwner = ctx.session?.role === "admin" || ctx.session?.role === "owner";
        const rootWriteCapable = rootSeed !== undefined && rootSeed >= PermissionLevel.WRITE;
        const report = [
          "VaultGuard import permission diagnostic (260623-dpc)",
          `session: ${ctx.session ? "present" : "NONE (not logged in)"}`,
          `session.role (org): ${ctx.session?.role ?? "—"}`,
          `session.roles: ${ctx.session?.roles?.join(", ") || "—"}`,
          `session.vaultMemberRole (per-vault): ${ctx.session?.vaultMemberRole ?? "—"}`,
          `admin/owner short-circuit: ${isAdminOwner ? "YES → every path resolves ADMIN" : "no"}`,
          `vaultLeaseDenied (limited-access): ${ctx.vaultLeaseDenied}`,
          `placeholderPaths.size: ${ctx.placeholderPathsSize}`,
          `serverVaultId: ${ctx.settings.serverVaultId ? "set" : "MISSING"}`,
          `root "" cache seed: ${levelName(rootSeed)}${rootWriteCapable ? " (write-capable baseline)" : " (NOT write-capable for new paths)"}`,
          "new-path probes (what /import-knowledge create() hits):",
          ...probed,
        ].join("\n");

        console.log(`${ctx.logPrefix} ${report}`);
        new Notice(report, 0);
      },
    });
  }

  if (process.env.NODE_ENV !== "production") {
    ctx.addCommand({
      id: "sync-diagnostics",
      name: "Copy sync diagnostics",
      callback: async () => {
        const state: Record<string, unknown> = {
          pluginVersion: ctx.manifestVersion,
          platform: Platform.isMobileApp ? "mobile" : "desktop",
          connectionStatus: ctx.connectionState.status,
          sessionPresent: !!ctx.session,
          userId: ctx.session?.userId ? ctx.session.userId.slice(0, 8) : "—",
          roles: ctx.session?.roles?.join(", ") || "—",
          vaultMemberRole: ctx.session?.vaultMemberRole ?? "—",
          serverVaultId: ctx.settings.serverVaultId || "—",
          bindingReconciledVaultId: ctx.settings.bindingReconciledVaultId ?? "—",
          orgSlug: ctx.settings.orgSlug || "—",
          folderLifecycleListenersRegistered: ctx.folderLifecycleListenersRegistered,
          syncTimerAlive: ctx.syncTimerAlive,
          syncIntervalSec: ctx.settings.syncInterval,
          keyLeasePresent: !!ctx.keyLease,
          keyLeaseExpiry: ctx.keyLease?.expiresAt ?? "—",
          vaultLeaseDenied: ctx.vaultLeaseDenied,
          lastSync: ctx.syncState.lastSync ?? "—",
          lastSyncTimestampSetting: ctx.settings.lastSyncTimestamp ?? "—",
          offlineQueueLength: ctx.offlineQueueLength,
          deletionTombstonesCount: ctx.deletionTombstonesCount,
          placeholderPathsCount: ctx.placeholderPathsSize,
        };

        const report = ctx.syncDiagnostics.buildReport(state);
        console.log(`${ctx.logPrefix} ${report}`);

        try {
          if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
            await navigator.clipboard.writeText(report);
          }
        } catch (err) {
          ctx.logError("Sync diagnostics: clipboard copy failed", err);
        }

        new Notice("VaultGuard: Sync diagnostics copied to clipboard + console.", 5000);
      },
    });
  }

  if (process.env.NODE_ENV !== "production") {
    ctx.addCommand({
      id: "diagnose-connection",
      name: "Diagnose connection (probe backend)",
      callback: async () => ctx.runConnectionDiagnostics(),
    });
  }

  ctx.addCommand({
    id: "manage-share-links",
    name: "Manage share links",
    checkCallback: (checking: boolean) => {
      const ready =
        !!ctx.session &&
        !!ctx.apiClient &&
        !!ctx.settings.serverVaultId;
      if (checking) return ready;
      if (ready) {
        if (!ctx.featureEnabled("shareLinks")) {
          new ProUpsellModal(ctx.app, "shareLinks").open();
        } else {
          ctx.openShareManagementModal();
        }
      }
    },
  });

  ctx.addCommand({
    id: "status",
    name: "Status",
    callback: () => ctx.showStatusNotice(),
  });

  ctx.addCommand({
    id: "open-menu",
    name: "Open sync menu",
    callback: () => ctx.showVaultGuardMenu(),
  });

  ctx.addCommand({
    id: "open-audit-log",
    name: "Open Audit Log",
    checkCallback: (checking: boolean) => {
      const isAdmin =
        ctx.session?.role === "admin" || ctx.session?.role === "owner";
      const ready = !!ctx.session && isAdmin && !!ctx.apiClient;
      if (checking) return ready;
      if (ready) ctx.openAuditLog();
    },
  });

  ctx.addCommand({
    id: "open-web-admin",
    name: "Open Web Admin Panel",
    checkCallback: (checking: boolean) => {
      const ready = !!ctx.session;
      if (checking) return ready;
      if (ready) ctx.openWebAdminPanel();
    },
  });

  ctx.addCommand({
    id: "open-settings",
    name: "Open settings",
    callback: () => ctx.openVaultGuardSettings(),
  });

  ctx.addCommand({
    id: "view-permissions",
    name: "View permissions",
    callback: () => ctx.showPermissionsModal(),
  });

  ctx.addCommand({
    id: "manage-permission-rules",
    name: "Manage permissions",
    callback: () => ctx.showPermissionRulesModal(),
  });

  ctx.addCommand({
    id: "files-panel",
    name: "Open files panel",
    callback: () => void ctx.activateVaultGuardSidebar(),
  });

  ctx.addCommand({
    id: "create-agent-bridge-lease",
    name: "Create agent bridge lease",
    checkCallback: (checking: boolean) => {
      if (Platform.isMobileApp) return false;
      const ready = !!ctx.session && !!ctx.settings.serverVaultId;
      if (checking) return ready;
      ctx.openAgentBridgeLeaseModal();
    },
  });

  ctx.addCommand({
    id: "revoke-agent-bridge-leases",
    name: "Revoke agent bridge leases",
    checkCallback: (checking: boolean) => {
      if (Platform.isMobileApp) return false;
      if (checking) return true;
      ctx.revokeAllAgentBridgeLeases();
      void ctx.stopAgentBridgeServer().catch((err) =>
        ctx.logError("Stopping agent bridge server failed", err)
      );
      new Notice("VaultGuard Sync: Agent bridge leases revoked.");
    },
  });

  ctx.addCommand({
    id: "vaultguard-agent-bridge-info",
    name: "VaultGuard: Agent bridge (desktop only)",
    callback: () => {
      if (Platform.isMobileApp) {
        new Notice(
          "Agent bridge requires Obsidian desktop. This feature is unavailable on mobile.",
          6000
        );
        return;
      }
      if (!ctx.session || !ctx.settings.serverVaultId) {
        new Notice(
          "Agent bridge requires Obsidian desktop. Sign in and pick a vault to mint a lease.",
          6000
        );
        return;
      }
      ctx.openAgentBridgeLeaseModal();
    },
  });

  ctx.addCommand({
    id: "check-for-updates",
    name: "Check for plugin updates",
    callback: async () => {
      if (!ctx.updateChecker) {
        new Notice("VaultGuard Sync: update checker is not initialized.");
        return;
      }
      new Notice("VaultGuard Sync: checking for updates…");
      const result = await ctx.updateChecker.checkNow();
      if (result.latest === null) {
        new Notice(
          ctx.settings.disableUpdateChecks
            ? "VaultGuard Sync: update checks are disabled in settings."
            : "VaultGuard Sync: couldn't reach the release feed. Try again later.",
          6000
        );
        return;
      }
      if (!result.isNewer) {
        new Notice(
          `VaultGuard Sync: you're on the latest version (${ctx.manifestVersion}).`,
          5000
        );
      }
    },
  });

  ctx.addCommand({
    id: "encrypt-vault-at-rest",
    name: "Encrypt vault at rest (full pass)",
    callback: () => void ctx.encryptVaultAtRest(),
  });

  ctx.addCommand({
    id: "decrypt-vault-at-rest",
    name: "Decrypt vault at rest (back to plaintext)",
    callback: () => void ctx.decryptVaultAtRest(),
  });

  ctx.addCommand({
    id: "pick-vault",
    name: "Pick or switch server vault",
    checkCallback: (checking: boolean) => {
      if (checking) {
        return !!ctx.session && !!ctx.apiClient;
      }
      void ctx.switchServerVault();
    },
  });

  ctx.addCommand({
    id: "admin",
    name: "Manage organization",
    checkCallback: (checking: boolean) => {
      const isAdmin =
        ctx.session?.role === "admin" || ctx.session?.role === "owner";
      if (checking) {
        return isAdmin;
      }
      if (isAdmin) {
        ctx.showAdminPanel();
      }
    },
  });

  ctx.registerEvent(
    ctx.onFileMenu((menu, file) => {
      if (!ctx.session || !ctx.apiClient) return;

      const isAdmin = ctx.isEffectiveAdmin();
      const path = file.path;
      const isFolder = file instanceof TFolder;
      const label = isFolder ? "folder" : "file";

      menu.addItem((item) => {
        item
          .setTitle(`VaultGuard Sync: View ${label} permissions`)
          .setIcon("shield")
          .onClick(() => {
            ctx.showPathPermissionsModal(path, isFolder);
          });
      });

      menu.addItem((item) => {
        item
          .setTitle(`VaultGuard Sync: Explain ${label} permissions`)
          .setIcon("circle-help")
          .onClick(() => {
            ctx.showPathPermissionsModal(path, isFolder, true);
          });
      });

      if (!isFolder) {
        menu.addItem((item) => {
          item
            .setTitle("VaultGuard Sync: Copy share link")
            .setIcon("link")
            .onClick(() => {
              if (!ctx.featureEnabled("shareLinks")) {
                new ProUpsellModal(ctx.app, "shareLinks").open();
                return;
              }
              void ctx.copyShareLinkForPath(path);
            });
        });
      }

      if (isAdmin) {
        menu.addItem((item) => {
          item
            .setTitle(`VaultGuard Sync: Set permissions on ${label}`)
            .setIcon("lock")
            .onClick(() => {
              ctx.showAddPermissionForPath(path, isFolder);
            });
        });
      }
    })
  );

  ctx.addCommand({
    id: "vaultguard-open-chat",
    name: "VaultGuard Chat: Open AI chat panel",
    callback: () => {
      void ctx.activateVaultGuardChat();
    },
  });

  ctx.addCommand({
    id: "vaultguard-open-permissions-graph",
    name: "VaultGuard: Open permissions graph",
    checkCallback: (checking: boolean) => {
      if (Platform.isMobileApp) return false;
      const ready = !!ctx.session && !!ctx.settings.serverVaultId;
      if (checking) return ready;
      void ctx.activatePermissionsGraph();
    },
  });

  ctx.addCommand({
    id: "vaultguard-chat-history",
    name: "VaultGuard Chat: Previous chats",
    callback: () => {
      void ctx.openVaultGuardChatHistory();
    },
  });

  ctx.addCommand({
    id: "vaultguard-chat-new-tab",
    name: "VaultGuard Chat: New chat tab",
    callback: () => {
      void ctx.openNewVaultGuardChatTab();
    },
  });

  if (process.env.NODE_ENV !== "production") {
    ctx.addCommand({
      id: "vaultguard-chat-copy-dom-debug-report",
      name: "VaultGuard Chat: Copy DOM debug report",
      callback: () => {
        void ctx.copyVaultGuardChatDomDebugReport();
      },
    });
  }

  if (process.env.NODE_ENV !== "production") {
    ctx.registerChatDebugCommand();
  }
}
