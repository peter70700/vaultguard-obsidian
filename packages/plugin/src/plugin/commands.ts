import { Notice, Platform, TFolder } from "obsidian";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import { PermissionLevel } from "../types";
import type { VaultGuardCommandContext } from "./plugin-runtime-types";

/**
 * The sync engine's text/binary split is CONTENT-based, not extension-based:
 * readTextForSync strict-UTF-8-decodes the bytes and anything lossy is
 * skipped as binary (AR1). A debug report only sees metadata, so it
 * approximates with a deny-list of definitely-binary attachment formats —
 * a queued WRITE with one of these extensions can only mean binary content
 * entered the string pipeline, which is the AR1 regression signal. Text-ish
 * extensions we don't enumerate (.base, .yml, …) are legitimately queueable.
 */
const KNOWN_BINARY_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "ico",
  "pdf", "zip", "7z", "gz", "tar",
  "mp3", "wav", "ogg", "m4a", "flac",
  "mp4", "mov", "mkv", "webm",
  "woff", "woff2", "ttf", "otf",
]);

const SESSION_BINDING_KEY_MARKER = "vaultguard-session:";

/**
 * Debug-command output contract: every report goes to the console AND the
 * clipboard (so it can be pasted straight into a bug report / chat), with a
 * short Notice confirming the copy. Reports must contain metadata only —
 * never note plaintext, tokens, or key material.
 */
export async function copyDebugReport(
  ctx: Pick<VaultGuardCommandContext, "logPrefix" | "logError">,
  title: string,
  report: string
): Promise<void> {
  console.log(`${ctx.logPrefix} ${report}`);
  let copied = false;
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(report);
      copied = true;
    }
  } catch (err) {
    ctx.logError(`${title}: clipboard copy failed`, err);
  }
  new Notice(
    copied
      ? `VaultGuard debug: ${title} copied to clipboard.`
      : `VaultGuard debug: ${title} logged to console (clipboard unavailable).`,
    5000
  );
}

/** SY5 verification: offline-queue contents (metadata only) + envelope files on disk. */
export async function buildOfflineQueueDebugReport(ctx: VaultGuardCommandContext): Promise<string> {
  const pluginDir = `${ctx.app.vault.configDir}/plugins/${ctx.pluginId}`;
  const queue = ctx.offlineQueueSnapshot;
  const lines: string[] = [
    "VaultGuard offline-queue & envelope diagnostic",
    `connectionStatus: ${ctx.connectionState.status}`,
    `vaultLeaseDenied (limited-access): ${ctx.vaultLeaseDenied}`,
    `deletionTombstones: ${ctx.deletionTombstonesCount}`,
    `offlineQueue entries: ${queue.length}`,
  ];
  for (const entry of queue.slice(0, 50)) {
    lines.push(
      `  [${entry.operation}] ${entry.path} — ${entry.dataBytes} bytes (plaintext withheld), queued ${entry.timestamp}`
    );
  }
  if (queue.length > 50) {
    lines.push(`  … ${queue.length - 50} more entries`);
  }
  lines.push(`envelope files under ${pluginDir}:`);
  for (const name of ["offline-queue.envelope", "lak.envelope", "agent-leases.envelope", "data.json"]) {
    try {
      const stat = await ctx.app.vault.adapter.stat(`${pluginDir}/${name}`);
      lines.push(
        stat
          ? `  ${name}: ${stat.size} bytes, mtime ${new Date(stat.mtime).toISOString()}`
          : `  ${name}: absent`
      );
    } catch (err) {
      lines.push(`  ${name}: stat failed — ${String(err)}`);
    }
  }
  return lines.join("\n");
}

/** PL4/PL6 verification: session, token expiry, lease, and stored session bindings. */
export function buildAuthStateDebugReport(ctx: VaultGuardCommandContext): string {
  const s = ctx.session;
  let bindingsLine = "stored session bindings: localStorage unavailable";
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      const bindingIds: string[] = [];
      for (let i = 0; i < window.localStorage.length; i++) {
        const key = window.localStorage.key(i);
        const markerIndex = key?.indexOf(SESSION_BINDING_KEY_MARKER) ?? -1;
        if (key && markerIndex >= 0) {
          bindingIds.push(key.slice(markerIndex + SESSION_BINDING_KEY_MARKER.length).slice(0, 12));
        }
      }
      bindingsLine = `stored session bindings: ${bindingIds.length}${
        bindingIds.length > 0 ? ` (${bindingIds.join(", ")}…)` : " (none — clean logout state)"
      }`;
    }
  } catch {
    /* keep the unavailable line */
  }
  return [
    "VaultGuard session & auth diagnostic",
    `session: ${s ? "present" : "NONE (logged out)"}`,
    `userId: ${s?.userId ? s.userId.slice(0, 8) : "—"}`,
    `org role: ${s?.role ?? "—"} | roles: ${s?.roles?.join(", ") || "—"} | vaultMemberRole (live): ${
      ctx.vaultMemberRole ?? s?.vaultMemberRole ?? "— (no membership row; org role governs)"
    }`,
    `accessToken expires: ${s?.tokenExpiresAt ?? "—"} (expiring soon: ${ctx.isSessionTokenExpiring()})`,
    `keyLease: ${ctx.keyLease ? `present, expires ${ctx.keyLease.expiresAt}` : "none"}`,
    `vaultLeaseDenied (limited-access): ${ctx.vaultLeaseDenied}`,
    `connectionStatus: ${ctx.connectionState.status}`,
    `serverVaultId: ${ctx.settings.serverVaultId ? "set" : "MISSING"} | orgSlug: ${ctx.settings.orgSlug || "—"}`,
    bindingsLine,
  ].join("\n");
}

/** AR1 verification: attachment inventory + proof no binary WRITE rides the string offline queue. */
export function buildAttachmentDebugReport(ctx: VaultGuardCommandContext): string {
  const files = ctx.app.vault.getFiles();
  const extCounts = new Map<string, number>();
  const attachments: { path: string; size: number; mtime: number }[] = [];
  for (const file of files) {
    const ext = (file.extension || "").toLowerCase();
    extCounts.set(ext, (extCounts.get(ext) ?? 0) + 1);
    if (KNOWN_BINARY_EXTENSIONS.has(ext)) {
      attachments.push({ path: file.path, size: file.stat.size, mtime: file.stat.mtime });
    }
  }
  const histogram = [...extCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([ext, count]) => `${ext || "<none>"}:${count}`)
    .join(" ");
  const queuedBinaryWrites = ctx.offlineQueueSnapshot.filter((entry) => {
    if (entry.operation !== "write") {
      return false;
    }
    const ext = entry.path.split(".").pop()?.toLowerCase() ?? "";
    return KNOWN_BINARY_EXTENSIONS.has(ext);
  });
  const lines: string[] = [
    "VaultGuard attachment & binary-sync diagnostic",
    "(engine text/binary split is content-based strict UTF-8; this report deny-lists known binary formats)",
    `files total: ${files.length} (${histogram})`,
    `binary attachments (known binary extensions): ${attachments.length}`,
  ];
  for (const bin of attachments.slice(0, 15)) {
    lines.push(`  ${bin.path} — ${bin.size} bytes, mtime ${new Date(bin.mtime).toISOString()}`);
  }
  if (attachments.length > 15) {
    lines.push(`  … ${attachments.length - 15} more`);
  }
  lines.push(
    queuedBinaryWrites.length === 0
      ? "queued binary WRITEs in offline queue: 0 ✅ (binaries stay off the string pipeline)"
      : `queued binary WRITEs in offline queue: ${queuedBinaryWrites.length} ⚠️ AR1 REGRESSION — ${queuedBinaryWrites
          .map((entry) => entry.path)
          .join(", ")}`
  );
  return lines.join("\n");
}

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
          `vaultMemberRole (live): ${ctx.vaultMemberRole ?? "—"} | session snapshot: ${ctx.session?.vaultMemberRole ?? "—"}`,
          `admin/owner short-circuit: ${isAdminOwner ? "YES → every path resolves ADMIN" : "no"}`,
          `vaultLeaseDenied (limited-access): ${ctx.vaultLeaseDenied}`,
          `placeholderPaths.size: ${ctx.placeholderPathsSize}`,
          `serverVaultId: ${ctx.settings.serverVaultId ? "set" : "MISSING"}`,
          `root "" cache seed: ${levelName(rootSeed)}${rootWriteCapable ? " (write-capable baseline)" : " (NOT write-capable for new paths)"}`,
          "new-path probes (what /import-knowledge create() hits):",
          ...probed,
        ].join("\n");

        await copyDebugReport(ctx, "import permission state", report);
        new Notice(report, 0);
      },
    });
  }

  if (process.env.NODE_ENV !== "production") {
    ctx.addCommand({
      id: "sync-diagnostics",
      name: "VaultGuard (debug): Copy sync diagnostics",
      callback: async () => {
        const state: Record<string, unknown> = {
          pluginVersion: ctx.manifestVersion,
          platform: Platform.isMobileApp ? "mobile" : "desktop",
          connectionStatus: ctx.connectionState.status,
          sessionPresent: !!ctx.session,
          userId: ctx.session?.userId ? ctx.session.userId.slice(0, 8) : "—",
          roles: ctx.session?.roles?.join(", ") || "—",
          vaultMemberRole: ctx.vaultMemberRole ?? ctx.session?.vaultMemberRole ?? "—",
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
      name: "VaultGuard (debug): Diagnose connection (probe backend)",
      callback: async () => ctx.runConnectionDiagnostics(),
    });

    ctx.addCommand({
      id: "vaultguard-debug-offline-queue",
      name: "VaultGuard (debug): Copy offline-queue & envelope state",
      callback: async () => {
        await copyDebugReport(
          ctx,
          "offline-queue & envelope state",
          await buildOfflineQueueDebugReport(ctx)
        );
      },
    });

    ctx.addCommand({
      id: "vaultguard-debug-auth-state",
      name: "VaultGuard (debug): Copy session & auth state",
      callback: async () => {
        await copyDebugReport(ctx, "session & auth state", buildAuthStateDebugReport(ctx));
      },
    });

    ctx.addCommand({
      id: "vaultguard-debug-attachments",
      name: "VaultGuard (debug): Copy attachment & binary-sync state",
      callback: async () => {
        await copyDebugReport(
          ctx,
          "attachment & binary-sync state",
          buildAttachmentDebugReport(ctx)
        );
      },
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
      name: "VaultGuard (debug): Copy chat DOM report",
      callback: () => {
        void ctx.copyVaultGuardChatDomDebugReport();
      },
    });
  }

  if (process.env.NODE_ENV !== "production") {
    ctx.registerChatDebugCommand();
  }
}
