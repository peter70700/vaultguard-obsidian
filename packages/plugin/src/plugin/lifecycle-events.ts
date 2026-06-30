import { Notice, TFile, TFolder } from "obsidian";
import type { EventRef } from "obsidian";
import type { LifecycleEventsContext } from "./plugin-runtime-types";

function getActiveObsidianDocument(): Document | null {
  if (typeof activeDocument !== "undefined") {
    return activeDocument;
  }
  return null;
}

export function registerInviteProtocolHandler(ctx: LifecycleEventsContext): void {
  if (typeof ctx.protocolHost.registerObsidianProtocolHandler !== "function") {
    ctx.log(
      "Obsidian protocol handlers are not available in this Obsidian version; invite links can still be pasted in settings.",
    );
    return;
  }

  // Register `obsidian://vaultguard-invite?org=...&email=...` deep link
  // so invitees can click the email button and have the plugin auto-configure.
  ctx.protocolHost.registerObsidianProtocolHandler(
    "vaultguard-invite",
    async (params) => {
      try {
        await ctx.redeemInvite(params);
      } catch (err) {
        ctx.logError("Invite redemption failed", err);
      }
    },
  );
}

export function registerShareProtocolHandler(ctx: LifecycleEventsContext): void {
  if (typeof ctx.protocolHost.registerObsidianProtocolHandler !== "function") {
    return;
  }

  ctx.protocolHost.registerObsidianProtocolHandler(
    "vaultguard-share",
    async (params) => {
      try {
        await ctx.handleShareLink(params);
      } catch (err) {
        ctx.logError("Share link handling failed", err);
      }
    },
  );
}

export function registerSidebarPermissionLifecycle(ctx: LifecycleEventsContext): void {
  ctx.registerEvent(
    ctx.permissionStore.on("changed", () => {
      ctx.reloadVaultGuardSidebar();
    }),
  );
}

export function registerSidebarLayoutLifecycle(ctx: LifecycleEventsContext): void {
  ctx.app.workspace.onLayoutReady(() => {
    ctx.ensureVaultGuardSidebar();
  });
}

export function registerSessionActivityTracking(ctx: LifecycleEventsContext): void {
  const recordActivity = () => ctx.noteSessionActivity();
  const doc = getActiveObsidianDocument();

  if (doc) {
    ctx.registerDomEvent(doc, "mousedown", recordActivity);
    ctx.registerDomEvent(doc, "keydown", recordActivity);
    ctx.registerDomEvent(doc, "touchstart", recordActivity);
  }
  ctx.registerDomEvent(window, "focus", recordActivity);
}

export function registerFocusSyncHandlers(ctx: LifecycleEventsContext): void {
  const doc = getActiveObsidianDocument();

  ctx.registerDomEvent(window, "focus", () => {
    ctx.handleFocusSyncTrigger();
  });
  if (!doc) return;
  ctx.registerDomEvent(doc, "visibilitychange", () => {
    if (doc.visibilityState === "visible") {
      ctx.resumeSyncLoop("window visible");
      ctx.handleFocusSyncTrigger();
    } else {
      ctx.pauseSyncLoop("window hidden");
    }
  });
  ctx.registerDomEvent(window, "online", () => {
    ctx.handleBrowserOnline();
  });
  ctx.registerDomEvent(window, "offline", () => {
    ctx.handleBrowserOffline();
  });
  ctx.log("Focus-sync handlers registered.");
}

export function registerFolderLifecycleListeners(ctx: LifecycleEventsContext): void {
  if (ctx.folderLifecycleListenersRegistered) {
    ctx.syncDiagnostics.record("registerFolderLifecycleListeners.alreadyRegistered");
    return;
  }
  ctx.setFolderLifecycleListenersRegistered(true);
  ctx.syncDiagnostics.record("registerFolderLifecycleListeners.registered");

  ctx.registerEvent(
    ctx.app.vault.on("create", (file) => {
      if (!(file instanceof TFolder)) return;
      ctx.handleFolderCreated(file.path);
    }),
  );

  ctx.registerEvent(
    ctx.app.vault.on("delete", (file) => {
      if (!(file instanceof TFolder)) return;
      ctx.handleFolderDeleted(file.path);
    }),
  );

  ctx.registerEvent(
    ctx.app.vault.on("rename", (file, oldPath) => {
      if (!(file instanceof TFolder)) return;
      if (oldPath === file.path) return;
      ctx.handleFolderRenamed(file.path, oldPath);
    }),
  );

  // For files, vault.on('rename') is the only signal that fires when a
  // child file's path changes because its parent folder was renamed —
  // adapter.rename only fires once for the parent. Without this listener
  // every child file stays at its old key in S3 and the admin panel shows
  // duplicates after every folder rename. The DELETE old + PUT new logic
  // is idempotent with our adapter.rename interceptor for direct file
  // renames, so double-firing is harmless.
  ctx.registerEvent(
    ctx.app.vault.on("rename", (file, oldPath) => {
      if (!(file instanceof TFile)) return;
      if (oldPath === file.path) return;
      ctx.handleVaultFileRenamed(file.path, oldPath);
    }),
  );

  // Same rationale for delete: when a folder is removed, adapter.remove
  // doesn't fire for its child files (Obsidian uses adapter.rmdir under
  // the hood). The vault event is the only way to learn each child's path.
  ctx.registerEvent(
    ctx.app.vault.on("delete", (file) => {
      if (!(file instanceof TFile)) return;
      ctx.handleVaultFileDeleted(file.path);
    }),
  );

  ctx.log("Folder lifecycle listeners registered.");
}

export function registerObsidianSyncWarning(ctx: LifecycleEventsContext): void {
  renderObsidianSyncNotice(ctx);
  registerObsidianSyncListener(ctx);
}

export function renderObsidianSyncNotice(ctx: LifecycleEventsContext): void {
  try {
    // internalPlugins is not part of the public Obsidian API but is stable
    // and the only way to detect that the built-in Sync core plugin is
    // active. We narrow the unknown shape to the minimal surface we touch
    // rather than casting to `any`.
    interface InternalPluginRef {
      readonly enabled?: boolean;
      readonly _loaded?: boolean;
    }
    interface InternalPlugins {
      getPluginById?(id: string): InternalPluginRef | undefined;
    }
    const appWithInternals = ctx.app as unknown as {
      internalPlugins?: InternalPlugins;
    };
    const syncPlugin = appWithInternals.internalPlugins?.getPluginById?.("sync");
    const isSyncEnabled = !!(
      syncPlugin &&
      (syncPlugin.enabled ?? syncPlugin._loaded ?? false)
    );

    if (isSyncEnabled && !ctx.obsidianSyncNotice) {
      console.warn(
        `${ctx.logPrefix} Obsidian Sync is active. VaultGuard handles all sync and backup — ` +
          "running both will cause file conflicts. Please disable Obsidian Sync.",
      );
      ctx.setObsidianSyncNotice(
        new Notice(
          "VaultGuard Sync: Obsidian Sync is enabled. VaultGuard Sync handles all sync and " +
            "backup for this vault — please disable Obsidian Sync to prevent " +
            "file conflicts.\n\nSettings → Core plugins → Sync → Disable",
          0, // persistent until dismissed
        ),
      );
    } else if (!isSyncEnabled && ctx.obsidianSyncNotice) {
      ctx.obsidianSyncNotice.hide();
      ctx.setObsidianSyncNotice(null);
    }
  } catch {
    // Defensive: if the internal API changes, don't block plugin load
  }
}

export function registerObsidianSyncListener(ctx: LifecycleEventsContext): void {
  try {
    interface InternalPluginsEvented {
      on?(event: string, cb: () => void): EventRef;
    }
    const appWithInternals = ctx.app as unknown as {
      internalPlugins?: InternalPluginsEvented;
    };
    const internalPlugins = appWithInternals.internalPlugins;

    // Primary: react to enable/disable events. `internalPlugins.on("change", ...)`
    // fires when any core plugin is toggled, so the Notice reconciles the
    // moment the user disables Sync.
    const ref = internalPlugins?.on?.("change", () => renderObsidianSyncNotice(ctx));
    if (ref) {
      ctx.registerEvent(ref);
      return;
    }

    // Fallback: poll every 60s if the event API isn't present on this
    // Obsidian build. registerInterval scopes the timer to plugin lifetime
    // so it's auto-cleared on unload.
    // window.setInterval returns a number (what registerInterval expects);
    // this path is renderer-only, so window is always present here.
    ctx.registerInterval(
      window.setInterval(() => renderObsidianSyncNotice(ctx), 60_000),
    );
  } catch {
    // Defensive: never block plugin load
  }
}
