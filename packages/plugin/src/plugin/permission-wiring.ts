import { FileExplorerDecorations } from "../ui/file-explorer-decorations";
import { FilePermissionHeader } from "../ui/file-permission-header";
import { PermissionStore } from "./permission-store";
import {
  type PermissionStoreFactoryContext,
  type PermissionSurfaceContext,
} from "./plugin-runtime-types";
import { ReadOnlyGuard } from "./readonly-guard";

export function createPermissionStore(ctx: PermissionStoreFactoryContext): PermissionStore {
  return new PermissionStore({
    getSession: () => ctx.getSession(),
    getVaultMemberRole: () => ctx.getVaultMemberRole(),
    isOnline: () => ctx.isOnline(),
    log: (msg) => ctx.log(msg),
    onOfflineDetected: () => ctx.setConnectionOffline(),
    fetchPermissionLevelFromServer: (path) => ctx.fetchPermissionLevelFromServer(path),
    isNetworkError: (err) => ctx.isNetworkError(err),
    // SD-03-F15 / F16: both read through the ctx arrow at CALL time, so the
    // store sees the live org policy and the live warm-cycle state rather than
    // whatever was true when this factory ran (the store is constructed during
    // onload, long before any org settings arrive).
    isAdminRestrictionActive: () => ctx.isAdminRestrictionActive(),
    requestWarmup: () => ctx.requestWarmup(),
    app: ctx.app,
  });
}

export function initFilePermissionHeader(
  ctx: PermissionSurfaceContext,
): FilePermissionHeader | null {
  if (!ctx.apiClient) return null;

  const filePermissionHeader = new FilePermissionHeader({
    app: ctx.app,
    // LIVE getter, not `ctx.apiClient` (quick-260820-mv4). The null-check
    // above is a construction gate only; this surface outlives every
    // `rebuildApiClient()` and must read the client that exists at call time,
    // or it keeps querying the vault this folder was bound to BEFORE a
    // rebind.
    getApiClient: () => ctx.apiClient,
    currentUserId: ctx.session?.userId ?? "",
    currentUserEmail: ctx.session?.email ?? "",
    currentUserRole: ctx.getEffectiveUiRole(),
    isAdmin: ctx.isEffectiveAdmin(),
    allowAdminPerFileRestrictions:
      ctx.orgSettings?.allowAdminPerFileRestrictions === true,
    getPermissionLevel: (path) => ctx.getEffectivePermission(path),
    getPermissionDecision: (path) => ctx.permissionStore.getPermissionDecision(path),
    isEnabled: () => ctx.isPermissionBannerEnabled(),
    isLoggedIn: () => ctx.session !== null,
    isOnline: () => ctx.isOnline(),
    onRetryConnection: () => ctx.reconnectNow(),
    onRulesChanged: (_path, options) => {
      ctx.permissionStore.emit("changed", {
        serverConfirmed: true,
        preserveVisibleFileRows: options?.preserveVisibleFileRows === true,
      });
    },
  });

  ctx.registerEvent(
    ctx.app.workspace.on("active-leaf-change", () => {
      filePermissionHeader.update();
    })
  );

  ctx.registerEvent(
    ctx.app.workspace.on("file-open", () => {
      filePermissionHeader.update();
    })
  );

  ctx.registerEvent(
    ctx.permissionStore.on("changed", (...args: unknown[]) => {
      const payload = (args[0] as { path?: string } | undefined) ?? {};
      filePermissionHeader.invalidateCache(payload.path);
      void filePermissionHeader.update();
    })
  );

  ctx.registerEvent(
    ctx.permissionStore.on("state-changed", () => {
      filePermissionHeader.invalidateCache();
      void filePermissionHeader.update();
    })
  );

  filePermissionHeader.update();
  return filePermissionHeader;
}

export function initReadOnlyGuard(ctx: PermissionSurfaceContext): ReadOnlyGuard {
  const readOnlyGuard = new ReadOnlyGuard({
    app: ctx.app,
    plugin: ctx.plugin,
    getPermissionLevel: (path) => ctx.getEffectivePermission(path),
    isLoggedIn: () => ctx.session !== null,
  });
  readOnlyGuard.start();

  ctx.registerEvent(
    ctx.permissionStore.on("changed", () => {
      readOnlyGuard.refreshAll();
    })
  );

  return readOnlyGuard;
}

export function initFileExplorerDecorations(
  ctx: PermissionSurfaceContext,
): FileExplorerDecorations | null {
  if (!ctx.apiClient) return null;

  const fileExplorerDecorations = new FileExplorerDecorations({
    app: ctx.app,
    // LIVE getter — same contract as the header above (quick-260820-mv4).
    getApiClient: () => ctx.apiClient,
    currentUserId: ctx.session?.userId ?? "",
    currentUserRole: ctx.getEffectiveUiRole(),
    isReady: () => ctx.isFileExplorerDecorationDataReady(),
    getPermissionStoreState: () => ctx.permissionStore.getStoreState(),
    getPermissionLevel: (path) => ctx.getEffectivePermission(path),
  });

  setTimeout(() => {
    ctx.syncFileExplorerDecorationsState();
  }, 1000);

  ctx.registerEvent(
    ctx.permissionStore.on("changed", (...args: unknown[]) => {
      const payload = (args[0] as {
        path?: string;
        preserveVisibleFileRows?: boolean;
      } | undefined) ?? {};
      fileExplorerDecorations.invalidate(payload.path, {
        preserveVisibleFileRows: payload.preserveVisibleFileRows === true,
      });
    })
  );

  ctx.registerEvent(
    ctx.permissionStore.on("state-changed", () => {
      fileExplorerDecorations.syncPermissionState();
    })
  );

  ctx.registerEvent(
    ctx.app.workspace.on("layout-change", () => {
      ctx.syncFileExplorerDecorationsState();
    })
  );
  ctx.registerEvent(
    ctx.app.workspace.on("active-leaf-change", () => {
      ctx.syncFileExplorerDecorationsState();
    })
  );

  return fileExplorerDecorations;
}
