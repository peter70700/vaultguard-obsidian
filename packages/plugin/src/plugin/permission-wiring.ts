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
    app: ctx.app,
  });
}

export function initFilePermissionHeader(
  ctx: PermissionSurfaceContext,
): FilePermissionHeader | null {
  if (!ctx.apiClient) return null;

  const filePermissionHeader = new FilePermissionHeader({
    app: ctx.app,
    apiClient: ctx.apiClient,
    currentUserId: ctx.session?.userId ?? "",
    currentUserEmail: ctx.session?.email ?? "",
    currentUserRole: ctx.getEffectiveUiRole(),
    isAdmin: ctx.isEffectiveAdmin(),
    allowAdminPerFileRestrictions:
      ctx.orgSettings?.allowAdminPerFileRestrictions === true,
    getPermissionLevel: (path) => ctx.getEffectivePermission(path),
    isEnabled: () => ctx.isPermissionBannerEnabled(),
    onRulesChanged: () => {
      ctx.permissionStore.emit("changed", { serverConfirmed: true });
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
    apiClient: ctx.apiClient,
    currentUserId: ctx.session?.userId ?? "",
    currentUserRole: ctx.getEffectiveUiRole(),
    isReady: () => ctx.isFileExplorerDecorationDataReady(),
    getPermissionLevel: (path) => ctx.getEffectivePermission(path),
  });

  setTimeout(() => {
    ctx.syncFileExplorerDecorationsState();
  }, 1000);

  ctx.registerEvent(
    ctx.permissionStore.on("changed", (...args: unknown[]) => {
      const payload = (args[0] as { path?: string } | undefined) ?? {};
      fileExplorerDecorations.invalidate(payload.path);
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
