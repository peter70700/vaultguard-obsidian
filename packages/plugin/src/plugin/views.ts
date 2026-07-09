import { Notice, Platform, addIcon } from "obsidian";
import { VaultGuardChatView, VAULTGUARD_CHAT_VIEW_TYPE } from "../ui/chat/chat-view";
import {
  PermissionsGraphView,
  VAULTGUARD_GRAPH_VIEW_TYPE,
} from "../ui/graph/permissions-graph-view";
import { VaultGuardSidebarView, VAULTGUARD_VIEW_TYPE } from "../ui/vaultguard-sidebar-view";
import {
  VAULTGUARD_CHAT_ICON_ID,
  VAULTGUARD_ICON,
  type VaultGuardRibbonContext,
  type VaultGuardRibbonElements,
  type VaultGuardSidebarActivationContext,
  type VaultGuardViewRegistrationContext,
} from "./plugin-runtime-types";

type ChatPluginHost = ConstructorParameters<typeof VaultGuardChatView>[1];
type GraphPluginHost = ConstructorParameters<typeof PermissionsGraphView>[1];

export function registerVaultGuardRibbons(
  ctx: VaultGuardRibbonContext,
): VaultGuardRibbonElements {
  addIcon("vaultguard-shield", VAULTGUARD_ICON);
  const vaultGuardRibbonEl =
    ctx.addRibbonIcon("vaultguard-shield", "VaultGuard", (evt: MouseEvent) => {
      ctx.showVaultGuardMenu(evt);
    }) ?? null;
  ctx.setVaultGuardRibbonEl(vaultGuardRibbonEl);
  ctx.updateRibbonAuthIndicator();

  const vaultGuardChatRibbonEl =
    ctx.addRibbonIcon(VAULTGUARD_CHAT_ICON_ID, "VaultGuard Chat", () => {
      void ctx.activateVaultGuardChat();
    }) ?? null;
  ctx.setVaultGuardChatRibbonEl(vaultGuardChatRibbonEl);

  let vaultGuardGraphRibbonEl: HTMLElement | null = null;
  if (!Platform.isMobileApp) {
    vaultGuardGraphRibbonEl =
      ctx.addRibbonIcon("git-fork", "VaultGuard Permissions", () => {
        void ctx.activatePermissionsGraph();
      }) ?? null;
  }
  ctx.setVaultGuardGraphRibbonEl(vaultGuardGraphRibbonEl);
  ctx.updateRibbonAuthIndicator();

  return {
    vaultGuardRibbonEl,
    vaultGuardChatRibbonEl,
    vaultGuardGraphRibbonEl,
  };
}

export function registerVaultGuardViews(ctx: VaultGuardViewRegistrationContext): void {
  ctx.registerView(VAULTGUARD_VIEW_TYPE, (leaf) => {
    const view = new VaultGuardSidebarView(leaf, {
      getAuthState: () => ctx.getSidebarAuthState(),
      // W1 pull: back the fresh-view seed with the plugin's single source of
      // truth. Optional on the ctx (Task 2 supplies the plugin backing) — until
      // then it coalesces to a calm default so the build stays green.
      getAtRestRecoveryState: () =>
        ctx.getAtRestRecoveryState?.() ?? {
          needsRecovery: false,
          reason: "",
          canReset: false,
        },
      onLogin: () => ctx.handleLogin(),
      onOpenSettings: () => ctx.openVaultGuardSettings(),
      onStartAtRestRecovery: () => ctx.startAtRestRecoveryFlow?.(),
      onRestoreFromRecoveryCode: () => ctx.startAtRestRecoveryFromRecoveryCode?.(),
    });
    if (ctx.sidebarViewConfig) {
      view.configure(ctx.sidebarViewConfig);
    }
    return view;
  });

  ctx.registerView(
    VAULTGUARD_CHAT_VIEW_TYPE,
    (leaf) => new VaultGuardChatView(leaf, ctx.pluginForViews as ChatPluginHost),
  );

  ctx.registerView(
    VAULTGUARD_GRAPH_VIEW_TYPE,
    (leaf) => new PermissionsGraphView(leaf, ctx.pluginForViews as GraphPluginHost),
  );
}

export async function activateVaultGuardChat(ctx: VaultGuardSidebarActivationContext): Promise<void> {
  const existing = ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
  if (existing.length > 0) {
    ctx.app.workspace.revealLeaf(existing[0]);
    return;
  }

  const leaf = ctx.app.workspace.getRightLeaf(false);
  if (leaf) {
    await leaf.setViewState({ type: VAULTGUARD_CHAT_VIEW_TYPE, active: true });
    ctx.app.workspace.revealLeaf(leaf);
  }
}

export async function activatePermissionsGraph(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  const existing = ctx.app.workspace.getLeavesOfType(VAULTGUARD_GRAPH_VIEW_TYPE);
  if (existing.length > 0) {
    ctx.app.workspace.revealLeaf(existing[0]);
    return;
  }

  const leaf = ctx.app.workspace.getLeaf("tab");
  if (leaf) {
    await leaf.setViewState({ type: VAULTGUARD_GRAPH_VIEW_TYPE, active: true });
    ctx.app.workspace.revealLeaf(leaf);
  }
}

export async function openNewVaultGuardChatTab(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  await activateVaultGuardChat(ctx);
  const leaves = ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
  const view = leaves[0]?.view;
  if (view instanceof VaultGuardChatView) {
    view.openFreshChatTab();
  }
}

export async function openVaultGuardChatHistory(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  await activateVaultGuardChat(ctx);
  const leaves = ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
  const view = leaves[0]?.view;
  if (view instanceof VaultGuardChatView) {
    view.showHistoryPicker();
  }
}

export async function copyVaultGuardChatDomDebugReport(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  await activateVaultGuardChat(ctx);
  const leaves = ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
  const view = leaves[0]?.view;
  if (view instanceof VaultGuardChatView) {
    await view.copyDomDebugReport();
    return;
  }
  new Notice("VaultGuard Chat: open the chat panel before copying a DOM debug report.");
}

export function reloadVaultGuardSidebar(ctx: VaultGuardSidebarActivationContext): void {
  ctx.setSidebarViewConfig(ctx.createSidebarViewConfig());
  const sidebarViewConfig = ctx.getSidebarViewConfig();
  const leaves = ctx.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
  for (const leaf of leaves) {
    const view = leaf.view as
      | (VaultGuardSidebarView & {
          configure?: (cfg: typeof sidebarViewConfig) => void;
        })
      | undefined;
    if (view?.configure) {
      view.configure(sidebarViewConfig);
    }
    if (view?.reload) {
      void view.reload();
    }
  }
}

export async function ensureVaultGuardSidebar(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  const existing = ctx.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
  if (existing.length > 0) return;

  const leaf = ctx.app.workspace.getRightLeaf(false);
  if (leaf) {
    await leaf.setViewState({
      type: VAULTGUARD_VIEW_TYPE,
      active: true,
    });
  }
}

export async function activateVaultGuardSidebar(
  ctx: VaultGuardSidebarActivationContext,
): Promise<void> {
  const sidebarConfig = ctx.createSidebarViewConfig();
  if (sidebarConfig) {
    ctx.setSidebarViewConfig(sidebarConfig);
  }
  const sidebarViewConfig = ctx.getSidebarViewConfig();

  const existing = ctx.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
  if (existing.length > 0) {
    ctx.app.workspace.revealLeaf(existing[0]);
    const view = existing[0].view as VaultGuardSidebarView;
    if (sidebarViewConfig) {
      view.configure(sidebarViewConfig);
    }
    await view.reload();
    return;
  }

  const leaf = ctx.app.workspace.getRightLeaf(false);
  if (leaf) {
    await leaf.setViewState({
      type: VAULTGUARD_VIEW_TYPE,
      active: true,
    });
    ctx.app.workspace.revealLeaf(leaf);

    const view = leaf.view as VaultGuardSidebarView;
    if (view?.configure && sidebarViewConfig) {
      view.configure(sidebarViewConfig);
      await view.reload();
    }
  }
}
