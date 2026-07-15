import type { Command } from "obsidian";

export const PERMISSIONS_GRAPH_VIRTUAL_QA_COMMAND_ID =
  "vaultguard-debug-permissions-graph-virtual-qa";

export const PERMISSIONS_GRAPH_VIRTUAL_QA_COMMAND_NAME =
  "VaultGuard (debug): Open virtual permissions graph QA";

export function getPermissionsGraphVirtualQaCompletionMarkers() {
  return [
    "vg-permissions-graph-overview-edges-phase-e-v1",
    "vg-permissions-graph-transition-phase-f-v1",
    "vg-permissions-graph-stress-evidence-phase-g-v1",
    "vg-permissions-graph-activation-evidence-phase-h-v1",
  ] as const;
}

export function hasValidPermissionsGraphVirtualQaCompletionMarkers(): boolean {
  const markers = getPermissionsGraphVirtualQaCompletionMarkers();
  return (
    markers.length === 4 &&
    new Set(markers).size === 4 &&
    markers.every((marker) => marker.startsWith("vg-permissions-graph-"))
  );
}

export interface PermissionsGraphVirtualQaCommandGateInput {
  readonly isDevelopment: boolean;
  readonly isMobileApp: boolean;
  readonly debugLogging: boolean;
}

export interface PermissionsGraphVirtualQaCommandContext {
  readonly settings: { debugLogging: boolean };
  isOptionalModuleEnabled?(moduleId: "permissionsGraph"): boolean;
  addCommand(command: Command): void;
  openPermissionsGraphVirtualQaModal(): Promise<void>;
}

export function canRegisterPermissionsGraphVirtualQaCommand(
  input: PermissionsGraphVirtualQaCommandGateInput,
): boolean {
  return input.isDevelopment && !input.isMobileApp && input.debugLogging;
}

/**
 * Register the synthetic-only QA seam only after every build/platform/setting
 * gate passes. The invocation rechecks the mutable debug setting and fails
 * closed if the tester disables it after plugin load.
 */
export function registerPermissionsGraphVirtualQaCommand(
  ctx: PermissionsGraphVirtualQaCommandContext,
  environment: Pick<PermissionsGraphVirtualQaCommandGateInput, "isDevelopment" | "isMobileApp">,
): boolean {
  const gateInput = (): PermissionsGraphVirtualQaCommandGateInput => ({
    ...environment,
    debugLogging: ctx.settings.debugLogging,
  });
  if (
    !canRegisterPermissionsGraphVirtualQaCommand(gateInput()) ||
    !hasValidPermissionsGraphVirtualQaCompletionMarkers()
  ) return false;

  ctx.addCommand({
    id: PERMISSIONS_GRAPH_VIRTUAL_QA_COMMAND_ID,
    name: PERMISSIONS_GRAPH_VIRTUAL_QA_COMMAND_NAME,
    checkCallback: (checking: boolean) => {
      if (
        !canRegisterPermissionsGraphVirtualQaCommand(gateInput()) ||
        ctx.isOptionalModuleEnabled?.("permissionsGraph") === false
      ) return false;
      if (checking) return true;
      void ctx.openPermissionsGraphVirtualQaModal();
    },
  });
  return true;
}
