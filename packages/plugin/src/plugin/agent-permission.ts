import { PermissionLevel } from "../types";

/**
 * The two plugin capabilities the Agent Bridge's per-file permission value is
 * derived from. Structural so both the bridge runtime context and the plugin
 * itself can satisfy it.
 */
export interface AgentPermissionSource {
  isLocalProjectMemoryModeEnabled(): boolean;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
}

/**
 * The single definition of the per-path permission value the Agent Bridge
 * list/read surface gates on (`agent-bridge.ts:2507-2508`, `:4193-4196`).
 *
 * Local Project Memory Mode has no server vault and therefore no permission
 * store answer; it short-circuits to WRITE exactly as the bridge wiring always
 * has. Any other caller that gates a surface on "what the read path would say"
 * MUST route through this function rather than re-deriving it — SD-13-F5 was a
 * UI surface that skipped the gate entirely.
 */
export function resolveAgentPermission(
  source: AgentPermissionSource,
  path: string,
): Promise<PermissionLevel> {
  return source.isLocalProjectMemoryModeEnabled()
    ? Promise.resolve(PermissionLevel.WRITE)
    : source.getEffectivePermission(path);
}
