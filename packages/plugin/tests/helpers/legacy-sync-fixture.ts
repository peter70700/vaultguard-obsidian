/** Explicit compatibility for fixtures exercising the legacy path protocol.
 * The real replica still selects its route; an absent response must stay closed.
 * Each recreated runtime receives the same synthetic legacy server discovery. */
export function selectLegacySync(plugin: any): void {
  const ensure = plugin.ensureWorkspaceSyncRuntime.bind(plugin);
  plugin.ensureWorkspaceSyncRuntime = () => {
    const runtime = ensure();
    runtime.ctx.api = () => ({ getSyncCompatibility: async () => ({ revision: null, syncCompatibility: { mode: "legacy" } }) });
    if (runtime.mode === "unknown" && !runtime.snapshot()) {
      runtime.mode = "legacy";
      runtime.discoveryGeneration = plugin.sessionEpoch;
    }
    return runtime;
  };
  plugin.ensureWorkspaceSyncRuntime();
}
