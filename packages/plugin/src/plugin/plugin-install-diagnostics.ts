export const PLUGIN_INSTALL_DIAGNOSTIC_SCHEMA_VERSION = 1 as const;

export type PluginInstallDiagnosticStatus =
  | "current"
  | "installed_stale"
  | "runtime_stale"
  | "wrong_plugin"
  | "wrong_vault"
  | "unknown";

export type PluginInstallActionCode =
  | "collect_install_diagnostics"
  | "install_verified_assets"
  | "reload_plugin"
  | "select_expected_plugin"
  | "select_target_vault";

interface PluginIdentity {
  pluginId: string;
  version: string;
  buildRevision: string;
  assetDigest: string;
  vaultFingerprint: string;
}

export interface PluginInstallDiagnostic {
  schemaVersion: typeof PLUGIN_INSTALL_DIAGNOSTIC_SCHEMA_VERSION;
  status: PluginInstallDiagnosticStatus;
  actionCodes: PluginInstallActionCode[];
  comparisons: {
    pluginMatches: boolean | null;
    vaultMatches: boolean | null;
    installedAssetsMatchSource: boolean | null;
    runtimeMatchesInstalled: boolean | null;
  };
}

export function evaluatePluginInstallDiagnostic(input: unknown): PluginInstallDiagnostic {
  const record = asRecord(input);
  const source = parseIdentity(record?.source);
  const installed = parseIdentity(record?.installed);
  const runtime = parseIdentity(record?.runtime);
  if (!source || !installed || !runtime) return unknownDiagnostic();

  const pluginMatches =
    source.pluginId === installed.pluginId && installed.pluginId === runtime.pluginId;
  const vaultMatches =
    source.vaultFingerprint === installed.vaultFingerprint &&
    installed.vaultFingerprint === runtime.vaultFingerprint;
  const installedAssetsMatchSource =
    source.version === installed.version &&
    source.buildRevision === installed.buildRevision &&
    source.assetDigest === installed.assetDigest;
  const runtimeMatchesInstalled =
    installed.version === runtime.version &&
    installed.buildRevision === runtime.buildRevision &&
    installed.assetDigest === runtime.assetDigest;

  const comparisons = {
    pluginMatches,
    vaultMatches,
    installedAssetsMatchSource,
    runtimeMatchesInstalled,
  };

  if (!pluginMatches) {
    return diagnostic("wrong_plugin", ["select_expected_plugin"], comparisons);
  }
  if (!vaultMatches) {
    return diagnostic("wrong_vault", ["select_target_vault"], comparisons);
  }
  if (!installedAssetsMatchSource) {
    return diagnostic(
      "installed_stale",
      ["install_verified_assets", "reload_plugin"],
      comparisons,
    );
  }
  if (!runtimeMatchesInstalled) {
    return diagnostic("runtime_stale", ["reload_plugin"], comparisons);
  }
  return diagnostic("current", [], comparisons);
}

function diagnostic(
  status: PluginInstallDiagnosticStatus,
  actionCodes: PluginInstallActionCode[],
  comparisons: PluginInstallDiagnostic["comparisons"],
): PluginInstallDiagnostic {
  return {
    schemaVersion: PLUGIN_INSTALL_DIAGNOSTIC_SCHEMA_VERSION,
    status,
    actionCodes: [...actionCodes],
    comparisons: { ...comparisons },
  };
}

function unknownDiagnostic(): PluginInstallDiagnostic {
  return diagnostic(
    "unknown",
    ["collect_install_diagnostics"],
    {
      pluginMatches: null,
      vaultMatches: null,
      installedAssetsMatchSource: null,
      runtimeMatchesInstalled: null,
    },
  );
}

function parseIdentity(value: unknown): PluginIdentity | null {
  const record = asRecord(value);
  if (!record) return null;
  const pluginId = safeToken(record.pluginId, /^[a-z0-9][a-z0-9-]{0,79}$/);
  const version = safeToken(record.version, /^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$/);
  const buildRevision = safeToken(record.buildRevision, /^[0-9A-Za-z][0-9A-Za-z._-]{0,79}$/);
  const assetDigest = safeToken(record.assetDigest, /^[a-fA-F0-9]{64}$/)?.toLocaleLowerCase();
  const vaultFingerprint = safeToken(record.vaultFingerprint, /^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$/);
  if (!pluginId || !version || !buildRevision || !assetDigest || !vaultFingerprint) return null;
  return { pluginId, version, buildRevision, assetDigest, vaultFingerprint };
}

function safeToken(value: unknown, pattern: RegExp): string | null {
  if (typeof value !== "string" || !pattern.test(value)) return null;
  return value;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
