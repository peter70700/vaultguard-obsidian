import { Notice, Platform, TFolder } from "obsidian";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import { PermissionLevel } from "../types";
import type {
  AttachmentPreviewDatum,
  AttachmentPreviewReport,
  VaultGuardCommandContext,
} from "./plugin-runtime-types";

/**
 * The sync engine's text/binary split is CONTENT-based, not extension-based:
 * readForSync strict-UTF-8-decodes the bytes and anything lossy is classified
 * as binary (AR1). A debug report only sees metadata, so it approximates with a
 * deny-list of definitely-binary attachment formats. Post-BIN-A, a queued WRITE
 * is judged by its `encoding`: an entry marked "base64" rode the byte pipeline
 * (legitimate — binaries now sync), while a binary-extension entry WITHOUT that
 * marker means binary content entered the STRING pipeline, which is still the
 * AR1 regression signal. Text-ish extensions we don't enumerate (.base, .yml, …)
 * are legitimately queueable.
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
  for (const name of ["offline-queue.envelope", "lak.envelope", "lak-pin.envelope", "lak-prf.envelope", "agent-leases.envelope", "data.json"]) {
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

/**
 * AR1 / BIN-A verification: attachment inventory + a split of legitimate
 * byte-path binary WRITEs (offline-queue v2, encoding "base64") from binary
 * content that leaked into the STRING offline queue (the AR1 regression class).
 */
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
  // BIN-A / D-11: a queued binary WRITE marked encoding:"base64" is LEGITIMATE —
  // it rides the byte pipeline (interceptedWriteBinary → offline-queue v2), so
  // binaries now sync. A binary-extension WRITE WITHOUT that marker means binary
  // content entered the STRING pipeline, which is still the AR1 regression signal.
  const queuedBinaryByteWrites = ctx.offlineQueueSnapshot.filter(
    (entry) => entry.operation === "write" && entry.encoding === "base64"
  );
  const queuedBinaryStringRegressions = ctx.offlineQueueSnapshot.filter((entry) => {
    if (entry.operation !== "write" || entry.encoding === "base64") {
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
  if (
    queuedBinaryByteWrites.length === 0 &&
    queuedBinaryStringRegressions.length === 0
  ) {
    lines.push(
      "queued binary WRITEs in offline queue: 0 ✅ (binaries ride the byte path (BIN-A); strings stay text-only)"
    );
  } else {
    if (queuedBinaryByteWrites.length > 0) {
      lines.push(
        `queued binary WRITEs (byte path, BIN-A): ${queuedBinaryByteWrites.length} ✅`
      );
    }
    if (queuedBinaryStringRegressions.length > 0) {
      lines.push(
        `queued binary WRITEs in offline queue: ${queuedBinaryStringRegressions.length} ⚠️ AR1 REGRESSION — ${queuedBinaryStringRegressions
          .map((entry) => entry.path)
          .join(", ")}`
      );
    }
  }
  return lines.join("\n");
}

// Renderable media whose preview goes through getResourcePath()→app:// (a direct
// on-disk read the plugin does NOT intercept) — the attachments most likely to
// fail rendering under at-rest encryption. Used only by the dev preview diagnostic.
const RENDERABLE_MEDIA_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "svg",
  "pdf",
  "mp4", "webm", "mov", "ogv",
  "mp3", "wav", "ogg", "m4a", "flac",
]);

const PREVIEW_HEADER_BYTES = 8;
const VG1_MAGIC = [0x56, 0x47, 0x31, 0x00]; // "VG1\0" at-rest header

/** Injected disk/render primitives for the preview diagnostic — keeps raw-read capability off the general command surface. */
export interface AttachmentPreviewDeps {
  files: readonly { path: string; extension: string }[];
  getResourcePath(path: string): string;
  /** Raw on-disk read (bypasses at-rest decryption) — what the app:// renderer sees. */
  rawReadBinary: ((path: string) => Promise<ArrayBuffer>) | undefined;
  /** At-rest decrypted read — the real file content. */
  readDecrypted(path: string): Promise<ArrayBuffer>;
  getResourcePathIntercepted: boolean;
  readBinaryIntercepted: boolean;
  atRestActive: boolean;
}

/**
 * BIN-A preview diagnostic gatherer. For up to `limit` renderable-media
 * attachments, captures the on-disk header (what Obsidian's app:// renderer
 * decodes via getResourcePath — which the plugin does NOT intercept) alongside
 * the decrypted header (the real content). When the two differ (VG1 vs the true
 * PNG/PDF magic) the file previews as broken even though the bytes are intact.
 * Header hex only — never enough bytes to leak note content. Standalone (not a
 * plugin method) so the production build tree-shakes it out with the dev command.
 */
export async function collectAttachmentPreviewData(
  deps: AttachmentPreviewDeps,
  limit: number
): Promise<AttachmentPreviewReport> {
  const toHeaderHex = (bytes: Uint8Array): string =>
    Array.from(bytes.slice(0, PREVIEW_HEADER_BYTES))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
  const isVg1 = (bytes: Uint8Array): boolean =>
    bytes.length >= 4 && VG1_MAGIC.every((b, i) => bytes[i] === b);

  const attachments = deps.files.filter((f) =>
    RENDERABLE_MEDIA_EXTENSIONS.has((f.extension || "").toLowerCase())
  );
  const analyzed: AttachmentPreviewDatum[] = [];
  for (const file of attachments.slice(0, Math.max(0, limit))) {
    const path = file.path;
    const datum: AttachmentPreviewDatum = {
      path,
      resourceUrl: deps.getResourcePath(path),
      onDiskHeaderHex: "(unread)",
      onDiskEncrypted: false,
      decryptedHeaderHex: null,
    };
    try {
      if (deps.rawReadBinary) {
        const raw = new Uint8Array(await deps.rawReadBinary(path));
        datum.onDiskHeaderHex = toHeaderHex(raw);
        datum.onDiskEncrypted = isVg1(raw);
      }
    } catch (err) {
      datum.error = `raw read failed: ${String(err)}`;
    }
    try {
      const decrypted = new Uint8Array(await deps.readDecrypted(path));
      datum.decryptedHeaderHex = toHeaderHex(decrypted);
    } catch (err) {
      datum.error = `${datum.error ? datum.error + "; " : ""}decrypt failed: ${String(err)}`;
    }
    analyzed.push(datum);
  }

  return {
    getResourcePathIntercepted: deps.getResourcePathIntercepted,
    readBinaryIntercepted: deps.readBinaryIntercepted,
    atRestActive: deps.atRestActive,
    totalAttachments: attachments.length,
    analyzed,
  };
}

/**
 * Best-effort file-format label from a header hex string (space-separated bytes,
 * as produced by collectAttachmentPreviewData). Pure — no I/O — so it is unit
 * tested directly. Recognises the VG1 at-rest magic plus the common attachment
 * signatures, which is all the preview diagnostic needs to contrast on-disk
 * ciphertext against the real decrypted content.
 */
export function describeBinaryMagic(headerHex: string | null): string {
  if (!headerHex) return "—";
  const b = headerHex
    .trim()
    .split(/\s+/)
    .map((h) => parseInt(h, 16));
  const at = (i: number, ...vals: number[]): boolean =>
    vals.every((v, k) => b[i + k] === v);
  if (at(0, 0x56, 0x47, 0x31, 0x00)) return "VG1 ciphertext";
  if (at(0, 0x89, 0x50, 0x4e, 0x47)) return "PNG";
  if (at(0, 0xff, 0xd8, 0xff)) return "JPEG";
  if (at(0, 0x47, 0x49, 0x46, 0x38)) return "GIF";
  if (at(0, 0x25, 0x50, 0x44, 0x46)) return "PDF";
  if (at(0, 0x42, 0x4d)) return "BMP";
  if (at(0, 0x52, 0x49, 0x46, 0x46)) return "RIFF (WebP/WAV/AVI)";
  if (at(0, 0x4f, 0x67, 0x67, 0x53)) return "Ogg";
  if (at(0, 0x49, 0x44, 0x33)) return "MP3 (ID3)";
  if (at(4, 0x66, 0x74, 0x79, 0x70)) return "MP4/MOV (ftyp)";
  if (at(0, 0x3c, 0x3f, 0x78, 0x6d) || at(0, 0x3c, 0x73, 0x76, 0x67)) return "SVG/XML";
  return "unknown";
}

/**
 * Formats the attachment-preview diagnostic (BIN-A). Pure — takes the structured
 * data from ctx.collectAttachmentPreviewData and renders the human report + a
 * root-cause verdict. Metadata + header hex only; never note plaintext.
 */
export function formatAttachmentPreviewReport(report: AttachmentPreviewReport): string {
  const lines: string[] = [
    "VaultGuard attachment PREVIEW diagnostic",
    "(why encrypted images/PDFs don't render: Obsidian loads getResourcePath()→app:// which reads",
    " the RAW on-disk bytes directly, bypassing the plugin's readBinary decryption)",
    "",
    `getResourcePath intercepted by plugin: ${report.getResourcePathIntercepted ? "YES" : "NO  ← renderer reads on-disk bytes directly"}`,
    `adapter.readBinary intercepted (decrypts): ${report.readBinaryIntercepted ? "YES" : "NO"}`,
    `at-rest encryption active (files are VG1 on disk): ${report.atRestActive ? "YES" : "NO"}`,
    `renderable attachments: ${report.totalAttachments} (analyzed ${report.analyzed.length})`,
    "",
  ];

  let brokenCount = 0;
  for (const d of report.analyzed) {
    const onDisk = describeBinaryMagic(d.onDiskHeaderHex);
    const decrypted = describeBinaryMagic(d.decryptedHeaderHex);
    const broken =
      d.onDiskEncrypted && !report.getResourcePathIntercepted && !d.error;
    if (broken) brokenCount++;
    lines.push(`  ${d.path}`);
    lines.push(`    resourceURL: ${d.resourceUrl}`);
    lines.push(
      `    on-disk header: ${d.onDiskHeaderHex} → ${onDisk}${d.onDiskEncrypted ? " ❌ renderer can't decode" : ""}`
    );
    lines.push(
      `    decrypted header: ${d.decryptedHeaderHex ?? "—"} → ${decrypted}${d.decryptedHeaderHex && decrypted !== "unknown" && decrypted !== "VG1 ciphertext" ? " ✅ real content intact" : ""}`
    );
    if (d.error) {
      lines.push(`    ⚠ ${d.error}`);
    } else if (broken) {
      lines.push("    verdict: BROKEN PREVIEW — file is fine, renderer sees ciphertext");
    } else if (d.onDiskEncrypted && report.getResourcePathIntercepted) {
      lines.push("    verdict: renders via decrypted blob URL (getResourcePath intercepted) ✅");
    } else {
      lines.push("    verdict: renders normally (plaintext on disk / not encrypted)");
    }
  }

  lines.push("");
  if (brokenCount > 0) {
    lines.push(
      `DIAGNOSIS: ${brokenCount}/${report.analyzed.length} analyzed attachments preview BROKEN.`,
      "Binaries are at-rest encrypted (VG1) on disk, but Obsidian renders media via",
      "getResourcePath()→app:// which reads disk directly, bypassing readBinary decryption.",
      "FIX: override adapter.getResourcePath to serve decrypted content (blob:/data: URL",
      "cache keyed by path+mtime), or a custom decrypting protocol handler.",
    );
  } else if (report.analyzed.length === 0) {
    lines.push("No renderable attachments found to analyze.");
  } else if (report.getResourcePathIntercepted) {
    lines.push(
      "DIAGNOSIS: preview fix ACTIVE — getResourcePath serves decrypted blob URLs,",
      "so encrypted media renders while staying VG1 on disk. No broken previews.",
    );
  } else {
    lines.push("DIAGNOSIS: no broken previews detected in the analyzed sample.");
  }
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
    checkCallback: (checking: boolean) => {
      if (checking) return !ctx.localProjectMemoryMode;
      void ctx.performSync({ userInitiated: true, forceCatchup: true });
    },
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

    ctx.addCommand({
      id: "vaultguard-debug-attachment-preview",
      name: "VaultGuard (debug): Diagnose attachment preview (why images/PDFs don't render)",
      callback: async () => {
        await copyDebugReport(
          ctx,
          "attachment preview state",
          formatAttachmentPreviewReport(await ctx.collectAttachmentPreviewData(8))
        );
      },
    });
  }

  ctx.addCommand({
    id: "manage-share-links",
    name: "Manage share links",
    checkCallback: (checking: boolean) => {
      const ready =
        !ctx.localProjectMemoryMode &&
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
      const ready = !ctx.localProjectMemoryMode && !!ctx.session && isAdmin && !!ctx.apiClient;
      if (checking) return ready;
      if (ready) ctx.openAuditLog();
    },
  });

  ctx.addCommand({
    id: "open-web-admin",
    name: "Open Web Admin Panel",
    checkCallback: (checking: boolean) => {
      const ready = !ctx.localProjectMemoryMode && !!ctx.session;
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
    id: "enable-local-project-memory-mode",
    name: "Enable Local Project Memory Mode",
    callback: () => void ctx.enableLocalProjectMemoryMode(),
  });

  ctx.addCommand({
    id: "view-permissions",
    name: "View permissions",
    checkCallback: (checking: boolean) => {
      if (checking) return !ctx.localProjectMemoryMode;
      ctx.showPermissionsModal();
    },
  });

  ctx.addCommand({
    id: "manage-permission-rules",
    name: "Manage permissions",
    checkCallback: (checking: boolean) => {
      if (checking) return !ctx.localProjectMemoryMode;
      ctx.showPermissionRulesModal();
    },
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
      if (ctx.localProjectMemoryMode) return false;
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
      if (ctx.localProjectMemoryMode) return false;
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
      if (ctx.localProjectMemoryMode) {
        new Notice("VaultGuard Sync: server bridge leases are disabled in Local Project Memory Mode.", 6000);
        return;
      }
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
    checkCallback: (checking: boolean) => {
      if (checking) return !ctx.localProjectMemoryMode;
      void ctx.encryptVaultAtRest();
    },
  });

  ctx.addCommand({
    id: "decrypt-vault-at-rest",
    name: "Decrypt vault and disable at-rest encryption",
    callback: () => void ctx.decryptVaultAndDisableAtRestEncryption(),
  });

  ctx.addCommand({
    id: "decrypt-vault-and-disable-at-rest-encryption",
    name: "Decrypt vault and disable at-rest encryption",
    callback: () => void ctx.decryptVaultAndDisableAtRestEncryption(),
  });

  ctx.addCommand({
    id: "pick-vault",
    name: "Pick or switch server vault",
    checkCallback: (checking: boolean) => {
      if (checking) {
        return !ctx.localProjectMemoryMode && !!ctx.session && !!ctx.apiClient;
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
        return !ctx.localProjectMemoryMode && isAdmin;
      }
      if (isAdmin) {
        ctx.showAdminPanel();
      }
    },
  });

  ctx.registerEvent(
    ctx.onFileMenu((menu, file) => {
      if (ctx.localProjectMemoryMode) return;
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
      if (ctx.localProjectMemoryMode) return false;
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
