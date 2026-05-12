/**
 * Polls the public release repo for newer plugin versions and surfaces a
 * non-blocking Notice when one appears. Pure read-only HTTP — no telemetry,
 * no auto-install. The user still downloads + installs manually (or via BRAT).
 *
 * Self-throttles to one check per 24 h across reloads via persisted state.
 * Suppresses repeat notifications for the same version so an unread notice
 * doesn't re-fire on every plugin load.
 */

import { Notice, requestUrl } from "obsidian";
import type VaultGuardPlugin from "./main";

const RELEASES_API_URL =
  "https://api.github.com/repos/peter70700/vaultguard-obsidian/releases/latest";
const RELEASES_PAGE_URL =
  "https://github.com/peter70700/vaultguard-obsidian/releases";

const CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const STARTUP_DELAY_MS = 30_000;
const NOTICE_DURATION_MS = 15_000;

export interface UpdateCheckState {
  /** Epoch ms of last successful HTTP check (regardless of result). */
  lastCheckedAt: number;
  /** Last version string we already informed the user about. */
  lastSeenVersion: string;
}

export class UpdateChecker {
  private startupTimer: number | null = null;
  private intervalTimer: number | null = null;

  constructor(private readonly plugin: VaultGuardPlugin) {}

  start(): void {
    if (this.startupTimer !== null || this.intervalTimer !== null) return;

    this.startupTimer = window.setTimeout(() => {
      this.startupTimer = null;
      void this.runCheck();
      this.intervalTimer = window.setInterval(() => {
        void this.runCheck();
      }, CHECK_INTERVAL_MS);
    }, STARTUP_DELAY_MS);
  }

  stop(): void {
    if (this.startupTimer !== null) {
      window.clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
    if (this.intervalTimer !== null) {
      window.clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }

  /** Manually trigger a check (e.g. from a command). Bypasses the 24h throttle. */
  async checkNow(): Promise<{ latest: string | null; isNewer: boolean }> {
    return this.runCheck({ force: true });
  }

  private async runCheck(opts: { force?: boolean } = {}): Promise<{
    latest: string | null;
    isNewer: boolean;
  }> {
    if (this.plugin.settings.disableUpdateChecks) {
      return { latest: null, isNewer: false };
    }

    const state: UpdateCheckState =
      this.plugin.settings.updateCheckState ?? { lastCheckedAt: 0, lastSeenVersion: "" };

    if (!opts.force && Date.now() - state.lastCheckedAt < CHECK_INTERVAL_MS) {
      return { latest: null, isNewer: false };
    }

    let latest: string | null = null;
    let isNewer = false;

    try {
      const response = await requestUrl({
        url: RELEASES_API_URL,
        method: "GET",
        headers: { Accept: "application/vnd.github+json" },
        throw: false,
      });

      if (response.status === 200 && response.json && typeof response.json === "object") {
        const tagName =
          typeof (response.json as { tag_name?: unknown }).tag_name === "string"
            ? ((response.json as { tag_name: string }).tag_name).trim()
            : "";
        const htmlUrl =
          typeof (response.json as { html_url?: unknown }).html_url === "string"
            ? (response.json as { html_url: string }).html_url
            : RELEASES_PAGE_URL;

        if (tagName) {
          latest = tagName;
          const current = this.plugin.manifest.version;
          if (compareVersions(tagName, current) > 0) {
            isNewer = true;
            if (opts.force || tagName !== state.lastSeenVersion) {
              this.notifyNewVersion(current, tagName, htmlUrl);
              state.lastSeenVersion = tagName;
            }
          }
        }
      }
      // Non-200 responses (404 no releases, 403 rate limit, etc.) are silent.
    } catch {
      // Offline / DNS / TLS failure — silent. We'll retry on next interval.
    }

    state.lastCheckedAt = Date.now();
    this.plugin.settings.updateCheckState = state;
    try {
      await this.plugin.saveSettings();
    } catch {
      // Settings save failure shouldn't escalate from a background check.
    }

    return { latest, isNewer };
  }

  private notifyNewVersion(current: string, latest: string, releaseUrl: string): void {
    const fragment = document.createDocumentFragment();
    fragment.appendChild(
      document.createTextNode(
        `VaultGuard ${latest} is available (you're on ${current}). `
      )
    );
    const link = document.createElement("a");
    link.href = releaseUrl;
    link.textContent = "View release";
    link.setAttribute("target", "_blank");
    link.setAttribute("rel", "noopener noreferrer");
    fragment.appendChild(link);
    new Notice(fragment, NOTICE_DURATION_MS);
  }
}

/**
 * Numeric-segment version comparison. Strips a leading `v`, splits on `.`,
 * treats non-numeric segments as 0. Returns >0 if `a` is newer, <0 if `b`
 * is newer, 0 if equal.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string): number[] =>
    v.replace(/^v/i, "").split(".").map((s) => {
      const n = parseInt(s, 10);
      return Number.isFinite(n) ? n : 0;
    });
  const av = parse(a);
  const bv = parse(b);
  const len = Math.max(av.length, bv.length);
  for (let i = 0; i < len; i++) {
    const diff = (av[i] ?? 0) - (bv[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
