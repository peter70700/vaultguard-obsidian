/**
 * VaultGuard - Biometric capability probe (Phase 12, vault idle-lock)
 *
 * The D1 / O-2 "pluggable secret-source" seam. It answers one question — can a
 * WebAuthn platform authenticator (Touch ID / Windows Hello) gate an unlock on
 * THIS device? — and self-disables everywhere it can't, so the biometric UI
 * never renders until the capability is real.
 *
 * Why it is false on all CURRENT Obsidian (as of 2026-07): Obsidian ships
 * Electron 39 / Chromium 142. Chromium supports WebAuthn PRF, but Touch ID from
 * a plugin needs Electron 43's main-process `app.configureWebAuthn()` PLUS a
 * native module + code-sign entitlements a JS-only community plugin cannot
 * provide; mobile (Capacitor webview) is unreliable. So PIN ships as the only
 * unlock today. This probe is the additive hook: when a future Obsidian exposes
 * a serviceable platform authenticator, the biometric flow drops in behind a
 * `lak-prf.envelope` (a PRF-derived secret) with the PIN remaining the crypto
 * boundary + recovery — no rework of the lock loop required.
 *
 * WebAuthn's `navigator.credentials` / `PublicKeyCredential` is NOT `fetch`,
 * `EventSource`, or `XMLHttpRequest` and makes no network egress — the
 * telemetry-policy is unaffected.
 */

import { Platform } from "obsidian";

/**
 * True only if a user-verifying platform authenticator is actually available.
 * Never throws — any probe failure resolves to false (self-disabling).
 */
export async function biometricAvailable(): Promise<boolean> {
  if (Platform.isMobileApp) return false;
  if (typeof PublicKeyCredential === "undefined") return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
