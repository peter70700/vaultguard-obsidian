// Encrypted at-rest storage for the user's Anthropic API key (AI-CHAT-PANEL.md §7).
//
// The key never lives in settings as plaintext. We encrypt it with the OS
// keychain via Electron safeStorage when available (the same probe the at-rest
// cipher uses), and fall back to the plugin's AtRestCipher (LAK-wrapped) when
// safeStorage is unavailable — exactly mirroring the degraded-mode story
// documented for vault files. Either way the ciphertext is base64-encoded and
// persisted through the plugin's normal `saveSettings()` path.
//
// The stored envelope is method-tagged so decode knows how it was produced:
//   "ss:<base64 safeStorage blob>"   (OS keychain)
//   "ar:<base64 AtRestCipher blob>"  (LAK fallback)
//
// Plaintext is never retained beyond a single call. Callers that need the key
// (e.g. the chat client) read it on demand and must not cache it.

import type VaultGuardPlugin from "../../plugin/main";
import { probeSafeStorage } from "../../crypto/safe-storage";

const LOG_PREFIX = "[VaultGuard Chat]";
const SS_PREFIX = "ss:";
const AR_PREFIX = "ar:";

export class AnthropicKeyStore {
  private fallbackWarningLogged = false;

  constructor(private readonly plugin: VaultGuardPlugin) {}

  /** True if an encrypted key is currently persisted. Does not decrypt. */
  hasKey(): boolean {
    return !!this.plugin.settings.encryptedAnthropicKey;
  }

  /**
   * Encrypt `plain` and persist it. Prefers OS-keychain safeStorage; falls
   * back to the plugin's AtRestCipher (and logs a one-time warning) when
   * safeStorage is unavailable. Throws if neither path is available so the
   * caller can surface a clear error rather than silently dropping the key.
   */
  async setKey(plain: string): Promise<void> {
    const trimmed = plain.trim();
    if (!trimmed) {
      throw new Error("Anthropic API key cannot be empty.");
    }

    const safeStorage = probeSafeStorage();
    if (safeStorage) {
      const blob = safeStorage.encryptString(trimmed);
      const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
      this.plugin.settings.encryptedAnthropicKey = `${SS_PREFIX}${bytesToBase64(bytes)}`;
      await this.plugin.saveSettings();
      return;
    }

    const cipher = this.plugin.getAtRestCipher();
    if (cipher?.isReady()) {
      if (!this.fallbackWarningLogged) {
        console.warn(
          `${LOG_PREFIX} OS keychain (safeStorage) unavailable — storing the Anthropic API key ` +
            "with the local at-rest key (LAK) fallback. Anyone with the full Electron profile " +
            "directory could recover it; see docs/AT-REST-ENCRYPTION.md.",
        );
        this.fallbackWarningLogged = true;
      }
      const buf = await cipher.encryptString(trimmed);
      this.plugin.settings.encryptedAnthropicKey = `${AR_PREFIX}${bytesToBase64(new Uint8Array(buf))}`;
      await this.plugin.saveSettings();
      return;
    }

    throw new Error(
      "Cannot store the API key: neither the OS keychain nor the local at-rest cipher is available. " +
        "Unlock VaultGuard's local encryption first.",
    );
  }

  /**
   * Decrypt and return the stored key, or null if none is stored. Returns null
   * (and logs) on a decrypt failure rather than throwing, so a corrupt or
   * cross-device envelope degrades to "no key" rather than crashing the caller.
   */
  async getKey(): Promise<string | null> {
    const envelope = this.plugin.settings.encryptedAnthropicKey;
    if (!envelope) return null;

    try {
      if (envelope.startsWith(SS_PREFIX)) {
        const safeStorage = probeSafeStorage();
        if (!safeStorage) {
          console.warn(
            `${LOG_PREFIX} Stored Anthropic key was encrypted with the OS keychain, which is ` +
              "unavailable on this device. Re-enter the key in VaultGuard settings.",
          );
          return null;
        }
        const bytes = base64ToBytes(envelope.slice(SS_PREFIX.length));
        return safeStorage.decryptString(bytes);
      }

      if (envelope.startsWith(AR_PREFIX)) {
        const cipher = this.plugin.getAtRestCipher();
        if (!cipher?.isReady()) {
          console.warn(
            `${LOG_PREFIX} Stored Anthropic key needs the local at-rest cipher, which is not ready. ` +
              "Unlock VaultGuard's local encryption and retry.",
          );
          return null;
        }
        const bytes = base64ToBytes(envelope.slice(AR_PREFIX.length));
        return cipher.decryptString(bytes);
      }

      console.warn(`${LOG_PREFIX} Unrecognized Anthropic key envelope format; ignoring.`);
      return null;
    } catch (e) {
      console.warn(`${LOG_PREFIX} Could not decrypt the stored Anthropic key:`, e);
      return null;
    }
  }

  /** Remove the stored key entirely. */
  async clearKey(): Promise<void> {
    if (!this.plugin.settings.encryptedAnthropicKey) return;
    this.plugin.settings.encryptedAnthropicKey = undefined;
    await this.plugin.saveSettings();
  }
}

// ─── tiny base64 helpers (browser/Node parity, no Buffer dependency) ─────────

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return typeof btoa === "function"
    ? btoa(bin)
    : Buffer.from(bin, "binary").toString("base64");
}

function base64ToBytes(b64: string): Uint8Array {
  const bin =
    typeof atob === "function"
      ? atob(b64)
      : Buffer.from(b64, "base64").toString("binary");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
