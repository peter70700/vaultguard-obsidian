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

import { requireApiVersion, type App } from "obsidian";
import type VaultGuardPlugin from "../../plugin/main";
import { probeSafeStorage } from "../../crypto/safe-storage";

const LOG_PREFIX = "[VaultGuard Chat]";
const SS_PREFIX = "ss:";
const AR_PREFIX = "ar:";
export const OBSIDIAN_SECRET_STORAGE_MIN_VERSION = "1.11.5";

type ApiVersionCheck = (minimumVersion: string) => boolean;

/**
 * Native secrets shipped experimentally in 1.11.4, but VaultGuard only offers
 * the boundary from 1.11.5 where Obsidian documents encrypted-at-rest storage.
 * Structural checks keep the plugin safe on its supported 1.8.7 baseline.
 */
export function canUseObsidianSecretStorage(
  app: App,
  apiVersionCheck?: ApiVersionCheck,
): boolean {
  const check = apiVersionCheck ?? (
    typeof requireApiVersion === "function" ? requireApiVersion : null
  );
  if (!check?.(OBSIDIAN_SECRET_STORAGE_MIN_VERSION)) return false;

  const storage = (app as Partial<App>).secretStorage;
  return !!storage &&
    typeof storage.getSecret === "function" &&
    typeof storage.setSecret === "function" &&
    typeof storage.listSecrets === "function";
}

export class AnthropicKeyStore {
  private readonly store: EncryptedApiKeyStore;

  constructor(
    plugin: VaultGuardPlugin,
    nativeStorageAvailable = () => canUseObsidianSecretStorage(plugin.app),
  ) {
    this.store = new EncryptedApiKeyStore(plugin, {
      label: "Anthropic",
      emptyError: "Anthropic API key cannot be empty.",
      getEnvelope: () => plugin.settings.encryptedAnthropicKey,
      setEnvelope: (envelope) => {
        plugin.settings.encryptedAnthropicKey = envelope;
      },
      getStorageMode: () => plugin.settings.anthropicKeyStorageMode ?? "vaultguard",
      getSecretId: () => plugin.settings.anthropicSecretId,
      setSecretId: (secretId) => {
        plugin.settings.anthropicSecretId = secretId;
      },
    }, nativeStorageAvailable);
  }

  /** True if an encrypted key is currently persisted. Does not decrypt. */
  hasKey(): boolean {
    return this.store.hasKey();
  }

  /**
   * Encrypt `plain` and persist it. Prefers OS-keychain safeStorage; falls
   * back to the plugin's AtRestCipher (and logs a one-time warning) when
   * safeStorage is unavailable. Throws if neither path is available so the
   * caller can surface a clear error rather than silently dropping the key.
   */
  async setKey(plain: string): Promise<void> {
    return this.store.setKey(plain);
  }

  /**
   * Decrypt and return the stored key, or null if none is stored. Returns null
   * (and logs) on a decrypt failure rather than throwing, so a corrupt or
   * cross-device envelope degrades to "no key" rather than crashing the caller.
   */
  async getKey(): Promise<string | null> {
    return this.store.getKey();
  }

  /** Remove the stored key entirely. */
  async clearKey(): Promise<void> {
    return this.store.clearKey();
  }

  usesObsidianSecretStorage(): boolean {
    return this.store.usesObsidianSecretStorage();
  }

  isObsidianSecretStorageAvailable(): boolean {
    return this.store.isObsidianSecretStorageAvailable();
  }

  getSecretId(): string {
    return this.store.getSecretId();
  }

  async setSecretId(secretId: string): Promise<void> {
    return this.store.setSecretId(secretId);
  }
}

export class OpenAiKeyStore {
  private readonly store: EncryptedApiKeyStore;

  constructor(
    plugin: VaultGuardPlugin,
    nativeStorageAvailable = () => canUseObsidianSecretStorage(plugin.app),
  ) {
    this.store = new EncryptedApiKeyStore(plugin, {
      label: "OpenAI",
      emptyError: "OpenAI API key cannot be empty.",
      getEnvelope: () => plugin.settings.encryptedOpenAiKey,
      setEnvelope: (envelope) => {
        plugin.settings.encryptedOpenAiKey = envelope;
      },
      getStorageMode: () => plugin.settings.openAiKeyStorageMode ?? "vaultguard",
      getSecretId: () => plugin.settings.openAiSecretId,
      setSecretId: (secretId) => {
        plugin.settings.openAiSecretId = secretId;
      },
    }, nativeStorageAvailable);
  }

  hasKey(): boolean {
    return this.store.hasKey();
  }

  async setKey(plain: string): Promise<void> {
    return this.store.setKey(plain);
  }

  async getKey(): Promise<string | null> {
    return this.store.getKey();
  }

  async clearKey(): Promise<void> {
    return this.store.clearKey();
  }

  usesObsidianSecretStorage(): boolean {
    return this.store.usesObsidianSecretStorage();
  }

  isObsidianSecretStorageAvailable(): boolean {
    return this.store.isObsidianSecretStorageAvailable();
  }

  getSecretId(): string {
    return this.store.getSecretId();
  }

  async setSecretId(secretId: string): Promise<void> {
    return this.store.setSecretId(secretId);
  }
}

interface EncryptedApiKeyStoreConfig {
  label: string;
  emptyError: string;
  getEnvelope(): string | undefined;
  setEnvelope(envelope: string | undefined): void;
  getStorageMode(): "vaultguard" | "obsidian";
  getSecretId(): string | undefined;
  setSecretId(secretId: string | undefined): void;
}

class EncryptedApiKeyStore {
  private fallbackWarningLogged = false;

  constructor(
    private readonly plugin: VaultGuardPlugin,
    private readonly config: EncryptedApiKeyStoreConfig,
    private readonly nativeStorageAvailable: () => boolean,
  ) {}

  hasKey(): boolean {
    if (this.usesObsidianSecretStorage()) {
      if (!this.isObsidianSecretStorageAvailable()) return false;
      const secretId = this.getSecretId();
      if (!secretId) return false;
      try {
        return !!this.plugin.app.secretStorage.getSecret(secretId);
      } catch {
        return false;
      }
    }
    return !!this.config.getEnvelope();
  }

  async setKey(plain: string): Promise<void> {
    if (this.usesObsidianSecretStorage()) {
      throw new Error(
        `Select or create the ${this.config.label} key with Obsidian's native secret control.`,
      );
    }
    const trimmed = plain.trim();
    if (!trimmed) {
      throw new Error(this.config.emptyError);
    }

    const safeStorage = probeSafeStorage();
    if (safeStorage) {
      const blob = safeStorage.encryptString(trimmed);
      const bytes = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
      this.config.setEnvelope(`${SS_PREFIX}${bytesToBase64(bytes)}`);
      await this.plugin.saveSettings();
      return;
    }

    const cipher = this.plugin.getAtRestCipher();
    if (cipher?.isReady()) {
      if (!this.fallbackWarningLogged) {
        console.warn(
          `${LOG_PREFIX} OS keychain (safeStorage) unavailable — storing the ${this.config.label} API key ` +
            "with the local at-rest key (LAK) fallback. Anyone with the full Electron profile " +
            "directory could recover it; see docs/AT-REST-ENCRYPTION.md.",
        );
        this.fallbackWarningLogged = true;
      }
      const buf = await cipher.encryptString(trimmed);
      this.config.setEnvelope(`${AR_PREFIX}${bytesToBase64(new Uint8Array(buf))}`);
      await this.plugin.saveSettings();
      return;
    }

    throw new Error(
      "Cannot store the API key: neither the OS keychain nor the local at-rest cipher is available. " +
      "Unlock VaultGuard's local encryption first.",
    );
  }

  async getKey(): Promise<string | null> {
    if (this.usesObsidianSecretStorage()) {
      if (!this.isObsidianSecretStorageAvailable()) return null;
      const secretId = this.getSecretId();
      if (!secretId) return null;
      try {
        return this.plugin.app.secretStorage.getSecret(secretId);
      } catch (e) {
        console.warn(`${LOG_PREFIX} Could not read the native ${this.config.label} secret:`, e);
        return null;
      }
    }

    const envelope = this.config.getEnvelope();
    if (!envelope) return null;

    try {
      if (envelope.startsWith(SS_PREFIX)) {
        const safeStorage = probeSafeStorage();
        if (!safeStorage) {
          console.warn(
            `${LOG_PREFIX} Stored ${this.config.label} key was encrypted with the OS keychain, which is ` +
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
            `${LOG_PREFIX} Stored ${this.config.label} key needs the local at-rest cipher, which is not ready. ` +
              "Unlock VaultGuard's local encryption and retry.",
          );
          return null;
        }
        const bytes = base64ToBytes(envelope.slice(AR_PREFIX.length));
        return cipher.decryptString(bytes);
      }

      console.warn(`${LOG_PREFIX} Unrecognized ${this.config.label} key envelope format; ignoring.`);
      return null;
    } catch (e) {
      console.warn(`${LOG_PREFIX} Could not decrypt the stored ${this.config.label} key:`, e);
      return null;
    }
  }

  async clearKey(): Promise<void> {
    if (this.usesObsidianSecretStorage()) {
      if (!this.getSecretId()) return;
      // SecretStorage is global to Obsidian. Forget only VaultGuard's reference;
      // never delete or overwrite a secret another plugin may also use.
      this.config.setSecretId(undefined);
      await this.plugin.saveSettings();
      return;
    }
    if (!this.config.getEnvelope()) return;
    this.config.setEnvelope(undefined);
    await this.plugin.saveSettings();
  }

  usesObsidianSecretStorage(): boolean {
    return this.config.getStorageMode() === "obsidian";
  }

  isObsidianSecretStorageAvailable(): boolean {
    try {
      return this.nativeStorageAvailable();
    } catch {
      return false;
    }
  }

  getSecretId(): string {
    return this.config.getSecretId()?.trim() ?? "";
  }

  async setSecretId(secretId: string): Promise<void> {
    if (!this.usesObsidianSecretStorage()) {
      throw new Error("Switch the provider key source to Obsidian secrets first.");
    }
    if (!this.isObsidianSecretStorageAvailable()) {
      throw new Error(
        `Obsidian ${OBSIDIAN_SECRET_STORAGE_MIN_VERSION} or newer is required for native secret storage.`,
      );
    }
    const normalized = secretId.trim() || undefined;
    if (normalized === this.config.getSecretId()) return;
    this.config.setSecretId(normalized);
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
