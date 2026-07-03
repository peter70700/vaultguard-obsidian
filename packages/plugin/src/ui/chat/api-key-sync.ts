// Cross-device sync for the AI-chat Anthropic API key (AI-CHAT-PANEL.md §7).
//
// The local key store (AnthropicKeyStore) is DEVICE-LOCAL — its safeStorage/LAK
// envelopes do not roam. This module adds an OPT-IN roaming copy: the key is
// wrapped with the LIVE vault DEK (plugin.wrapAiKeySecret) into an opaque
// envelope and stored server-side (one blob per user per vault, in the existing
// UserKeys table). A key entered on desktop then auto-provisions on mobile with
// no re-entry.
//
// Invariants:
//   - The plaintext key is NEVER sent to the server and NEVER logged. Only the
//     DEK-wrapped envelope crosses the wire.
//   - §11: provision/heal/upload fire ONLY when a session + bound vault +
//     api client exist. A fresh, session-less install makes ZERO calls here.
//   - Every network op is BEST-EFFORT: a failure (incl. a 404 from an
//     un-deployed backend) logs and resolves — it never throws to the caller.
//   - A blob wrapped with a rotated/retired DEK unwraps to null (soft-fail,
//     treated as "no key"); a live-keyed device heals the server blob.

import { Notice } from "obsidian";
import type VaultGuardPlugin from "../../plugin/main";
import { AnthropicKeyStore } from "./api-key-store";

const LOG_PREFIX = "[VaultGuard Chat]";

export class ApiKeySync {
  constructor(private readonly plugin: VaultGuardPlugin) {}

  /**
   * Resolved sync context, or null when any prerequisite is missing (§11).
   * Never triggers a network call by itself.
   */
  private context(): { apiClient: NonNullable<ReturnType<VaultGuardPlugin["getAiKeySyncContext"]>["apiClient"]>; vaultId: string } | null {
    const ctx = this.plugin.getAiKeySyncContext();
    if (!ctx.apiClient || !ctx.session || !ctx.vaultId) return null;
    return { apiClient: ctx.apiClient, vaultId: ctx.vaultId };
  }

  /**
   * Wrap + upload the local key when key sync is enabled and a session/vault/
   * lease exist. Best-effort: on failure it logs and (only when the caller
   * marks the attempt user-initiated) shows a single non-blocking Notice.
   */
  async uploadIfEnabled(opts?: { userInitiated?: boolean }): Promise<void> {
    if (!this.plugin.settings.aiChatKeySyncEnabled) return;
    const ctx = this.context();
    if (!ctx) return;

    const key = await new AnthropicKeyStore(this.plugin).getKey();
    if (!key) return;

    const envelope = await this.plugin.wrapAiKeySecret(key);
    if (!envelope) {
      // No valid lease yet — keep the key device-local; a later heal re-tries.
      console.debug?.(`${LOG_PREFIX} API key not synced (no valid key lease yet).`);
      return;
    }

    try {
      await ctx.apiClient.putAiKeyBlob(ctx.vaultId, envelope);
    } catch (e) {
      console.warn(`${LOG_PREFIX} could not sync API key to Cloud`, e);
      if (opts?.userInitiated) {
        new Notice("VaultGuard Chat: couldn't sync your API key to Cloud (saved on this device).");
      }
    }
  }

  /**
   * When no local key is stored, try to provision one from the server blob.
   * Returns the provisioned (now locally-stored) plaintext key, the existing
   * local key, or null. §11: returns null with ZERO network calls when there is
   * no session/vault. Best-effort: any network failure resolves to null.
   */
  async provisionIfMissing(): Promise<string | null> {
    if (!this.plugin.settings.aiChatKeySyncEnabled) return null;
    const ctx = this.context();
    if (!ctx) return null;

    const store = new AnthropicKeyStore(this.plugin);
    if (store.hasKey()) return store.getKey();

    let envelope: string | null;
    try {
      envelope = await ctx.apiClient.getAiKeyBlob(ctx.vaultId);
    } catch (e) {
      console.warn(`${LOG_PREFIX} could not fetch a synced API key`, e);
      return null;
    }
    if (!envelope) return null;

    const plain = await this.plugin.unwrapAiKeySecret(envelope);
    if (!plain) {
      // Rotated/retired DEK or corrupt blob — soft-fail (debug only).
      console.debug?.(`${LOG_PREFIX} synced API key could not be unwrapped (rotated/corrupt); ignoring.`);
      return null;
    }

    try {
      await store.setKey(plain);
    } catch (e) {
      console.warn(`${LOG_PREFIX} could not store the synced API key locally`, e);
      return null;
    }

    new Notice("VaultGuard Chat: API key synced from your other device.");
    return plain;
  }

  /**
   * Cheap self-heal after a successful local key use: if the server blob is
   * missing OR stale (wrapped with a rotated DEK), re-upload the current
   * envelope so other devices can provision again. One GET, at most one PUT;
   * never throws.
   */
  async healIfStale(): Promise<void> {
    if (!this.plugin.settings.aiChatKeySyncEnabled) return;
    const ctx = this.context();
    if (!ctx) return;

    try {
      const envelope = await ctx.apiClient.getAiKeyBlob(ctx.vaultId);
      if (envelope === null) {
        await this.uploadIfEnabled();
      } else if (await this.plugin.isAiKeyEnvelopeStale(envelope)) {
        await this.uploadIfEnabled();
      }
    } catch (e) {
      console.warn(`${LOG_PREFIX} API key heal check failed`, e);
    }
  }

  /**
   * Best-effort delete of the server blob — used when key sync is turned OFF or
   * the key is cleared. Deliberately does NOT gate on aiChatKeySyncEnabled (the
   * toggle-off handler flips it to false first, then calls this to clean up).
   */
  async deleteRemote(): Promise<void> {
    const ctx = this.context();
    if (!ctx) return;
    try {
      await ctx.apiClient.deleteAiKeyBlob(ctx.vaultId);
    } catch (e) {
      console.warn(`${LOG_PREFIX} could not delete the synced API key`, e);
    }
  }
}
