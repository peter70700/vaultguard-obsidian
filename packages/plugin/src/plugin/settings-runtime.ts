import { Notice, requestUrl } from "obsidian";
import { VaultGuardApiClient } from "../api/client";
import {
  normalizeVaultGuardApiBaseUrl,
  resolveVaultGuardApiBaseUrl,
} from "../api/endpoint-resolver";
import { probeSafeStorage } from "../crypto/safe-storage";
import {
  ASSUMED_SERVER_FEATURES,
  ConflictResolutionStrategy,
  type ServerEdition,
  type ServerFeatures,
  type UserSession,
  type VaultGuardSettings,
} from "../types";
import {
  DEFAULT_EXCLUDED_PATHS,
  DEFAULT_SETTINGS,
  SAAS_DEFAULTS,
} from "./settings";
import { deriveConnectionConfigFromTokenPayload } from "./session-config";
import type { PluginSettingsRuntimeContext } from "./plugin-runtime-types";

type VaultGuardPluginData = Partial<VaultGuardSettings> & {
  storedSessions?: Record<string, unknown>;
};

interface ProtectedSessionEnvelope {
  v: 1;
  storage: "electron-safe-storage" | "at-rest-cipher";
  ciphertext: string;
}

export class PluginSettingsRuntime {
  /** Vault-local storage key prefix for per-vault session persistence. */
  private static readonly SESSION_STORAGE_KEY_PREFIX = "vaultguard-session:";

  /**
   * Reasonable upper bound for a well-known config document. The legitimate
   * payload is ~500 bytes; 64 KB leaves ~125x headroom while preventing a
   * malicious server from exhausting Obsidian's memory with a multi-GB body.
   */
  private static readonly MANUAL_CONFIG_MAX_BYTES = 64 * 1024;

  /** Timeout for the manual config fetch — Obsidian's requestUrl has no abort. */
  private static readonly MANUAL_CONFIG_TIMEOUT_MS = 10_000;

  constructor(private readonly ctx: PluginSettingsRuntimeContext) {}

  async loadSettings(): Promise<void> {
    const data = ((await this.ctx.loadData()) ?? {}) as VaultGuardPluginData;
    this.ctx.setPersistedSessions(this.normalizePersistedSessions(data.storedSessions));
    delete data.storedSessions;
    this.ctx.setSettings(Object.assign({}, DEFAULT_SETTINGS, data));

    // Migrate the legacy single "show permission indicators" toggle into the
    // three granular display toggles. Object.assign above already seeded the
    // new keys from DEFAULT_SETTINGS (all `true`), so we must read the RAW
    // `data` object — not the merged `this.settings` — to detect whether the
    // user actually had the new keys persisted. Only when they are absent and
    // the user had explicitly set the old toggle do we carry that choice over.
    const legacyIndicators = (data as { showPermissionIndicators?: unknown }).showPermissionIndicators;
    const hasGranularKeys =
      typeof (data as { showMyPermissionLevel?: unknown }).showMyPermissionLevel === "boolean" ||
      typeof (data as { showOthersAccess?: unknown }).showOthersAccess === "boolean";
    if (!hasGranularKeys && typeof legacyIndicators === "boolean") {
      this.settings.showMyPermissionLevel = legacyIndicators;
      this.settings.showOthersAccess = legacyIndicators;
      // The note-header banner was always on regardless of the old toggle, so
      // it stays enabled by default after migration.
      this.settings.showPermissionBanner = true;
    }

    this.settings.defaultConflictResolution = this.normalizeConflictStrategy(
      this.settings.defaultConflictResolution,
    );
    this.settings.excludedPaths = this.withRequiredExcludedPaths(this.settings.excludedPaths);
    this.settings.apiEndpoint = normalizeVaultGuardApiBaseUrl(this.settings.apiEndpoint);
    this.ctx.setConfiguredApiEndpoint(this.settings.apiEndpoint);
    this.ctx.setServerEdition(this.normalizeServerEdition(this.settings.serverEdition));
    this.ctx.setServerFeatures(this.normalizeServerFeatures(this.settings.serverFeatures));

    // Initialize the tombstone map for legacy data.json that predates the field,
    // then prune any entries older than the TTL (or with malformed timestamps).
    // Do NOT saveSettings here — the next normal save persists the pruned set.
    if (!this.settings.deletionTombstones) this.settings.deletionTombstones = {};
    this.ctx.pruneDeletionTombstones();

    this.ctx.setDerivedBindingId(await this.computeDerivedVaultBindingId());
  }

  async saveSettings(): Promise<void> {
    const normalizedApiEndpoint = normalizeVaultGuardApiBaseUrl(this.settings.apiEndpoint);
    const apiEndpointChanged = normalizedApiEndpoint !== this.ctx.configuredApiEndpoint;
    this.settings.apiEndpoint = normalizedApiEndpoint;
    await this.ctx.savePluginData();

    if (apiEndpointChanged) {
      this.ctx.setConfiguredApiEndpoint(normalizedApiEndpoint);
      this.resetResolvedApiEndpoint();
      this.rebuildApiClient();
    }
  }

  async resetCloudConnectionDefaults(): Promise<void> {
    if (this.ctx.session) {
      await this.ctx.forceLogout("VaultGuard Sync: Logged out because the connection target changed.");
    }
    this.settings.manualConfig = false;
    this.clearResolvedConnectionFields();
    await this.saveSettings();
  }

  async setManualConfigurationMode(manualConfig: boolean): Promise<void> {
    if ((this.settings.manualConfig ?? false) === manualConfig) {
      return;
    }

    if (this.ctx.session) {
      await this.ctx.forceLogout("VaultGuard Sync: Logged out because the connection mode changed.");
    }

    this.settings.manualConfig = manualConfig;
    this.clearResolvedConnectionFields();
    await this.saveSettings();
  }

  getConnectionTargetLabel(): string {
    const config = this.getEffectiveConfig();
    const endpoint = config.apiEndpoint || "not configured";
    const mode = this.settings.manualConfig ? "manual/self-hosted" : "VaultGuard Cloud";
    const org =
      this.settings.orgSlug ||
      this.settings.organizationId ||
      (this.settings.manualConfig ? "" : "not connected");
    return org ? `${mode}: ${endpoint} (${org})` : `${mode}: ${endpoint}`;
  }

  async applyManualServerConfigUrl(rawUrl: string): Promise<void> {
    const url = this.normalizeManualServerConfigUrl(rawUrl);
    const pastedOrigin = new URL(url);

    // WR-04: bound the wait with a manual timeout (requestUrl has no native
    // abort path) so a stalled or pathological server can't hang the plugin.
    const response = await Promise.race([
      requestUrl({ url, method: "GET", throw: false }),
      new Promise<never>((_resolve, reject) =>
        setTimeout(
          () => reject(new Error("Server config request timed out after 10 seconds.")),
          PluginSettingsRuntime.MANUAL_CONFIG_TIMEOUT_MS,
        ),
      ),
    ]);

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Server returned ${response.status}`);
    }

    // WR-04: cap response size before doing any further parsing/work.
    const bodyText = response.text ?? "";
    if (bodyText.length > PluginSettingsRuntime.MANUAL_CONFIG_MAX_BYTES) {
      throw new Error(
        "Server config response is unexpectedly large; rejecting to prevent memory exhaustion.",
      );
    }

    // Strict shape: must be a JSON object literal (not null, not array, not primitive).
    if (
      !response.json ||
      typeof response.json !== "object" ||
      Array.isArray(response.json)
    ) {
      throw new Error("Invalid config response from server: expected a JSON object");
    }

    const config = response.json as Record<string, unknown>;

    // WR-05 + CR-01: validate the response shape AND enforce that any apiEndpoint
    // in the body shares the same hostname as the pasted URL. The well-known doc
    // is by RFC-8615 convention served from the API root, so the pasted URL's
    // host is the authoritative API host — the response body must not be allowed
    // to redirect the user to a different (attacker-controlled) host.
    this.validateWellKnownConfig(config, pastedOrigin);

    if (this.ctx.session) {
      await this.ctx.forceLogout("VaultGuard Sync: Logged out because the connection target changed.");
    }

    this.settings.manualConfig = true;
    // Use the pasted URL's origin as the apiEndpoint fallback when the body
    // omits it. When the body provides an apiEndpoint, it has just been
    // hostname-pinned to the pasted URL by validateWellKnownConfig.
    this.applyResolvedConnectionConfig(config, pastedOrigin.origin, this.settings.orgSlug);
    await this.saveSettings();
    this.rebuildApiClient();
  }

  getEffectiveConfig(): {
    apiEndpoint: string;
    cognitoUserPoolId: string;
    cognitoClientId: string;
    organizationId: string;
  } {
    if (this.settings.manualConfig) {
      return {
        apiEndpoint: this.settings.apiEndpoint,
        cognitoUserPoolId: this.settings.cognitoUserPoolId,
        cognitoClientId: this.settings.cognitoClientId,
        organizationId: this.settings.organizationId,
      };
    }
    return {
      apiEndpoint: this.settings.apiEndpoint || SAAS_DEFAULTS.apiEndpoint,
      cognitoUserPoolId: this.settings.cognitoUserPoolId || SAAS_DEFAULTS.cognitoUserPoolId,
      cognitoClientId: this.settings.cognitoClientId || SAAS_DEFAULTS.cognitoClientId,
      organizationId: this.settings.organizationId,
    };
  }

  rebuildApiClient(): void {
    if (this.ctx.apiClient) {
      this.ctx.apiClient.destroy();
      this.ctx.setApiClient(null);
    }

    const config = this.getEffectiveConfig();

    if (!config.apiEndpoint) {
      return;
    }

    const apiClient = new VaultGuardApiClient({
      baseUrl: config.apiEndpoint,
      orgId: config.organizationId,
      vaultId: this.settings.serverVaultId,
      getAuthTokens: async (forceRefresh = false) => {
        if (!this.ctx.session) {
          return null;
        }

        const expiresAt = new Date(this.ctx.session.tokenExpiresAt).getTime();
        if (forceRefresh || expiresAt - Date.now() <= 60_000) {
          const refreshResult = await this.ctx.refreshAccessToken(this.ctx.session);
          if (!refreshResult.ok) {
            return null;
          }
        }

        if (!this.ctx.session) {
          return null;
        }

        return {
          accessToken: this.ctx.session.accessToken,
          refreshToken: this.ctx.session.refreshToken,
          idToken: this.ctx.session.idToken,
          expiresAt: new Date(this.ctx.session.tokenExpiresAt).getTime(),
        };
      },
      getSessionId: () => this.ctx.session?.sessionId ?? null,
    });

    this.ctx.setApiClient(apiClient);
    if (this.ctx.session) {
      this.ctx.initializeApiClientFromSession(this.ctx.session);
    }
  }

  async getResolvedApiEndpoint(idToken?: string, probePath?: string): Promise<string> {
    const configuredApiEndpoint = normalizeVaultGuardApiBaseUrl(this.getEffectiveConfig().apiEndpoint);
    if (!configuredApiEndpoint) {
      return "";
    }

    if (this.ctx.resolvedApiEndpoint) {
      return this.ctx.resolvedApiEndpoint;
    }

    if (!idToken) {
      return configuredApiEndpoint;
    }

    if (this.ctx.apiEndpointResolutionPromise) {
      return await this.ctx.apiEndpointResolutionPromise;
    }

    const resolutionPromise = resolveVaultGuardApiBaseUrl(
      configuredApiEndpoint,
      idToken,
      probePath,
    );
    this.ctx.setApiEndpointResolutionPromise(resolutionPromise);

    try {
      const resolvedApiEndpoint = await resolutionPromise;
      this.ctx.setResolvedApiEndpoint(resolvedApiEndpoint);
      return resolvedApiEndpoint;
    } finally {
      if (this.ctx.apiEndpointResolutionPromise === resolutionPromise) {
        this.ctx.setApiEndpointResolutionPromise(null);
      }
    }
  }

  async resolveOrgConfig(slug: string, options: { silent?: boolean } = {}): Promise<void> {
    const slugCandidates = Array.from(
      new Set(
        [slug.trim().toLowerCase(), slug.trim().toLowerCase().replace(/^org-/, "")]
          .filter((value) => value.length > 0),
      ),
    );

    const fallbackBases = this.settings.manualConfig ? [] : [SAAS_DEFAULTS.fallbackApiUrl];
    const bases = Array.from(
      new Set(
        [
          this.getEffectiveConfig().apiEndpoint,
          ...fallbackBases,
        ].filter(Boolean),
      ),
    );

    // If no base URL at all, the user must enter one manually
    if (bases.length === 0) {
      throw new Error(
        "No API endpoint configured. Enter an API endpoint manually or ask your admin for the org slug.",
      );
    }

    let lastError: Error | null = null;

    for (const base of bases) {
      const normalizedBase = normalizeVaultGuardApiBaseUrl(base);

      for (const slugCandidate of slugCandidates) {
        const url = `${normalizedBase}/orgs/${encodeURIComponent(slugCandidate)}/config`;

        try {
          let response;
          try {
            response = await requestUrl({ url, method: "GET", throw: false });
          } catch {
            // A genuine network/connection failure (DNS, offline) — requestUrl
            // can still throw these even with throw:false. Surface a friendly
            // message and try the next base/slug candidate.
            lastError = new Error(
              "Couldn't reach the server. Check your internet connection and the org slug.",
            );
            continue;
          }

          if (response.status === 404) {
            throw new Error(`Organization "${slug}" not found. Check the slug and try again.`);
          }

          if (response.status === 401 || response.status === 403) {
            throw new Error(
              `The server rejected the connection for "${slug}". Double-check the org slug or ask your admin.`,
            );
          }

          if (response.status >= 500) {
            throw new Error(
              `"${slug}"'s server is temporarily unavailable. Please try again in a moment.`,
            );
          }

          if (response.status < 200 || response.status >= 300) {
            throw new Error(
              `Couldn't connect to "${slug}" (error ${response.status}). Check the slug and try again.`,
            );
          }

          const config = response.json;

          if (!config || typeof config !== "object") {
            throw new Error("Invalid config response from server");
          }

          this.applyResolvedConnectionConfig(
            config as Record<string, unknown>,
            normalizedBase,
            slugCandidate,
          );
          await this.saveSettings();

          // Rebuild the API client with new settings
          this.rebuildApiClient();

          this.ctx.log(`Org config resolved for "${this.settings.orgSlug}": API=${this.settings.apiEndpoint}`);
          if (!options.silent) {
            const orgName = this.readConfigString(config as Record<string, unknown>, "orgName");
            new Notice(`VaultGuard Sync: Connected to ${orgName || this.settings.orgSlug}`);
          }
          return;
        } catch (err) {
          lastError = err instanceof Error ? err : new Error(String(err));
        }
      }
    }

    throw lastError ?? new Error("Failed to resolve org configuration");
  }

  syncSettingsFromTokenPayload(
    payload: Record<string, unknown>,
    fallbackRoles: string[] = [],
  ): boolean {
    const derived = deriveConnectionConfigFromTokenPayload(payload, fallbackRoles);
    let changed = false;

    if (
      derived.organizationId &&
      derived.organizationId !== this.settings.organizationId
    ) {
      this.settings.organizationId = derived.organizationId;
      changed = true;
    }

    if (derived.orgSlug && derived.orgSlug !== this.settings.orgSlug) {
      this.settings.orgSlug = derived.orgSlug;
      changed = true;
    }

    if (
      derived.cognitoUserPoolId &&
      derived.cognitoUserPoolId !== this.settings.cognitoUserPoolId
    ) {
      this.settings.cognitoUserPoolId = derived.cognitoUserPoolId;
      changed = true;
    }

    if (
      derived.cognitoClientId &&
      derived.cognitoClientId !== this.settings.cognitoClientId
    ) {
      this.settings.cognitoClientId = derived.cognitoClientId;
      changed = true;
    }

    return changed;
  }

  async savePluginData(): Promise<void> {
    const saveOperation = this.ctx.pluginDataSaveQueue
      .catch(() => undefined)
      .then(async () => {
        await this.ctx.saveData(this.buildPluginData());
      });

    this.ctx.setPluginDataSaveQueue(saveOperation);
    await saveOperation;
  }

  async computeDerivedVaultBindingId(): Promise<string> {
    const vault = (this.ctx.app as unknown as {
      vault?: {
        adapter?: Partial<{
          getBasePath: () => string;
          basePath: string;
        }>;
        getName?: () => string;
      };
    } | undefined)?.vault;
    const adapter = vault?.adapter as Partial<{
      getBasePath: () => string;
      basePath: string;
    }> | undefined;
    let basePath = "";
    try {
      basePath =
        typeof adapter?.getBasePath === "function"
          ? adapter.getBasePath() ?? ""
          : adapter?.basePath ?? "";
    } catch {
      basePath = "";
    }
    const appId = (
      (this.ctx.app as unknown as { appId?: string } | undefined)?.appId ?? ""
    ).toString();
    let vaultName = "";
    try {
      vaultName = typeof vault?.getName === "function" ? vault.getName() ?? "" : "";
    } catch {
      vaultName = "";
    }

    const fingerprintInput = [basePath, appId, vaultName]
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .join("|");

    if (fingerprintInput) {
      const hash = await this.ctx.computeHash(`vaultguard-vault::${fingerprintInput}`);
      return hash.slice(0, 32);
    }

    // No usable runtime identifier — fall back to a random ID persisted only
    // to data.json (per-vault on disk), which still avoids the shared-storage
    // collision because each vault generates its own.
    if (!this.settings.vaultBindingId) {
      this.settings.vaultBindingId = PluginSettingsRuntime.generateVaultBindingId();
      await this.ctx.savePluginData();
    }
    return this.settings.vaultBindingId;
  }

  protectSessionForStorage(session: UserSession): ProtectedSessionEnvelope | null {
    const safeStorage = probeSafeStorage();
    if (!safeStorage) return null;

    try {
      const encrypted = safeStorage.encryptString(JSON.stringify(session));
      const bytes = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
      return {
        v: 1,
        storage: "electron-safe-storage",
        ciphertext: this.bytesToBase64(bytes),
      };
    } catch (error) {
      this.ctx.logError("Failed to protect session with safeStorage", error);
      return null;
    }
  }

  async protectSessionWithAtRest(
    session: UserSession,
  ): Promise<ProtectedSessionEnvelope | null> {
    const cipher = this.ctx.atRestCipher;
    if (!cipher?.isReady()) return null;

    try {
      const ciphertext = await cipher.encryptString(JSON.stringify(session));
      const bytes = new Uint8Array(ciphertext);
      return {
        v: 1,
        storage: "at-rest-cipher",
        ciphertext: this.bytesToBase64(bytes),
      };
    } catch (error) {
      this.ctx.logError("Failed to protect session with AtRestCipher", error);
      return null;
    }
  }

  unprotectStoredSession(value: unknown): UserSession | null {
    if (!value || typeof value !== "object") return null;
    const envelope = value as Partial<ProtectedSessionEnvelope>;
    if (
      envelope.v !== 1 ||
      !this.isNonEmptyString(envelope.ciphertext) ||
      envelope.storage !== "electron-safe-storage"
    ) {
      return null;
    }

    const safeStorage = probeSafeStorage();
    if (!safeStorage) {
      this.notifySafeStorageUnavailable();
      return null;
    }

    try {
      const plaintext = safeStorage.decryptString(this.base64ToBytes(envelope.ciphertext));
      const parsed = JSON.parse(plaintext) as Partial<UserSession>;
      return this.materializeSession(parsed);
    } catch (error) {
      this.ctx.logError("Failed to restore protected session", error);
      return null;
    }
  }

  async unprotectAtRestSession(value: unknown): Promise<UserSession | null> {
    if (!value || typeof value !== "object") return null;
    const envelope = value as Partial<ProtectedSessionEnvelope>;
    if (
      envelope.v !== 1 ||
      envelope.storage !== "at-rest-cipher" ||
      !this.isNonEmptyString(envelope.ciphertext)
    ) {
      return null;
    }

    const cipher = this.ctx.atRestCipher;
    if (!cipher?.isReady()) {
      // The LAK isn't loaded (cipher in needs-recovery / disabled state).
      // We can't decrypt the envelope; treat it as "no session" so the
      // user re-authenticates. No Notice — the cipher init path already
      // surfaces its own banner when this happens.
      return null;
    }

    try {
      const ciphertext = this.base64ToBytes(envelope.ciphertext);
      const plaintext = await cipher.decryptString(ciphertext);
      const parsed = JSON.parse(plaintext) as Partial<UserSession>;
      return this.materializeSession(parsed);
    } catch (error) {
      this.ctx.logError("Failed to restore at-rest-protected session", error);
      return null;
    }
  }

  loadSessionFromStore(): UserSession | null {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return null;

    try {
      const raw: unknown = this.ctx.app.loadLocalStorage(this.getSessionStorageKey(bindingId));
      if (raw) {
        const session = this.unprotectStoredSession(raw);
        if (session) return session;
      }
    } catch {
      // Fall through to data.json backup.
    }

    return this.unprotectStoredSession(this.ctx.persistedSessions[bindingId]);
  }

  async loadAtRestSessionFromStore(): Promise<UserSession | null> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return null;

    try {
      const raw: unknown = this.ctx.app.loadLocalStorage(this.getSessionStorageKey(bindingId));
      if (raw) {
        const session = await this.unprotectAtRestSession(raw);
        if (session) return session;
      }
    } catch {
      // Fall through to data.json backup.
    }

    return this.unprotectAtRestSession(this.ctx.persistedSessions[bindingId]);
  }

  async persistSession(session: UserSession): Promise<void> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return;

    // Wave 2 issue A (1.0.31): stamp the last-known vaultMemberRole
    // onto the session before sealing. On the next plugin reload,
    // restoreSession reads this back so the initial warmup uses the
    // real role instead of synthesizing one from session.role —
    // closes the race that mattered for users whose org role and
    // vault role disagree.
    const sessionToPersist: UserSession = {
      ...session,
      vaultMemberRole: this.ctx.vaultMemberRole ?? session.vaultMemberRole ?? null,
    };

    let protectedSession = this.ctx.protectSessionForStorage(sessionToPersist) as
      | ProtectedSessionEnvelope
      | null;
    if (!protectedSession) {
      // Desktop with broken keychain or mobile renderer — try the at-rest
      // cipher before warning. On mobile this is the normal path and the
      // user shouldn't see any Notice at all.
      protectedSession = await this.ctx.protectSessionWithAtRest(sessionToPersist) as
        | ProtectedSessionEnvelope
        | null;
    }
    if (!protectedSession) {
      this.notifySafeStorageUnavailable();
      return;
    }

    const persistedSessions = {
      ...this.ctx.persistedSessions,
      [bindingId]: protectedSession,
    };
    this.ctx.setPersistedSessions(persistedSessions);
    try {
      this.ctx.app.saveLocalStorage(this.getSessionStorageKey(bindingId), protectedSession);
    } catch (error) {
      this.ctx.logError("Failed to persist session to Obsidian local storage", error);
    }

    try {
      await this.ctx.savePluginData();
      this.ctx.log(`Session persisted for ${session.displayName}`);
    } catch (error) {
      this.ctx.logError("Failed to persist session to Obsidian data store", error);
    }
  }

  async clearStoredSession(): Promise<void> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return;

    const persistedSessions = { ...this.ctx.persistedSessions };
    delete persistedSessions[bindingId];
    this.ctx.setPersistedSessions(persistedSessions);
    this.removeStoredSessionKey(bindingId);

    try {
      await this.ctx.savePluginData();
    } catch (error) {
      this.ctx.logError("Failed to remove persisted session from Obsidian data store", error);
    }

    this.ctx.log("Stored session cleared.");
  }

  normalizePersistedSessions(
    storedSessions: Record<string, unknown> | undefined,
  ): Record<string, unknown> {
    if (!storedSessions || typeof storedSessions !== "object") return {};

    const normalized: Record<string, unknown> = {};
    for (const [bindingId, value] of Object.entries(storedSessions)) {
      if (!value || typeof value !== "object") continue;
      const envelope = value as Partial<ProtectedSessionEnvelope>;
      const storage = envelope.storage;
      if (
        envelope.v === 1 &&
        (storage === "electron-safe-storage" || storage === "at-rest-cipher") &&
        this.isNonEmptyString(envelope.ciphertext)
      ) {
        normalized[bindingId] = value;
      }
    }
    return normalized;
  }

  materializeSession(parsed: Partial<UserSession> | null): UserSession | null {
    if (!parsed || typeof parsed !== "object") return null;
    if (
      !this.isNonEmptyString(parsed.userId) ||
      !this.isNonEmptyString(parsed.refreshToken) ||
      !this.isNonEmptyString(parsed.idToken) ||
      !this.isNonEmptyString(parsed.accessToken) ||
      !this.isNonEmptyString(parsed.tokenExpiresAt) ||
      !this.isNonEmptyString(parsed.organizationId) ||
      !this.isNonEmptyString(parsed.displayName) ||
      !this.isNonEmptyString(parsed.email) ||
      !this.isValidSessionRole(parsed.role) ||
      !this.isNonEmptyString(parsed.createdAt)
    ) {
      return null;
    }

    const roles = Array.isArray(parsed.roles)
      ? parsed.roles.filter((role): role is string => this.isNonEmptyString(role))
      : [];

    return {
      sessionId: this.isNonEmptyString(parsed.sessionId) ? parsed.sessionId : "",
      userId: parsed.userId,
      organizationId: parsed.organizationId,
      displayName: parsed.displayName,
      email: parsed.email,
      accessToken: parsed.accessToken,
      idToken: parsed.idToken,
      refreshToken: parsed.refreshToken,
      tokenExpiresAt: parsed.tokenExpiresAt,
      role: parsed.role,
      roles: roles.length > 0 ? roles : [parsed.role],
      createdAt: parsed.createdAt,
      // Wave 2 issue A (1.0.31): preserve the last-known vault role
      // across plugin reloads. Optional, so older envelopes without
      // the field stay valid; `null` means "we don't know, fall back
      // to the synthesized derivation".
      vaultMemberRole: this.isValidVaultMemberRole(parsed.vaultMemberRole)
        ? parsed.vaultMemberRole
        : null,
    };
  }

  cacheServerCapabilities(config: Record<string, unknown>): boolean {
    const edition = this.normalizeServerEdition(config.edition) ?? "pro";
    const features =
      this.normalizeServerFeatures(config.features) ??
      (edition === "community"
        ? this.communityServerFeatures()
        : { ...ASSUMED_SERVER_FEATURES });

    const changed =
      this.ctx.serverEdition !== edition ||
      !this.ctx.serverFeatures ||
      this.ctx.serverFeatures.shareLinks !== features.shareLinks ||
      this.ctx.serverFeatures.advancedAudit !== features.advancedAudit ||
      this.ctx.serverFeatures.billing !== features.billing ||
      this.ctx.serverFeatures.webAdmin !== features.webAdmin;

    this.ctx.setServerEdition(edition);
    this.ctx.setServerFeatures({ ...features });
    this.settings.serverEdition = edition;
    this.settings.serverFeatures = { ...features };
    this.settings.serverFeaturesResolvedAt = new Date().toISOString();
    return changed;
  }

  async refreshServerCapabilitiesFromConfiguredEndpoint(): Promise<boolean> {
    const cfg = this.getEffectiveConfig();
    const base = normalizeVaultGuardApiBaseUrl(cfg.apiEndpoint);
    const identifiers = Array.from(
      new Set(
        [
          this.settings.orgSlug,
          cfg.organizationId,
        ]
          .map((value) => (value ?? "").trim())
          .filter((value) => value.length > 0),
      ),
    );

    if (!base || identifiers.length === 0) {
      return false;
    }

    let lastError: Error | null = null;
    for (const identifier of identifiers) {
      const url = `${base}/orgs/${encodeURIComponent(identifier)}/config`;
      try {
        const response = await requestUrl({ url, method: "GET", throw: false });
        if (response.status === 404) {
          continue;
        }
        if (response.status === 401 || response.status === 403) {
          return false;
        }
        if (response.status < 200 || response.status >= 300) {
          lastError = new Error(`Server returned ${response.status}`);
          continue;
        }
        if (!response.json || typeof response.json !== "object") {
          lastError = new Error("Invalid config response from server");
          continue;
        }

        const config = response.json as Record<string, unknown>;
        if (typeof config.orgSlug === "string" && config.orgSlug) {
          this.settings.orgSlug = config.orgSlug;
        }
        const changed = this.cacheServerCapabilities(config);
        await this.saveSettings();
        return changed;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    if (lastError) {
      this.ctx.logError("Server capability discovery failed", lastError);
    }
    return false;
  }

  readConfigString(config: Record<string, unknown>, key: string): string {
    const value = config[key];
    return typeof value === "string" ? value.trim() : "";
  }

  applyResolvedConnectionConfig(
    config: Record<string, unknown>,
    fallbackApiEndpoint: string,
    fallbackOrgSlug = "",
  ): void {
    const cognitoUserPoolId = this.readConfigString(config, "cognitoUserPoolId");
    const cognitoClientId = this.readConfigString(config, "cognitoClientId");
    if (!cognitoUserPoolId || !cognitoClientId) {
      throw new Error("Invalid config response from server");
    }

    const apiEndpoint = normalizeVaultGuardApiBaseUrl(
      this.readConfigString(config, "apiEndpoint") || fallbackApiEndpoint,
    );
    if (!apiEndpoint) {
      throw new Error("Invalid config response from server: missing API endpoint");
    }

    const orgSlug = this.readConfigString(config, "orgSlug") || fallbackOrgSlug;
    const organizationId =
      this.readConfigString(config, "orgId") ||
      this.readConfigString(config, "organizationId");

    if (orgSlug) {
      this.settings.orgSlug = orgSlug;
    }
    this.settings.apiEndpoint = apiEndpoint;
    this.settings.organizationId = organizationId;
    this.settings.cognitoUserPoolId = cognitoUserPoolId;
    this.settings.cognitoClientId = cognitoClientId;
    this.cacheServerCapabilities(config);
  }

  normalizeServerEdition(value: unknown): ServerEdition | null {
    return value === "community" || value === "pro" ? value : null;
  }

  normalizeServerFeatures(value: unknown): ServerFeatures | null {
    if (!value || typeof value !== "object") {
      return null;
    }
    const features = value as Partial<Record<keyof ServerFeatures, unknown>>;
    return {
      shareLinks: Boolean(features.shareLinks),
      advancedAudit: Boolean(features.advancedAudit),
      billing: Boolean(features.billing),
      webAdmin: Boolean(features.webAdmin),
    };
  }

  private get settings(): VaultGuardSettings {
    return this.ctx.settings;
  }

  private buildPluginData(): VaultGuardPluginData {
    return {
      ...this.settings,
      storedSessions: this.ctx.persistedSessions,
    };
  }

  private normalizeConflictStrategy(value: unknown): ConflictResolutionStrategy {
    switch (value) {
      case ConflictResolutionStrategy.ASK_USER:
      case ConflictResolutionStrategy.KEEP_LOCAL:
      case ConflictResolutionStrategy.KEEP_REMOTE:
      case ConflictResolutionStrategy.DUPLICATE:
        return value;
      default:
        return ConflictResolutionStrategy.DUPLICATE;
    }
  }

  private communityServerFeatures(): ServerFeatures {
    return {
      shareLinks: false,
      advancedAudit: false,
      billing: false,
      webAdmin: false,
    };
  }

  private withRequiredExcludedPaths(paths: string[] | undefined): string[] {
    const merged: string[] = [];
    const seen = new Set<string>();

    const add = (path: string): void => {
      const cleaned = path.trim().replace(/^\/+/, "").replace(/\/+$/, "");
      if (!cleaned || seen.has(cleaned)) return;
      seen.add(cleaned);
      merged.push(cleaned);
    };

    for (const path of paths ?? []) {
      add(path);
    }
    for (const path of DEFAULT_EXCLUDED_PATHS) {
      add(path);
    }

    return merged;
  }

  private clearResolvedConnectionFields(): void {
    this.settings.orgSlug = "";
    this.settings.apiEndpoint = "";
    this.settings.organizationId = "";
    this.settings.cognitoUserPoolId = "";
    this.settings.cognitoClientId = "";
    this.settings.serverEdition = undefined;
    this.settings.serverFeatures = undefined;
    this.settings.serverFeaturesResolvedAt = undefined;
    this.ctx.setServerEdition(null);
    this.ctx.setServerFeatures(null);
  }

  private assertHttpsOrLocalhostUrl(rawUrl: string, label: string): URL {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl.trim());
    } catch {
      throw new Error(`Enter a valid ${label}.`);
    }

    const hostname = parsed.hostname.toLowerCase();
    const isLocalhost =
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      hostname === "[::1]";
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocalhost)) {
      throw new Error(`${label} must use HTTPS, except localhost during development.`);
    }

    return parsed;
  }

  private normalizeManualServerConfigUrl(rawUrl: string): string {
    const parsed = this.assertHttpsOrLocalhostUrl(rawUrl, "server config URL");
    return parsed.toString();
  }

  private validateWellKnownConfig(
    config: Record<string, unknown>,
    pastedOrigin: URL,
  ): void {
    const cognitoUserPoolId = this.readConfigString(config, "cognitoUserPoolId");
    const cognitoClientId = this.readConfigString(config, "cognitoClientId");
    if (!cognitoUserPoolId || !cognitoClientId) {
      throw new Error("Invalid config response from server: missing Cognito identifiers");
    }

    // Cognito User Pool IDs follow `<region>_<random>` where region is a
    // standard AWS region name. Reject anything that doesn't match — a real
    // server can never return e.g. an HTML error page parsed as a string here.
    if (!/^[a-z]{2}-[a-z]+-\d+_[A-Za-z0-9]{6,}$/.test(cognitoUserPoolId)) {
      throw new Error(
        "Invalid config response from server: cognitoUserPoolId is not a valid Cognito pool identifier",
      );
    }

    // Cognito App Client IDs are 20-26 lowercase alphanumeric characters.
    if (!/^[a-z0-9]{20,26}$/.test(cognitoClientId)) {
      throw new Error(
        "Invalid config response from server: cognitoClientId is not a valid Cognito app client identifier",
      );
    }

    // orgSlug (if present) must match the backend's slug regex.
    const orgSlug = this.readConfigString(config, "orgSlug");
    if (orgSlug && !/^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/.test(orgSlug)) {
      throw new Error(
        "Invalid config response from server: orgSlug is not a valid identifier",
      );
    }

    // CR-01: any apiEndpoint in the response body must point at the same host
    // the user pasted. We never honor a body-supplied redirect to a different
    // host — that would let a malicious .well-known doc silently route the
    // user's credentials and encrypted vault traffic to attacker infrastructure.
    const apiEndpoint = this.readConfigString(config, "apiEndpoint");
    if (apiEndpoint) {
      let parsed: URL;
      try {
        parsed = new URL(apiEndpoint);
      } catch {
        throw new Error(
          "Invalid config response from server: apiEndpoint is not a parseable URL",
        );
      }
      this.assertHttpsOrLocalhostUrl(apiEndpoint, "API endpoint");
      if (parsed.hostname.toLowerCase() !== pastedOrigin.hostname.toLowerCase()) {
        throw new Error(
          `Invalid config response from server: apiEndpoint host (${parsed.hostname}) does not match the pasted URL host (${pastedOrigin.hostname}). To use a separate API host, paste that host's /.well-known/vaultguard.json URL directly.`,
        );
      }
    }
  }

  private resetResolvedApiEndpoint(): void {
    this.ctx.setResolvedApiEndpoint(null);
    this.ctx.setApiEndpointResolutionPromise(null);
  }

  private static generateVaultBindingId(): string {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }

    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0"),
    );

    return [
      hex.slice(0, 4).join(""),
      hex.slice(4, 6).join(""),
      hex.slice(6, 8).join(""),
      hex.slice(8, 10).join(""),
      hex.slice(10, 16).join(""),
    ].join("-");
  }

  private getSessionBindingId(): string | null {
    if (!this.ctx.derivedBindingId) {
      this.ctx.log(
        "Derived vault binding ID is not yet available; refusing to use shared session storage.",
      );
      return null;
    }

    return this.ctx.derivedBindingId;
  }

  private getSessionStorageKey(bindingId: string): string {
    return `${PluginSettingsRuntime.SESSION_STORAGE_KEY_PREFIX}${bindingId}`;
  }

  private removeStoredSessionKey(bindingId: string): void {
    try {
      this.ctx.app.saveLocalStorage(this.getSessionStorageKey(bindingId), null);
    } catch {
      // Storage may be unavailable in tests or restricted renderer contexts.
    }
  }

  private notifySafeStorageUnavailable(): void {
    if (this.ctx.safeStorageUnavailableNotified) return;
    this.ctx.setSafeStorageUnavailableNotified(true);
    this.ctx.log(
      "No secure session storage available (safeStorage unreachable AND at-rest cipher unavailable) — session will not be persisted to disk.",
    );
    new Notice(
      "VaultGuard Sync: Your platform doesn't expose secure credential storage. " +
        "You'll need to log in each time the plugin loads — we never store " +
        "auth tokens in plaintext.",
      10000,
    );
  }

  private isValidVaultMemberRole(
    value: unknown,
  ): value is "admin" | "editor" | "viewer" {
    return value === "admin" || value === "editor" || value === "viewer";
  }

  private isValidSessionRole(value: unknown): value is UserSession["role"] {
    return (
      value === "member" ||
      value === "editor" ||
      value === "admin" ||
      value === "owner"
    );
  }

  private isNonEmptyString(value: unknown): value is string {
    return typeof value === "string" && value.trim().length > 0;
  }

  private base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  private bytesToBase64(bytes: Uint8Array): string {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

export function createPluginSettingsRuntime(
  ctx: PluginSettingsRuntimeContext,
): PluginSettingsRuntime {
  return new PluginSettingsRuntime(ctx);
}
