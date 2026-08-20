import type { SafeStorageLike } from "../crypto/safe-storage";

/**
 * Same-device uninstall/reinstall recovery for the local at-rest key material.
 *
 * The vault-root manifest is deliberately non-secret. Every field that can name
 * an account or server vault lives only inside the authenticated capsule. The
 * capsule never contains a plaintext LAK: it carries the already device-wrapped
 * `lak.envelope`, or (for require-PIN-on-startup) only the PIN envelope and its
 * sealed pepper/settings.
 */

export const LOCAL_RECOVERY_ROOT = ".vaultguard";
export const LOCAL_RECOVERY_MANIFEST_PATH = `${LOCAL_RECOVERY_ROOT}/manifest.v1.json`;
export const LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH =
  `${LOCAL_RECOVERY_ROOT}/manifest.v1.previous.json`;
export const LOCAL_RECOVERY_SCHEMA = 1 as const;
export const LOCAL_RECOVERY_MAX_PROFILE_ENTRIES = 16;

const MANIFEST_NEXT_PATH = `${LOCAL_RECOVERY_ROOT}/manifest.v1.next.json`;
const PROFILE_INDEX_KEY = "vaultguard.local-recovery.index.v1";
const PROFILE_DEVICE_ID_KEY = "vaultguard.local-recovery.device.v1";
const PROFILE_CAPSULE_PREFIX = "vaultguard.local-recovery.capsule.v1";
const AES_GCM_NONCE_BYTES = 12;

export interface LocalRecoveryBindingHint {
  serverVaultId: string;
  serverVaultName?: string;
  serverVaultSlug?: string;
  organizationId?: string;
  accountUserId?: string;
  /**
   * Display only, so a returning session can NAME the account that connected
   * this folder instead of saying "a different account". Lives in the
   * authenticated capsule alongside `accountUserId` — never in the vault-root
   * manifest, which stays non-secret. Optional: capsules written before this
   * field existed simply fall back to the anonymous wording.
   */
  accountEmail?: string;
}

export interface LocalRecoveryConnectionHint {
  orgSlug?: string;
  apiEndpoint?: string;
  organizationId?: string;
  cognitoUserPoolId?: string;
  cognitoClientId?: string;
  manualConfig?: boolean;
}

export interface LocalRecoveryDeviceState {
  /** Existing device-local safeStorage/fallback wrapper. Never a plaintext LAK. */
  wrappedLak?: string;
  /** PIN-derived LAK wrapper. Required for max-security recovery. */
  pinEnvelope?: string;
  /** safeStorage-wrapped (or documented degraded-tier) PIN pepper. */
  pinPepperWrapped?: string;
  pinState?: {
    enrolled: boolean;
    failedAttempts: number;
    lockedUntil: number | null;
  };
  requirePinOnStartup: boolean;
  pinOnboardingPromptShown?: boolean;
  binding?: LocalRecoveryBindingHint;
  connection?: LocalRecoveryConnectionHint;
}

export interface LocalRecoveryManifestV1 {
  schema: 1;
  vaultInstanceId: string;
  protectionMarker: "vaultguard-local-at-rest";
  capsule: {
    capsuleId: string;
    deviceId: string;
    currentGeneration: number;
    previousGeneration?: number;
  };
}

export interface LocalRecoveryCapsuleIo {
  readVault(path: string): Promise<string | null>;
  writeVault(path: string, value: string): Promise<void>;
  renameVault(from: string, to: string): Promise<void>;
  removeVault(path: string): Promise<void>;
  listVaultRecoveryFiles?(): Promise<string[]>;
  ensureVaultRecoveryRoot(): Promise<void>;
  loadProfile(key: string): unknown;
  saveProfile(key: string, value: unknown): void;
}

export type LocalRecoveryCopy = "vault" | "profile";

export type LocalRecoveryRestoreResult =
  | { kind: "none"; priorProtectionEvidence: false }
  | {
      kind: "needs-recovery";
      priorProtectionEvidence: true;
      reason: string;
    }
  | {
      kind: "restored";
      priorProtectionEvidence: true;
      state: LocalRecoveryDeviceState;
      generation: number;
      vaultInstanceId: string;
      capsuleId: string;
      source: LocalRecoveryCopy;
    };

export interface LocalRecoveryPersistResult {
  vaultInstanceId: string;
  capsuleId: string;
  generation: number;
  copies: LocalRecoveryCopy[];
}

type SealedCapsuleV1 = {
  schema: 1;
  vaultInstanceId: string;
  capsuleId: string;
  deviceId: string;
  generation: number;
  storage: "electron-safe-storage" | "fallback-kek";
  nonce?: string;
  ciphertext: string;
};

type CapsulePlaintextV1 = {
  schema: 1;
  vaultInstanceId: string;
  capsuleId: string;
  deviceId: string;
  generation: number;
  vaultLocator: string;
  state: LocalRecoveryDeviceState;
};

type ProfileIndexV1 = {
  schema: 1;
  entries: Array<{
    locatorHash: string;
    vaultInstanceId: string;
    capsuleId: string;
    deviceId: string;
    currentGeneration: number;
    previousGeneration?: number;
    updatedAt: number;
  }>;
};

type CapsuleCandidate = {
  source: LocalRecoveryCopy;
  serialized: string;
  vaultInstanceId: string;
  capsuleId: string;
  deviceId: string;
  allowedGenerations: Set<number>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{32}$/.test(value);
}

function isNonEmptyString(value: unknown, max = 16_384): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

function parseManifest(value: string | null): LocalRecoveryManifestV1 | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isRecord(parsed) || parsed.schema !== 1) return null;
    if (!isIdentifier(parsed.vaultInstanceId)) return null;
    if (parsed.protectionMarker !== "vaultguard-local-at-rest") return null;
    if (!isRecord(parsed.capsule)) return null;
    const capsule = parsed.capsule;
    if (!isIdentifier(capsule.capsuleId) || !isIdentifier(capsule.deviceId)) return null;
    if (!Number.isSafeInteger(capsule.currentGeneration) || Number(capsule.currentGeneration) < 1) {
      return null;
    }
    if (
      capsule.previousGeneration !== undefined &&
      (!Number.isSafeInteger(capsule.previousGeneration) || Number(capsule.previousGeneration) < 1)
    ) {
      return null;
    }
    return parsed as unknown as LocalRecoveryManifestV1;
  } catch {
    return null;
  }
}

function parseProfileIndex(value: unknown): ProfileIndexV1 {
  if (!isRecord(value) || value.schema !== 1 || !Array.isArray(value.entries)) {
    return { schema: 1, entries: [] };
  }
  const entries = value.entries.filter((entry): entry is ProfileIndexV1["entries"][number] => {
    if (!isRecord(entry)) return false;
    return (
      isNonEmptyString(entry.locatorHash, 64) &&
      isIdentifier(entry.vaultInstanceId) &&
      isIdentifier(entry.capsuleId) &&
      isIdentifier(entry.deviceId) &&
      Number.isSafeInteger(entry.currentGeneration) &&
      Number(entry.currentGeneration) >= 1 &&
      Number.isFinite(entry.updatedAt)
    );
  });
  return { schema: 1, entries: entries.slice(0, LOCAL_RECOVERY_MAX_PROFILE_ENTRIES) };
}

function parseSealedCapsule(value: string): SealedCapsuleV1 | null {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isRecord(parsed) || parsed.schema !== 1) return null;
    if (
      !isIdentifier(parsed.vaultInstanceId) ||
      !isIdentifier(parsed.capsuleId) ||
      !isIdentifier(parsed.deviceId) ||
      !Number.isSafeInteger(parsed.generation) ||
      Number(parsed.generation) < 1 ||
      (parsed.storage !== "electron-safe-storage" && parsed.storage !== "fallback-kek") ||
      !isNonEmptyString(parsed.ciphertext, 256_000)
    ) {
      return null;
    }
    if (parsed.storage === "fallback-kek" && !isNonEmptyString(parsed.nonce, 128)) return null;
    return parsed as unknown as SealedCapsuleV1;
  } catch {
    return null;
  }
}

function validateDeviceState(value: unknown): LocalRecoveryDeviceState | null {
  if (!isRecord(value) || typeof value.requirePinOnStartup !== "boolean") return null;
  const wrappedLak = value.wrappedLak;
  const pinEnvelope = value.pinEnvelope;
  const pinPepperWrapped = value.pinPepperWrapped;
  if (wrappedLak !== undefined && !isNonEmptyString(wrappedLak, 64_000)) return null;
  if (pinEnvelope !== undefined && !isNonEmptyString(pinEnvelope, 64_000)) return null;
  if (pinPepperWrapped !== undefined && !isNonEmptyString(pinPepperWrapped, 64_000)) return null;
  if (value.requirePinOnStartup && wrappedLak !== undefined) return null;
  if (value.requirePinOnStartup && pinEnvelope === undefined) return null;
  if (wrappedLak === undefined && pinEnvelope === undefined) return null;
  if (value.pinState !== undefined) {
    if (!isRecord(value.pinState) || typeof value.pinState.enrolled !== "boolean") return null;
    if (!Number.isSafeInteger(value.pinState.failedAttempts) || Number(value.pinState.failedAttempts) < 0) {
      return null;
    }
    if (
      value.pinState.lockedUntil !== null &&
      (!Number.isFinite(value.pinState.lockedUntil) || Number(value.pinState.lockedUntil) < 0)
    ) {
      return null;
    }
    if (value.requirePinOnStartup && value.pinState.enrolled !== true) return null;
  }
  if (value.binding !== undefined) {
    if (!isRecord(value.binding) || !isNonEmptyString(value.binding.serverVaultId, 256)) return null;
    for (const key of [
      "serverVaultName",
      "serverVaultSlug",
      "organizationId",
      "accountUserId",
      "accountEmail",
    ] as const) {
      const candidate = value.binding[key];
      if (candidate !== undefined && !isNonEmptyString(candidate, 512)) return null;
    }
  }
  if (value.connection !== undefined) {
    if (!isRecord(value.connection)) return null;
    for (const key of [
      "orgSlug",
      "apiEndpoint",
      "organizationId",
      "cognitoUserPoolId",
      "cognitoClientId",
    ] as const) {
      const candidate = value.connection[key];
      if (candidate !== undefined && !isNonEmptyString(candidate, 2048)) return null;
    }
    if (value.connection.manualConfig !== undefined && typeof value.connection.manualConfig !== "boolean") {
      return null;
    }
  }
  if (
    value.pinOnboardingPromptShown !== undefined &&
    typeof value.pinOnboardingPromptShown !== "boolean"
  ) {
    return null;
  }
  return value as unknown as LocalRecoveryDeviceState;
}

function bytesToBase64(bytes: Uint8Array): string {
  const chunk = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode.apply(
      null,
      bytes.subarray(offset, offset + chunk) as unknown as number[],
    );
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function randomIdentifier(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(value: string): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
  );
  return Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function capsuleVaultPath(capsuleId: string, slot: "current" | "previous" | "next"): string {
  return `${LOCAL_RECOVERY_ROOT}/capsule.${capsuleId}.${slot}.v1.json`;
}

function capsuleProfileKey(capsuleId: string, slot: "current" | "previous"): string {
  return `${PROFILE_CAPSULE_PREFIX}:${capsuleId}:${slot}`;
}

function capsuleAad(capsule: Pick<SealedCapsuleV1, "vaultInstanceId" | "capsuleId" | "deviceId" | "generation">): Uint8Array {
  return new TextEncoder().encode(
    `vaultguard-local-recovery:v1:${capsule.vaultInstanceId}:${capsule.capsuleId}:${capsule.deviceId}:${capsule.generation}`,
  );
}

export class LocalRecoveryCapsuleStore {
  constructor(
    private readonly io: LocalRecoveryCapsuleIo,
    private readonly vaultLocator: string,
    private readonly safeStorage: SafeStorageLike | null,
    private readonly fallbackKekBase64: string | null,
  ) {}

  async hasPriorProtectionEvidence(hasVg1: boolean): Promise<boolean> {
    if (hasVg1) return true;
    if ((await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH)) !== null) return true;
    if ((await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH)) !== null) return true;
    const locatorHash = await sha256Hex(this.vaultLocator);
    return parseProfileIndex(this.io.loadProfile(PROFILE_INDEX_KEY)).entries.some(
      (entry) => entry.locatorHash === locatorHash,
    );
  }

  async restore(hasVg1: boolean): Promise<LocalRecoveryRestoreResult> {
    const currentRaw = await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH);
    const previousRaw = await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH);
    const currentManifest = parseManifest(currentRaw);
    const previousManifest = parseManifest(previousRaw);
    const locatorHash = await sha256Hex(this.vaultLocator);
    const profileEntry = parseProfileIndex(this.io.loadProfile(PROFILE_INDEX_KEY)).entries.find(
      (entry) => entry.locatorHash === locatorHash,
    );
    const evidence = hasVg1 || currentRaw !== null || previousRaw !== null || profileEntry !== undefined;
    if (!evidence) return { kind: "none", priorProtectionEvidence: false };

    const candidates: CapsuleCandidate[] = [];
    const addManifestCandidates = async (manifest: LocalRecoveryManifestV1 | null): Promise<void> => {
      if (!manifest) return;
      const allowed = new Set<number>([manifest.capsule.currentGeneration]);
      if (manifest.capsule.previousGeneration) allowed.add(manifest.capsule.previousGeneration);
      for (const slot of ["current", "previous"] as const) {
        const serialized = await this.io.readVault(capsuleVaultPath(manifest.capsule.capsuleId, slot));
        if (serialized) {
          candidates.push({
            source: "vault",
            serialized,
            vaultInstanceId: manifest.vaultInstanceId,
            capsuleId: manifest.capsule.capsuleId,
            deviceId: manifest.capsule.deviceId,
            allowedGenerations: allowed,
          });
        }
      }
    };
    await addManifestCandidates(currentManifest);
    await addManifestCandidates(previousManifest);

    if (profileEntry) {
      const allowed = new Set<number>([profileEntry.currentGeneration]);
      if (profileEntry.previousGeneration) allowed.add(profileEntry.previousGeneration);
      for (const slot of ["current", "previous"] as const) {
        const value = this.io.loadProfile(capsuleProfileKey(profileEntry.capsuleId, slot));
        if (typeof value === "string" && value.length > 0) {
          candidates.push({
            source: "profile",
            serialized: value,
            vaultInstanceId: profileEntry.vaultInstanceId,
            capsuleId: profileEntry.capsuleId,
            deviceId: profileEntry.deviceId,
            allowedGenerations: allowed,
          });
        }
      }
    }

    const restored: Array<Extract<LocalRecoveryRestoreResult, { kind: "restored" }>> = [];
    for (const candidate of candidates.slice(0, 8)) {
      const sealed = parseSealedCapsule(candidate.serialized);
      if (
        !sealed ||
        sealed.vaultInstanceId !== candidate.vaultInstanceId ||
        sealed.capsuleId !== candidate.capsuleId ||
        sealed.deviceId !== candidate.deviceId ||
        !candidate.allowedGenerations.has(sealed.generation)
      ) {
        continue;
      }
      const plaintext = await this.unseal(sealed).catch(() => null);
      if (!plaintext || plaintext.vaultLocator !== this.vaultLocator) continue;
      restored.push({
        kind: "restored",
        priorProtectionEvidence: true,
        state: plaintext.state,
        generation: plaintext.generation,
        vaultInstanceId: plaintext.vaultInstanceId,
        capsuleId: plaintext.capsuleId,
        source: candidate.source,
      });
    }
    restored.sort((left, right) => right.generation - left.generation);
    if (restored[0]) return restored[0];
    return {
      kind: "needs-recovery",
      priorProtectionEvidence: true,
      reason:
        "VaultGuard found prior-protection evidence, but no authenticated same-device recovery capsule could be opened. Restore with the local recovery code; encrypted files were left unchanged.",
    };
  }

  async persist(state: LocalRecoveryDeviceState): Promise<LocalRecoveryPersistResult> {
    const validated = validateDeviceState(state);
    if (!validated) throw new Error("Local recovery state is invalid or violates max-security mode.");
    const locatorHash = await sha256Hex(this.vaultLocator);
    const index = parseProfileIndex(this.io.loadProfile(PROFILE_INDEX_KEY));
    const currentManifest = parseManifest(await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH));
    const priorEntry = index.entries.find((entry) => entry.locatorHash === locatorHash);
    const deviceId = this.getOrCreateDeviceId();
    const vaultInstanceId = currentManifest?.vaultInstanceId ?? priorEntry?.vaultInstanceId ?? randomIdentifier();
    const capsuleId = currentManifest?.capsule.capsuleId ?? priorEntry?.capsuleId ?? randomIdentifier();
    const previousGeneration = Math.max(
      currentManifest?.capsule.currentGeneration ?? 0,
      priorEntry?.currentGeneration ?? 0,
    );
    const generation = previousGeneration + 1;
    const sealed = await this.seal({
      schema: 1,
      vaultInstanceId,
      capsuleId,
      deviceId,
      generation,
      vaultLocator: this.vaultLocator,
      state: validated,
    });
    const serialized = JSON.stringify(sealed);
    const copies: LocalRecoveryCopy[] = [];

    await this.io.ensureVaultRecoveryRoot();
    const nextPath = capsuleVaultPath(capsuleId, "next");
    const currentPath = capsuleVaultPath(capsuleId, "current");
    const previousPath = capsuleVaultPath(capsuleId, "previous");
    await this.io.writeVault(nextPath, serialized);
    await this.assertCapsule(nextPath, vaultInstanceId, capsuleId, deviceId, generation);
    await this.io.removeVault(previousPath);
    const current = await this.io.readVault(currentPath);
    // Keep the old current blob addressable through the previous slot until
    // the new manifest commits. The old manifest accepts its current
    // generation from either physical slot, so a crash anywhere before that
    // commit can still recover the pre-transition state. Max-security purges
    // the rollback immediately after the PIN-only manifest becomes current.
    if (current !== null) {
      await this.io.renameVault(currentPath, previousPath);
    }
    await this.io.renameVault(nextPath, currentPath);
    await this.assertCapsule(currentPath, vaultInstanceId, capsuleId, deviceId, generation);
    copies.push("vault");

    const profileCurrentKey = capsuleProfileKey(capsuleId, "current");
    const profilePreviousKey = capsuleProfileKey(capsuleId, "previous");
    const profileCurrent = this.io.loadProfile(profileCurrentKey);
    if (typeof profileCurrent === "string" && profileCurrent.length > 0) {
      // Keep this rollback copy until the new manifest commits. Max-security
      // mode purges it immediately after that commit; retaining it during the
      // replacement closes the crash window between profile and manifest writes.
      this.io.saveProfile(profilePreviousKey, profileCurrent);
    }
    this.io.saveProfile(profileCurrentKey, serialized);
    if (this.io.loadProfile(profileCurrentKey) === serialized) copies.push("profile");

    const manifest: LocalRecoveryManifestV1 = {
      schema: 1,
      vaultInstanceId,
      protectionMarker: "vaultguard-local-at-rest",
      capsule: {
        capsuleId,
        deviceId,
        currentGeneration: generation,
        ...(!validated.requirePinOnStartup && previousGeneration > 0
          ? { previousGeneration }
          : {}),
      },
    };
    await this.writeManifestAtomically(manifest);
    if (validated.requirePinOnStartup) {
      // writeManifestAtomically keeps the old manifest for ordinary rollback.
      // In max-security mode that old manifest can point at a generation which
      // carried a transparent wrapper, so remove the pointer after the new
      // PIN-only current generation has been written and verified in both homes.
      await this.io.removeVault(previousPath);
      await this.io.removeVault(LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH);
    }

    const entry: ProfileIndexV1["entries"][number] = {
      locatorHash,
      vaultInstanceId,
      capsuleId,
      deviceId,
      currentGeneration: generation,
      ...(!validated.requirePinOnStartup && previousGeneration > 0
        ? { previousGeneration }
        : {}),
      updatedAt: Date.now(),
    };
    const entries = [entry, ...index.entries.filter((candidate) => candidate.locatorHash !== locatorHash)]
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .slice(0, LOCAL_RECOVERY_MAX_PROFILE_ENTRIES);
    this.io.saveProfile(PROFILE_INDEX_KEY, { schema: 1, entries } satisfies ProfileIndexV1);
    if (validated.requirePinOnStartup) {
      // The profile index now authorizes only the new PIN-only generation, so
      // the old rollback blob can be destroyed without opening a recovery gap.
      this.io.saveProfile(profilePreviousKey, null);
    }
    return { vaultInstanceId, capsuleId, generation, copies };
  }

  /**
   * Remove every discoverable local recovery copy for this vault locator.
   * Used when the user has proved the vault is plaintext and disables local
   * protection, and before committing a deliberately rotated/replaced LAK.
   */
  async clear(): Promise<void> {
    const locatorHash = await sha256Hex(this.vaultLocator);
    const index = parseProfileIndex(this.io.loadProfile(PROFILE_INDEX_KEY));
    const manifests = [
      parseManifest(await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH)),
      parseManifest(await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH)),
    ];
    const profileEntries = index.entries.filter((entry) => entry.locatorHash === locatorHash);
    const capsuleIds = new Set<string>();
    for (const manifest of manifests) {
      if (manifest) capsuleIds.add(manifest.capsule.capsuleId);
    }
    for (const entry of profileEntries) capsuleIds.add(entry.capsuleId);

    // A directory listing lets us remove orphaned/torn capsule files even when
    // their manifest was damaged. Only this fixed hidden recovery root is read.
    for (const path of (await this.io.listVaultRecoveryFiles?.()) ?? []) {
      if (path.startsWith(`${LOCAL_RECOVERY_ROOT}/capsule.`)) {
        await this.io.removeVault(path);
      }
    }
    for (const capsuleId of capsuleIds) {
      for (const slot of ["current", "previous", "next"] as const) {
        await this.io.removeVault(capsuleVaultPath(capsuleId, slot));
      }
      this.io.saveProfile(capsuleProfileKey(capsuleId, "current"), null);
      this.io.saveProfile(capsuleProfileKey(capsuleId, "previous"), null);
    }
    for (const path of [
      MANIFEST_NEXT_PATH,
      LOCAL_RECOVERY_MANIFEST_PATH,
      LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH,
    ]) {
      await this.io.removeVault(path);
    }
    this.io.saveProfile(PROFILE_INDEX_KEY, {
      schema: 1,
      entries: index.entries.filter((entry) => entry.locatorHash !== locatorHash),
    } satisfies ProfileIndexV1);
  }

  private getOrCreateDeviceId(): string {
    const existing = this.io.loadProfile(PROFILE_DEVICE_ID_KEY);
    if (isIdentifier(existing)) return existing;
    const generated = randomIdentifier();
    this.io.saveProfile(PROFILE_DEVICE_ID_KEY, generated);
    return generated;
  }

  private async writeManifestAtomically(manifest: LocalRecoveryManifestV1): Promise<void> {
    const serialized = JSON.stringify(manifest);
    await this.io.writeVault(MANIFEST_NEXT_PATH, serialized);
    if (!parseManifest(await this.io.readVault(MANIFEST_NEXT_PATH))) {
      throw new Error("Local recovery manifest validation failed before replacement.");
    }
    await this.io.removeVault(LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH);
    if ((await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH)) !== null) {
      await this.io.renameVault(
        LOCAL_RECOVERY_MANIFEST_PATH,
        LOCAL_RECOVERY_MANIFEST_PREVIOUS_PATH,
      );
    }
    await this.io.renameVault(MANIFEST_NEXT_PATH, LOCAL_RECOVERY_MANIFEST_PATH);
    const reread = parseManifest(await this.io.readVault(LOCAL_RECOVERY_MANIFEST_PATH));
    if (!reread || reread.capsule.currentGeneration !== manifest.capsule.currentGeneration) {
      throw new Error("Local recovery manifest validation failed after replacement.");
    }
  }

  private async assertCapsule(
    path: string,
    vaultInstanceId: string,
    capsuleId: string,
    deviceId: string,
    generation: number,
  ): Promise<void> {
    const serialized = await this.io.readVault(path);
    const sealed = serialized ? parseSealedCapsule(serialized) : null;
    if (
      !sealed ||
      sealed.vaultInstanceId !== vaultInstanceId ||
      sealed.capsuleId !== capsuleId ||
      sealed.deviceId !== deviceId ||
      sealed.generation !== generation ||
      !(await this.unseal(sealed))
    ) {
      throw new Error(`Local recovery capsule validation failed at ${path}.`);
    }
  }

  private async seal(plaintext: CapsulePlaintextV1): Promise<SealedCapsuleV1> {
    const serialized = JSON.stringify(plaintext);
    if (this.safeStorage?.isEncryptionAvailable()) {
      const encrypted = this.safeStorage.encryptString(serialized);
      return {
        schema: 1,
        vaultInstanceId: plaintext.vaultInstanceId,
        capsuleId: plaintext.capsuleId,
        deviceId: plaintext.deviceId,
        generation: plaintext.generation,
        storage: "electron-safe-storage",
        ciphertext: bytesToBase64(
          encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted),
        ),
      };
    }
    if (!this.fallbackKekBase64) {
      throw new Error("No device-local sealing key is available for the recovery capsule.");
    }
    const rawKek = base64ToBytes(this.fallbackKekBase64);
    if (rawKek.length !== 32) throw new Error("The fallback recovery sealing key is invalid.");
    const key = await crypto.subtle.importKey(
      "raw",
      rawKek as BufferSource,
      "AES-GCM",
      false,
      ["encrypt"],
    );
    rawKek.fill(0);
    const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
    const metadata = {
      vaultInstanceId: plaintext.vaultInstanceId,
      capsuleId: plaintext.capsuleId,
      deviceId: plaintext.deviceId,
      generation: plaintext.generation,
    };
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonce as BufferSource,
          additionalData: capsuleAad(metadata) as BufferSource,
        },
        key,
        new TextEncoder().encode(serialized),
      ),
    );
    return {
      schema: 1,
      ...metadata,
      storage: "fallback-kek",
      nonce: bytesToBase64(nonce),
      ciphertext: bytesToBase64(ciphertext),
    };
  }

  private async unseal(sealed: SealedCapsuleV1): Promise<CapsulePlaintextV1 | null> {
    let serialized: string;
    if (sealed.storage === "electron-safe-storage") {
      if (!this.safeStorage?.isEncryptionAvailable()) return null;
      serialized = this.safeStorage.decryptString(base64ToBytes(sealed.ciphertext));
    } else {
      if (!this.fallbackKekBase64 || !sealed.nonce) return null;
      const rawKek = base64ToBytes(this.fallbackKekBase64);
      if (rawKek.length !== 32) return null;
      const key = await crypto.subtle.importKey(
        "raw",
        rawKek as BufferSource,
        "AES-GCM",
        false,
        ["decrypt"],
      );
      rawKek.fill(0);
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64ToBytes(sealed.nonce) as BufferSource,
          additionalData: capsuleAad(sealed) as BufferSource,
        },
        key,
        base64ToBytes(sealed.ciphertext) as BufferSource,
      );
      serialized = new TextDecoder().decode(plaintext);
    }
    const parsed: unknown = JSON.parse(serialized);
    if (!isRecord(parsed) || parsed.schema !== 1) return null;
    if (
      parsed.vaultInstanceId !== sealed.vaultInstanceId ||
      parsed.capsuleId !== sealed.capsuleId ||
      parsed.deviceId !== sealed.deviceId ||
      parsed.generation !== sealed.generation ||
      parsed.vaultLocator !== this.vaultLocator
    ) {
      return null;
    }
    const state = validateDeviceState(parsed.state);
    if (!state) return null;
    return { ...(parsed as unknown as CapsulePlaintextV1), state };
  }
}
