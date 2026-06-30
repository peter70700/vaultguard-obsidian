import { Notice } from "obsidian";
import { classifyExtension, dispatchConvert } from "../ui/import/converters/dispatch";
import { makeImportSourceFs } from "../ui/import/local-file-importer";
import { VaultGuardChatView, VAULTGUARD_CHAT_VIEW_TYPE } from "../ui/chat/chat-view";
import {
  ConversationStore,
  type ConversationStorageAdapter,
} from "../ui/chat/conversation-store";
import { WriteConfirmModal } from "../ui/chat/render/write-confirm-modal";
import { AgentBridgeLeaseModal } from "./agent-bridge-modal";
import {
  type AgentBridgeAskUserHandler,
  type AgentBridgeConfirmPausedHandler,
  type AgentBridgeLeaseInput,
  type AgentBridgeLeaseSecret,
  type AgentBridgeLeaseSummary,
  type AgentBridgePersistenceAdapter,
  type AgentBridgeServerInfo,
  type AgentBridgeToolSurface,
  type AccessQueryProvider,
  VaultGuardAgentBridge,
} from "./agent-bridge";
import {
  inspectSkillInstall,
  installSkill,
  uninstallSkill,
  type InstallResult,
  type SkillInstallStatus,
  type SkillInstallerDeps,
} from "./agent-bridge-skill/installer";
import { VaultGraph } from "./graph/vault-graph";
import type { AgentBridgeRuntimeContext } from "./plugin-runtime-types";

export class AgentBridgeRuntime {
  private bridge: VaultGuardAgentBridge | null = null;

  constructor(private readonly ctx: AgentBridgeRuntimeContext) {}

  init(): void {
    this.bridge = new VaultGuardAgentBridge({
      getSession: () => this.ctx.getSession(),
      getServerVaultId: () => this.ctx.getServerVaultId(),
      getVaultConfigDir: () => this.ctx.normalizeVaultPath(this.ctx.app.vault.configDir),
      getAllFilePaths: () =>
        this.ctx.app.vault
          .getFiles()
          .map((file) => this.ctx.normalizeVaultPath(file.path)),
      fileExists: async (path) => this.ctx.app.vault.adapter.exists(path),
      ensureParentFolders: (path) => this.ctx.ensureParentFoldersForPath(path),
      isPathExcluded: (path) => this.ctx.isPathExcluded(path),
      getPermission: (path) => this.ctx.getEffectivePermission(path),
      makeVaultGraph: (graphDeps) => new VaultGraph(this.ctx.app, graphDeps),
      isMetadataSuppressed: (path) => this.ctx.isMetadataSuppressed(path),
      readText: (path) => this.ctx.readText(path),
      writeText: (path, content) => this.ctx.writeText(path, content),
      deleteFile: (path) => this.ctx.deleteFile(path),
      renameFile: (oldPath, newPath) => this.ctx.renameFile(oldPath, newPath),
      confirmWrite: (request) => this.confirmWrite(request),
      log: (message) => this.ctx.log(message),
      emitAudit: (action, resourcePath, metadata) =>
        this.ctx.emitAudit(action, resourcePath, metadata),
      withAgentContext: (agentName, leaseId, fn) => {
        const client = this.ctx.getApiClient();
        return client ? client.withAgentContext(agentName, leaseId, fn) : fn();
      },
      queryAccess: this.createAccessProvider(),
      importFs: makeImportSourceFs(),
      importConvert: (input) => dispatchConvert(input),
      importClassify: (ext) => classifyExtension(ext),
      askUser: async (request) => this.askUserInChat(request),
      confirmWritePaused: async (request) => this.pauseConfirmInChat(request),
      persistence: this.makePersistenceAdapter(),
    });
  }

  async shutdown(): Promise<void> {
    if (!this.bridge) return;
    await this.bridge.stopHttpServer().catch((err) =>
      this.ctx.logError("Stopping agent bridge server failed", err),
    );
    this.bridge.revokeAllLeases();
    this.bridge = null;
  }

  async stopServerIfInitialized(): Promise<void> {
    if (!this.bridge) return;
    await this.bridge.stopHttpServer();
  }

  getConversationStore(): ConversationStore | null {
    const cipher = this.ctx.getAtRestCipher();
    if (!cipher) return null;

    const pluginId = this.ctx.manifestId ?? "vaultguard-sync";
    const dir = this.ctx.vaultConfigPath("plugins", pluginId, "chat");
    const adapter: ConversationStorageAdapter = {
      exists: async (name) => {
        try {
          return await this.ctx.app.vault.adapter.exists(`${dir}/${name}`);
        } catch {
          return false;
        }
      },
      readBinary: async (name) => {
        const readBin = this.ctx.getAdapterReadBinary();
        if (!readBin) throw new Error("Vault adapter not initialized.");
        return readBin(`${dir}/${name}`);
      },
      writeBinary: async (name, bytes) => {
        const writeBin = this.ctx.getAdapterWriteBinary();
        if (!writeBin) throw new Error("Vault adapter not initialized.");
        await this.ctx.ensureParentFoldersForPath(`${dir}/${name}`);
        await writeBin(`${dir}/${name}`, bytes);
      },
      remove: async (name) => {
        try {
          if (await this.ctx.app.vault.adapter.exists(`${dir}/${name}`)) {
            await this.ctx.app.vault.adapter.remove(`${dir}/${name}`);
          }
        } catch (err) {
          this.ctx.logError("Failed to remove conversation envelope", err);
        }
      },
      list: async () => {
        try {
          if (!(await this.ctx.app.vault.adapter.exists(dir))) return [];
          const listing = await this.ctx.app.vault.adapter.list(dir);
          return listing.files.map((p) => p.slice(p.lastIndexOf("/") + 1));
        } catch {
          return [];
        }
      },
    };

    return new ConversationStore({ cipher, adapter });
  }

  getToolSurface(): AgentBridgeToolSurface {
    return this.ensureBridge().getToolSurface();
  }

  createLease(input: AgentBridgeLeaseInput = {}): AgentBridgeLeaseSecret {
    return this.ensureBridge().createLease(input);
  }

  beginImportSession(absRoot: string): Promise<string> {
    return this.ensureBridge().beginImportSession(absRoot);
  }

  endImportSession(): void {
    this.bridge?.endImportSession();
  }

  hasActiveImportSession(): boolean {
    return this.bridge?.hasActiveImportSession() ?? false;
  }

  rotateLeaseToken(leaseId: string): AgentBridgeLeaseSecret {
    return this.ensureBridge().rotateLeaseToken(leaseId);
  }

  loadPersistedLeases(): Promise<{ restored: number; dropped: number }> {
    return this.ensureBridge().loadPersistedLeases();
  }

  async restorePersistentLeases(): Promise<void> {
    if (!this.ctx.getSession() || !this.ctx.getServerVaultId()) return;
    if (!this.ctx.getAtRestCipher()?.isReady()) return;

    try {
      const { restored } = await this.loadPersistedLeases();
      if (restored > 0) {
        const server = await this.startServer();
        new Notice(
          `VaultGuard Sync: ${restored} persistent agent bridge ${restored === 1 ? "lease is" : "leases are"} active. Endpoint: ${server.endpoint}.`,
          8000,
        );
      }
    } catch (err) {
      this.ctx.logError("Failed to restore persistent agent bridge leases", err);
    }
  }

  revokePersistentLeasesForSessionEnd(reason: string): Promise<number> {
    if (!this.bridge) return Promise.resolve(0);
    return this.bridge.revokePersistentLeasesForSessionEnd(reason);
  }

  getSkillStatus(): (SkillInstallStatus & { available: true }) | { available: false } {
    const deps = this.getSkillInstallerDeps();
    if (!deps) return { available: false };
    return { ...inspectSkillInstall(deps), available: true };
  }

  async installSkill(options: { overwriteUnmanaged?: boolean } = {}): Promise<InstallResult> {
    const deps = this.getSkillInstallerDeps();
    if (!deps) {
      throw new Error(
        "Skill install requires Node filesystem access (desktop Obsidian). Skipping on this device.",
      );
    }
    const result = installSkill(deps, options);
    await this.ctx.emitAudit("bridge.skill_installed", result.filePath, {
      action: result.action,
      overwriteUnmanaged: options.overwriteUnmanaged === true,
    });
    return result;
  }

  async uninstallSkill(options: { force?: boolean } = {}): Promise<{
    filePath: string;
    removed: boolean;
  }> {
    const deps = this.getSkillInstallerDeps();
    if (!deps) {
      throw new Error("Skill uninstall requires Node filesystem access (desktop Obsidian).");
    }
    const result = uninstallSkill(deps, options);
    if (result.removed) {
      await this.ctx.emitAudit("bridge.skill_uninstalled", result.filePath, {
        force: options.force === true,
      });
    }
    return result;
  }

  revokeLease(leaseId: string): boolean {
    return this.ensureBridge().revokeLease(leaseId);
  }

  revokeAllLeases(): void {
    this.ensureBridge().revokeAllLeases();
  }

  startServer(): Promise<AgentBridgeServerInfo> {
    return this.ensureBridge().startHttpServer();
  }

  stopServer(): Promise<void> {
    return this.ensureBridge().stopHttpServer();
  }

  openLeaseModal(): void {
    new AgentBridgeLeaseModal(
      this.ctx.pluginForModal as ConstructorParameters<typeof AgentBridgeLeaseModal>[0],
    ).open();
  }

  private ensureBridge(): VaultGuardAgentBridge {
    if (!this.bridge) {
      this.init();
    }
    return this.bridge!;
  }

  private createAccessProvider(): AccessQueryProvider {
    const requireClient = () => {
      const client = this.ctx.getApiClient();
      if (!client) throw new Error("VaultGuard is not connected.");
      return client;
    };

    return {
      getPathAccess: (path) => requireClient().getPathAccess(path),
      getBatchPathAccess: (paths) => requireClient().getBatchPathAccess(paths),
      getUserPermissions: (userId) => requireClient().getUserPermissions(userId),
      listPermissionRules: (pathFilter) => requireClient().getPermissions(pathFilter),
      listVaultMembers: (vaultId) => requireClient().listVaultMembers(vaultId),
      queryAudit: async (filters) => {
        const page = await requireClient().getAuditLogPage(filters);
        return { entries: page.entries, count: page.count, nextCursor: page.nextCursor };
      },
      getFileHistory: (path) => requireClient().getFileHistory(path),
      getDeletedFiles: () => requireClient().getDeletedFiles(),
      restoreDeletedFile: (path) => requireClient().restoreDeletedFile(path),
      getVaultOverview: () => requireClient().getVaultOverview(),
      listShares: () => requireClient().listShares(),
      createShare: (input) => requireClient().createShare(input),
      revokeShare: (shareId) => requireClient().revokeShare(shareId),
      listOrgUsers: () => requireClient().listUsers(),
      addVaultMember: (vaultId, userId, role) =>
        requireClient().addVaultMember(vaultId, userId, role),
      removeVaultMember: (vaultId, userId) =>
        requireClient().removeVaultMember(vaultId, userId),
      updateVaultMember: (vaultId, userId, role) =>
        requireClient().updateVaultMember(vaultId, userId, role),
      setPermissionLevel: (input) => requireClient().setPermissionLevel(input),
    };
  }

  private async askUserInChat(
    request: Parameters<AgentBridgeAskUserHandler>[0],
  ) {
    const leaves = this.ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
    for (const leaf of leaves) {
      if (leaf.view instanceof VaultGuardChatView) {
        this.ctx.app.workspace.revealLeaf(leaf);
        return leaf.view.askUserFromAgent(request);
      }
    }
    throw new Error("VaultGuard AI Chat is not open to answer this question.");
  }

  private async pauseConfirmInChat(
    request: Parameters<AgentBridgeConfirmPausedHandler>[0],
  ): Promise<void> {
    const leaves = this.ctx.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
    for (const leaf of leaves) {
      if (leaf.view instanceof VaultGuardChatView) {
        this.ctx.app.workspace.revealLeaf(leaf);
        return leaf.view.confirmWriteFromAgent(request);
      }
    }
    throw new Error("VaultGuard AI Chat is not open to confirm this change.");
  }

  private makePersistenceAdapter(): AgentBridgePersistenceAdapter | null {
    const pluginId = this.ctx.manifestId ?? "vaultguard-sync";
    const path = this.ctx.vaultConfigPath("plugins", pluginId, "agent-leases.envelope");
    return {
      readEnvelope: async (): Promise<string | null> => {
        const cipher = this.ctx.getAtRestCipher();
        if (!cipher?.isReady()) return null;
        const readBin = this.ctx.getAdapterReadBinary();
        if (!readBin) return null;
        try {
          const exists = await this.ctx.app.vault.adapter.exists(path);
          if (!exists) return null;
          const cipherBytes = await readBin(path);
          return cipher.decryptString(cipherBytes);
        } catch (err) {
          this.ctx.logError("Failed to read agent bridge lease envelope", err);
          return null;
        }
      },
      writeEnvelope: async (plaintext: string): Promise<void> => {
        const cipherRuntime = this.ctx.getAtRestCipher();
        if (!cipherRuntime?.isReady()) {
          throw new Error(
            "VaultGuard Sync at-rest encryption is not ready; cannot persist agent bridge leases.",
          );
        }
        const writeBin = this.ctx.getAdapterWriteBinary();
        if (!writeBin) {
          throw new Error(
            "Vault adapter is not initialized; cannot persist agent bridge leases.",
          );
        }
        await this.ctx.ensureParentFoldersForPath(path);
        const cipher = await cipherRuntime.encryptString(plaintext);
        await writeBin(path, cipher);
      },
      deleteEnvelope: async (): Promise<void> => {
        try {
          const exists = await this.ctx.app.vault.adapter.exists(path);
          if (!exists) return;
          await this.ctx.app.vault.adapter.remove(path);
        } catch (err) {
          this.ctx.logError("Failed to delete agent bridge lease envelope", err);
        }
      },
    };
  }

  private getSkillInstallerDeps(): SkillInstallerDeps | null {
    const maybeWindow =
      typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
    const req =
      typeof maybeWindow.require === "function"
        ? (maybeWindow.require as NodeRequire)
        : null;
    if (!req) return null;
    try {
      const fs = req("fs") as SkillInstallerDeps["fs"];
      const path = req("path") as SkillInstallerDeps["path"];
      const os = req("os") as { homedir(): string };
      return {
        fs,
        path,
        homedir: () => os.homedir(),
        log: (msg) => this.ctx.log(msg),
      };
    } catch (err) {
      this.ctx.logError("Could not load Node FS modules for skill installer", err);
      return null;
    }
  }

  private async confirmWrite(request: {
    lease: AgentBridgeLeaseSummary;
    operation:
      | "create"
      | "apply_patch"
      | "delete"
      | "rename"
      | "set_permission"
      | "restore"
      | "share_create"
      | "share_revoke"
      | "member_add"
      | "member_remove"
      | "member_set_role";
    path: string;
    preview: string;
  }): Promise<boolean> {
    if (this.ctx.app?.workspace) {
      return new Promise<boolean>((resolve) => {
        new WriteConfirmModal(
          this.ctx.app,
          {
            agentName: request.lease.agentName,
            operation: request.operation,
            path: request.path,
            scopes: request.lease.scopes,
            expiresAt: request.lease.expiresAt,
            preview: request.preview,
          },
          (allow) => resolve(allow),
        ).open();
      });
    }

    return false;
  }
}

export function createAgentBridgeRuntime(
  ctx: AgentBridgeRuntimeContext,
): AgentBridgeRuntime {
  return new AgentBridgeRuntime(ctx);
}
