import type { App } from "obsidian";

import {
  classifyForbiddenAutomationCommand,
  type AutomationCommandRuntime,
  type AutomationRuntimeCommand,
  type AutomationRuntimeContext,
  normalizeAutomationVaultPath,
} from "./agent-automation-registry";

/**
 * The single narrow boundary around Obsidian's private command/plugin APIs.
 * Neither `App.commands` nor `App.plugins` is public in the installed typings,
 * so every property is feature-detected and every failure disables only this
 * optional capability. No caller should cast these private shapes elsewhere.
 */

interface PrivateCommandRecord {
  id?: unknown;
  name?: unknown;
}

interface PrivateCommandManager {
  listCommands?: () => unknown;
  findCommand?: (id: string) => unknown;
  executeCommandById?: (id: string) => unknown;
}

interface PrivatePluginManifest {
  id?: unknown;
  name?: unknown;
  version?: unknown;
}

interface PrivatePluginManager {
  manifests?: unknown;
  enabledPlugins?: unknown;
}

interface PrivateWorkspace {
  getActiveFile?: () => unknown;
}

interface AppWithAutomationInternals {
  commands?: unknown;
  plugins?: unknown;
  workspace?: unknown;
}

export interface ObsidianAutomationRuntimeOptions {
  /** Must be explicit. Missing/false evidence means fail closed. */
  isDesktop: boolean;
  obsidianVersion?: string;
  getActiveFilePath?: () => string | null | undefined;
  maximumCommands?: number;
}

const DEFAULT_MAX_COMMANDS = 2000;
const ABSOLUTE_MAX_COMMANDS = 5000;
const MAX_COMMAND_NAME = 160;
const SAFE_COMMAND_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$/;

// A command with an unknown namespace is not silently treated as core. The
// list covers stable built-in namespaces; additional namespaces can be added
// after physical runtime evidence without weakening community-plugin pinning.
const CORE_COMMAND_NAMESPACES = new Set([
  "app",
  "audio-recorder",
  "backlink",
  "bases",
  "bookmarks",
  "canvas",
  "command-palette",
  "daily-notes",
  "editor",
  "file-explorer",
  "file-recovery",
  "global-search",
  "graph",
  "markdown",
  "note-composer",
  "outline",
  "outgoing-links",
  "page-preview",
  "properties",
  "random-note",
  "slides",
  "switcher",
  "tag-pane",
  "templates",
  "webviewer",
  "word-count",
  "workspace",
  "workspaces",
  "zk-prefixer",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function cleanCommandId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return SAFE_COMMAND_ID.test(trimmed) ? trimmed : null;
}

function cleanCommandName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
  return cleaned && cleaned.length <= MAX_COMMAND_NAME ? cleaned : null;
}

function privateCommandManager(app: App): PrivateCommandManager | null {
  const raw = (app as unknown as AppWithAutomationInternals).commands;
  if (!isRecord(raw)) return null;
  return raw as PrivateCommandManager;
}

function privatePluginManager(app: App): PrivatePluginManager | null {
  const raw = (app as unknown as AppWithAutomationInternals).plugins;
  if (!isRecord(raw)) return null;
  return raw as PrivatePluginManager;
}

function pluginManifests(app: App): Record<string, PrivatePluginManifest> {
  const manifests = privatePluginManager(app)?.manifests;
  if (!isRecord(manifests)) return {};
  const output: Record<string, PrivatePluginManifest> = {};
  for (const [id, raw] of Object.entries(manifests)) {
    if (isRecord(raw)) output[id] = raw as PrivatePluginManifest;
  }
  return output;
}

function enabledPlugins(app: App): Set<string> | null {
  const value = privatePluginManager(app)?.enabledPlugins;
  if (!(value instanceof Set)) return null;
  const output = new Set<string>();
  for (const item of value) {
    if (typeof item === "string") output.add(item);
  }
  return output;
}

function matchingPluginId(commandId: string, manifests: Record<string, PrivatePluginManifest>): string | null {
  const matches = Object.keys(manifests).filter((id) => commandId.startsWith(`${id}:`));
  matches.sort((left, right) => right.length - left.length);
  return matches[0] ?? null;
}

function sameCommand(left: AutomationRuntimeCommand, right: AutomationRuntimeCommand): boolean {
  return (
    left.id === right.id &&
    left.name === right.name &&
    left.source === right.source &&
    left.pluginId === right.pluginId &&
    left.pluginVersion === right.pluginVersion &&
    left.pluginEnabled === right.pluginEnabled
  );
}

export class ObsidianAutomationRuntime implements AutomationCommandRuntime {
  constructor(
    private readonly app: App,
    private readonly options: ObsidianAutomationRuntimeOptions,
  ) {}

  isAvailable(): boolean {
    if (this.options.isDesktop !== true) return false;
    const commands = privateCommandManager(this.app);
    return Boolean(
      commands &&
        typeof commands.listCommands === "function" &&
        typeof commands.findCommand === "function" &&
        typeof commands.executeCommandById === "function",
    );
  }

  list(): AutomationRuntimeCommand[] {
    if (!this.isAvailable()) return [];
    const commands = privateCommandManager(this.app);
    if (!commands?.listCommands) return [];
    try {
      const raw = commands.listCommands.call(commands);
      if (!Array.isArray(raw)) return [];
      const maximum = Math.max(
        1,
        Math.min(
          ABSOLUTE_MAX_COMMANDS,
          Math.floor(this.options.maximumCommands ?? DEFAULT_MAX_COMMANDS),
        ),
      );
      const result: AutomationRuntimeCommand[] = [];
      const seen = new Set<string>();
      for (const item of raw.slice(0, maximum)) {
        const descriptor = this.describePrivateCommand(item);
        if (!descriptor || seen.has(descriptor.id)) continue;
        seen.add(descriptor.id);
        result.push(descriptor);
      }
      result.sort((left, right) => left.id.localeCompare(right.id));
      return result;
    } catch {
      return [];
    }
  }

  find(commandId: string): AutomationRuntimeCommand | null {
    if (!this.isAvailable()) return null;
    const safeId = cleanCommandId(commandId);
    if (!safeId) return null;
    const commands = privateCommandManager(this.app);
    if (!commands?.findCommand) return null;
    try {
      const descriptor = this.describePrivateCommand(commands.findCommand.call(commands, safeId));
      return descriptor?.id === safeId ? descriptor : null;
    } catch {
      return null;
    }
  }

  getContext(): AutomationRuntimeContext {
    let activeFilePath: string | null | undefined;
    try {
      if (this.options.getActiveFilePath) {
        activeFilePath = this.options.getActiveFilePath();
      } else {
        const rawWorkspace = (this.app as unknown as AppWithAutomationInternals).workspace;
        const workspace = isRecord(rawWorkspace) ? (rawWorkspace as PrivateWorkspace) : null;
        const activeFile = workspace?.getActiveFile?.();
        activeFilePath =
          isRecord(activeFile) && typeof activeFile.path === "string" ? activeFile.path : null;
      }
    } catch {
      activeFilePath = null;
    }
    return {
      platform: this.options.isDesktop === true ? "desktop" : "mobile",
      ...(this.options.obsidianVersion ? { obsidianVersion: this.options.obsidianVersion } : {}),
      activeFilePath: typeof activeFilePath === "string" ? activeFilePath : null,
    };
  }

  async execute(
    commandId: string,
    expected: AutomationRuntimeCommand | undefined,
    expectedActiveFilePath?: string,
  ): Promise<boolean> {
    if (!this.isAvailable()) return false;
    const safeId = cleanCommandId(commandId);
    const authorizedActivePath = normalizeAutomationVaultPath(expectedActiveFilePath);
    if (!safeId || !expected || !authorizedActivePath) return false;
    const ambientActivePath = normalizeAutomationVaultPath(this.getContext().activeFilePath);
    if (ambientActivePath !== authorizedActivePath) return false;
    // Re-resolve immediately before invocation. This is the adapter's final
    // defense against a command being removed/remapped or ambient context
    // changing after confirmation.
    const current = this.find(safeId);
    if (!current || !sameCommand(current, expected)) return false;
    const commands = privateCommandManager(this.app);
    if (!commands?.executeCommandById) return false;
    try {
      const result = await Promise.resolve(
        commands.executeCommandById.call(commands, safeId),
      );
      // Some Obsidian builds return void despite the de-facto boolean contract.
      // Reaching this point means exactly one invocation was issued; false is
      // the only explicit rejection. Observable success is still decided by the
      // registry's postcondition, never by this return value alone.
      return result !== false;
    } catch {
      return false;
    }
  }

  private describePrivateCommand(value: unknown): AutomationRuntimeCommand | null {
    if (!isRecord(value)) return null;
    const record = value as PrivateCommandRecord;
    const id = cleanCommandId(record.id);
    const name = cleanCommandName(record.name);
    if (!id || !name) return null;

    const manifests = pluginManifests(this.app);
    const pluginId = matchingPluginId(id, manifests);
    if (classifyForbiddenAutomationCommand({ commandId: id, pluginId: pluginId ?? undefined })) {
      return null;
    }
    if (pluginId) {
      const manifest = manifests[pluginId];
      const version = typeof manifest.version === "string" ? manifest.version.trim() : undefined;
      return {
        id,
        name,
        source: "community",
        pluginId,
        ...(version ? { pluginVersion: version } : {}),
        pluginEnabled: enabledPlugins(this.app)?.has(pluginId) === true,
      };
    }

    const namespace = id.split(":", 1)[0]?.toLocaleLowerCase() ?? "";
    return {
      id,
      name,
      source: CORE_COMMAND_NAMESPACES.has(namespace) ? "core" : "unknown",
    };
  }
}
