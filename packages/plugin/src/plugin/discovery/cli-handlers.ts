import type { CliData } from "obsidian";
import { PermissionLevel } from "../../types";
import type { PermissionDecision } from "../permission-store";
import {
  normalizeVaultRelativePath,
  validateSecureSearchRequest,
  type SecureSearchRequest,
  type SecureSearchResponse,
} from "./search-model";

export interface DiscoveryCliContext {
  isModuleEnabled(): boolean;
  isCliRuntimeSupported(): boolean;
  getSession(): { userId: string } | null;
  getConnectionStatus(): string;
  getBoundVault(): { id: string; name: string } | null;
  getSemanticStatus(): {
    enabled: boolean;
    indexState: string;
    indexedFiles: number;
    stale: boolean;
  };
  getCapabilities(): {
    bases: boolean;
    cli: boolean;
    semanticProvider: boolean;
  };
  getPermissionDecision(path: string): Promise<PermissionDecision>;
  search(request: SecureSearchRequest): Promise<SecureSearchResponse>;
}

export interface DiscoveryCliHandlers {
  status(params: CliData): Promise<string>;
  access(params: CliData): Promise<string>;
  search(params: CliData): Promise<string>;
}

interface CliError {
  code:
    | "module_disabled"
    | "unsupported_runtime"
    | "not_authenticated"
    | "vault_unbound"
    | "invalid_arguments"
    | "access_unavailable"
    | "search_cancelled"
    | "semantic_disabled"
    | "semantic_unavailable"
    | "request_failed";
  message: string;
}

function success(data: unknown): string {
  return JSON.stringify({ schemaVersion: 1, ok: true, data });
}

function failure(error: CliError): string {
  return JSON.stringify({ schemaVersion: 1, ok: false, error });
}

function runtimeGuard(ctx: DiscoveryCliContext): string | null {
  if (!ctx.isModuleEnabled()) {
    return failure({
      code: "module_disabled",
      message: "Secure Discovery is disabled in VaultGuard settings.",
    });
  }
  if (!ctx.isCliRuntimeSupported()) {
    return failure({
      code: "unsupported_runtime",
      message: "This Obsidian runtime does not support VaultGuard CLI handlers.",
    });
  }
  return null;
}

function authenticatedGuard(ctx: DiscoveryCliContext): string | null {
  if (!ctx.getSession()) {
    return failure({
      code: "not_authenticated",
      message: "Sign in to VaultGuard before using this command.",
    });
  }
  if (!ctx.getBoundVault()) {
    return failure({
      code: "vault_unbound",
      message: "Bind this local folder to a VaultGuard vault first.",
    });
  }
  return null;
}

function hasOnly(params: CliData, allowed: readonly string[]): boolean {
  const allow = new Set(allowed);
  return Object.keys(params).every((key) => allow.has(key));
}

function permissionName(level: PermissionLevel): "read" | "write" | "admin" | null {
  if (level >= PermissionLevel.ADMIN) return "admin";
  if (level >= PermissionLevel.WRITE) return "write";
  if (level >= PermissionLevel.READ) return "read";
  return null;
}

function invalidArguments(message: string): string {
  return failure({ code: "invalid_arguments", message });
}

/** Build handlers from live getters so login/logout/rebinding never leaves stale authority. */
export function createDiscoveryCliHandlers(ctx: DiscoveryCliContext): DiscoveryCliHandlers {
  return {
    status: async (params) => {
      const guarded = runtimeGuard(ctx);
      if (guarded) return guarded;
      if (!hasOnly(params, [])) return invalidArguments("Status accepts no flags.");
      const vault = ctx.getBoundVault();
      return success({
        authenticated: Boolean(ctx.getSession()),
        connected: ctx.getConnectionStatus() === "connected" || ctx.getConnectionStatus() === "online",
        boundVault: vault ? { id: vault.id, name: vault.name } : null,
        semantic: ctx.getSemanticStatus(),
        capabilities: ctx.getCapabilities(),
      });
    },

    access: async (params) => {
      const guarded = runtimeGuard(ctx) ?? authenticatedGuard(ctx);
      if (guarded) return guarded;
      if (!hasOnly(params, ["path"]) || typeof params.path !== "string") {
        return invalidArguments("Access requires exactly one path flag.");
      }
      const path = normalizeVaultRelativePath(params.path);
      if (!path || [...path].length > 1_024) {
        return invalidArguments("Path must be a safe current-vault path.");
      }
      try {
        const decision = await ctx.getPermissionDecision(path);
        if (decision.kind === "unknown") {
          return failure({
            code: "access_unavailable",
            message: "Access could not be established for that path.",
          });
        }
        const level = permissionName(decision.level);
        if (!level) {
          return failure({
            code: "access_unavailable",
            message: "Access could not be established for that path.",
          });
        }
        return success({ path, level, provenance: decision.kind });
      } catch {
        return failure({
          code: "request_failed",
          message: "VaultGuard could not complete the access check.",
        });
      }
    },

    search: async (params) => {
      const guarded = runtimeGuard(ctx) ?? authenticatedGuard(ctx);
      if (guarded) return guarded;
      if (!hasOnly(params, ["query", "scope", "content", "semantic", "limit"])) {
        return invalidArguments("Search received an unsupported flag.");
      }
      if (typeof params.query !== "string") {
        return invalidArguments("Search requires query=<text>.");
      }
      if (params.content !== undefined && params.content !== "true") {
        return invalidArguments("Content is a boolean flag.");
      }
      if (params.semantic !== undefined && params.semantic !== "true") {
        return invalidArguments("Semantic is a boolean flag.");
      }
      let limit: number | undefined;
      if (params.limit !== undefined) {
        if (typeof params.limit !== "string" || !/^\d+$/u.test(params.limit)) {
          return invalidArguments("Limit must be a positive integer.");
        }
        limit = Number(params.limit);
      }
      try {
        const request = validateSecureSearchRequest({
          query: params.query,
          scope: params.scope as "current" | "all" | undefined,
          includeContent: params.content === "true",
          semantic: params.semantic === "true",
          limit,
        });
        return success(await ctx.search(request));
      } catch (error) {
        if (error instanceof Error && /query|scope|current vault/i.test(error.message)) {
          return invalidArguments(error.message);
        }
        return failure({
          code: "request_failed",
          message: "VaultGuard could not complete the search.",
        });
      }
    },
  };
}
