// In-process tool runtime that maps a Claude tool_use to the existing
// AgentBridge tool surface (AI-CHAT-PANEL.md §6.2).
//
// The structural guarantee here is that execute() NEVER throws. Every failure —
// permission-denied, scope-violation, byte-cap, write-rejected, unknown tool —
// is returned as `{ isError: true }` so the agentic loop can thread it back to
// the model as a tool_result and let the model re-plan. Only transport/auth
// failures (raised by the AnthropicClient, not here) abort a turn.

import type { AgentBridgeToolSurface } from "../../plugin/agent-bridge";
import type { GraphArgs } from "../../plugin/graph/graph-types";

export interface ToolResult {
  content: string;
  isError: boolean;
}

const ok = (result: unknown): ToolResult => ({
  content: JSON.stringify(result),
  isError: false,
});

export class VaultToolRuntime {
  constructor(
    private readonly surface: AgentBridgeToolSurface,
    private readonly leaseId: string,
  ) {}

  async execute(name: string, input: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case "vaultguard_list":
          return ok(await this.surface.list(this.leaseId, input as { scope?: string; limit?: number }));
        case "vaultguard_search":
          return ok(
            await this.surface.search(
              this.leaseId,
              input as { query: string; scope?: string; limit?: number },
            ),
          );
        case "vaultguard_read":
          return ok(await this.surface.read(this.leaseId, input as { path: string; maxBytes?: number }));
        case "vaultguard_apply_patch":
          // confirmWrite() fires INSIDE applyPatch when lease.writeMode==="confirm".
          return ok(await this.surface.applyPatch(this.leaseId, input as { path: string; diff: string }));
        case "vaultguard_create":
          return ok(await this.surface.create(this.leaseId, input as { path: string; content: string }));
        case "vaultguard_delete":
          return ok(await this.surface.delete(this.leaseId, input as { path: string }));
        case "vaultguard_rename":
          return ok(await this.surface.rename(this.leaseId, input as { path: string; newPath: string }));
        case "vaultguard_graph":
          // Read-only structural navigation. Service errors (bad op, missing
          // path/tag, permission gate) still surface as { isError: true }.
          return ok(await this.surface.graph(this.leaseId, input as unknown as GraphArgs));
        case "vaultguard_access":
          // Permission/membership queries. Gate failures (lease lacks the
          // capability, ambiguous user, no connection, backend 403) surface as
          // { isError: true } so the model can re-plan or explain the denial.
          return ok(
            await this.surface.access(
              this.leaseId,
              input as {
                op: string;
                path?: string;
                user?: string;
                scope?: string;
                minLevel?: string;
                limit?: number;
              },
            ),
          );
        case "vaultguard_set_permission":
          // Permission mutation. Gate failures (lease lacks allowPermissionWrites,
          // no connection, invalid level/role, ambiguous user, confirm rejected,
          // backend 403) surface as { isError: true } so the model can explain
          // the denial or re-plan. The change is always user-confirmed.
          return ok(
            await this.surface.setPermission(
              this.leaseId,
              input as { path: string; level: string; user?: string; role?: string },
            ),
          );
        case "vaultguard_audit":
          // Read-only audit-log query. Gate failures (lease lacks
          // allowAuditQueries, no connection, backend 403 for non-admins) surface
          // as { isError: true } so the model can explain the denial.
          return ok(
            await this.surface.audit(
              this.leaseId,
              input as {
                search?: string;
                action?: string;
                path?: string;
                outcome?: "success" | "denied" | "error";
                since?: string;
                until?: string;
                limit?: number;
              },
            ),
          );
        case "vaultguard_files":
          // File history / overview / deleted / restore. Gate failures (lease
          // lacks allowFileHistory, no connection, backend 403 for non-admins,
          // confirm rejected on restore) surface as { isError: true }.
          return ok(
            await this.surface.files(
              this.leaseId,
              input as { op: string; path?: string; limit?: number },
            ),
          );
        case "vaultguard_share":
          // Share-link management. Gate failures (lease lacks
          // allowShareManagement, no connection, Pro-only on Community, confirm
          // rejected, backend 403) surface as { isError: true }.
          return ok(
            await this.surface.share(
              this.leaseId,
              input as { op: string; path?: string; shareId?: string; expiresInDays?: number },
            ),
          );
        case "vaultguard_membership":
          // Vault-membership management. Gate failures (lease lacks
          // allowMembershipWrites, no connection, confirm rejected, backend 403,
          // ambiguous/unknown user) surface as { isError: true }.
          return ok(
            await this.surface.membership(
              this.leaseId,
              input as { op: string; user?: string; role?: string },
            ),
          );
        case "vaultguard_ask_user":
          // Interactive chat prompt. The bridge/view owns the UI; this awaits
          // the user's choice and returns it to the model as a normal tool_result.
          return ok(
            await this.surface.askUser(
              this.leaseId,
              input as {
                question: string;
                context?: string;
                options?: Array<{
                  id?: string;
                  label: string;
                  value?: string;
                  description?: string;
                }>;
                allowFreeform?: boolean;
                placeholder?: string;
              },
            ),
          );
        case "vaultguard_import_list":
          // Gated source-read (sd4). Gate failures (lease lacks allowImportRead,
          // no active import session, sandbox escape, not desktop) surface as
          // { isError: true } so the model sees the denial and can re-plan.
          return ok(
            await this.surface.importList(this.leaseId, input as { path?: string; limit?: number }),
          );
        case "vaultguard_import_read":
          // Gated source-read (sd4). Same fail-soft contract: a refusal to read
          // outside the picked folder comes back as { isError: true }, never throws.
          return ok(
            await this.surface.importRead(
              this.leaseId,
              input as { path: string; maxBytes?: number },
            ),
          );
        default:
          return { content: `Unknown tool: ${name}`, isError: true };
      }
    } catch (e) {
      return { content: (e as Error).message, isError: true };
    }
  }
}
