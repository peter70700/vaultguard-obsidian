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
        case "vaultguard_graph":
          // Read-only structural navigation. Service errors (bad op, missing
          // path/tag, permission gate) still surface as { isError: true }.
          return ok(await this.surface.graph(this.leaseId, input as unknown as GraphArgs));
        default:
          return { content: `Unknown tool: ${name}`, isError: true };
      }
    } catch (e) {
      return { content: (e as Error).message, isError: true };
    }
  }
}
