/** Human-only work creation on the existing vault-scoped workspace/changes API.
 * MCP retains its existing list/get/claim/intent catalog. */
export interface CreateHumanWorkItem {
  baseWorkspaceRevisionId: string;
  idempotencyKey: string;
  goal: string;
  riskClass: 'low' | 'medium' | 'high';
  resources: readonly { fileId: string; fileVersionId: string }[];
  dependencies?: readonly string[];
}
export interface HumanWorkItem {
  workItemId: string;
  goal: string;
  state: string;
  revision: string;
  expiresAt: number;
}
