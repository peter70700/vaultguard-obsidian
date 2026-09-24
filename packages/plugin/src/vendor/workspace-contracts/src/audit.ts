import type {
  AgentIdentityId,
  AgentSessionId,
  AnyStableId,
  ApprovalId,
  AuditEventId,
  ChangeSetId,
  FileId,
  FileVersionId,
  IdempotencyRecordId,
  OAuthClientId,
  OAuthGrantId,
  OrganizationId,
  PermissionRevisionId,
  PolicyRevisionId,
  ProposalId,
  ReceiptId,
  RequestId,
  Sha256,
  SubjectId,
  VaultId,
  WorkIntentId,
  WorkspaceRevisionId,
} from "./ids.js";
import type { ErrorCode, OAuthScope, RiskClass } from "./types.js";

export type AuditOutcome =
  | { readonly status: "success"; readonly errorCode?: never; readonly retryable?: never }
  | { readonly status: "denied" | "error" | "conflict"; readonly errorCode: ErrorCode; readonly retryable: boolean }
  | { readonly status: "pending"; readonly errorCode?: ErrorCode; readonly retryable: true };

export interface AuditFileChange {
  readonly fileId: FileId;
  readonly beforeVersionId?: FileVersionId;
  readonly afterVersionId?: FileVersionId;
  readonly beforeHash?: Sha256;
  readonly afterHash?: Sha256;
}

export interface AuditEvent {
  readonly schemaVersion: string;
  readonly auditEventId: AuditEventId;
  readonly requestId: RequestId;
  readonly occurredAt: string;
  readonly durationMs: number;
  readonly actor: {
    readonly orgId: OrganizationId;
    readonly subjectId?: SubjectId;
    readonly oauthClientId?: OAuthClientId;
    readonly oauthGrantId?: OAuthGrantId;
    readonly agentIdentityId?: AgentIdentityId;
    readonly agentSessionId?: AgentSessionId;
    readonly hostKind?: "generic_text" | "openai_chatgpt" | "anthropic_claude" | "vaultguard";
  };
  readonly target: {
    readonly vaultId?: VaultId;
    readonly resourceKind:
      | "connector"
      | "workspace"
      | "file"
      | "folder"
      | "graph"
      | "context"
      | "proposal"
      | "change_set"
      | "permission"
      | "membership"
      | "share"
      | "audit";
    readonly resourceId?: AnyStableId;
    readonly resourcePathHash?: Sha256;
  };
  readonly action: {
    readonly toolName: string;
    readonly operation: string;
    readonly riskClass: RiskClass;
    readonly scopes: readonly OAuthScope[];
    readonly workIntentId?: WorkIntentId;
    readonly proposalId?: ProposalId;
    readonly proposalRevision?: number;
    readonly approvalId?: ApprovalId;
    readonly changeSetId?: ChangeSetId;
    readonly receiptId?: ReceiptId;
    readonly idempotencyRecordId?: IdempotencyRecordId;
  };
  readonly revisions: {
    readonly baseWorkspaceRevisionId?: WorkspaceRevisionId;
    readonly currentWorkspaceRevisionId?: WorkspaceRevisionId;
    readonly resultWorkspaceRevisionId?: WorkspaceRevisionId;
    readonly permissionRevisionId?: PermissionRevisionId;
    readonly policyRevisionId?: PolicyRevisionId;
  };
  readonly outcome: AuditOutcome & {
    readonly idempotentReplay: boolean;
    readonly rebased: boolean;
  };
  readonly affectedFiles: readonly AuditFileChange[];
}
