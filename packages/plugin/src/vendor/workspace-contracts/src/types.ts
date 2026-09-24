import type {
  AgentIdentityId,
  AgentSessionId,
  ChangeSetId,
  ConflictId,
  FeatureId,
  FileId,
  FileVersionId,
  GraphRevisionId,
  HandoffId,
  OAuthClientId,
  OAuthGrantId,
  OrganizationId,
  PermissionRevisionId,
  PolicyRevisionId,
  ProjectionRevisionId,
  ProposalId,
  ReceiptId,
  SchemaDocumentId,
  Sha256,
  SubjectId,
  VaultId,
  WorkspaceRevisionId,
} from "./ids.js";

export type { SafeId, Sha256 } from "./ids.js";
export type Consistency = "exact" | "stale" | "unavailable";
export type RiskClass = "read" | "propose" | "apply" | "admin" | "ceremony";
export type ProviderProfileId = "generic-text" | "openai-chatgpt" | "anthropic-claude";

export type OAuthScope =
  | "workspace:read"
  | "files:list"
  | "files:search"
  | "files:read"
  | "history:read"
  | "history:restore"
  | "graph:read"
  | "semantic:read"
  | "context:read"
  | "context:propose"
  | "changes:read"
  | "changes:propose"
  | "changes:apply"
  | "coordination:read"
  | "coordination:write"
  | "access:read"
  | "permissions:read"
  | "access:propose"
  | "access:apply"
  | "members:read"
  | "shares:read"
  | "shares:write"
  | "audit:read"
  | "transfers:prepare"
  | "connector:read";

export interface SessionContext {
  readonly kind: "trusted-session-context";
  readonly schemaVersion: string;
  readonly orgId: OrganizationId;
  readonly vaultId: VaultId;
  readonly subjectId: SubjectId;
  readonly oauthClientId: OAuthClientId;
  readonly oauthGrantId: OAuthGrantId;
  readonly agentIdentityId: AgentIdentityId;
  readonly agentSessionId: AgentSessionId;
  readonly providerProfileId: ProviderProfileId;
  readonly scopes: readonly OAuthScope[];
  readonly riskCeiling: RiskClass;
  readonly permissionRevisionId: PermissionRevisionId;
  readonly policyRevisionId: PolicyRevisionId;
  readonly expiresAt: string;
  readonly revocationCheckedAt: string;
}

export type RevisionSelector =
  | { readonly mode: "exact"; readonly workspaceRevisionId: WorkspaceRevisionId }
  | { readonly mode: "latest" };

export interface ExactRevision {
  readonly kind: "resolved-workspace-revision";
  readonly selector: RevisionSelector;
  readonly workspaceRevisionId: WorkspaceRevisionId;
  readonly currentWorkspaceRevisionId: WorkspaceRevisionId;
  readonly consistency: Consistency;
}

export interface VersionCitation {
  readonly vaultId: VaultId;
  readonly workspaceRevisionId: WorkspaceRevisionId;
  readonly fileId: FileId;
  readonly fileVersionId: FileVersionId;
  readonly path: string;
  readonly contentHash: Sha256;
}

export interface ProjectionCitation {
  readonly sourceWorkspaceRevisionId: WorkspaceRevisionId;
  readonly currentWorkspaceRevisionId: WorkspaceRevisionId;
  readonly projectionRevisionId: GraphRevisionId | ProjectionRevisionId | null;
  readonly permissionRevisionId: PermissionRevisionId;
  readonly consistency: Consistency;
}

export type Citation = VersionCitation | ProjectionCitation;

export interface PageRequest {
  readonly cursor?: string;
  readonly limit?: number;
}

export interface PageInfo {
  readonly nextCursor: string | null;
  readonly returned: number;
  readonly truncated: boolean;
  readonly consistency: Consistency;
}

export interface Pagination {
  readonly request: PageRequest;
  readonly pageInfo: PageInfo;
}

export type ErrorCode =
  | "invalid_request"
  | "unauthenticated"
  | "denied"
  | "not_found"
  | "stale"
  | "conflict"
  | "approval_required"
  | "approval_expired"
  | "idempotency_mismatch"
  | "unsupported"
  | "feature_disabled"
  | "rate_limited"
  | "too_large"
  | "index_stale"
  | "temporarily_unavailable"
  | "internal_error"
  | "selector_mismatch"
  | "graph_not_ready"
  | "index_unavailable"
  | "cursor_invalid"
  | "cursor_expired"
  | "revision_not_found"
  | "unsupported_source"
  | "parse_failed"
  | "AUTH_REQUIRED"
  | "TOKEN_INVALID"
  | "GRANT_INACTIVE"
  | "SESSION_INACTIVE"
  | "SCOPE_DENIED"
  | "VAULT_ACCESS_DENIED"
  | "RESOURCE_ACCESS_DENIED"
  | "VAULT_ARCHIVED"
  | "BASE_REQUIRED"
  | "WORKSPACE_BASE_STALE"
  | "FILE_BASE_STALE"
  | "PATH_CLAIM_CONFLICT"
  | "SEMANTIC_TARGET_AMBIGUOUS"
  | "LINK_IMPACT_INCOMPLETE"
  | "PARSER_INCOMPLETE"
  | "GRAPH_NOT_EXACT"
  | "APPROVAL_REQUIRED"
  | "APPROVAL_STALE"
  | "IDEMPOTENCY_KEY_REUSED"
  | "CHANGESET_CONFLICT"
  | "CHANGESET_PENDING"
  | "ROTATION_IN_PROGRESS"
  | "AUDIT_UNAVAILABLE"
  | "QUOTA_EXCEEDED"
  | "RETRYABLE_UNAVAILABLE";

export type HandoffPurpose =
  | "connector_authorize"
  | "connector_manage"
  | "proposal_review"
  | "access_review"
  | "share_review"
  | "restore_review"
  | "import_upload"
  | "export_download"
  | "security_settings"
  | "vault_administration"
  | "mfa"
  | "recovery"
  | "billing"
  | "legal_consent";

export interface WebHandoff {
  readonly handoffId: HandoffId;
  readonly purpose: HandoffPurpose;
  readonly url: string;
  readonly expiresAt: string;
  readonly statusTool: string;
  readonly statusArgs: Readonly<Record<string, string>>;
}

export interface SecureHandoff {
  readonly handoff: WebHandoff;
  readonly binding: {
    readonly subjectId: SubjectId;
    readonly oauthClientId: OAuthClientId;
    readonly vaultId?: VaultId;
    readonly nonceHash: Sha256;
    readonly singleUse: true;
    readonly independentlyAuthenticated: true;
    readonly stepUp: "not_required" | "policy";
  };
}

export interface StableError {
  readonly error: {
    readonly code: ErrorCode;
    readonly message: string;
    readonly requestId: string;
    readonly retryable: boolean;
    readonly retryAfterMs?: number;
    readonly retryAfterSeconds?: number;
    readonly conflictId?: ConflictId;
    readonly handoff?: WebHandoff;
  };
}

export interface MutationReceiptFile {
  readonly fileId: FileId;
  readonly path: string;
  readonly oldVersionId?: FileVersionId;
  readonly newVersionId?: FileVersionId;
  readonly newHash?: Sha256;
}

export interface MutationReceipt {
  readonly receiptId: ReceiptId;
  readonly changeSetId: ChangeSetId;
  readonly proposalId: ProposalId;
  readonly proposalRevision: number;
  readonly result: "applied" | "conflicted" | "failed" | "partially_applied";
  readonly oldWorkspaceRevisionId: WorkspaceRevisionId;
  readonly newWorkspaceRevisionId?: WorkspaceRevisionId;
  readonly files: readonly MutationReceiptFile[];
  readonly verification: "verified" | "failed" | "unknown";
}

export interface ProviderProfile {
  readonly profileId: ProviderProfileId;
  readonly schemaCatalogVersion: string;
  readonly coreSchemas: "identical";
  readonly fallbackProfileId: "generic-text";
  readonly permittedAdaptations: readonly string[];
  readonly structuredResultRequired: true;
  readonly safetyDisclosuresRequired: true;
}

export interface ToolDescriptor {
  readonly name: string;
  readonly schemaVersion: string;
  readonly inputSchemaId: SchemaDocumentId;
  readonly outputSchemaId: SchemaDocumentId;
  readonly annotations: {
    readonly readOnly: boolean;
    readonly idempotent: boolean;
    readonly destructive: boolean;
    readonly externalEffect: boolean;
  };
  readonly requiredScopes: readonly OAuthScope[];
  readonly policyFeature: FeatureId;
  readonly riskClass: RiskClass;
  readonly bounds: Readonly<{
    maxPageSize?: number;
    maxInputBytes?: number;
    maxOutputBytes?: number;
    maxItems?: number;
  }>;
  readonly optionalUi: boolean;
  readonly availability: "available";
}

export interface Discovery {
  readonly schemaCatalogVersion: string;
  readonly providerProfileId: ProviderProfileId;
  readonly agentSessionId: AgentSessionId;
  readonly tools: readonly ToolDescriptor[];
  readonly unavailable: readonly {
    readonly name: string;
    readonly reason:
      | "scope_required"
      | "role_required"
      | "feature_disabled"
      | "provider_unsupported"
      | "reconnect_required"
      | "temporarily_unavailable";
  }[];
  readonly reconnectRequired: boolean;
  readonly limits: {
    readonly defaultPageSize: 50;
    readonly maxPageSize: 200;
    readonly maxReadWindowBytes: 262144;
    readonly maxBatchReadBytes: 524288;
    readonly maxBatchFiles: 20;
  };
}
