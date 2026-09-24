import type { AuthorizationMutationLease } from "./authorization-mutation-lease";
import { AsyncLocalStorage } from "node:async_hooks";
/** Explicit domain input. Contains no claims, token or fabricated Gateway event. */
export interface AuthorityMutationRequest {
  vaultId: string;
  targetId?: string;
  body: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
}
/**
 * VAULTGUARD-113 (P4-GAP-3): the trusted correlation of one approved
 * access-workflow operation, attached to every canonical audit event the
 * operation's domain handler writes (`buildAuditEntry`).
 *
 * It exists ONLY inside the invocation-local runtime below, which only
 * `WorkspaceAccessService.apply` builds, from its own durable, validated
 * proposal and approval records and the live applier it just re-authorized. No
 * request body, header or HTTP-edge input can reach it, so a direct
 * administration call can never claim to be a workflow apply.
 */
export interface AuthorityAuditCorrelation {
  readonly channel: "approval_workflow";
  readonly workflow: "access";
  readonly proposalId: string;
  /** `${proposalId}:${operationIndex}`, the domain receipt of this operation. */
  readonly receiptId: string;
  readonly operationIndex: number;
  readonly approvalId: string;
  readonly reviewerUserId: string;
  readonly reviewerSessionId: string;
  readonly applierKind: "human" | "delegated-agent";
  readonly applierUserId: string;
  /** The human web session, or the delegated connector session. */
  readonly applierSessionId: string;
  /** Human appliers only. */
  readonly applierChannel?: string;
  /** Delegated appliers only. */
  readonly agentIdentityId?: string;
  readonly agentSessionId?: string;
  readonly grantId?: string;
  readonly clientId?: string;
  readonly hostKind?: string;
}
/** Invocation-local SDK decoration. Existing handlers use their unchanged SDK
 * owner; governed adapters can attach current-authority conditions and durable
 * write receipts to those SAME domain transactions. No process-global state. */
const runtime = new AsyncLocalStorage<{
  send(command: any): Promise<any>;
  authorizationLease?: AuthorizationMutationLease;
  audit?: AuthorityAuditCorrelation;
}>();
export function withAuthorityMutation<T>(
  owner: {
    send(command: any): Promise<any>;
    authorizationLease?: AuthorizationMutationLease;
    audit?: AuthorityAuditCorrelation;
  },
  action: () => Promise<T>,
): Promise<T> {
  return runtime.run(owner, action);
}
export function authorityCommand(fallback: { send(command: any): Promise<any> }, command: any): Promise<any> {
  return (runtime.getStore() ?? fallback).send(command);
}

export const currentAuthorizationMutationLease = () => runtime.getStore()?.authorizationLease;

/** The correlation of the approved operation in flight, or `undefined` outside one. */
export const currentAuthorityAuditCorrelation = () => runtime.getStore()?.audit;
