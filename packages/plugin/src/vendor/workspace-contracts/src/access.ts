/** Closed source contract; enabling a transport or issuing these scopes is separate. */
export type AccessOperation =
  | {
      op: "set_path_level";
      pathPattern: string;
      principal: { userId: string } | { role: "viewer" | "editor" | "admin" };
      level: "none" | "read" | "write" | "admin";
    }
  | { op: "add_member"; userId: string; role: "viewer" | "editor" | "admin"; expiresAt?: string }
  | {
      op: "set_member_role";
      userId: string;
      expectedMembershipRevision: string;
      role: "viewer" | "editor" | "admin";
    }
  | { op: "remove_member"; userId: string; expectedMembershipRevision: string }
  | { op: "create_share"; file: { fileId: string; fileVersionId: string; path: string }; expiresAt?: string }
  | { op: "revoke_share"; shareId: string };
export type AccessCommand =
  | {
      action: "propose";
      expectedPermissionRevision: string;
      operations: AccessOperation[];
      idempotencyKey: string;
    }
  | { action: "status" | "review" | "revoke"; proposalId: string }
  | {
      action: "decide";
      proposalId: string;
      reviewToken: string;
      decision: "approve" | "reject";
      idempotencyKey: string;
    }
  | {
      action: "apply";
      proposalId: string;
      proposalRevision: number;
      previewHash: string;
      approvalId: string;
      idempotencyKey: string;
    };
export interface AccessDomainReceipt {
  operationIndex: number;
  domain: "membership" | "permission" | "internal-share";
  status: "applied" | "not-applied" | "reconciliation-required" | "fresh-review-required";
  receiptId: string;
  /** No automatic rollback. A compensating change is a newly reviewed proposal. */
  recovery: "none" | "new-proposal" | "inspect-domain-receipts";
  confirmedEffects?: {
    kind: "member" | "permission-rule" | "share" | "synchronization";
    id: string;
    state: "written" | "deleted";
  }[];
}
export interface AccessStatus {
  readonly idempotentReplay?: boolean;
  proposalId: string;
  proposalRevision: 1;
  previewHash: string;
  state:
    | "pending"
    | "approved"
    | "rejected"
    | "revoked"
    | "applying"
    | "completed"
    | "partial"
    | "reconciliation-required"
    | "expired";
  expiresAt: string;
  reviewPath: string;
  approvalId?: string;
  receipts: AccessDomainReceipt[];
  remainingOperationIndexes: number[];
  atomic: false;
}
export interface AccessReview extends AccessStatus {
  reviewToken: string;
  operations: AccessOperation[];
  impacts: {
    operationIndex: number;
    domain: AccessDomainReceipt["domain"];
    before: unknown;
    disclosure: string;
  }[];
  disclosures: string[];
}
