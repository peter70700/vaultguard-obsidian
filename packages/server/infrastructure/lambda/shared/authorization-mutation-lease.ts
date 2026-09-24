import { randomUUID } from "node:crypto";
import { QueryCommand, UpdateCommand, type TransactWriteCommandInput } from "@aws-sdk/lib-dynamodb";
type ApprovalCondition = NonNullable<
  NonNullable<TransactWriteCommandInput["TransactItems"]>[number]["ConditionCheck"]
>;
interface CollaborationScope {
  orgId: string;
  vaultId: string;
}
/** A short exclusion lease, not authorization. It fences authorization writers
 * while an approved access/content transaction revalidates current permissions. */
export interface AuthorizationMutationLease extends CollaborationScope {
  id: string;
  expiresAt: number;
}
export class AuthorizationMutationBusyError extends Error {
  constructor() {
    super("Authorization is changing; retry after reconciliation.");
    this.name = "AuthorizationMutationBusyError";
  }
}
export function authorizationMutationAdmission(
  table: string,
  scope: CollaborationScope,
  now: number,
  lease?: AuthorizationMutationLease,
): ApprovalCondition {
  return {
    TableName: table,
    Key: { orgId: scope.orgId, vaultId: scope.vaultId },
    ConditionExpression:
      "attribute_exists(orgId) AND (attribute_not_exists(authorizationMutationLeaseId) OR authorizationMutationLeaseExpiresAt <= :leaseNow" +
      (lease
        ? " OR (authorizationMutationLeaseId = :leaseId AND authorizationMutationLeaseExpiresAt = :leaseExpiry)"
        : "") +
      ")",
    ExpressionAttributeValues: {
      ":leaseNow": now,
      ...(lease ? { ":leaseId": lease.id, ":leaseExpiry": lease.expiresAt } : {}),
    },
  };
}
export class DynamoAuthorizationMutationLease {
  constructor(
    private readonly options: {
      vaultsTable: string;
      activityTable: string;
      send(command: any): Promise<any>;
      now?: () => number;
    },
  ) {}
  private now() {
    return this.options.now?.() ?? Date.now();
  }
  condition(lease: AuthorizationMutationLease): ApprovalCondition {
    if (lease.expiresAt <= this.now()) throw new AuthorizationMutationBusyError();
    return {
      TableName: this.options.vaultsTable,
      Key: { orgId: lease.orgId, vaultId: lease.vaultId },
      ConditionExpression:
        "authorizationMutationLeaseId = :leaseId AND authorizationMutationLeaseExpiresAt = :leaseExpiry AND authorizationMutationLeaseExpiresAt > :leaseNow",
      ExpressionAttributeValues: {
        ":leaseId": lease.id,
        ":leaseExpiry": lease.expiresAt,
        ":leaseNow": this.now(),
      },
    };
  }
  async acquire(scope: CollaborationScope): Promise<AuthorizationMutationLease> {
    const lease = { ...scope, id: randomUUID(), expiresAt: this.now() + 120_000 };
    const admission = authorizationMutationAdmission(this.options.vaultsTable, scope, this.now());
    try {
      await this.options.send(
        new UpdateCommand({
          ...admission,
          UpdateExpression:
            "SET authorizationMutationLeaseId = :newLeaseId, authorizationMutationLeaseExpiresAt = :newLeaseExpiry",
          ExpressionAttributeValues: {
            ...admission.ExpressionAttributeValues,
            ":newLeaseId": lease.id,
            ":newLeaseExpiry": lease.expiresAt,
          },
        }),
      );
      // Read AFTER acquiring. A legacy writer that won its admission before us
      // has a strongly visible pending intent; one starting later is fenced.
      let cursor: Record<string, any> | undefined,
        pages = 0;
      const seen = new Set<string>();
      do {
        if (++pages > 10) throw new AuthorizationMutationBusyError();
        const page = await this.options.send(
          new QueryCommand({
            TableName: this.options.activityTable,
            KeyConditionExpression: "vaultId = :vault AND begins_with(sk, :prefix)",
            ExpressionAttributeValues: { ":vault": scope.vaultId, ":prefix": "!INTENT#" },
            ConsistentRead: true,
            Limit: 100,
            ...(cursor ? { ExclusiveStartKey: cursor } : {}),
          }),
        );
        if (!Array.isArray(page.Items) || page.Items.length) throw new AuthorizationMutationBusyError();
        cursor = page.LastEvaluatedKey;
        if (cursor) {
          const token = JSON.stringify(cursor);
          if (seen.has(token)) throw new AuthorizationMutationBusyError();
          seen.add(token);
        }
      } while (cursor);
      this.condition(lease);
      return lease;
    } catch (error) {
      await this.release(lease).catch(() => undefined);
      throw error;
    }
  }
  async release(lease: AuthorizationMutationLease): Promise<void> {
    await this.options.send(
      new UpdateCommand({
        TableName: this.options.vaultsTable,
        Key: { orgId: lease.orgId, vaultId: lease.vaultId },
        UpdateExpression: "REMOVE authorizationMutationLeaseId, authorizationMutationLeaseExpiresAt",
        ConditionExpression: "authorizationMutationLeaseId = :leaseId",
        ExpressionAttributeValues: { ":leaseId": lease.id },
      }),
    );
  }
}
