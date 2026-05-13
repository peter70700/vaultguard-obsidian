/**
 * billing — Community Edition stub.
 *
 * Stripe-backed subscription lifecycle is a Pro-tier feature. This stub keeps the terraform graph
 * valid while refusing every request with a 404. Upgrade at
 * https://example.com.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

export async function handler(_event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  return {
    statusCode: 404,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: "Not found",
      detail: "Billing is a Pro-tier feature. See https://example.com.",
    }),
  };
}

// No-op cross-handler exports for CE (callers in users/handler + reconciler).
// See export-public-server-repo.mjs:buildStubHandler() for rationale.
export async function syncStripeSeats(
  _orgId: string,
): Promise<{ synced: boolean; currentUsers: number; quantity?: number; message?: string; reason?: string }> {
  return { synced: false, currentUsers: 0, message: "Billing not enabled in Community Edition" };
}
