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
