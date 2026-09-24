/**
 * workspace-projection — Community Edition stub.
 *
 * Private workspace projection delivery is not a Community Edition feature — it is unreleased, not paid. This stub keeps the terraform graph
 * valid while refusing every request with a 404. Its source stays private while the workspace awaits final verification.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

export async function handler(_event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  return {
    statusCode: 404,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: "Not found",
      detail: "Workspace projection delivery is not available in Community Edition.",
    }),
  };
}