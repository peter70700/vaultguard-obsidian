/**
 * mcp-read — Community Edition stub.
 *
 * Remote MCP production read host and internal preparation is not a Community Edition feature — it is unreleased, not paid. This stub keeps the terraform graph
 * valid while refusing every request with a 404. Its source stays private while remote MCP awaits final verification.
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";

export async function handler(_event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  return {
    statusCode: 404,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      message: "Not found",
      detail: "The remote MCP read host is not available in Community Edition.",
    }),
  };
}

// The private preparation entry remains unavailable in the public stub too.
export const prepareHandler = handler;
