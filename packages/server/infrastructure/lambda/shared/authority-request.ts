import type { APIGatewayProxyEvent } from "aws-lambda";
import { parseBody, getClientIp, getUserAgent } from "./utils";
import type { AuthorityMutationRequest } from "./authority-mutation";
/** Used only at the genuine HTTP edge; preserve canonical decode/size/audit rules. */
export function authorityMutationRequest(
  event: APIGatewayProxyEvent,
  readBody = false,
): AuthorityMutationRequest {
  return {
    vaultId: event.pathParameters?.vaultId ?? "",
    targetId: event.pathParameters?.userId ?? event.pathParameters?.shareId,
    body: readBody ? parseBody(event) : {},
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
  };
}
