import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
  CognitoIdentityProviderClient,
  GetUserCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import {
  CONNECTOR_OAUTH_SCOPES,
  type ConnectorTokenVerifier,
} from "./connector-auth";

/** Transport normalization only. Live grant/session/policy checks remain in
 * ConnectorAuthService. Cognito GetUser is required to observe native revoke;
 * an offline JWT signature check alone cannot observe it.
 */
export function createCognitoConnectorVerifier(options: {
  userPoolId: string;
  clientIds: string[];
  resource: string;
  verifySignature?: (token: string) => Promise<Record<string, unknown>>;
  getUser?: (
    token: string,
  ) => Promise<{ UserAttributes?: { Name?: string; Value?: string }[] }>;
}): ConnectorTokenVerifier {
  if (
    !/^eu-central-1_[A-Za-z0-9]+$/u.test(options.userPoolId) ||
    options.clientIds.length === 0 ||
    !options.clientIds.every((id) => /^[a-z0-9]{10,128}$/u.test(id)) ||
    !/^https:\/\/[a-z0-9]+\.execute-api\.eu-central-1\.amazonaws\.com\/gates\/mcp$/u.test(
      options.resource,
    )
  )
    throw new Error("INVALID_CONNECTOR_ISSUER_CONFIG");
  const verifier = CognitoJwtVerifier.create({
    userPoolId: options.userPoolId,
    tokenUse: "access",
    clientId: options.clientIds,
  });
  const client = new CognitoIdentityProviderClient({
    region: "eu-central-1",
    maxAttempts: 1,
  });
  const verifySignature =
    options.verifySignature ?? ((token: string) => verifier.verify(token));
  const getUser =
    options.getUser ??
    ((token: string) =>
      client.send(new GetUserCommand({ AccessToken: token })));
  return {
    async verify(token) {
      if (typeof token !== "string" || token.length > 16 * 1024)
        throw new Error("INVALID_CREDENTIAL");
      const claims = await verifySignature(token);
      if (
        claims.iss !==
          `https://cognito-idp.eu-central-1.amazonaws.com/${options.userPoolId}` ||
        claims.token_use !== "access" ||
        claims.aud !== options.resource ||
        typeof claims.client_id !== "string" ||
        !options.clientIds.includes(claims.client_id) ||
        typeof claims.sub !== "string" ||
        typeof claims.scope !== "string"
      )
        throw new Error("INVALID_CREDENTIAL");
      const wireScopes = claims.scope.split(" ");
      if (
        !wireScopes.includes("aws.cognito.signin.user.admin") ||
        new Set(wireScopes).size !== wireScopes.length
      )
        throw new Error("INVALID_CREDENTIAL");
      const scopes: string[] = [];
      for (const scope of wireScopes) {
        if (scope === "openid" || scope === "aws.cognito.signin.user.admin")
          continue;
        const expected = CONNECTOR_OAUTH_SCOPES.find(
          (candidate) => scope === `${options.resource}/${candidate}`,
        );
        if (!expected) throw new Error("INVALID_CREDENTIAL");
        scopes.push(expected);
      }
      if (!scopes.length) throw new Error("INVALID_CREDENTIAL");
      const user = await getUser(token);
      if (
        !Array.isArray(user.UserAttributes) ||
        user.UserAttributes.filter((attribute) => attribute.Name === "sub")
          .length !== 1 ||
        user.UserAttributes.find((attribute) => attribute.Name === "sub")
          ?.Value !== claims.sub
      )
        throw new Error("INVALID_CREDENTIAL");
      return { ...claims, scope: scopes.join(" ") };
    },
  };
}
