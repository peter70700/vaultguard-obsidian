export interface DerivedConnectionConfig {
  organizationId?: string;
  orgSlug?: string;
  cognitoUserPoolId?: string;
  cognitoClientId?: string;
}

export function deriveConnectionConfigFromTokenPayload(
  payload: Record<string, unknown>,
  fallbackRoles: string[] = []
): DerivedConnectionConfig {
  const groups = Array.isArray(payload["cognito:groups"])
    ? payload["cognito:groups"].filter(
        (value): value is string => typeof value === "string"
      )
    : [];
  const roles = [...groups, ...fallbackRoles];

  return {
    organizationId: asNonEmptyString(payload["custom:org"]),
    orgSlug: deriveOrgSlug(roles),
    cognitoUserPoolId: deriveUserPoolId(asNonEmptyString(payload.iss)),
    cognitoClientId: asNonEmptyString(payload.aud),
  };
}

function deriveOrgSlug(roles: string[]): string | undefined {
  const orgRole = roles.find(
    (role) => typeof role === "string" && role.toLowerCase().startsWith("org-")
  );
  if (!orgRole) {
    return undefined;
  }

  const slug = orgRole.slice(4).trim().toLowerCase();
  return slug.length > 0 ? slug : undefined;
}

function deriveUserPoolId(issuer: string | undefined): string | undefined {
  if (!issuer) {
    return undefined;
  }

  const trimmedIssuer = issuer.trim().replace(/\/+$/, "");
  const poolId = trimmedIssuer.split("/").pop()?.trim();
  return poolId && poolId.length > 0 ? poolId : undefined;
}

function asNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0
    ? value.trim()
    : undefined;
}
