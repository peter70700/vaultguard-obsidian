/**
 * VaultGuard — Signup & Org Provisioning Lambda
 *
 * Handles public signup (no auth required) and org auto-provisioning.
 * Also serves the public org config endpoint for plugin auto-discovery.
 *
 * Endpoints:
 * - POST /signup           — Create org + admin user (public, no auth)
 * - GET  /orgs/{slug}/config — Public config for plugin auto-discovery
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  CreateGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  docClient,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  PutCommand,
  QueryCommand,
  GetCommand,
  ScanCommand,
  ORGANIZATIONS_TABLE,
  PERMISSIONS_TABLE,
  VAULTS_TABLE,
  VAULT_MEMBERS_TABLE,
  PLAN_LIMITS,
  VaultRecord,
  VaultMemberRecord,
} from '../shared/utils';
import { EDITION, FEATURES } from '../shared/edition';
import { sendEmail } from '../email/handler';

// ─── Configuration ───────────────────────────────────────────────────────────

const REGION = process.env.AWS_REGION || 'eu-central-1';
const USER_POOL_ID = process.env.USER_POOL_ID!;
const CLIENT_ID = process.env.CLIENT_ID!;

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });

/** Derive the API base URL from the incoming request context. */
function getApiUrl(event: APIGatewayProxyEvent): string {
  const { requestContext } = event;
  if (requestContext?.domainName && requestContext?.stage) {
    return `https://${requestContext.domainName}/${requestContext.stage}/`;
  }
  return process.env.API_URL || '';
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const resource = event.resource || '';

  try {
    switch (true) {
      case method === 'POST' && resource === '/signup':
        return await handleSignup(event, requestId);

      case method === 'GET' && (resource === '/orgs/{slug}/config' || resource === '/orgs/{orgId}/config'):
        return await handleOrgConfig(event, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
  } catch (err: unknown) {
    console.error('[SIGNUP_HANDLER_ERROR]', (err as Error).message);

    if (err && typeof err === 'object' && 'statusCode' in err) {
      const typed = err as { statusCode: number; message: string };
      return formatError(typed.statusCode, typed.message, requestId);
    }

    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── POST /signup ───────────────────────────────────────────────────────────

/**
 * Public signup: creates an organization and its first admin user.
 *
 * Request body:
 * - orgName: Display name for the organization (e.g., "Acme Corp")
 * - orgSlug: URL-safe identifier (e.g., "acme-corp") — must be unique
 * - email: Admin user email
 * - password: Admin user password (must meet Cognito policy)
 * - displayName: Admin user display name
 *
 * Provisioning steps:
 * 1. Validate slug uniqueness
 * 2. Create org record in DynamoDB
 * 3. Create Cognito group for the org
 * 4. Create Cognito admin user
 * 5. Seed default wildcard permission rule
 */
async function handleSignup(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Community Edition is single-tenant by default: once the first org exists,
  // public signup is locked. Self-hosters can opt back in by setting
  // VAULTGUARD_ALLOW_PUBLIC_SIGNUP=true on the signup lambda. Pro (managed
  // SaaS) keeps public signup open so new customers can sign up unattended.
  if (EDITION === 'community' && process.env.VAULTGUARD_ALLOW_PUBLIC_SIGNUP !== 'true') {
    if (await hasAnyOrg()) {
      return formatError(
        403,
        'Public signup is disabled on this Community Edition deployment. ' +
          'Set VAULTGUARD_ALLOW_PUBLIC_SIGNUP=true on the signup lambda to re-enable.',
        requestId
      );
    }
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['orgName', 'orgSlug', 'email', 'password', 'displayName']);

  const orgName = (body.orgName as string).trim();
  const orgSlug = (body.orgSlug as string).trim().toLowerCase();
  const email = (body.email as string).trim().toLowerCase();
  const password = body.password as string;
  const displayName = (body.displayName as string).trim();

  // Validate slug format: alphanumeric + hyphens, 3-48 chars
  if (!/^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(orgSlug)) {
    return formatError(400, 'Org slug must be 3-48 characters, alphanumeric and hyphens only, cannot start/end with hyphen', requestId);
  }

  // Reserved slugs
  const reserved = ['admin', 'api', 'app', 'www', 'auth', 'signup', 'login', 'vaultguard', 'support', 'help', 'docs'];
  if (reserved.includes(orgSlug)) {
    return formatError(400, `Slug "${orgSlug}" is reserved`, requestId);
  }

  // Step 1: Check slug uniqueness
  const existing = await docClient.send(
    new GetCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: orgSlug },
    })
  );

  if (existing.Item) {
    return formatError(409, `Organization slug "${orgSlug}" is already taken`, requestId);
  }

  const orgId = generateId();
  const now = new Date().toISOString();
  const tier = 'free';
  const limits = PLAN_LIMITS[tier];

  // Step 2: Create Cognito user
  // Use email as username so users can sign in with their email address
  const cognitoUsername = email;

  try {
    await cognitoClient.send(
      new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: cognitoUsername,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'name', Value: displayName },
          { Name: 'custom:org', Value: orgId },
          { Name: 'custom:orgRole', Value: 'owner' },
          { Name: 'custom:role', Value: 'admin' },
        ],
        TemporaryPassword: password,
        MessageAction: 'SUPPRESS', // Use our own branded emails, not Cognito defaults
      })
    );

    // Set permanent password
    await cognitoClient.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: USER_POOL_ID,
        Username: cognitoUsername,
        Password: password,
        Permanent: true,
      })
    );
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName === 'UsernameExistsException') {
      return formatError(409, 'A user with this email already exists', requestId);
    }
    if (errName === 'InvalidPasswordException') {
      return formatError(400, 'Password does not meet requirements: min 12 chars, uppercase, lowercase, digit, symbol', requestId);
    }
    throw err;
  }

  // Step 3: Create Cognito group for the org and add user
  const groupName = `org-${orgSlug}`;
  try {
    await cognitoClient.send(
      new CreateGroupCommand({
        UserPoolId: USER_POOL_ID,
        GroupName: groupName,
        Description: `Organization: ${orgName}`,
      })
    );
  } catch (err: unknown) {
    // Group may already exist if a previous signup partially failed
    if ((err as { name?: string })?.name !== 'GroupExistsException') {
      throw err;
    }
  }

  // Also create admin group if needed
  try {
    await cognitoClient.send(
      new CreateGroupCommand({
        UserPoolId: USER_POOL_ID,
        GroupName: 'admin',
        Description: 'VaultGuard administrators',
      })
    );
  } catch {
    // Already exists — fine
  }

  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
      GroupName: groupName,
    })
  );

  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
      GroupName: 'admin',
    })
  );

  // Step 4: Get the userId (Cognito sub)
  const userInfo = await cognitoClient.send(
    new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
    })
  );
  const userId = userInfo.UserAttributes?.find(a => a.Name === 'sub')?.Value || cognitoUsername;

  // Step 5: Create org record
  // Note: omit null Stripe fields — DynamoDB GSI keys cannot be null
  const orgRecord: Record<string, unknown> = {
    slug: orgSlug,
    orgId,
    name: orgName,
    ownerUserId: userId,
    ownerEmail: email,
    tier,
    maxUsers: limits.maxUsers,
    maxStorageBytes: limits.maxStorageBytes,
    currentUsers: 1,
    currentStorageBytes: 0,
    settings: {
      syncMode: 'periodic',
      syncIntervalMinutes: 1,
      enforceEncryption: true,
      maxSessionDurationHours: 24,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
    },
    createdAt: now,
    updatedAt: now,
    status: 'active',
  };

  await docClient.send(
    new PutCommand({
      TableName: ORGANIZATIONS_TABLE,
      Item: orgRecord,
    })
  );

  // Step 6: Seed a default vault. Every org needs at least one vault for the
  // plugin to bind to — without it the user lands in the picker with nothing
  // to pick. We auto-create a `default` vault, add the org owner as its admin,
  // and seed an org-wide allow-all permission rule scoped to it.
  const defaultVaultId = generateId();
  const defaultVault: VaultRecord = {
    orgId,
    vaultId: defaultVaultId,
    name: `${orgName} — Default`,
    slug: 'default',
    kind: 'team',
    defaultRole: 'editor',
    createdAt: now,
    createdBy: userId,
    archived: false,
    description: 'Default vault auto-created at signup.',
  };
  await docClient.send(
    new PutCommand({
      TableName: VAULTS_TABLE,
      Item: defaultVault,
    })
  );

  const ownerMembership: VaultMemberRecord = {
    vaultId: defaultVaultId,
    userId,
    role: 'admin',
    joinedAt: now,
    invitedBy: userId,
  };
  await docClient.send(
    new PutCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Item: ownerMembership,
    })
  );

  // Step 7: Seed default wildcard permission inside the new vault.
  // Permissions table uses pk (ruleId) + sk (RULE) as composite key.
  const ruleId = generateId();
  const defaultRule = {
    pk: ruleId,
    sk: `RULE`,
    id: ruleId,
    orgId,
    vaultId: defaultVaultId,
    userId: '*',
    pathPattern: '/**',
    actions: ['read', 'write', 'list', 'delete', 'admin'],
    effect: 'allow',
    priority: 1,
    createdAt: now,
    updatedAt: now,
    createdBy: userId,
  };

  await docClient.send(
    new PutCommand({
      TableName: PERMISSIONS_TABLE,
      Item: defaultRule,
    })
  );

  await logAudit({
    userId,
    userEmail: email,
    orgId,
    action: 'org.created',
    resourcePath: `/orgs/${orgSlug}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { orgId, orgSlug, orgName, tier, email },
  });

  // Send welcome email to new org admin
  await sendEmail('welcome', {
    email,
    orgName: orgName,
    orgSlug: orgSlug,
    adminName: displayName || email.split('@')[0],
  });

  return formatSuccess(
    201,
    {
      message: 'Organization created successfully',
      org: {
        slug: orgSlug,
        orgId,
        name: orgName,
        tier,
      },
      user: {
        userId,
        email,
        displayName,
        role: 'owner',
        loginUsername: email, // Users log in with email
      },
      vault: {
        vaultId: defaultVaultId,
        name: defaultVault.name,
        slug: defaultVault.slug,
      },
      config: buildOrgConfig(orgSlug, orgId, orgName, getApiUrl(event)),
    },
    requestId
  );
}

// ─── GET /orgs/{slug}/config ────────────────────────────────────────────────

/**
 * Public endpoint: returns the config the Obsidian plugin needs to connect.
 * No authentication required — the config contains no secrets.
 *
 * Returns:
 * - apiEndpoint: The API Gateway URL
 * - cognitoUserPoolId: Cognito pool ID
 * - cognitoClientId: Cognito app client ID
 * - cognitoRegion: AWS region
 * - orgId: Internal org ID
 * - orgName: Display name
 */
async function handleOrgConfig(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const slug = event.pathParameters?.slug || event.pathParameters?.orgId || '';

  if (!slug) {
    return formatError(400, 'Organization slug is required', requestId);
  }

  // Look up by slug first
  let org = await getOrgBySlug(slug);

  // If not found by slug, try by orgId
  if (!org) {
    org = await getOrgByOrgId(slug);
  }

  if (!org) {
    return formatError(404, `Organization not found: ${slug}`, requestId);
  }

  if (org.status !== 'active') {
    return formatError(403, 'Organization is suspended or cancelled', requestId);
  }

  return formatSuccess(200, buildOrgConfig(org.slug as string, org.orgId as string, org.name as string, getApiUrl(event)), requestId);
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildOrgConfig(
  slug: string,
  orgId: string,
  orgName?: string,
  apiUrl?: string
): Record<string, unknown> {
  return {
    apiEndpoint: apiUrl || '',
    cognitoUserPoolId: USER_POOL_ID,
    cognitoClientId: CLIENT_ID,
    cognitoRegion: REGION,
    orgId,
    orgSlug: slug,
    orgName: orgName || slug,
    edition: EDITION,
    features: FEATURES,
  };
}

async function getOrgBySlug(slug: string): Promise<Record<string, unknown> | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug },
    })
  );
  return result.Item as Record<string, unknown> | null ?? null;
}

/**
 * Returns true if at least one org record exists. Used by the CE single-tenant
 * guard — a 1-item Scan is cheap enough for this admin-control check.
 */
async function hasAnyOrg(): Promise<boolean> {
  const result = await docClient.send(
    new ScanCommand({
      TableName: ORGANIZATIONS_TABLE,
      Limit: 1,
      ProjectionExpression: 'slug',
    })
  );
  return (result.Items?.length ?? 0) > 0;
}

async function getOrgByOrgId(orgId: string): Promise<Record<string, unknown> | null> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: ORGANIZATIONS_TABLE,
      IndexName: 'orgId-index',
      KeyConditionExpression: 'orgId = :oid',
      ExpressionAttributeValues: { ':oid': orgId },
    })
  );
  return (result.Items?.[0] as Record<string, unknown>) || null;
}
