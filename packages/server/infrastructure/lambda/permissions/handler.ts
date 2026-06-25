/**
 * VaultGuard — Permissions Management Lambda Handler
 *
 * Manages the permission rule system that controls access to vault files.
 * All rules are scoped to a single vault — rules in vault A do not leak
 * into vault B. Supports user-level, role-level, and glob-pattern-based
 * permissions with inheritance, time-bound grants, and conflict resolution.
 *
 * Endpoints (all under /vaults/{vaultId}):
 * - GET    /permissions                — List rules in this vault (vault-admin or org-admin)
 * - GET    /vaults/{vaultId}/permissions/user/{userId} — Effective permissions for a user (self or vault-admin)
 * - POST   /permissions                — Create rule (vault-admin or org-admin)
 * - PUT    /vaults/{vaultId}/permissions/{id} — Update rule (vault-admin)
 * - DELETE /vaults/{vaultId}/permissions/{id} — Delete rule (vault-admin)
 * - POST   /vaults/{vaultId}/permissions/check — Check if user can perform action on path (any vault member, self only)
 * - POST   /vaults/{vaultId}/permissions/access — Effective per-file access summary (any member with read)
 * - POST   /vaults/{vaultId}/permissions/access/batch — Batch access summaries (any member, capped paths)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  AdminGetUserCommand,
  CognitoIdentityProviderClient,
  ListUsersCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  docClient,
  verifyActiveUser,
  evaluatePermission,
  authorizePermissionMutation,
  ruleLevelRank,
  shouldRespectAdminBypassFor,
  requireOrgId,
  requireVaultMember,
  pathMatchesPattern,
  getVaultMembership,
  listVaultMembers,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  isAdmin,
  recordVaultActivity,
  UserContext,
  VaultRecord,
  VaultMemberRecord,
  PermissionRule,
  PermissionAction,
  AuthError,
  ValidationError,
  PutCommand,
  QueryCommand,
  DeleteCommand,
  UpdateCommand,
  ScanCommand,
  PERMISSIONS_TABLE,
  LEASES_TABLE,
} from '../shared/utils';

// ─── Constants ───────────────────────────────────────────────────────────────

/** Valid permission actions that can be granted or denied. */
const VALID_ACTIONS: PermissionAction[] = ['read', 'write', 'delete', 'admin', 'list'];

/** Valid permission effects. */
const VALID_EFFECTS = ['allow', 'deny'] as const;

/** Constant sort key for permission rule items. */
const RULE_SK = 'RULE';
const USER_POOL_ID = process.env.USER_POOL_ID!;
const COGNITO_REGION = process.env.AWS_REGION || 'eu-west-1';
const cognitoClient = new CognitoIdentityProviderClient({ region: COGNITO_REGION });

interface PrincipalIdentity {
  userId: string;
  email: string;
  displayName?: string;
}

type PathAccessLevel = 'none' | 'read' | 'write' | 'admin';

interface PathAccessPrincipal {
  userId: string;
  email?: string;
  displayName?: string;
  role?: string;
  level: PathAccessLevel;
}

// ─── Main Handler ────────────────────────────────────────────────────────────

/**
 * Lambda entry point. Routes permission management requests based on
 * HTTP method and resource path.
 *
 * @param event - API Gateway proxy event
 * @returns API Gateway proxy result with JSON body
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const resource = event.resource || '';

  try {
    // Authenticate all requests
    const user = await verifyActiveUser(event);

    const vaultId = event.pathParameters?.vaultId || '';
    if (!vaultId) {
      return formatError(400, 'vaultId path parameter is required', requestId);
    }

    // Read access requires viewer; mutations require admin (checked per-handler).
    const vault = await requireVaultMember(user, vaultId, 'viewer');

    switch (true) {
      case method === 'GET' && resource === '/vaults/{vaultId}/permissions':
        return await handleListPermissions(event, user, vault, requestId);

      case method === 'GET' && resource === '/vaults/{vaultId}/permissions/user/{userId}':
        return await handleGetUserPermissions(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions': {
        // Two-mode endpoint:
        //   - body.level (a PathAccessLevel string) → set-level mode: server
        //     computes inherited level and picks delete/update/create itself.
        //     This is the canonical entry point from the file/folder
        //     permission UIs, which only know the desired effective level.
        //   - otherwise → legacy create mode: caller supplies the exact
        //     (actions, effect) rule shape, used by the advanced rule editor
        //     and any API consumers that need direct control.
        //
        // Mode-switching is intentionally NOT a separate API Gateway resource
        // — keeping the dispatch in code means no API Gateway / Terraform
        // change is required to ship the set-level fix.
        const probe = parseBody(event);
        if (typeof probe.level === 'string') {
          return await handleSetLevel(event, user, vault, requestId, probe);
        }
        return await handleCreatePermission(event, user, vault, requestId);
      }

      case method === 'PUT' && resource === '/vaults/{vaultId}/permissions/{id}':
        return await handleUpdatePermission(event, user, vault, requestId);

      case method === 'DELETE' && resource === '/vaults/{vaultId}/permissions/{id}':
        return await handleDeletePermission(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions/check':
        return await handleCheckPermission(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions/access':
        return await handlePathAccess(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions/access/batch':
        return await handleBatchPathAccess(event, user, vault, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
  } catch (err: unknown) {
    if (err instanceof AuthError) {
      return formatError(err.statusCode, err.message, requestId, err.code);
    }
    if (err instanceof ValidationError) {
      return formatError(err.statusCode, err.message, requestId);
    }

    console.error('[PERMISSIONS_HANDLER_ERROR]', (err as Error).message);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── GET /permissions ────────────────────────────────────────────────────────

/**
 * Lists all permission rules in the system.
 * Only accessible by administrators.
 *
 * Query Parameters:
 * - limit: Maximum results per page (default 50, max 500)
 * - lastEvaluatedKey: For pagination
 * - pathFilter: Filter rules by path pattern (substring match)
 * - effectFilter: Filter by 'allow' or 'deny'
 *
 * @param event - API Gateway event with optional filters
 * @param user - Authenticated user context (must be admin)
 * @param requestId - Request ID for tracing
 * @returns Paginated list of all permission rules
 */
async function handleListPermissions(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Permission rules can reveal hidden path names and target principals, so
  // full rule listing is admin-only. A file-level admin may list only rules
  // that overlap the requested pathFilter, which gives the plugin enough raw
  // rule IDs to edit that file without leaking unrelated paths.
  const limit = Math.min(parseInt(event.queryStringParameters?.limit || '50', 10), 500);
  const pathFilter = event.queryStringParameters?.pathFilter;
  const effectFilter = event.queryStringParameters?.effectFilter;
  const pathFilterTarget = pathFilter ? normalizePermissionPath(pathFilter) : null;
  let fullRuleList = false;

  try {
    await requireVaultMember(user, vault.vaultId, 'admin');
    fullRuleList = true;
  } catch (err) {
    if (!(err instanceof AuthError)) throw err;
    if (!pathFilterTarget) {
      return formatError(403, 'Vault admin access is required to list all permission rules', requestId);
    }

    const callerRoles = await resolvePermissionRolesForTarget(user.userId, user, vault);
    const callerAliases = await aliasesForTargetUser(user.userId, user, vault.orgId);
    const adminCheck = await evaluatePermission(
      user.userId,
      callerRoles,
      'admin',
      pathFilterTarget,
      vault.orgId,
      vault.vaultId,
      { userAliases: callerAliases }
    );
    if (!adminCheck.allowed) {
      return formatError(403, `You do not have admin on ${pathFilterTarget}`, requestId);
    }
  }

  let filterExpression: string = 'orgId = :orgId AND vaultId = :vaultId';
  const expressionValues: Record<string, unknown> = {
    ':orgId': vault.orgId,
    ':vaultId': vault.vaultId,
  };

  if (effectFilter) {
    filterExpression += ' AND #effect = :effectFilter';
    expressionValues[':effectFilter'] = effectFilter;
  }

  const scanParams: Record<string, unknown> = {
    TableName: PERMISSIONS_TABLE,
    Limit: limit,
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionValues,
    ConsistentRead: true,
  };

  if (filterExpression.includes('#effect')) {
    (scanParams as Record<string, unknown>).ExpressionAttributeNames = { '#effect': 'effect' };
  }

  const result = await docClient.send(new ScanCommand(scanParams as any));
  let rules = (result.Items || []) as PermissionRule[];
  if (pathFilterTarget) {
    rules = rules.filter((rule) => permissionRuleOverlapsPath(rule, pathFilterTarget));
  }
  if (!fullRuleList) {
    rules = rules.slice(0, limit);
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.list',
    resourcePath: `/vaults/${vault.vaultId}/permissions`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { resultCount: rules.length, pathFilter: pathFilterTarget, delegatedFileAdmin: !fullRuleList },
  });

  return formatSuccess(
    200,
    {
      rules,
      count: rules.length,
      lastEvaluatedKey: result.LastEvaluatedKey || null,
    },
    requestId
  );
}

// ─── GET /vaults/{vaultId}/permissions/user/{userId} ────────────────────────

/**
 * Returns the effective permissions for a specific user.
 * Consolidates user-specific, role-based, and wildcard rules into
 * a unified view showing what the user can access.
 *
 * Admins can query any user; non-admins can only query themselves.
 *
 * @param event - API Gateway event with userId path parameter
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns Effective permission summary for the target user
 */
async function handleGetUserPermissions(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const targetUserId = event.pathParameters?.userId;

  if (!targetUserId) {
    return formatError(400, 'userId path parameter is required', requestId);
  }

  // Non-admins can only query their own permissions
  if (!isAdmin(user) && targetUserId !== user.userId) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'permissions.user.denied',
      resourcePath: `/vaults/${vault.vaultId}/permissions/user/${targetUserId}`,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
    });
    return formatError(403, 'You can only view your own permissions', requestId);
  }

  // Fetch all rules applicable to this user inside this vault, including
  // role-based rules derived from the target's vault membership. Without
  // the role-index pass, the "effective permissions" view omitted grants or
  // denies attached to viewer/editor/admin roles even though enforcement used
  // them.
  const targetMembership = await getVaultMembership(vault.vaultId, targetUserId);
  const targetRoles =
    targetMembership
      ? [targetMembership.role]
      : targetUserId === user.userId
        ? user.roles
        : [];
  const targetAliases = await aliasesForTargetUser(targetUserId, user, vault.orgId);
  const userRules = await fetchAllUserRules(
    targetUserId,
    vault.orgId,
    vault.vaultId,
    targetRoles,
    targetAliases
  );

  // Group by path pattern for a readable summary
  const effectivePermissions = consolidatePermissions(userRules);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.user.view',
    resourcePath: `/vaults/${vault.vaultId}/permissions/user/${targetUserId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { targetUserId, ruleCount: userRules.length },
  });

  return formatSuccess(
    200,
    {
      userId: targetUserId,
      rules: userRules,
      effectivePermissions,
      ruleCount: userRules.length,
    },
    requestId
  );
}

// ─── POST /permissions ───────────────────────────────────────────────────────

/**
 * Creates a new permission rule. Admin only.
 *
 * Request body:
 * - userId: Target user ID (or '*' for all users via role)
 * - role: Role name for role-based rules (or null for user-specific)
 * - pathPattern: Glob pattern (e.g., '/engineering/**', '/docs/*.md')
 * - actions: Array of actions to grant/deny ['read', 'write', 'delete', 'admin', 'list']
 * - effect: 'allow' or 'deny'
 * - priority: Numeric priority for conflict resolution (optional, auto-calculated)
 *
 * @param event - API Gateway event with rule definition in body
 * @param user - Authenticated user context (must be admin)
 * @param requestId - Request ID for tracing
 * @returns The created permission rule with generated ID
 */
async function handleCreatePermission(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['pathPattern', 'actions', 'effect']);

  // Validate inputs
  let userId = (body.userId as string) || '*';
  const role = (body.role as string) || null;
  const pathPattern = body.pathPattern as string;
  const actions = body.actions as string[];
  const effect = body.effect as string;
  const priority = (body.priority as number) || calculatePriority(pathPattern);
  const upsert = body.upsert === true;
  const expiresAt = typeof body.expiresAt === 'string' && body.expiresAt
    ? body.expiresAt
    : undefined;

  // Validate actions
  for (const action of actions) {
    if (!VALID_ACTIONS.includes(action as PermissionAction)) {
      return formatError(
        400,
        `Invalid action: '${action}'. Valid actions: ${VALID_ACTIONS.join(', ')}`,
        requestId
      );
    }
  }

  // Validate effect
  if (!VALID_EFFECTS.includes(effect as typeof VALID_EFFECTS[number])) {
    return formatError(400, `Invalid effect: '${effect}'. Must be 'allow' or 'deny'`, requestId);
  }

  // Validate path pattern
  if (!pathPattern.startsWith('/')) {
    return formatError(400, 'pathPattern must start with /', requestId);
  }

  if (!role) {
    const canonicalUserId = await canonicalizeRuleUserId(userId, vault.orgId);
    if (!canonicalUserId) {
      return formatError(400, `Unknown user in this organization: ${userId}`, requestId);
    }
    userId = canonicalUserId;
  }

  // Authorize the mutation. Vault/org admins keep full power; a non-vault-admin
  // is authorized IFF they hold file-level admin on the rule path, capped at
  // their own derived level, and may not drop their own admin.
  const { viaFileAdmin } = await authorizePermissionMutation(
    user, vault, pathPattern,
    { userId, role, actions: actions as PermissionAction[], effect: effect as 'allow' | 'deny' }
  );

  // Reject duplicate: same principal + same exact path already has a rule
  const existingUserRules = await fetchAllUserRules(
    userId,
    vault.orgId,
    vault.vaultId,
    role ? [role] : []
  );
  const duplicate = existingUserRules.find((rule) => {
    const samePath = rule.pathPattern === pathPattern;
    const samePrincipal = role
      ? rule.role === role
      : !rule.role && rule.userId === userId;
    return samePath && samePrincipal;
  });
  if (duplicate) {
    if (upsert) {
      const updates: Record<string, unknown> = {
        actions: actions as PermissionAction[],
        effect: effect as 'allow' | 'deny',
      };
      if (body.priority !== undefined) updates.priority = priority;
      if (body.expiresAt !== undefined) {
        updates.expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt : null;
      }
      updates.updatedAt = new Date().toISOString();

      const updateExpression = 'SET ' + Object.keys(updates)
        .map((key, i) => `#k${i} = :v${i}`)
        .join(', ');
      const expressionAttributeNames: Record<string, string> = {};
      const expressionAttributeValues: Record<string, unknown> = {};
      Object.keys(updates).forEach((key, i) => {
        expressionAttributeNames[`#k${i}`] = key;
        expressionAttributeValues[`:v${i}`] = updates[key];
      });

      await docClient.send(
        new UpdateCommand({
          TableName: PERMISSIONS_TABLE,
          Key: { pk: duplicate.id, sk: RULE_SK },
          UpdateExpression: updateExpression,
          ExpressionAttributeNames: expressionAttributeNames,
          ExpressionAttributeValues: expressionAttributeValues,
        })
      );

      const updatedRule = { ...duplicate, ...updates };
      await revokeOverlappingLeases(
        pathPattern,
        duplicate.userId,
        duplicate.role,
        user.userId,
        vault.orgId,
        vault.vaultId
      );

      await recordVaultActivity({
        orgId: vault.orgId,
        vaultId: vault.vaultId,
        action: 'permission_changed',
        path: pathPattern,
        actorUserId: user.userId,
      });

      await logAudit({
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'permissions.update',
        resourcePath: `/vaults/${vault.vaultId}/permissions/${duplicate.id}`,
        outcome: 'success',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: {
          ruleId: duplicate.id,
          updatedFields: Object.keys(updates).filter((key) => key !== 'updatedAt'),
          previousValues: Object.keys(updates).reduce((acc, key) => {
            if (key !== 'updatedAt') acc[key] = (duplicate as unknown as Record<string, unknown>)[key];
            return acc;
          }, {} as Record<string, unknown>),
          viaFileAdmin,
          targetPrincipal: duplicate.role ? `role:${duplicate.role}` : duplicate.userId,
          resultingLevel: ruleLevelRank(actions as PermissionAction[], effect as 'allow' | 'deny'),
          upsert: true,
        },
      });

      return formatSuccess(200, { rule: updatedRule, upserted: true }, requestId);
    }

    return formatError(
      409,
      `A permission rule already exists for this user on ${pathPattern}. Update the existing rule instead.`,
      requestId
    );
  }

  // Check for conflicting rules
  const conflicts = await findConflictingRules(
    userId,
    role,
    pathPattern,
    actions as PermissionAction[],
    effect,
    vault.orgId,
    vault.vaultId
  );
  if (conflicts.length > 0) {
    // Warn about conflicts but still create (admin decision)
    console.warn(
      `[PERMISSION_CONFLICT] New rule conflicts with ${conflicts.length} existing rules`,
      { pathPattern, conflicts: conflicts.map((c) => c.id) }
    );
  }

  const now = new Date().toISOString();
  const ruleId = generateId();
  const rule: PermissionRule = {
    id: ruleId,
    orgId: vault.orgId,
    vaultId: vault.vaultId,
    userId,
    role,
    pathPattern,
    actions: actions as PermissionAction[],
    effect: effect as 'allow' | 'deny',
    priority,
    createdAt: now,
    updatedAt: now,
    createdBy: user.userId,
    ...(expiresAt ? { expiresAt } : {}),
  };

  // DynamoDB GSI keys cannot be null — strip null role so the item
  // is simply omitted from the role-index rather than causing a
  // ValidationException.
  const item: Record<string, unknown> = { ...rule, pk: ruleId, sk: RULE_SK };
  if (item.role === null) {
    delete item.role;
  }

  await docClient.send(
    new PutCommand({
      TableName: PERMISSIONS_TABLE,
      Item: item,
    })
  );

  // Revoke leases whose scope overlaps the new permission path
  // (permission landscape changed — affected users should re-fetch leases)
  await revokeOverlappingLeases(pathPattern, userId, role, user.userId, vault.orgId, vault.vaultId);

  // Bump the vault cursor so peer clients learn that the permission
  // landscape moved. The warm-path sync recognises `permission_changed`
  // events and falls back to a full S3 + permission re-evaluation pass,
  // since a single rule can flip accessibility for many files at once.
  await recordVaultActivity({
    orgId: vault.orgId,
    vaultId: vault.vaultId,
    action: 'permission_changed',
    path: pathPattern,
    actorUserId: user.userId,
  });

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.create',
    resourcePath: `/vaults/${vault.vaultId}/permissions`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      ruleId: rule.id,
      targetUserId: userId,
      pathPattern,
      actions,
      effect,
      conflictCount: conflicts.length,
      viaFileAdmin,
      targetPrincipal: role ? `role:${role}` : userId,
      resultingLevel: ruleLevelRank(actions as PermissionAction[], effect as 'allow' | 'deny'),
    },
  });

  return formatSuccess(
    201,
    {
      rule,
      conflicts: conflicts.length > 0
        ? { count: conflicts.length, message: 'Rule created with potential conflicts. Review recommended.' }
        : null,
    },
    requestId
  );
}

// ─── PUT /vaults/{vaultId}/permissions/{id} ─────────────────────────────────

/**
 * Updates an existing permission rule. Admin only.
 * Only the fields provided in the body are updated; others remain unchanged.
 *
 * Updatable fields:
 * - pathPattern, actions, effect, priority, userId, role
 *
 * @param event - API Gateway event with rule ID and updated fields in body
 * @param user - Authenticated user context (must be admin)
 * @param requestId - Request ID for tracing
 * @returns The updated permission rule
 */
async function handleUpdatePermission(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const ruleId = event.pathParameters?.id;
  if (!ruleId) {
    return formatError(400, 'Permission rule ID is required', requestId);
  }

  // Fetch existing rule
  const existingResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      KeyConditionExpression: 'pk = :pk AND sk = :sk',
      ExpressionAttributeValues: { ':pk': ruleId, ':sk': RULE_SK },
    })
  );

  const existingRule = existingResult.Items?.[0] as PermissionRule | undefined;
  if (!existingRule || existingRule.orgId !== vault.orgId || existingRule.vaultId !== vault.vaultId) {
    return formatError(404, `Permission rule not found: ${ruleId}`, requestId);
  }

  const body = parseBody(event);
  const updates: Record<string, unknown> = {};

  // Validate and apply updates
  if (body.pathPattern !== undefined) {
    const pathPattern = body.pathPattern as string;
    if (!pathPattern.startsWith('/')) {
      return formatError(400, 'pathPattern must start with /', requestId);
    }
    updates.pathPattern = pathPattern;
  }

  if (body.actions !== undefined) {
    const actions = body.actions as string[];
    for (const action of actions) {
      if (!VALID_ACTIONS.includes(action as PermissionAction)) {
        return formatError(400, `Invalid action: '${action}'`, requestId);
      }
    }
    updates.actions = actions;
  }

  if (body.effect !== undefined) {
    if (!VALID_EFFECTS.includes(body.effect as typeof VALID_EFFECTS[number])) {
      return formatError(400, `Invalid effect: '${body.effect}'`, requestId);
    }
    updates.effect = body.effect;
  }

  if (body.priority !== undefined) updates.priority = body.priority;
  if (body.userId !== undefined) {
    const canonicalUserId = await canonicalizeRuleUserId(body.userId as string, vault.orgId);
    if (!canonicalUserId) {
      return formatError(400, `Unknown user in this organization: ${body.userId}`, requestId);
    }
    updates.userId = canonicalUserId;
  }
  // Normalize an empty/whitespace role to null so it is treated as "no role"
  // (a user-targeted rule). `role` is the hash key of the role-index GSI, which
  // rejects null/empty keys — the update-expression builder below routes a null
  // role into a REMOVE clause, mirroring how handleCreatePermission strips a
  // null role before PutItem.
  if (body.role !== undefined) {
    updates.role = typeof body.role === 'string' && body.role.trim() ? body.role : null;
  }
  if (body.expiresAt !== undefined) {
    updates.expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt : null;
  }

  if (Object.keys(updates).length === 0) {
    return formatError(400, 'No valid fields to update', requestId);
  }

  // Authorize the mutation against the resulting rule shape (after updates are
  // merged onto the existing rule). Vault/org admins keep full power; a
  // non-vault-admin needs file-level admin on the updated path, capped at their
  // own derived level, and may not drop their own admin.
  const updatedPath = (updates.pathPattern as string) ?? existingRule.pathPattern;
  // CR-01 defense-in-depth: updates.userId is already canonicalized at the
  // body.userId path above; when the update does NOT change userId, the target
  // falls back to existingRule.userId — canonicalize that fallback too (email →
  // caller's sub) so an email-aliased self rule resolves at the call site. The
  // helper-side alias expansion remains the load-bearing fix.
  const targetUserId =
    (updates.userId as string) ??
    (await canonicalizeRuleUserId(existingRule.userId, vault.orgId)) ??
    existingRule.userId;
  const { viaFileAdmin } = await authorizePermissionMutation(
    user, vault, updatedPath,
    {
      userId: targetUserId,
      // role normalization (WR-04): see handleSetLevel for the rationale —
      // DDB returns `role` as undefined when the row was written without
      // the attribute, so coalesce to null before passing to the helper.
      role: (updates.role as string | null) ?? existingRule.role ?? null,
      actions: (updates.actions as PermissionAction[]) ?? existingRule.actions,
      effect: (updates.effect as 'allow' | 'deny') ?? existingRule.effect,
    },
    existingRule
  );

  // CR-02 old-path admit gate (FADM-02): authorizePermissionMutation only ever
  // sees ONE path (the new/updated path). A permission rule is a vault-global
  // object keyed only by id, so a file-admin could otherwise fetch ANY rule and
  // move it into their scope. When a file-admin (viaFileAdmin) CHANGES the path,
  // additionally require that they hold admin on the EXISTING (pre-update) path —
  // otherwise reject with 403. This runs AFTER authorizePermissionMutation
  // returns because viaFileAdmin is only known then. It is a path-admit gate
  // ONLY: cap/self-protection stay in authorizePermissionMutation (single source
  // of truth). Vault/org admins (viaFileAdmin === false) and same-path updates
  // are unaffected.
  if (viaFileAdmin && updates.pathPattern && updates.pathPattern !== existingRule.pathPattern) {
    const oldPathCheck = await evaluatePermission(
      user.userId, user.roles, 'admin', existingRule.pathPattern,
      vault.orgId, vault.vaultId, { userAliases: user.email ? [user.email] : [] }
    );
    if (!oldPathCheck.allowed) {
      return formatError(403, `You do not have admin on ${existingRule.pathPattern}`, requestId);
    }
  }

  updates.updatedAt = new Date().toISOString();

  // Build the update expression. A null `role` must be REMOVEd, not
  // `SET role = null`: role is the role-index GSI hash key and DynamoDB rejects
  // a null/empty key value with a ValidationException (which surfaced to the
  // client as "Internal server error" when editing a user-targeted rule). Every
  // other field — including a null expiresAt, which is a plain attribute — is a
  // normal SET.
  const expressionAttributeNames: Record<string, string> = {};
  const expressionAttributeValues: Record<string, unknown> = {};
  const setClauses: string[] = [];
  const removeClauses: string[] = [];

  Object.keys(updates).forEach((key, i) => {
    expressionAttributeNames[`#k${i}`] = key;
    if (key === 'role' && updates[key] === null) {
      removeClauses.push(`#k${i}`);
    } else {
      setClauses.push(`#k${i} = :v${i}`);
      expressionAttributeValues[`:v${i}`] = updates[key];
    }
  });

  // updatedAt is always present, so there is always at least one SET clause and
  // ExpressionAttributeValues is never empty.
  const updateExpression = [
    setClauses.length ? `SET ${setClauses.join(', ')}` : '',
    removeClauses.length ? `REMOVE ${removeClauses.join(', ')}` : '',
  ].filter(Boolean).join(' ');

  await docClient.send(
    new UpdateCommand({
      TableName: PERMISSIONS_TABLE,
      Key: { pk: ruleId, sk: RULE_SK },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
    })
  );

  const updatedRule = { ...existingRule, ...updates };

  // Post-write side effects run AFTER the rule is already persisted, so a
  // failure here must NOT turn a successful update into a 500. Previously an
  // unguarded throw in lease revocation or the activity cursor surfaced to the
  // client as "Internal server error" even though the edit had saved (create
  // never hits this path, which is why only edits appeared to fail).
  const affectedPath = (updates.pathPattern as string) || existingRule.pathPattern;
  try {
    // Revoke leases overlapping both old and new path patterns.
    await revokeOverlappingLeases(
      affectedPath,
      existingRule.userId,
      existingRule.role,
      user.userId,
      vault.orgId,
      vault.vaultId
    );
    if (updates.pathPattern && updates.pathPattern !== existingRule.pathPattern) {
      await revokeOverlappingLeases(
        existingRule.pathPattern,
        existingRule.userId,
        existingRule.role,
        user.userId,
        vault.orgId,
        vault.vaultId
      );
    }
  } catch (err) {
    console.error(
      '[PERMISSIONS] update: lease revocation failed (rule already updated)',
      (err as Error).message
    );
  }

  // Cursor bump — see handleCreatePermission for rationale. Best-effort.
  try {
    await recordVaultActivity({
      orgId: vault.orgId,
      vaultId: vault.vaultId,
      action: 'permission_changed',
      path: affectedPath,
      actorUserId: user.userId,
    });
  } catch (err) {
    console.error(
      '[PERMISSIONS] update: recordVaultActivity failed (rule already updated)',
      (err as Error).message
    );
  }

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.update',
    resourcePath: `/vaults/${vault.vaultId}/permissions/${ruleId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        ruleId,
        updatedFields: Object.keys(updates).filter((k) => k !== 'updatedAt'),
        previousValues: Object.keys(updates).reduce((acc, key) => {
          if (key !== 'updatedAt') acc[key] = (existingRule as unknown as Record<string, unknown>)[key];
          return acc;
        }, {} as Record<string, unknown>),
        viaFileAdmin,
        targetPrincipal: existingRule.role ? `role:${existingRule.role}` : existingRule.userId,
        resultingLevel: ruleLevelRank(
          (updates.actions as PermissionAction[]) ?? existingRule.actions,
          (updates.effect as 'allow' | 'deny') ?? existingRule.effect
        ),
      },
    });

  return formatSuccess(200, { rule: updatedRule }, requestId);
}

// ─── DELETE /vaults/{vaultId}/permissions/{id} ──────────────────────────────

/**
 * Revokes (deletes) a specific permission rule. Admin only.
 * Deletion is permanent — the rule is removed from the table.
 *
 * @param event - API Gateway event with rule ID path parameter
 * @param user - Authenticated user context (must be admin)
 * @param requestId - Request ID for tracing
 * @returns Confirmation of deletion
 */
async function handleDeletePermission(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const ruleId = event.pathParameters?.id;
  if (!ruleId) {
    return formatError(400, 'Permission rule ID is required', requestId);
  }

  // Verify rule exists
  const existingResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      KeyConditionExpression: 'pk = :pk AND sk = :sk',
      ExpressionAttributeValues: { ':pk': ruleId, ':sk': RULE_SK },
    })
  );

  const existingRule = existingResult.Items?.[0] as PermissionRule | undefined;
  if (!existingRule || existingRule.orgId !== vault.orgId || existingRule.vaultId !== vault.vaultId) {
    return formatError(404, `Permission rule not found: ${ruleId}`, requestId);
  }

  // Authorize the deletion. The `effect: 'deny'` deny sentinel models removal so
  // cap-at-own-level (rank 0) always passes and self-protection fires when the
  // existing rule granted the caller admin. Self-protection logic lives solely
  // inside authorizePermissionMutation — there is no handler-side short-circuit.
  //
  // CR-01 defense-in-depth: canonicalize the existing rule's principal (email →
  // caller's sub when it resolves) BEFORE passing it as the mutation target, so
  // an email-aliased self rule also resolves to the sub at the call site. The
  // helper-side alias expansion is the load-bearing fix; this mirrors the create
  // path. Fall back to the raw value if canonicalize returns null so an unknown
  // email does not crash the delete.
  const targetUserId =
    (await canonicalizeRuleUserId(existingRule.userId, vault.orgId)) ?? existingRule.userId;
  const { viaFileAdmin } = await authorizePermissionMutation(
    user, vault, existingRule.pathPattern,
    // role normalization (WR-04): same DDB-strip rationale as handleSetLevel.
    { userId: targetUserId, role: existingRule.role ?? null, actions: existingRule.actions, effect: 'deny' },
    existingRule
  );

  // Delete the rule
  await docClient.send(
    new DeleteCommand({
      TableName: PERMISSIONS_TABLE,
      Key: { pk: ruleId, sk: RULE_SK },
    })
  );

  // Revoke leases overlapping the deleted permission's path
  await revokeOverlappingLeases(
    existingRule.pathPattern,
    existingRule.userId,
    existingRule.role,
    user.userId,
    vault.orgId,
    vault.vaultId
  );

  // Cursor bump — see handleCreatePermission for rationale.
  await recordVaultActivity({
    orgId: vault.orgId,
    vaultId: vault.vaultId,
    action: 'permission_changed',
    path: existingRule.pathPattern,
    actorUserId: user.userId,
  });

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.delete',
    resourcePath: `/vaults/${vault.vaultId}/permissions/${ruleId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      ruleId,
      deletedRule: {
        userId: existingRule.userId,
        pathPattern: existingRule.pathPattern,
        actions: existingRule.actions,
        effect: existingRule.effect,
      },
      viaFileAdmin,
      targetPrincipal: existingRule.role ? `role:${existingRule.role}` : existingRule.userId,
      resultingLevel: 0,
    },
  });

  return formatSuccess(
    200,
    {
      message: `Permission rule ${ruleId} deleted successfully`,
      deletedRule: existingRule,
    },
    requestId
  );
}

// ─── POST /vaults/{vaultId}/permissions/check ───────────────────────────────

/**
 * Checks whether a user can perform a specific action on a given path.
 * Used internally by other services and for debugging permission issues.
 *
 * This endpoint evaluates the full permission stack:
 * 1. User-specific rules
 * 2. Role-based rules
 * 3. Wildcard rules
 * 4. Path inheritance (parent folders)
 * 5. Conflict resolution (most-specific wins, deny overrides allow)
 *
 * Request body:
 * - userId: The user to check permissions for
 * - action: The action to check ('read', 'write', 'delete', 'admin', 'list')
 * - path: The file/folder path to check
 * - roles: Optional array of roles (if not provided, fetched from user record)
 *
 * @param event - API Gateway event with check parameters in body
 * @param user - Authenticated user context
 * @param requestId - Request ID for tracing
 * @returns Permission check result with explanation
 */
async function handleCheckPermission(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['userId', 'action', 'path']);

  const targetUserId = body.userId as string;
  const action = body.action as string;
  const path = body.path as string;

  // Non-admins can only check their own permissions
  if (!isAdmin(user) && targetUserId !== user.userId) {
    return formatError(403, 'You can only check your own permissions', requestId);
  }

  // Validate action
  if (!VALID_ACTIONS.includes(action as PermissionAction)) {
    return formatError(400, `Invalid action: '${action}'. Valid: ${VALID_ACTIONS.join(', ')}`, requestId);
  }

  // Roles are derived server-side from verified identity — body.roles is
  // ignored. evaluatePermission would otherwise treat caller-supplied
  // admin-like roles as bypasses, allowing a non-admin caller to make their
  // own check return `allowed: true` regardless of real entitlement.
  //
  // For both self-checks and admin cross-user checks, use the target user's
  // vault membership role. This keeps "what I see for myself" identical to
  // "what an admin sees when checking me" and prevents org-level roles from
  // accidentally masquerading as vault roles.
  const resolvedRoles = await resolvePermissionRolesForTarget(targetUserId, user, vault);

  // Evaluate permission within this vault.
  const targetAliases = await aliasesForTargetUser(targetUserId, user, vault.orgId);
  const result = await evaluatePermission(
    targetUserId,
    resolvedRoles,
    action as PermissionAction,
    path,
    vault.orgId,
    vault.vaultId,
    { userAliases: targetAliases }
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.check',
    resourcePath: path,
    outcome: result.allowed ? 'success' : 'denied',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId,
      checkedAction: action,
      allowed: result.allowed,
      matchedRuleId: result.matchedRule?.id,
      evaluatedRuleCount: result.evaluatedRules.length,
    },
  });

  return formatSuccess(
    200,
    {
      allowed: result.allowed,
      userId: targetUserId,
      action,
      path,
      matchedRule: result.matchedRule
        ? {
            id: result.matchedRule.id,
            pathPattern: result.matchedRule.pathPattern,
            effect: result.matchedRule.effect,
            priority: result.matchedRule.priority,
          }
        : null,
      evaluatedRules: result.evaluatedRules.map((r) => ({
        id: r.id,
        pathPattern: r.pathPattern,
        effect: r.effect,
        actions: r.actions,
      })),
      explanation: result.allowed
        ? `Allowed by rule ${result.matchedRule?.id} (${result.matchedRule?.pathPattern})`
        : result.matchedRule
          ? `Denied by rule ${result.matchedRule.id} (${result.matchedRule.pathPattern})`
          : 'No matching rule found — default deny',
    },
    requestId
  );
}

// ─── POST /vaults/{vaultId}/permissions/access ──────────────────────────────

/**
 * Returns the backend-computed access list for a single file path.
 *
 * This is the one source of truth used by the plugin header. The client no
 * longer reconstructs other users' effective access from raw rules, because
 * raw-rule merging can diverge from the Lambda evaluator when membership
 * defaults, legacy email principals, denies, and role rules overlap.
 */
async function handlePathAccess(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['path']);

  const path = normalizePermissionPath(String(body.path));
  const directory = await buildOrgIdentityMap(vault.orgId);
  const members = await listVaultMembers(vault.vaultId);

  const summary = await computePathAccessSummary(
    path,
    user,
    vault,
    directory,
    members
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.access',
    resourcePath: path,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      principalCount: summary.principals.length,
      visiblePrincipalCount: summary.principals.filter(
        (principal) => principal.level !== 'none'
      ).length,
    },
  });

  return formatSuccess(200, summary, requestId);
}

// ─── POST /vaults/{vaultId}/permissions/access/batch ────────────────────────

const BATCH_PATH_LIMIT = 100;

/**
 * Returns backend-computed access summaries for many paths in one request.
 *
 * Used by the plugin's file-explorer decorator so the sidebar dot/avatar
 * stack stay perfectly aligned with the file header. The handler reuses the
 * single-path evaluator per path, but folds the Cognito directory + member
 * lookup into one query each — that's where the per-path overhead would
 * otherwise dominate.
 *
 * The route returns summaries in the same order as the input. Duplicate
 * paths are deduplicated server-side; the caller's response array stays
 * keyed by `path` so duplicates still resolve via lookup.
 */
async function handleBatchPathAccess(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['paths']);

  if (!Array.isArray(body.paths)) {
    return formatError(400, 'paths must be an array of strings', requestId);
  }

  const rawPaths = body.paths
    .filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
    .map((value) => normalizePermissionPath(value));

  if (rawPaths.length === 0) {
    return formatSuccess(200, { summaries: [] }, requestId);
  }

  if (rawPaths.length > BATCH_PATH_LIMIT) {
    return formatError(
      400,
      `Too many paths: limit is ${BATCH_PATH_LIMIT} per batch (got ${rawPaths.length})`,
      requestId
    );
  }

  // Deduplicate but preserve input ordering — the client may rely on it.
  const uniquePaths: string[] = [];
  const seen = new Set<string>();
  for (const path of rawPaths) {
    if (seen.has(path)) continue;
    seen.add(path);
    uniquePaths.push(path);
  }

  const directory = await buildOrgIdentityMap(vault.orgId);
  const members = await listVaultMembers(vault.vaultId);

  const summaries = await Promise.all(
    uniquePaths.map((path) =>
      computePathAccessSummary(path, user, vault, directory, members)
    )
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.access.batch',
    resourcePath: `/vaults/${vault.vaultId}/permissions/access/batch`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      requestedPathCount: rawPaths.length,
      uniquePathCount: uniquePaths.length,
      memberCount: members.length,
    },
  });

  return formatSuccess(200, { summaries }, requestId);
}

// ─── POST /vaults/{vaultId}/permissions/set-level ──────────────────────────
//
// **The canonical endpoint for "make user X have level L on path P".**
//
// Why a dedicated endpoint instead of POST/PUT /permissions:
//
// A permission rule is shaped as `{actions: PermissionAction[], effect:
// 'allow'|'deny'}` — one rule carries ONE effect. The user-facing concept
// "Bob should have read access on /foo.md" can require an allow rule
// (Bob's membership doesn't grant read), a deny-cap (Bob's membership
// grants write and we need to STRIP write/delete/admin while leaving
// read to fall through to inheritance), or no rule at all (inheritance
// already matches). Picking the right shape requires knowing Bob's
// INHERITED level — i.e., the level Bob would have if no exact rule on
// /foo.md existed. The UI does not have that data (it only sees Bob's
// CURRENT effective level, which includes any existing exact rule on
// /foo.md), so it cannot reliably build the right mutation on its own.
//
// The matrix test
// (tests/permission-transition-matrix.test.ts) exposes the gap: every
// surface that built mutations from `currentLevel` instead of
// `inheritedLevel` produced incorrect end states for some scenario
// (viewer + admin-allow → write produced effective=read; editor +
// deny-cap → read produced effective=write; etc.).
//
// This endpoint accepts (userId|role, pathPattern, level) and on the
// server side:
//   1. Loads any existing exact rule for that principal on that path.
//   2. Evaluates the principal's level on the path WITH the existing
//      rule excluded (the "inherited" level — membership defaults plus
//      any broader rules).
//   3. Compares inherited vs target and picks exactly one of:
//        - delete the exact rule (inherited === target)
//        - upsert a deny-cap rule (inherited > target)
//        - upsert an allow rule (inherited < target)
//   4. Applies the same authorization (authorizePermissionMutation),
//      audit, lease-revocation, and cursor-bump as create/update/delete.
//
// The legacy POST/PUT /permissions endpoints remain for raw rule edits
// (the advanced rule editor) and for API consumers that want exact
// control over actions/effect; they are NOT removed.
async function handleSetLevel(
  event: APIGatewayProxyEvent,
  user: UserContext,
  vault: VaultRecord,
  requestId: string,
  preParsedBody?: Record<string, unknown>
): Promise<APIGatewayProxyResult> {
  const body = preParsedBody ?? parseBody(event);
  validateRequiredFields(body, ['pathPattern', 'level']);

  let userId = (body.userId as string) || '*';
  const role = (body.role as string | null) || null;
  const pathPattern = body.pathPattern as string;
  const level = body.level as PathAccessLevel;

  if (!pathPattern.startsWith('/')) {
    return formatError(400, 'pathPattern must start with /', requestId);
  }
  if (!['none', 'read', 'write', 'admin'].includes(level)) {
    return formatError(400, `Invalid level: '${level}'`, requestId);
  }
  const requestedPriority = parseOptionalPriority(body.priority);
  if (requestedPriority === null) {
    return formatError(400, 'priority must be a non-negative whole number', requestId);
  }
  if (!role && userId !== '*') {
    const canonicalUserId = await canonicalizeRuleUserId(userId, vault.orgId);
    if (!canonicalUserId) {
      return formatError(400, `Unknown user in this organization: ${userId}`, requestId);
    }
    userId = canonicalUserId;
  }

  // Vault admins/owners get an unconditional bypass in evaluatePermission
  // (utils.ts: `if (rolesIncludeOrgAdmin(roles)) return allowed=true`), so
  // any per-file deny rule written against them is a no-op. We reject the
  // mutation loudly rather than let it persist a silently-ineffective rule
  // — UNLESS the org has opted into
  // `allowAdminPerFileRestrictions`. With that toggle on,
  // evaluatePermission stops bypassing for admins on the target-side
  // resolution paths, so a per-file deny rule against an admin actually
  // takes effect; we let the mutation through. (Allowing `level === 'admin'`
  // unconditionally is a true no-op either way, so it always passes.)
  if (!role && userId !== '*' && level !== 'admin') {
    const adminsBypass = await shouldRespectAdminBypassFor(vault.orgId);
    if (adminsBypass) {
      const targetMembership = await getVaultMembership(vault.vaultId, userId);
      const targetVaultRole = targetMembership?.role?.toLowerCase();
      if (targetVaultRole === 'admin' || targetVaultRole === 'owner') {
        return formatError(
          400,
          `Cannot change per-file access for a vault ${targetVaultRole} — their access is granted by their vault role and overrides any per-file rule. Demote the vault role first or turn on "Allow per-file restrictions on admins" in org settings.`,
          requestId
        );
      }
    }
  }

  // 1. Find any existing exact rule for this principal on this path.
  //    Vault-global rule table (only id is unique), so we filter by
  //    principal + path here rather than relying on a composite key.
  const existingUserRules = await fetchAllUserRules(
    userId,
    vault.orgId,
    vault.vaultId,
    role ? [role] : []
  );
  const existing = existingUserRules.find((rule) => {
    const samePath = rule.pathPattern === pathPattern;
    const samePrincipal = role
      ? rule.role === role
      : !rule.role && rule.userId === userId;
    return samePath && samePrincipal;
  }) ?? null;

  // Aggregate principals (`*` and role rules) do not have one inherited level:
  // every matching vault member can inherit a different baseline from their
  // membership role and direct rules. For these targets, write the group rule
  // shape directly so "all users -> read" means a read-only cap and "all
  // users -> none" means an explicit deny-all. The per-user inherited-level
  // pipeline below remains the canonical path for individual users.
  if (userId === '*' || role) {
    const aggregateMutation = aggregateLevelMutation(level);
    const actions = aggregateMutation.actions;
    const effect = aggregateMutation.effect;
    const now = new Date().toISOString();

    await authorizePermissionMutation(
      user, vault, pathPattern,
      { userId, role, actions, effect },
      existing ?? undefined
    );

    let resultRule: PermissionRule;
    let decision: 'update' | 'create';

    if (existing) {
      const updates: Record<string, unknown> = {
        actions,
        effect,
        updatedAt: now,
      };
      if (requestedPriority !== undefined) {
        updates.priority = requestedPriority;
      }
      const updateExpression = 'SET ' + Object.keys(updates)
        .map((_, i) => `#k${i} = :v${i}`)
        .join(', ');
      const expressionAttributeNames: Record<string, string> = {};
      const expressionAttributeValues: Record<string, unknown> = {};
      Object.keys(updates).forEach((key, i) => {
        expressionAttributeNames[`#k${i}`] = key;
        expressionAttributeValues[`:v${i}`] = updates[key];
      });
      await docClient.send(
        new UpdateCommand({
          TableName: PERMISSIONS_TABLE,
          Key: { pk: existing.id, sk: RULE_SK },
          UpdateExpression: updateExpression,
          ExpressionAttributeNames: expressionAttributeNames,
          ExpressionAttributeValues: expressionAttributeValues,
        })
      );
      resultRule = { ...existing, actions, effect, ...(requestedPriority !== undefined ? { priority: requestedPriority } : {}), updatedAt: now };
      decision = 'update';
    } else {
      const ruleId = generateId();
      const rule: PermissionRule = {
        id: ruleId,
        orgId: vault.orgId,
        vaultId: vault.vaultId,
        userId,
        role,
        pathPattern,
        actions,
        effect,
        priority: requestedPriority ?? calculatePriority(pathPattern),
        createdAt: now,
        updatedAt: now,
        createdBy: user.userId,
      };
      const item: Record<string, unknown> = { ...rule, pk: ruleId, sk: RULE_SK };
      if (item.role === null) delete item.role;
      await docClient.send(
        new PutCommand({
          TableName: PERMISSIONS_TABLE,
          Item: item,
        })
      );
      resultRule = rule;
      decision = 'create';
    }

    await revokeOverlappingLeases(
      pathPattern,
      userId,
      role,
      user.userId,
      vault.orgId,
      vault.vaultId
    );
    await recordVaultActivity({
      orgId: vault.orgId,
      vaultId: vault.vaultId,
      action: 'permission_changed',
      path: pathPattern,
      actorUserId: user.userId,
    });
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'permissions.set-level',
      resourcePath: `/vaults/${vault.vaultId}/permissions/set-level`,
      outcome: 'success',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        decision,
        ruleId: resultRule.id,
        pathPattern,
        targetUserId: userId,
        role,
        level,
        inheritedLevel: level,
        actions,
        effect,
        aggregatePrincipal: true,
        aggregateInheritedLevel: 'mixed',
        priority: resultRule.priority,
      },
    });

    return formatSuccess(200, {
      decision,
      level,
      inheritedLevel: level,
      rule: resultRule,
    }, requestId);
  }

  // 2. Compute the principal's INHERITED level on this path — what would
  //    they have if no exact rule on this path existed? This drives the
  //    delete-vs-cap-vs-grant decision.
  const aliases = !role && userId !== '*'
    ? await aliasesForAccessTarget(userId, user, vault.orgId, new Map())
    : [];
  const evaluationRoles = role
    ? [role]
    : (userId === '*'
        ? []
        : await resolvePermissionRolesForTarget(userId, user, vault));
  const inheritedLevel = await computeInheritedAccessLevel(
    userId,
    evaluationRoles,
    pathPattern,
    vault,
    aliases,
    existing?.id ?? null
  );

  const targetRank = pathAccessLevelRank(level);
  const inheritedRank = pathAccessLevelRank(inheritedLevel);

  // 3. Decide the action.
  //    NOTE: every branch authorizes via the SAME authorizePermissionMutation
  //    used by the create/update/delete handlers — never inline a bypass here.
  const now = new Date().toISOString();

  if (targetRank === inheritedRank) {
    if (!existing) {
      // Inheritance already matches, no rule on this path. No-op.
      await logAudit({
        userId: user.userId,
        userEmail: user.email,
        orgId: user.orgId,
        vaultId: vault.vaultId,
        action: 'permissions.set-level',
        resourcePath: `/vaults/${vault.vaultId}/permissions/set-level`,
        outcome: 'success',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: {
          decision: 'noop',
          pathPattern,
          targetUserId: userId,
          role,
          level,
          inheritedLevel,
        },
      });
      return formatSuccess(200, {
        decision: 'noop',
        level,
        inheritedLevel,
        rule: null,
      }, requestId);
    }
    // Delete the exact rule so inheritance reasserts.
    // Delete-as-deny sentinel matches the delete handler's contract with
    // authorizePermissionMutation.
    //
    // role normalization (WR-04 defense-in-depth): DDB drops the `role`
    // attribute entirely when an item is written with `delete item.role`
    // (handleCreatePermission strips `role: null` before PutItem so the
    // role-index GSI doesn't reject the row). Reading it back gives
    // `undefined`, not null — feed `?? null` into the helper so the
    // null-typed contract holds even though the storage layer surfaces
    // undefined.
    await authorizePermissionMutation(
      user, vault, existing.pathPattern,
      {
        userId: existing.userId,
        role: existing.role ?? null,
        actions: existing.actions,
        effect: 'deny',
      },
      existing
    );
    await docClient.send(
      new DeleteCommand({
        TableName: PERMISSIONS_TABLE,
        Key: { pk: existing.id, sk: RULE_SK },
      })
    );
    await revokeOverlappingLeases(
      existing.pathPattern,
      existing.userId,
      existing.role,
      user.userId,
      vault.orgId,
      vault.vaultId
    );
    await recordVaultActivity({
      orgId: vault.orgId,
      vaultId: vault.vaultId,
      action: 'permission_changed',
      path: existing.pathPattern,
      actorUserId: user.userId,
    });
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: vault.vaultId,
      action: 'permissions.set-level',
      resourcePath: `/vaults/${vault.vaultId}/permissions/set-level`,
      outcome: 'success',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        decision: 'delete',
        deletedRuleId: existing.id,
        pathPattern,
        targetUserId: userId,
        role,
        level,
        inheritedLevel,
      },
    });
    return formatSuccess(200, {
      decision: 'delete',
      level,
      inheritedLevel,
      rule: null,
    }, requestId);
  }

  // 4. Build the right mutation shape for downgrade vs upgrade.
  let actions: PermissionAction[];
  let effect: 'allow' | 'deny';
  if (targetRank < inheritedRank) {
    // Deny-cap: strip the actions above target so inheritance falls
    // through for the actions ≤ target.
    const denyActions: PermissionAction[] = [];
    if (targetRank < 1) denyActions.push('read', 'list');
    if (targetRank < 2) denyActions.push('write', 'delete');
    if (targetRank < 3) denyActions.push('admin');
    actions = denyActions;
    effect = 'deny';
  } else {
    actions = levelToActions(level);
    effect = 'allow';
  }

  await authorizePermissionMutation(
    user, vault, pathPattern,
    { userId, role, actions, effect },
    existing ?? undefined
  );

  let resultRule: PermissionRule;
  let decision: 'update' | 'create';

  if (existing) {
    const updates: Record<string, unknown> = {
      actions,
      effect,
      updatedAt: now,
    };
    if (requestedPriority !== undefined) {
      updates.priority = requestedPriority;
    }
    const updateExpression = 'SET ' + Object.keys(updates)
      .map((_, i) => `#k${i} = :v${i}`)
      .join(', ');
    const expressionAttributeNames: Record<string, string> = {};
    const expressionAttributeValues: Record<string, unknown> = {};
    Object.keys(updates).forEach((key, i) => {
      expressionAttributeNames[`#k${i}`] = key;
      expressionAttributeValues[`:v${i}`] = updates[key];
    });
    await docClient.send(
      new UpdateCommand({
        TableName: PERMISSIONS_TABLE,
        Key: { pk: existing.id, sk: RULE_SK },
        UpdateExpression: updateExpression,
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
      })
    );
    resultRule = { ...existing, actions, effect, ...(requestedPriority !== undefined ? { priority: requestedPriority } : {}), updatedAt: now };
    decision = 'update';
  } else {
    const ruleId = generateId();
    const rule: PermissionRule = {
      id: ruleId,
      orgId: vault.orgId,
      vaultId: vault.vaultId,
      userId,
      role,
      pathPattern,
      actions,
      effect,
      priority: requestedPriority ?? calculatePriority(pathPattern),
      createdAt: now,
      updatedAt: now,
      createdBy: user.userId,
    };
    const item: Record<string, unknown> = { ...rule, pk: ruleId, sk: RULE_SK };
    if (item.role === null) delete item.role;
    await docClient.send(
      new PutCommand({
        TableName: PERMISSIONS_TABLE,
        Item: item,
      })
    );
    resultRule = rule;
    decision = 'create';
  }

  await revokeOverlappingLeases(
    pathPattern,
    userId,
    role,
    user.userId,
    vault.orgId,
    vault.vaultId
  );
  await recordVaultActivity({
    orgId: vault.orgId,
    vaultId: vault.vaultId,
    action: 'permission_changed',
    path: pathPattern,
    actorUserId: user.userId,
  });
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId: vault.vaultId,
    action: 'permissions.set-level',
    resourcePath: `/vaults/${vault.vaultId}/permissions/set-level`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      decision,
      ruleId: resultRule.id,
      pathPattern,
      targetUserId: userId,
      role,
      level,
      inheritedLevel,
      actions,
      effect,
      priority: resultRule.priority,
    },
  });

  return formatSuccess(200, {
    decision,
    level,
    inheritedLevel,
    rule: resultRule,
  }, requestId);
}

/**
 * Effective level for a principal on a path with a specific rule treated as
 * if it did not exist. Probes the same admin→write→read ordering as
 * `resolvePathAccessLevel` so the answers line up bit-for-bit with the
 * level the access-summary endpoint would return after a delete.
 */
async function computeInheritedAccessLevel(
  userId: string,
  roles: string[],
  path: string,
  vault: VaultRecord,
  aliases: string[],
  excludeRuleId: string | null
): Promise<PathAccessLevel> {
  const excludeIds = excludeRuleId ? [excludeRuleId] : [];
  const probes: Array<{ action: PermissionAction; level: PathAccessLevel }> = [
    { action: 'admin', level: 'admin' },
    { action: 'write', level: 'write' },
    { action: 'read', level: 'read' },
  ];
  // Set-level uses inherited to decide delete-vs-cap-vs-grant. We must
  // probe with the SAME bypass policy the access summary uses, otherwise
  // an admin's "inherited" level reads as "admin" via bypass even when
  // `allowAdminPerFileRestrictions` is on — and set-level would refuse to
  // create the deny rule (target==inherited==admin → delete branch),
  // making the toggle a no-op.
  const respectAdminBypass = await shouldRespectAdminBypassFor(vault.orgId);
  for (const probe of probes) {
    const result = await evaluatePermission(
      userId,
      roles,
      probe.action,
      path,
      vault.orgId,
      vault.vaultId,
      { userAliases: aliases, excludeRuleIds: excludeIds, respectAdminBypass }
    );
    if (result.allowed) return probe.level;
  }
  return 'none';
}

function pathAccessLevelRank(level: PathAccessLevel): number {
  switch (level) {
    case 'admin': return 3;
    case 'write': return 2;
    case 'read': return 1;
    default: return 0;
  }
}

function levelToActions(level: PathAccessLevel): PermissionAction[] {
  switch (level) {
    case 'admin': return ['read', 'write', 'delete', 'admin', 'list'];
    case 'write': return ['read', 'write', 'delete', 'list'];
    case 'read': return ['read', 'list'];
    default: return [];
  }
}

function aggregateLevelMutation(level: PathAccessLevel): {
  actions: PermissionAction[];
  effect: 'allow' | 'deny';
} {
  switch (level) {
    case 'none':
      return { actions: ['read', 'list', 'write', 'delete', 'admin'], effect: 'deny' };
    case 'read':
      return { actions: ['write', 'delete', 'admin'], effect: 'deny' };
    case 'write':
      return { actions: ['read', 'write', 'delete', 'list'], effect: 'allow' };
    case 'admin':
      return { actions: ['read', 'write', 'delete', 'admin', 'list'], effect: 'allow' };
  }
}

/**
 * Shared per-path evaluator used by both the single-path and batch endpoints.
 * The caller is responsible for fetching `directory` (Cognito identity map)
 * and `members` (vault member list) once and passing them in — these lookups
 * dominate the cost of a batch request, so they must not run per path.
 */
async function computePathAccessSummary(
  path: string,
  user: UserContext,
  vault: VaultRecord,
  directory: Map<string, PrincipalIdentity>,
  members: VaultMemberRecord[]
): Promise<PathAccessSummary> {
  const callerRoles = await resolvePermissionRolesForTarget(user.userId, user, vault);
  const callerAliases = await aliasesForAccessTarget(
    user.userId,
    user,
    vault.orgId,
    directory,
    user.email ? [user.email] : []
  );
  const callerLevel = await resolvePathAccessLevel(
    user.userId,
    callerRoles,
    path,
    vault,
    callerAliases
  );

  // Do not reveal the membership/principal list for a path the caller cannot
  // read. The current user's own status is still returned so the UI can
  // show a stable "No Access" state instead of inventing a local answer.
  if (callerLevel === 'none') {
    return { path, currentUserLevel: callerLevel, principals: [] };
  }

  const principals: PathAccessPrincipal[] = [];
  for (const member of members) {
    const aliases = await aliasesForAccessTarget(
      member.userId,
      user,
      vault.orgId,
      directory
    );
    const level = await resolvePathAccessLevel(
      member.userId,
      [member.role],
      path,
      vault,
      aliases
    );
    const identity = directory.get(member.userId);
    principals.push({
      userId: member.userId,
      ...(identity?.email ? { email: identity.email } : {}),
      ...(identity?.displayName ? { displayName: identity.displayName } : {}),
      role: member.role,
      level,
    });
  }

  if (!principals.some((principal) => principal.userId === user.userId)) {
    principals.push({
      userId: user.userId,
      email: user.email,
      displayName: user.email,
      role: isAdmin(user) ? 'admin' : undefined,
      level: callerLevel,
    });
  }

  return { path, currentUserLevel: callerLevel, principals };
}

interface PathAccessSummary {
  path: string;
  currentUserLevel: PathAccessLevel;
  principals: PathAccessPrincipal[];
}

// ─── Helper Functions ────────────────────────────────────────────────────────

function escapeCognitoFilterValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function attrsToRecord(
  attrs: Array<{ Name?: string; Value?: string }> | undefined
): Record<string, string> {
  return Object.fromEntries(
    (attrs ?? []).map((attr) => [attr.Name ?? '', attr.Value ?? ''])
  );
}

function displayNameFromAttrs(attrs: Record<string, string>, fallback: string): string {
  const explicitName = attrs.name?.trim() || '';
  const givenName = attrs.given_name || '';
  const familyName = attrs.family_name || '';
  const composed = [givenName, familyName].filter(Boolean).join(' ').trim();
  return explicitName || composed || attrs.email || fallback;
}

async function buildOrgIdentityMap(orgId: string): Promise<Map<string, PrincipalIdentity>> {
  const map = new Map<string, PrincipalIdentity>();
  if (!USER_POOL_ID || !orgId) return map;

  try {
    let paginationToken: string | undefined;
    do {
      const result = await cognitoClient.send(
        new ListUsersCommand({
          UserPoolId: USER_POOL_ID,
          Limit: 60,
          PaginationToken: paginationToken,
        })
      );

      for (const user of result.Users ?? []) {
        const attrs = attrsToRecord(user.Attributes);
        if (attrs['custom:org'] !== orgId) continue;
        const userId = attrs.sub || user.Username || '';
        if (!userId) continue;
        map.set(userId, {
          userId,
          email: attrs.email || '',
          displayName: displayNameFromAttrs(attrs, userId),
        });
      }

      paginationToken = result.PaginationToken;
    } while (paginationToken);
  } catch (error) {
    console.warn('[PERMISSIONS] Org identity lookup failed', {
      orgId,
      message: (error as Error).message,
    });
  }

  return map;
}

function identityBelongsToOrg(identity: PrincipalIdentity, attrs: Record<string, string>, orgId: string): boolean {
  return Boolean(identity.userId) && attrs['custom:org'] === orgId;
}

async function resolvePrincipalIdentity(value: string, orgId: string): Promise<PrincipalIdentity | null> {
  const principal = value.trim();
  if (!principal || principal === '*' || !USER_POOL_ID) return null;

  try {
    if (principal.includes('@')) {
      const result = await cognitoClient.send(
        new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: principal })
      );
      const attrs = attrsToRecord(result.UserAttributes);
      const identity = {
        userId: attrs.sub || result.Username || principal,
        email: attrs.email || principal,
        displayName: displayNameFromAttrs(attrs, principal),
      };
      return identityBelongsToOrg(identity, attrs, orgId) ? identity : null;
    }

    const result = await cognitoClient.send(
      new ListUsersCommand({
        UserPoolId: USER_POOL_ID,
        Filter: `sub = "${escapeCognitoFilterValue(principal)}"`,
        Limit: 1,
      })
    );
    const user = result.Users?.[0];
    if (!user) return null;
    const attrs = attrsToRecord(user.Attributes);
    const identity = {
      userId: attrs.sub || user.Username || principal,
      email: attrs.email || '',
      displayName: displayNameFromAttrs(attrs, principal),
    };
    return identityBelongsToOrg(identity, attrs, orgId) ? identity : null;
  } catch (error) {
    console.warn('[PERMISSIONS] Principal identity lookup failed', {
      principal,
      orgId,
      message: (error as Error).message,
    });
    return null;
  }
}

function normalizePermissionPath(path: string): string {
  const normalized = path.trim().replace(/\/+/g, '/');
  return normalized.startsWith('/') ? normalized : `/${normalized}`;
}

function permissionRuleOverlapsPath(rule: PermissionRule, targetPath: string): boolean {
  const rulePath = normalizePermissionPath(rule.pathPattern);
  return pathMatchesPattern(targetPath, rulePath) || pathMatchesPattern(rulePath, targetPath);
}

async function resolvePermissionRolesForTarget(
  targetUserId: string,
  caller: UserContext,
  vault: VaultRecord
): Promise<string[]> {
  if (targetUserId === caller.userId && isAdmin(caller)) {
    return caller.roles;
  }

  const membership = await getVaultMembership(vault.vaultId, targetUserId);
  if (membership) {
    return [membership.role];
  }

  return targetUserId === caller.userId ? caller.roles : [];
}

function aliasesFromDirectory(
  userId: string,
  directory: Map<string, PrincipalIdentity>,
  extras: string[] = []
): string[] {
  const identity = directory.get(userId);
  return principalLookupValues(userId, [
    ...(identity?.email ? [identity.email] : []),
    ...extras,
  ]).filter((value) => value !== userId);
}

async function aliasesForAccessTarget(
  userId: string,
  caller: UserContext,
  orgId: string,
  directory: Map<string, PrincipalIdentity>,
  extras: string[] = []
): Promise<string[]> {
  const aliases = aliasesFromDirectory(userId, directory, extras);
  if (aliases.length > 0) return aliases;
  if (userId === caller.userId && caller.email) {
    return aliasesFromDirectory(userId, directory, [caller.email, ...extras]);
  }

  const identity = await resolvePrincipalIdentity(userId, orgId);
  return principalLookupValues(userId, [
    ...(identity?.email ? [identity.email] : []),
    ...extras,
  ]).filter((value) => value !== userId);
}

async function resolvePathAccessLevel(
  userId: string,
  roles: string[],
  path: string,
  vault: VaultRecord,
  aliases: string[] = []
): Promise<PathAccessLevel> {
  const checks: Array<{ action: PermissionAction; level: PathAccessLevel }> = [
    { action: 'admin', level: 'admin' },
    { action: 'write', level: 'write' },
    { action: 'read', level: 'read' },
  ];

  // Target-side level computation honors the per-org
  // `allowAdminPerFileRestrictions` toggle — when ON, admins are subject to
  // per-file deny rules and the access summary reflects the restricted
  // level instead of the unconditional "admin" the bypass would otherwise
  // return. See shared/utils.ts:OrgSettings for the full design rationale.
  const respectAdminBypass = await shouldRespectAdminBypassFor(vault.orgId);

  for (const check of checks) {
    const result = await evaluatePermission(
      userId,
      roles,
      check.action,
      path,
      vault.orgId,
      vault.vaultId,
      { userAliases: aliases, respectAdminBypass }
    );
    if (result.allowed) return check.level;
  }

  return 'none';
}

async function canonicalizeRuleUserId(userId: string, orgId: string): Promise<string | null> {
  if (!userId || userId === '*') return userId || '*';
  if (!userId.includes('@')) return userId;
  const identity = await resolvePrincipalIdentity(userId, orgId);
  return identity?.userId ?? null;
}

async function aliasesForTargetUser(
  targetUserId: string,
  caller: UserContext,
  orgId: string
): Promise<string[]> {
  if (targetUserId === caller.userId) {
    return caller.email ? [caller.email] : [];
  }
  const identity = await resolvePrincipalIdentity(targetUserId, orgId);
  return identity?.email ? [identity.email] : [];
}

function principalLookupValues(userId: string, aliases: string[] = []): string[] {
  const seen = new Set<string>();
  const values: string[] = [];
  for (const value of [userId, ...aliases]) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    values.push(trimmed);
  }
  return values;
}

/**
 * Fetches all permission rules applicable to a user by ID, roles, and wildcards.
 *
 * @param userId - The user ID to look up
 * @returns Array of all applicable rules
 */
async function fetchAllUserRules(
  userId: string,
  orgId: string,
  vaultId: string,
  roles: string[] = [],
  aliases: string[] = []
): Promise<PermissionRule[]> {
  const results: PermissionRule[] = [];
  const seen = new Set<string>();
  const pushRules = (items: unknown[] | undefined) => {
    for (const rule of (items ?? []) as PermissionRule[]) {
      const key = rule.id || `${rule.userId}:${rule.role ?? ''}:${rule.pathPattern}:${rule.effect}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push(rule);
    }
  };

  // User-specific rules (scoped to org + vault). Include legacy aliases so
  // older email-targeted rules resolve to the same effective permissions
  // view as canonical Cognito subject rules.
  for (const lookupUserId of principalLookupValues(userId, aliases)) {
    const userResult = await docClient.send(
      new QueryCommand({
        TableName: PERMISSIONS_TABLE,
        IndexName: 'userId-index',
        KeyConditionExpression: 'userId = :uid',
        FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
        ExpressionAttributeValues: { ':uid': lookupUserId, ':orgId': orgId, ':vaultId': vaultId },
      })
    );
    pushRules(userResult.Items);
  }

  // Role-based rules (scoped to org + vault)
  for (const role of roles) {
    const roleResult = await docClient.send(
      new QueryCommand({
        TableName: PERMISSIONS_TABLE,
        IndexName: 'role-index',
        KeyConditionExpression: '#role = :role',
        ExpressionAttributeNames: { '#role': 'role' },
        FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
        ExpressionAttributeValues: { ':role': role, ':orgId': orgId, ':vaultId': vaultId },
      })
    );
    pushRules(roleResult.Items);
  }

  // Wildcard rules (scoped to org + vault)
  const wildcardResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
      ExpressionAttributeValues: { ':uid': '*', ':orgId': orgId, ':vaultId': vaultId },
    })
  );
  pushRules(wildcardResult.Items);

  return results;
}

/**
 * Consolidates permission rules into an effective permissions map.
 * Groups rules by path and resolves conflicts.
 *
 * @param rules - All applicable rules for a user
 * @returns Map of path patterns to their effective permissions
 */
function consolidatePermissions(
  rules: PermissionRule[]
): Record<string, { actions: PermissionAction[]; effect: string }> {
  const consolidated: Record<string, { actions: PermissionAction[]; effect: string }> = {};

  // Group by path pattern
  const byPath = new Map<string, PermissionRule[]>();
  for (const rule of rules) {
    const existing = byPath.get(rule.pathPattern) || [];
    existing.push(rule);
    byPath.set(rule.pathPattern, existing);
  }

  // Resolve conflicts per path
  for (const [pathPattern, pathRules] of byPath) {
    // Deny overrides allow at the same path
    const hasDeny = pathRules.some((r) => r.effect === 'deny');
    if (hasDeny) {
      const denyActions = pathRules
        .filter((r) => r.effect === 'deny')
        .flatMap((r) => r.actions);
      consolidated[pathPattern] = { actions: [...new Set(denyActions)], effect: 'deny' };
    } else {
      const allowActions = pathRules
        .filter((r) => r.effect === 'allow')
        .flatMap((r) => r.actions);
      consolidated[pathPattern] = { actions: [...new Set(allowActions)], effect: 'allow' };
    }
  }

  return consolidated;
}

/**
 * Finds existing rules that conflict with a proposed new rule.
 * A conflict occurs when rules overlap on the same path with different effects.
 *
 * @param userId - Target user of the new rule
 * @param role - Target role of the new rule
 * @param pathPattern - Path pattern of the new rule
 * @param actions - Actions in the new rule
 * @param effect - Effect of the new rule
 * @returns Array of conflicting existing rules
 */
async function findConflictingRules(
  userId: string,
  role: string | null,
  pathPattern: string,
  actions: PermissionAction[],
  effect: string,
  orgId: string,
  vaultId: string
): Promise<PermissionRule[]> {
  const existingRules = await fetchAllUserRules(
    userId,
    orgId,
    vaultId,
    role ? [role] : []
  );

  return existingRules.filter((rule) => {
    // Check if paths overlap
    const pathOverlaps =
      pathMatchesPattern(pathPattern, rule.pathPattern) ||
      pathMatchesPattern(rule.pathPattern, pathPattern);

    // Check if actions overlap
    const actionOverlaps = rule.actions.some((a) => actions.includes(a));

    // Conflict = same path + same actions + different effect
    return pathOverlaps && actionOverlaps && rule.effect !== effect;
  });
}

/**
 * Calculates a default priority based on path specificity.
 * More specific paths get higher priority.
 *
 * @param pathPattern - The path pattern to calculate priority for
 * @returns Numeric priority value
 */
function calculatePriority(pathPattern: string): number {
  const segments = pathPattern.split('/').filter(Boolean);
  let priority = segments.length * 10;

  // Reduce priority for wildcard segments
  for (const segment of segments) {
    if (segment === '**') priority -= 8;
    else if (segment === '*') priority -= 5;
    else if (segment.includes('*')) priority -= 3;
  }

  return Math.max(priority, 1);
}

function parseOptionalPriority(value: unknown): number | undefined | null {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  const priority = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(priority) || priority < 0) {
    return null;
  }
  return priority;
}

/**
 * Revokes active leases whose scope overlaps a changed permission path.
 * Called after permission create/update/delete to ensure stale leases
 * don't grant access to paths whose permissions have changed.
 *
 * @param pathPattern - The permission path that changed
 * @param userId - Target user ('*' revokes across all users for that path)
 * @param revokedBy - Admin who triggered the change
 * @returns Number of leases revoked
 */
async function revokeOverlappingLeases(
  pathPattern: string,
  userId: string,
  role: string | null | undefined,
  revokedBy: string,
  orgId: string,
  vaultId: string
): Promise<number> {
  const activeLeases =
    userId !== '*' && !role
      ? await queryActiveLeasesForUser(userId, orgId, vaultId)
      : await scanActiveLeasesForVault(orgId, vaultId);
  const now = new Date().toISOString();
  let revokedCount = 0;

  for (const lease of activeLeases) {
    const leaseScope = (lease.scope as string) || '/**';

    // Check if the lease scope overlaps with the changed permission path
    const scopeOverlaps =
      pathMatchesPattern(pathPattern, leaseScope) ||
      pathMatchesPattern(leaseScope, pathPattern);

    if (scopeOverlaps) {
      await docClient.send(
        new UpdateCommand({
          TableName: LEASES_TABLE,
          Key: { leaseId: lease.leaseId as string },
          UpdateExpression: 'SET #s = :revoked, revokedAt = :now, revokedBy = :by',
          ExpressionAttributeNames: { '#s': 'status' },
          ExpressionAttributeValues: {
            ':revoked': 'revoked',
            ':now': now,
            ':by': revokedBy,
          },
        })
      );
      revokedCount++;
    }
  }

  if (revokedCount > 0) {
    console.info(
      `[PERMISSIONS] Revoked ${revokedCount} leases overlapping scope '${pathPattern}' ` +
      `for ${role ? `role '${role}'` : `user '${userId}'`} in vault '${vaultId}'`
    );
  }

  return revokedCount;
}

async function queryActiveLeasesForUser(
  userId: string,
  orgId: string,
  vaultId: string
): Promise<Record<string, unknown>[]> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND orgId = :orgId AND (attribute_not_exists(vaultId) OR vaultId = :vaultId)',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':uid': userId,
        ':active': 'active',
        ':orgId': orgId,
        ':vaultId': vaultId,
      },
    })
  );
  return result.Items || [];
}

async function scanActiveLeasesForVault(
  orgId: string,
  vaultId: string
): Promise<Record<string, unknown>[]> {
  const items: Record<string, unknown>[] = [];
  let ExclusiveStartKey: Record<string, unknown> | undefined;

  do {
    const result = await docClient.send(
      new ScanCommand({
        TableName: LEASES_TABLE,
        FilterExpression: '#s = :active AND orgId = :orgId AND (attribute_not_exists(vaultId) OR vaultId = :vaultId)',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: {
          ':active': 'active',
          ':orgId': orgId,
          ':vaultId': vaultId,
        },
        ExclusiveStartKey,
      })
    );
    items.push(...(result.Items || []));
    ExclusiveStartKey = result.LastEvaluatedKey;
  } while (ExclusiveStartKey);

  return items;
}
