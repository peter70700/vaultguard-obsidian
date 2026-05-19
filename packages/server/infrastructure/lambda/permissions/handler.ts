/**
 * VaultGuard — Permissions Management Lambda Handler
 *
 * Manages the permission rule system that controls access to vault files.
 * All rules are scoped to a single vault — rules in vault A do not leak
 * into vault B. Supports user-level, role-level, and glob-pattern-based
 * permissions with inheritance, time-bound grants, and conflict resolution.
 *
 * Endpoints (all under /vaults/{vaultId}):
 * - GET    /permissions                — List rules in this vault (vault member)
 * - GET    /vaults/{vaultId}/permissions/user/{userId} — Effective permissions for a user (self or vault-admin)
 * - POST   /permissions                — Create rule (vault-admin or org-admin)
 * - PUT    /vaults/{vaultId}/permissions/{id} — Update rule (vault-admin)
 * - DELETE /vaults/{vaultId}/permissions/{id} — Delete rule (vault-admin)
 * - POST   /vaults/{vaultId}/permissions/check — Check if user can perform action on path (any vault member, self only)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  docClient,
  verifyActiveUser,
  evaluatePermission,
  requireOrgId,
  requireVaultMember,
  pathMatchesPattern,
  getVaultMembership,
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

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions':
        return await handleCreatePermission(event, user, vault, requestId);

      case method === 'PUT' && resource === '/vaults/{vaultId}/permissions/{id}':
        return await handleUpdatePermission(event, user, vault, requestId);

      case method === 'DELETE' && resource === '/vaults/{vaultId}/permissions/{id}':
        return await handleDeletePermission(event, user, vault, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/permissions/check':
        return await handleCheckPermission(event, user, vault, requestId);

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
  // Vault membership was already verified at the routing layer.
  const limit = Math.min(parseInt(event.queryStringParameters?.limit || '50', 10), 500);
  const pathFilter = event.queryStringParameters?.pathFilter;
  const effectFilter = event.queryStringParameters?.effectFilter;

  let filterExpression: string = 'orgId = :orgId AND vaultId = :vaultId';
  const expressionValues: Record<string, unknown> = {
    ':orgId': vault.orgId,
    ':vaultId': vault.vaultId,
  };

  if (pathFilter && effectFilter) {
    filterExpression += ' AND contains(pathPattern, :pathFilter) AND #effect = :effectFilter';
    expressionValues[':pathFilter'] = pathFilter;
    expressionValues[':effectFilter'] = effectFilter;
  } else if (pathFilter) {
    filterExpression += ' AND contains(pathPattern, :pathFilter)';
    expressionValues[':pathFilter'] = pathFilter;
  } else if (effectFilter) {
    filterExpression += ' AND #effect = :effectFilter';
    expressionValues[':effectFilter'] = effectFilter;
  }

  const scanParams: Record<string, unknown> = {
    TableName: PERMISSIONS_TABLE,
    Limit: limit,
    FilterExpression: filterExpression,
    ExpressionAttributeValues: expressionValues,
  };

  if (filterExpression.includes('#effect')) {
    (scanParams as Record<string, unknown>).ExpressionAttributeNames = { '#effect': 'effect' };
  }

  const result = await docClient.send(new ScanCommand(scanParams as any));
  const rules = (result.Items || []) as PermissionRule[];

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
    metadata: { resultCount: rules.length },
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

  // Fetch all rules applicable to this user inside this vault.
  const userRules = await fetchAllUserRules(targetUserId, vault.orgId, vault.vaultId);

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
  // Vault admin or org admin can create rules in this vault.
  await requireVaultMember(user, vault.vaultId, 'admin');

  const body = parseBody(event);
  validateRequiredFields(body, ['pathPattern', 'actions', 'effect']);

  // Validate inputs
  const userId = (body.userId as string) || '*';
  const role = (body.role as string) || null;
  const pathPattern = body.pathPattern as string;
  const actions = body.actions as string[];
  const effect = body.effect as string;
  const priority = (body.priority as number) || calculatePriority(pathPattern);
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

  // Reject duplicate: same principal + same exact path already has a rule
  const existingUserRules = await fetchAllUserRules(userId, vault.orgId, vault.vaultId);
  const duplicate = existingUserRules.find((rule) => {
    const samePath = rule.pathPattern === pathPattern;
    const samePrincipal = role
      ? rule.role === role
      : !rule.role && rule.userId === userId;
    return samePath && samePrincipal;
  });
  if (duplicate) {
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
  await requireVaultMember(user, vault.vaultId, 'admin');

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
  if (body.userId !== undefined) updates.userId = body.userId;
  if (body.role !== undefined) updates.role = body.role;
  if (body.expiresAt !== undefined) {
    updates.expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt : null;
  }

  if (Object.keys(updates).length === 0) {
    return formatError(400, 'No valid fields to update', requestId);
  }

  updates.updatedAt = new Date().toISOString();

  // Build update expression
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
      Key: { pk: ruleId, sk: RULE_SK },
      UpdateExpression: updateExpression,
      ExpressionAttributeNames: expressionAttributeNames,
      ExpressionAttributeValues: expressionAttributeValues,
    })
  );

  const updatedRule = { ...existingRule, ...updates };

  // Revoke leases overlapping both old and new path patterns
  const affectedPath = (updates.pathPattern as string) || existingRule.pathPattern;
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

  // Cursor bump — see handleCreatePermission for rationale. We log the
  // affected path so downstream consumers can correlate, but the path
  // value isn't used by the warm-path detection logic.
  await recordVaultActivity({
    orgId: vault.orgId,
    vaultId: vault.vaultId,
    action: 'permission_changed',
    path: affectedPath,
    actorUserId: user.userId,
  });

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
  await requireVaultMember(user, vault.vaultId, 'admin');

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
  // own check return `allowed: true` regardless of real entitlement. For
  // self-checks we trust the JWT claims; for admin cross-user checks we
  // resolve the target user's vault membership role from DynamoDB and skip
  // any org-level role inheritance (only an org admin issuing the check
  // gets the org-admin bypass — and only for themselves).
  let resolvedRoles: string[];
  if (targetUserId === user.userId) {
    resolvedRoles = user.roles;
  } else {
    const membership = await getVaultMembership(vault.vaultId, targetUserId);
    resolvedRoles = membership ? [membership.role] : [];
  }

  // Evaluate permission within this vault.
  const result = await evaluatePermission(
    targetUserId,
    resolvedRoles,
    action as PermissionAction,
    path,
    vault.orgId,
    vault.vaultId
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

// ─── Helper Functions ────────────────────────────────────────────────────────

/**
 * Fetches all permission rules applicable to a user by ID, roles, and wildcards.
 *
 * @param userId - The user ID to look up
 * @returns Array of all applicable rules
 */
async function fetchAllUserRules(
  userId: string,
  orgId: string,
  vaultId: string
): Promise<PermissionRule[]> {
  const results: PermissionRule[] = [];

  // User-specific rules (scoped to org + vault)
  const userResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
      ExpressionAttributeValues: { ':uid': userId, ':orgId': orgId, ':vaultId': vaultId },
    })
  );
  if (userResult.Items) results.push(...(userResult.Items as PermissionRule[]));

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
  if (wildcardResult.Items) results.push(...(wildcardResult.Items as PermissionRule[]));

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
  const existingRules = await fetchAllUserRules(userId, orgId, vaultId);

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
