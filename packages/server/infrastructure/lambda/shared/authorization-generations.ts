/**
 * Stable authorization-generation bindings shared by Lambda entry points.
 *
 * A binding is explanatory state, never durable authority. Callers must load
 * live authorization again before disclosure/commit and compare the resulting
 * generations with the state that authorized the work.
 */

export type VaultAuthorizationGenerationKind = 'membership' | 'permission';

export interface AuthorizationRevisionSet {
  membershipRevision: number | null;
  permissionRevision: number | null;
  policyRevision: number | null;
  oauthGrantRevision: number | null;
  sessionRevision: number | null;
}

export interface AuthorizationGenerationBinding extends AuthorizationRevisionSet {
  orgId: string;
  vaultId: string | null;
  subject: string;
  oauthGrantId: string | null;
  sessionId: string | null;
}

export interface BindAuthorizationGenerationsInput {
  orgId: string;
  vaultId?: string | null;
  subject: string;
  membershipRevision?: unknown;
  permissionRevision?: unknown;
  policyRevision?: unknown;
  oauthGrantId?: string | null;
  oauthGrantRevision?: unknown;
  sessionId?: string | null;
  sessionRevision?: unknown;
}

export class AuthorizationGenerationChangedError extends Error {
  readonly code = 'AUTHORIZATION_GENERATION_CHANGED';

  constructor(readonly generation: keyof AuthorizationRevisionSet | 'identity') {
    super('Authorization changed while the operation was in progress');
    this.name = 'AuthorizationGenerationChangedError';
  }
}

function revision(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError('Authorization revisions must be non-negative safe integers');
  }
  return value as number;
}

function optionalId(value: string | null | undefined, name: string): string | null {
  if (value === undefined || value === null) return null;
  if (value.trim().length === 0) throw new TypeError(`${name} must not be empty`);
  return value;
}

export function bindAuthorizationGenerations(
  input: BindAuthorizationGenerationsInput,
): AuthorizationGenerationBinding {
  if (!input.orgId || !input.subject) {
    throw new TypeError('Authorization binding requires orgId and subject');
  }
  return Object.freeze({
    orgId: input.orgId,
    vaultId: optionalId(input.vaultId, 'vaultId'),
    subject: input.subject,
    membershipRevision: revision(input.membershipRevision),
    permissionRevision: revision(input.permissionRevision),
    policyRevision: revision(input.policyRevision),
    oauthGrantId: optionalId(input.oauthGrantId, 'oauthGrantId'),
    oauthGrantRevision: revision(input.oauthGrantRevision),
    sessionId: optionalId(input.sessionId, 'sessionId'),
    sessionRevision: revision(input.sessionRevision),
  });
}

/** Fail closed if identity or any bound generation changed. */
export function assertAuthorizationBindingCurrent(
  bound: AuthorizationGenerationBinding,
  current: AuthorizationGenerationBinding,
): void {
  if (
    bound.orgId !== current.orgId ||
    bound.vaultId !== current.vaultId ||
    bound.subject !== current.subject ||
    bound.oauthGrantId !== current.oauthGrantId ||
    bound.sessionId !== current.sessionId
  ) {
    throw new AuthorizationGenerationChangedError('identity');
  }

  const generations: Array<keyof AuthorizationRevisionSet> = [
    'membershipRevision',
    'permissionRevision',
    'policyRevision',
    'oauthGrantRevision',
    'sessionRevision',
  ];
  for (const generation of generations) {
    if (bound[generation] !== current[generation]) {
      throw new AuthorizationGenerationChangedError(generation);
    }
  }
}

/**
 * Re-run the live owners immediately before egress/commit, then prove the
 * result is still the same generation that authorized the operation.
 */
export async function revalidateAuthorizationBeforeEgress(
  bound: AuthorizationGenerationBinding,
  reauthorize: () => Promise<AuthorizationGenerationBinding>,
): Promise<AuthorizationGenerationBinding> {
  const current = await reauthorize();
  assertAuthorizationBindingCurrent(bound, current);
  return current;
}

export function uniqueVaultGenerationKinds(
  kinds: readonly VaultAuthorizationGenerationKind[] | undefined,
): VaultAuthorizationGenerationKind[] {
  const unique: VaultAuthorizationGenerationKind[] = [];
  for (const kind of kinds ?? []) {
    if (kind !== 'membership' && kind !== 'permission') {
      throw new TypeError('Unknown vault authorization generation');
    }
    if (!unique.includes(kind)) unique.push(kind);
  }
  return unique;
}
