export const ROTATION_CONTROL_SK = 'ROTATION_CONTROL';

/** Shared by writer admission and the cohort transition transaction. */
export function rotationControlPk(orgId: string, vaultId: string, scope = '/**'): string {
  if (!orgId || !vaultId || !scope) {
    throw new Error('Rotation fence requires orgId, vaultId, and scope');
  }
  return `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${Buffer.from(scope, 'utf8').toString('base64url')}`;
}
