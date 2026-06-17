// Catalog of audit-log actions the backend can emit, grouped into the
// categories the "Audit logging" config UI presents. The org-wide
// `disabledAuditActions` setting stores the action `value`s an admin has
// opted out of; `logAudit` on the backend skips any action listed there.
//
// Keep this in sync with the admin panel's copy at
// `admin-panel/src/lib/audit-actions.ts` and with the actions actually
// emitted across `infrastructure/lambda/**`.

export interface AuditActionEntry {
  value: string;
  label: string;
}

export interface AuditActionCategory {
  label: string;
  actions: AuditActionEntry[];
}

export const AUDIT_ACTION_CATALOG: AuditActionCategory[] = [
  {
    label: 'Authentication',
    actions: [
      { value: 'auth.login', label: 'Login' },
      { value: 'auth.logout', label: 'Logout' },
      { value: 'auth.refresh', label: 'Refresh session' },
      { value: 'auth.refresh.denied', label: 'Refresh denied' },
      { value: 'auth.revoke', label: 'Revoke access' },
      { value: 'auth.revoke.denied', label: 'Revoke denied' },
      { value: 'auth.recover', label: 'Recover access' },
      { value: 'auth.recover.denied', label: 'Recover denied' },
      { value: 'auth.recovery_codes.store', label: 'Recovery codes stored' },
      { value: 'auth.recovery_codes.verify', label: 'Recovery codes verified' },
      { value: 'auth.recovery_codes.rate_limited', label: 'Recovery codes rate-limited' },
    ],
  },
  {
    label: 'Files',
    actions: [
      { value: 'files.list', label: 'List files' },
      { value: 'files.read', label: 'Read file' },
      { value: 'files.read.denied', label: 'Read denied' },
      { value: 'files.write', label: 'Write file' },
      { value: 'files.write.denied', label: 'Write denied' },
      { value: 'files.delete', label: 'Delete file' },
      { value: 'files.delete.denied', label: 'Delete denied' },
      { value: 'files.history', label: 'File history' },
      { value: 'files.history.denied', label: 'History denied' },
      { value: 'files.restore.version', label: 'Restore version' },
      { value: 'files.restore.version.denied', label: 'Restore version denied' },
      { value: 'files.sync', label: 'Sync' },
      { value: 'vault.overview', label: 'Vault overview' },
    ],
  },
  {
    label: 'Permissions',
    actions: [
      { value: 'permissions.list', label: 'List rules' },
      { value: 'permissions.user.view', label: 'View user permissions' },
      { value: 'permissions.user.denied', label: 'View user permissions denied' },
      { value: 'permissions.check', label: 'Permission check' },
      { value: 'permissions.create', label: 'Rule created' },
      { value: 'permissions.update', label: 'Rule updated' },
      { value: 'permissions.delete', label: 'Rule deleted' },
      { value: 'permissions.access', label: 'Access summary' },
      { value: 'permissions.access.batch', label: 'Access summary (batch)' },
    ],
  },
  {
    label: 'Vaults',
    actions: [
      { value: 'vault.created', label: 'Vault created' },
      { value: 'vault.updated', label: 'Vault updated' },
      { value: 'vault.archived', label: 'Vault archived' },
      { value: 'vault.member_added', label: 'Member added' },
      { value: 'vault.member_role_changed', label: 'Member role changed' },
      { value: 'vault.member_removed', label: 'Member removed' },
    ],
  },
  {
    label: 'Shares',
    actions: [
      { value: 'shares.create', label: 'Share created' },
      { value: 'shares.create.denied', label: 'Share create denied' },
      { value: 'shares.list', label: 'Shares listed' },
      { value: 'shares.resolve', label: 'Share resolved' },
      { value: 'shares.resolve.denied', label: 'Share resolve denied' },
      { value: 'shares.revoke', label: 'Share revoked' },
    ],
  },
  {
    label: 'Administration',
    actions: [
      { value: 'admin.list_users', label: 'List users' },
      { value: 'admin.list_roles', label: 'List roles' },
      { value: 'admin.user_invited', label: 'User invited' },
      { value: 'admin.role_changed', label: 'Role changed' },
      { value: 'admin.profile_updated', label: 'Profile updated' },
      { value: 'admin.user_removed', label: 'User removed' },
      { value: 'admin.user_reactivated', label: 'User reactivated' },
      { value: 'admin.invitation_resent', label: 'Invitation resent' },
      { value: 'admin.mfa_reset', label: 'MFA reset' },
      { value: 'admin.mfa_reset.denied', label: 'MFA reset denied' },
      { value: 'admin.settings_updated', label: 'Settings updated' },
      { value: 'admin.settings_reset', label: 'Settings reset' },
      { value: 'admin.access.denied', label: 'Admin access denied' },
    ],
  },
  {
    label: 'System',
    actions: [
      { value: 'audit.export', label: 'Audit export' },
      { value: 'audit.access.denied', label: 'Audit access denied' },
      { value: 'org.created', label: 'Organization created' },
      { value: 'reencryption.completed', label: 'Re-encryption completed' },
      { value: 'reconciler.org_reconciled', label: 'Org reconciled' },
    ],
  },
];

/** Flat list of every catalogued action value. */
export const ALL_AUDIT_ACTION_VALUES: string[] = AUDIT_ACTION_CATALOG.flatMap(
  (category) => category.actions.map((action) => action.value)
);
