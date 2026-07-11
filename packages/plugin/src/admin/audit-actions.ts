// Catalog of low-risk, high-volume audit-log actions the "Audit logging"
// config UI allows an admin to opt out of. Security/admin/auth/mutation/
// recovery/audit-management events are mandatory on the backend even if a
// client submits them in `disabledAuditActions`.
//
// Keep this in sync with the admin panel's copy at
// `admin-panel/src/lib/audit-actions.ts` and DISABLEABLE_AUDIT_ACTIONS in
// `infrastructure/lambda/shared/utils.ts`.

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
    label: 'Files and vault overview',
    actions: [
      { value: 'files.list', label: 'List files' },
      { value: 'files.read', label: 'Read file' },
      { value: 'files.history', label: 'File history' },
      { value: 'files.sync', label: 'Sync' },
      { value: 'vault.overview', label: 'Vault overview' },
    ],
  },
  {
    label: 'Permission lookups',
    actions: [
      { value: 'permissions.check', label: 'Permission check' },
      { value: 'permissions.access', label: 'Access summary' },
      { value: 'permissions.access.batch', label: 'Access summary (batch)' },
    ],
  },
  {
    label: 'Shares',
    actions: [
      { value: 'shares.list', label: 'Shares listed' },
    ],
  },
];

/** Flat list of every catalogued action value. */
export const ALL_AUDIT_ACTION_VALUES: string[] = AUDIT_ACTION_CATALOG.flatMap(
  (category) => category.actions.map((action) => action.value)
);
