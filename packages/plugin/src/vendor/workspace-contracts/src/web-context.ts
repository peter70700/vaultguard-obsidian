/** Explicit human-selected Context Pack governance. No default policy exists. */
export interface WorkspaceContextPolicyRecord {
  schemaVersion: 1;
  revision: number;
  createRole: 'editor' | 'admin';
  visibility: 'vault' | 'private';
  reviewer: 'owner-or-admin' | 'admin';
  allowSelfReview: boolean;
}
