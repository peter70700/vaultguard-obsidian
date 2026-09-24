/** Independent, disabled-by-default operational controls. No switch deletes storage. */
export const WORKSPACE_CAPABILITIES = [
  'remote_mcp', 'revision_reads', 'revision_writes', 'projections', 'context', 'web_editing', 'first_party_sync',
] as const;
export type WorkspaceCapability = typeof WORKSPACE_CAPABILITIES[number];
export type WorkspaceCapabilityGate = (capability: WorkspaceCapability) => void | Promise<void>;

export class WorkspaceCapabilityDisabledError extends Error {
  constructor(readonly capability: WorkspaceCapability) {
    super(`workspace capability unavailable: ${capability}`);
    this.name = 'WorkspaceCapabilityDisabledError';
  }
}

export const requireWorkspaceCapability = (capability: WorkspaceCapability): void => {
  // Read at every boundary. Missing, malformed and unknown values fail closed.
  if (process.env[`WORKSPACE_${capability.toUpperCase()}_ENABLED`] !== 'true') {
    throw new WorkspaceCapabilityDisabledError(capability);
  }
};

/** Revalidate before egress; callers still own authorization and transactional CAS. */
export async function withWorkspaceCapability<T>(
  capability: WorkspaceCapability,
  action: () => Promise<T>,
  gate: WorkspaceCapabilityGate = requireWorkspaceCapability,
): Promise<T> {
  await gate(capability);
  const result = await action();
  await gate(capability);
  return result;
}

/** Shared entry points for future context and web-edit providers. */
export function runWorkspaceContext<T>(action: () => Promise<T>, gate: WorkspaceCapabilityGate = requireWorkspaceCapability) {
  return withWorkspaceCapability('context', () => withWorkspaceCapability('revision_reads', action, gate), gate);
}
export function runWorkspaceWebEdit<T>(action: () => Promise<T>, gate: WorkspaceCapabilityGate = requireWorkspaceCapability) {
  return withWorkspaceCapability('web_editing', () => withWorkspaceCapability('revision_writes', action, gate), gate);
}
