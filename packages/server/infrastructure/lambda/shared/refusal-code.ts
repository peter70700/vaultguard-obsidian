/**
 * The stable INTERNAL code a typed owner refusal names, for authorized audit
 * only (VAULTGUARD-113, P4-GAP-2).
 *
 * Callers are answered through their own closed mappings, which deliberately
 * collapse several refusals into one answer (`stale_base` before admission is
 * answered `unavailable`, a hidden vault is `not_found`). Audit is where the
 * collapsed distinction belongs: a vault administrator reading the log needs to
 * tell a stale base from a revoked approval, and nothing reading the answer can.
 *
 * Only a closed list of owners is trusted to name a code, and the code must
 * match the snake-case vocabulary every one of them uses. Any other failure (an
 * SDK, crypto or parser exception, an upstream message) names nothing, so no
 * provider text, path or identifier can reach an audit row through this.
 *
 * Dependency-free on purpose: the MCP edge and the browser host both import it,
 * and neither may pull shared utilities in just to classify an error.
 */

const CODED_OWNERS: ReadonlySet<string> = new Set([
  'AccessWorkflowError',
  'ApplyPreparationError',
  'ApprovalError',
  'CollaborationError',
  'KnowledgeError',
  'ProposalError',
  'PublicationError',
  'WorkspaceConflictError',
  'WorkspaceWebError',
]);

/** Stable-code carriers of the MCP surface itself. */
const STABLE_OWNERS: ReadonlySet<string> = new Set(['McpRequestError', 'WorkspaceReadError']);

/** The older shared-utils owners report an HTTP status (see `publicationRefusal`). */
const STATUS_OWNERS: ReadonlySet<string> = new Set(['AuthError', 'PermissionError']);
const HIDDEN_STATUSES: ReadonlySet<number> = new Set([401, 403, 404]);

const CODE = /^[a-z][a-z_]{0,63}$/u;

const code = (value: unknown): string | null => (typeof value === 'string' && CODE.test(value) ? value : null);

export function ownerRefusalCode(error: unknown): string | null {
  if (!(error instanceof Error)) return null;
  if (error.name === 'WorkspaceCapabilityDisabledError') return 'feature_disabled';
  if (error.name === 'PublicationError') {
    // A pre-admission refusal keeps the owner refusal it collapsed.
    const refusal = code((error as { refusal?: { code?: unknown } }).refusal?.code);
    if (refusal) return refusal;
  }
  if (CODED_OWNERS.has(error.name)) return code((error as { code?: unknown }).code);
  if (STABLE_OWNERS.has(error.name)) return code((error as { stableCode?: unknown }).stableCode);
  if (STATUS_OWNERS.has(error.name)) {
    const named = code((error as { code?: unknown }).code);
    if (named) return named;
    const status = (error as { statusCode?: unknown }).statusCode;
    return typeof status === 'number' && HIDDEN_STATUSES.has(status) ? 'unavailable' : null;
  }
  return null;
}
