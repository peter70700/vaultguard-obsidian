/**
 * VaultGuard — audit query retention window.
 *
 * The single definition of how far back an audit query may read. It lived
 * inside `audit/handler.ts`; it moved here so the remote MCP audit read
 * (`mcp/governance-authority.ts`) applies exactly the same Community-edition
 * cap as the HTTP route instead of a second copy that could drift. The audit
 * handler re-exports both symbols, so existing importers are unchanged.
 */

import { DEFAULT_ORG_SETTINGS, getEffectiveOrgSettings } from './utils';
import { FEATURES } from './edition';

/**
 * Soft cap on the retention window for audit-log queries on Community Edition.
 *
 * Pro Edition honors the full `orgSettings.retentionDays` (default 365 days).
 * Community Edition clamps the query window to the most recent 30 days,
 * matching the ProUpsellModal copy and the SERVER_README marketing table.
 *
 * This is a *query-time* cap only — records are still stored per the org's
 * retentionDays and any DynamoDB TTL. CE users can upgrade to Pro to read
 * older entries without re-ingesting data.
 */
export const CE_AUDIT_RETENTION_DAYS = 30;

export async function applyRetentionWindow(
  orgId: string,
  startDate?: string,
  endDate?: string
): Promise<{ startDate?: string; endDate?: string }> {
  const settings = await getEffectiveOrgSettings(orgId);
  const orgRetentionDays = settings?.retentionDays ?? DEFAULT_ORG_SETTINGS.retentionDays;
  const retentionDays = FEATURES.advancedAudit
    ? orgRetentionDays
    : Math.min(orgRetentionDays, CE_AUDIT_RETENTION_DAYS);
  const retentionStart = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();

  let effectiveStartDate = startDate;
  if (!effectiveStartDate || new Date(effectiveStartDate).getTime() < new Date(retentionStart).getTime()) {
    effectiveStartDate = retentionStart;
  }

  return {
    startDate: effectiveStartDate,
    endDate,
  };
}
