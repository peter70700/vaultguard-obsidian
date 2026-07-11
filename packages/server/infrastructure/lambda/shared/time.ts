/**
 * VaultGuard — Shared time helpers.
 *
 * `isOffHours` was previously private to audit/handler.ts. It is shared here so
 * the permissions handler can emit the `OffHoursPermissionChange` security
 * metric (SD-09-F1) using the EXACT same off-hours definition the anomaly
 * detector already uses — the two can never drift because there is one source.
 */

// Off-hours window in UTC. Defaults: 20:00 → 06:00 UTC. Overridable per stage.
// When start === end the window is empty (off-hours detection disabled).
const OFF_HOURS_START_HOUR_UTC = parseInt(process.env.OFF_HOURS_START_HOUR_UTC || '20', 10);
const OFF_HOURS_END_HOUR_UTC = parseInt(process.env.OFF_HOURS_END_HOUR_UTC || '6', 10);

/**
 * True if the given ISO timestamp falls inside the configured off-hours window
 * (UTC). Handles a window that wraps past midnight (start > end).
 */
export function isOffHours(timestamp: string): boolean {
  const hour = new Date(timestamp).getUTCHours();

  if (OFF_HOURS_START_HOUR_UTC === OFF_HOURS_END_HOUR_UTC) {
    return false;
  }

  if (OFF_HOURS_START_HOUR_UTC < OFF_HOURS_END_HOUR_UTC) {
    return hour >= OFF_HOURS_START_HOUR_UTC && hour < OFF_HOURS_END_HOUR_UTC;
  }

  return hour >= OFF_HOURS_START_HOUR_UTC || hour < OFF_HOURS_END_HOUR_UTC;
}
