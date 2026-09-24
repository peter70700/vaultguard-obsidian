/** D-034: durable human consent, separate from browser sessions and access tokens.
 * The default applies only when creating fresh consent. Stored grants never grow.
 * A settings change moves policyRevision, requiring explicit fresh authorization.
 */
export const CONNECTOR_AUTHORIZATION_POLICY = Object.freeze({
  defaultDays: 30, minimumDays: 1, maximumDays: 90, presets: [14, 30] as const,
  accessTokenSeconds: 300, requestSeconds: 300, reviewMilliseconds: 900_000,
});
export function connectorAuthorizationDays(value: unknown): number {
  if (value === undefined) return CONNECTOR_AUTHORIZATION_POLICY.defaultDays;
  if (!Number.isSafeInteger(value) || Number(value) < CONNECTOR_AUTHORIZATION_POLICY.minimumDays ||
      Number(value) > CONNECTOR_AUTHORIZATION_POLICY.maximumDays) throw new Error('INVALID_CONNECTOR_AUTHORIZATION_DURATION');
  return Number(value);
}
