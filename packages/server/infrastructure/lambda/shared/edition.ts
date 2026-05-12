/**
 * Edition flag — toggles paid-tier features on/off at runtime.
 *
 * Set via the `VAULTGUARD_EDITION` lambda environment variable.
 *
 * - 'pro'        — full feature set (managed SaaS, paid self-host).
 * - 'community'  — open-source self-host. Excludes share links, the web admin
 *                  panel, advanced audit dashboards/alerts/exports, and the
 *                  billing/Stripe surface.
 *
 * The source repo defaults Terraform to 'pro' so the private deployment keeps
 * working with no env change. The public Community Edition export rewrites
 * the Terraform default to 'community', so a self-hosted backend never reports
 * paid-tier capabilities to the plugin.
 *
 * Capability discovery for clients lives in `signup/handler.ts` under
 * `GET /orgs/{slug}/config`, which returns the edition + features object.
 */

export type Edition = 'community' | 'pro';

function resolveEdition(): Edition {
  const raw = (process.env.VAULTGUARD_EDITION || '').toLowerCase();
  return raw === 'community' ? 'community' : 'pro';
}

export const EDITION: Edition = resolveEdition();

export const FEATURES = {
  /** Share-link tokens and the share-bridge SPA. Pro only. */
  shareLinks:    EDITION === 'pro',
  /** Audit dashboards, anomaly alerts, CSV export, per-user / per-file reports. Pro only. */
  advancedAudit: EDITION === 'pro',
  /** Stripe-backed subscription lifecycle. Pro only. */
  billing:       EDITION === 'pro',
  /** Hosted admin.example.com SPA. Pro only. */
  webAdmin:      EDITION === 'pro',
} as const;

export type Features = typeof FEATURES;
