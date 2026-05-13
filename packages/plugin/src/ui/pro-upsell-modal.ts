/**
 * ProUpsellModal — shown when a CE user clicks a Pro-only UI surface.
 * Replaces the historic "hide on CE" behavior with show-and-explain so users
 * see the value of upgrading instead of silently missing controls.
 *
 * The same compiled binary serves both Cloud and CE — Pro backends never open
 * this modal because their featureEnabled() returns true at the call sites.
 *
 * The modal opens with a prominent "PRO FEATURE — Not available in Community
 * Edition" badge above the title; banner classes are styled in styles.css.
 *
 * No URLs in the copy: the public-plugin export scrubber rewrites the hosted
 * production domain to a placeholder (scripts/export-public-plugin-repo.mjs
 * DOMAIN_REPLACEMENTS), which would leave nonsensical text in the binary
 * shipped to the Obsidian directory if we hard-coded any host name here.
 */

import { App, ButtonComponent, Modal } from "obsidian";

export type ProFeature = "shareLinks" | "advancedAudit" | "billing" | "webAdmin";

interface FeatureCopy {
  title: string;
  tagline: string;
  bullets: string[];
  footer: string;
}

const COMMON_FOOTER =
  "Connect to a VaultGuard Pro backend to unlock this surface — the same plugin binary works against both editions.";

const FEATURE_COPY: Record<ProFeature, FeatureCopy> = {
  shareLinks: {
    title: "Share links",
    tagline:
      "Send time-limited links to people outside your team without giving them an Obsidian login. Per-file permissions still apply. Links can be revoked at any time.",
    bullets: [
      "Mint a link to any file a vault member can read",
      "Recipient opens it in their own Obsidian via a one-click bridge",
      "Per-file permission rules continue to apply to the recipient",
      "Revoke a link at any time from the share-management view",
    ],
    footer: COMMON_FOOTER,
  },
  advancedAudit: {
    title: "Advanced audit",
    tagline:
      "Anomaly alerts, scheduled CSV exports, per-user and per-file reports, and longer retention.",
    bullets: [
      "Export the current audit view to CSV",
      "Scheduled exports delivered to your inbox",
      "Per-user and per-file activity reports",
      "Anomaly alerts on unusual access patterns",
      "Extended retention beyond the Community default",
    ],
    footer: COMMON_FOOTER,
  },
  billing: {
    title: "Billing",
    tagline:
      "Stripe-backed subscription management for your VaultGuard organization.",
    bullets: [
      "Self-serve plan changes",
      "Invoices and billing portal access",
      "Seat-based usage tracking",
    ],
    footer: COMMON_FOOTER,
  },
  webAdmin: {
    title: "Hosted admin panel",
    tagline:
      "A browser-based admin console for managing users, vaults, and audit logs without opening Obsidian.",
    bullets: [
      "Manage org users from any browser",
      "Browse audit logs across all vaults",
      "Configure vault membership and roles",
    ],
    footer: COMMON_FOOTER,
  },
};

export class ProUpsellModal extends Modal {
  private readonly feature: ProFeature;

  constructor(app: App, feature: ProFeature) {
    super(app);
    this.feature = feature;
  }

  onOpen(): void {
    this.modalEl.addClass("vaultguard-pro-upsell");
    const copy = FEATURE_COPY[this.feature];
    const c = this.contentEl;
    c.empty();
    const badge = c.createDiv({ cls: "vaultguard-pro-upsell-badge" });
    badge.createDiv({
      cls: "vaultguard-pro-upsell-badge-headline",
      text: "PRO FEATURE",
    });
    badge.createDiv({
      cls: "vaultguard-pro-upsell-badge-subline",
      text: "Not available in Community Edition",
    });
    c.createEl("h2", { text: copy.title });
    c.createEl("p", { text: copy.tagline });
    const ul = c.createEl("ul");
    for (const bullet of copy.bullets) {
      ul.createEl("li", { text: bullet });
    }
    c.createEl("p", {
      text: copy.footer,
      cls: "vaultguard-pro-upsell-footer",
    });
    const buttonRow = c.createDiv({ cls: "vaultguard-pro-upsell-actions" });
    new ButtonComponent(buttonRow)
      .setButtonText("Close")
      .onClick(() => this.close());
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

// Exported for tests; not intended for external consumers.
export const __TEST_FEATURE_COPY = FEATURE_COPY;
