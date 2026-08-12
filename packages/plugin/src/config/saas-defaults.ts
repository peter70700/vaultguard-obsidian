/**
 * SaaS-specific defaults baked into this build.
 *
 * These values are intentionally present in the public plugin build so a fresh
 * Obsidian Community Plugin install can connect to VaultGuard Cloud without
 * requiring the user to paste infrastructure details. Self-hosted Community
 * Edition users can switch to manual configuration, which bypasses these
 * defaults entirely.
 *
 * These values are public client-side config (not secrets): the API endpoint
 * is internet-reachable, and the Cognito User Pool / Client ID are the public
 * identifiers any unauthenticated client would receive during sign-in.
 */

export interface SaasDefaults {
  /** Default API endpoint shown on first install. Empty string = user must configure. */
  readonly apiEndpoint: string;
  /** Default Cognito User Pool ID. Empty string = user must configure. */
  readonly cognitoUserPoolId: string;
  /** Default Cognito Client ID. Empty string = user must configure. */
  readonly cognitoClientId: string;
  /**
   * Fallback API URL used when an org slug must be resolved but no API
   * endpoint has been configured yet. Empty string disables the fallback.
   */
  readonly fallbackApiUrl: string;
  /**
   * Hostnames whose pasted website/admin URLs should be rewritten to the API
   * host before making API calls. Empty array disables this rewrite.
   */
  readonly websiteHostnames: readonly string[];
  /**
   * Target API hostname used when rewriting a websiteHostnames match. Empty
   * string disables the rewrite even if websiteHostnames is non-empty.
   */
  readonly apiHostname: string;
  /**
   * Base URL of the hosted admin SPA, opened by "Open web admin". Empty string
   * disables the link (the caller shows a notice instead of a dead tab).
   *
   * Hosted URLs the plugin actually OPENS must live in this file. The public
   * export scrubs `vaultguard.cloud` -> `example.com` everywhere except here
   * (scripts/export-public-plugin-repo.mjs), so a hosted URL hardcoded in any
   * other module ships as a dead `example.com` link.
   */
  readonly adminBaseUrl: string;
  /**
   * Setup-guide URL shown on the login modal. Empty string hides the link
   * rather than rendering a dead one.
   */
  readonly docsSetupUrl: string;
  /**
   * Hosted registration URL shown on the login modal so a first-run user who
   * has no account yet is not dead-ended at a password prompt. Empty string
   * hides the link — self-hosted builds provision users through their own
   * admin, not through Cloud signup.
   */
  readonly signupUrl: string;
}

export const SAAS_DEFAULTS: SaasDefaults = {
  apiEndpoint: "https://api.vaultguard.cloud",
  cognitoUserPoolId: "eu-central-1_M5gA8YyG3",
  cognitoClientId: "3t7b08ka3ropqm7c5ta7j6sipv",
  fallbackApiUrl: "https://api.vaultguard.cloud",
  websiteHostnames: [
    "vaultguard.cloud",
    "www.vaultguard.cloud",
    "admin.vaultguard.cloud",
  ],
  apiHostname: "api.vaultguard.cloud",
  adminBaseUrl: "https://admin.vaultguard.cloud",
  docsSetupUrl: "https://vaultguard.cloud/#/docs/setup",
  signupUrl: "https://admin.vaultguard.cloud/#/signup",
};
