/**
 * SaaS-specific defaults stripped for the public self-hosted plugin release.
 *
 * Self-hosters must configure their backend manually via Settings > VaultGuard
 * > Connection. See docs/SELF_HOSTED_PLUGIN.md and docs/openapi.yaml for the
 * required backend contract.
 *
 * The hosted example.com build uses a populated version of this file so
 * SaaS users get a working configuration on first install.
 */

export interface SaasDefaults {
  readonly apiEndpoint: string;
  readonly cognitoUserPoolId: string;
  readonly cognitoClientId: string;
  readonly fallbackApiUrl: string;
  readonly websiteHostnames: readonly string[];
  readonly apiHostname: string;
}

export const SAAS_DEFAULTS: SaasDefaults = {
  apiEndpoint: "",
  cognitoUserPoolId: "",
  cognitoClientId: "",
  fallbackApiUrl: "",
  websiteHostnames: [],
  apiHostname: "",
};
