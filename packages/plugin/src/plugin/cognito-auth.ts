/**
 * Cognito authentication using USER_PASSWORD_AUTH flow.
 * Uses Obsidian's requestUrl to bypass Electron/CORS restrictions.
 */

import { RequestUrlResponse, requestUrl } from "obsidian";

/**
 * Build the ordered list of base URLs to try for an *unauthenticated*
 * VaultGuard backend call (forgot-password, confirm-reset, recovery-code
 * verify). These flows run before the user has a token, so they can't go
 * through the authenticated endpoint resolver (which probes `/vaults` with a
 * bearer token and caches the working base). Without that resolution, a stored
 * endpoint that carries a stage suffix — e.g. `https://api.example.com/dev`,
 * which is what `/orgs/{slug}/config` returns — points at a path the custom
 * domain doesn't expose (`/dev/auth/...`), so API Gateway answers the generic
 * 403 `{"message":"Missing Authentication Token"}` and the reset silently fails.
 *
 * We mirror what the resolver would eventually discover: try the configured
 * base first, then progressively strip trailing path segments down to the
 * origin root. The custom domain maps its root directly onto the deployed
 * stage, so the origin candidate is the one that actually carries the routes.
 */
function candidateAuthBases(apiBaseUrl: string): string[] {
  const trimmed = apiBaseUrl.replace(/\/+$/, "");
  const candidates: string[] = [];
  const push = (value: string) => {
    const normalized = value.replace(/\/+$/, "");
    if (normalized && !candidates.includes(normalized)) {
      candidates.push(normalized);
    }
  };

  push(trimmed);

  try {
    const parsed = new URL(trimmed);
    const segments = parsed.pathname.split("/").filter((segment) => segment.length > 0);
    // Progressively drop trailing segments: `/a/b` → `/a` → origin root.
    for (let end = segments.length - 1; end >= 0; end--) {
      const nextPath = segments.slice(0, end).join("/");
      parsed.pathname = nextPath ? `/${nextPath}` : "";
      parsed.search = "";
      parsed.hash = "";
      push(parsed.toString());
    }
  } catch {
    // Non-URL base (shouldn't happen after config validation) — the single
    // trimmed candidate above is the best we can do.
  }

  return candidates;
}

/**
 * True when a response is API Gateway's generic "this resource/method doesn't
 * exist here" rejection — the request never reached a VaultGuard Lambda, so
 * the base URL is wrong (typically a spurious stage suffix). Safe to retry
 * against another base: no email was sent and no reset code was consumed.
 */
function isGatewayResourceMiss(response: RequestUrlResponse): boolean {
  if (response.status !== 403) {
    return false;
  }
  const message =
    (response.json as { message?: string } | undefined)?.message ??
    response.text ??
    "";
  return message.includes("Missing Authentication Token");
}

/**
 * POST JSON to an unauthenticated VaultGuard `/auth/*` endpoint, transparently
 * retrying against stage-stripped base URLs when the gateway reports the
 * resource is missing. Returns the first response that actually reached a
 * Lambda (any status that isn't a gateway resource miss), so callers keep their
 * existing per-endpoint status handling.
 */
async function postToVaultGuardAuth(
  apiBaseUrl: string,
  path: string,
  body: unknown
): Promise<RequestUrlResponse> {
  const bases = candidateAuthBases(apiBaseUrl);
  let lastResponse: RequestUrlResponse | null = null;

  for (const base of bases) {
    const response = await requestUrl({
      url: `${base}${path}`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      throw: false,
    });
    lastResponse = response;
    if (!isGatewayResourceMiss(response)) {
      return response;
    }
  }

  // Every candidate was a gateway miss — return the last one so the caller's
  // error handling produces a message rather than throwing on a null.
  return lastResponse as RequestUrlResponse;
}

export interface CognitoTokens {
  accessToken: string;
  idToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface CognitoAuthResult {
  tokens: CognitoTokens;
  challengeName?: string;
  session?: string;
}

/**
 * Sentinel pool id that puts the plugin into local dev-server auth mode.
 * Matches the value documented in docs/SETUP.md (Option A) and the admin
 * panel's IS_LOCAL_DEV branch (admin-panel/src/lib/auth.ts).
 */
export const LOCAL_DEV_POOL_ID = "local-dev";

/** True when the plugin is configured to authenticate against the local dev server. */
export function isLocalDevAuth(userPoolId: string): boolean {
  return userPoolId === LOCAL_DEV_POOL_ID;
}

/**
 * Authenticate against the local dev server's mock `/auth/login` endpoint
 * (dev-server/server.ts) instead of Cognito. The dev server returns
 * Cognito-shaped JWT tokens for the seeded test accounts, so the rest of the
 * login flow is identical to the real path.
 *
 * Without this branch, `cognitoLogin` would derive a region of "local-dev"
 * from the pool id and POST to https://cognito-idp.local-dev.amazonaws.com/,
 * which fails with net::ERR_NAME_NOT_RESOLVED.
 */
export async function devServerLogin(
  apiBaseUrl: string,
  email: string,
  password: string
): Promise<CognitoAuthResult> {
  const base = apiBaseUrl.replace(/\/+$/, "");
  if (!base) {
    throw new Error("API endpoint must be configured for local dev login.");
  }

  const response = await requestUrl({
    url: `${base}/auth/login`,
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
    throw: false,
  });

  const data = response.json ?? {};

  if (response.status < 200 || response.status >= 300) {
    throw new Error(data.message || data.Message || "Invalid email or password.");
  }

  const tokens = data.tokens ?? {};
  if (!tokens.idToken) {
    throw new Error("Dev server did not return a valid session token.");
  }

  return {
    tokens: {
      accessToken: tokens.accessToken ?? tokens.idToken,
      idToken: tokens.idToken,
      refreshToken: tokens.refreshToken ?? "",
      expiresIn: 3600,
    },
  };
}

/**
 * Authenticate a user against Cognito using email/password.
 * Handles USER_PASSWORD_AUTH and NEW_PASSWORD_REQUIRED / MFA challenges.
 */
export async function cognitoLogin(
  userPoolId: string,
  clientId: string,
  email: string,
  password: string
): Promise<CognitoAuthResult> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    },
    body: JSON.stringify({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: clientId,
      AuthParameters: {
        USERNAME: email,
        PASSWORD: password,
      },
    }),
    throw: false,
  });

  const data = response.json;

  if (response.status < 200 || response.status >= 300) {
    const errorType = data.__type || "";
    const errorMessage = data.message || data.Message || "Authentication failed";

    if (errorType.includes("NotAuthorizedException")) {
      throw new Error("Invalid email or password.");
    }
    if (errorType.includes("UserNotFoundException")) {
      throw new Error("Invalid email or password.");
    }
    if (errorType.includes("UserNotConfirmedException")) {
      throw new Error("Account not confirmed. Check your email for a verification link.");
    }
    if (errorType.includes("PasswordResetRequiredException")) {
      throw new Error("Password reset required. Contact your administrator.");
    }
    throw new Error(errorMessage);
  }

  // Handle challenges (MFA, new password required, etc.)
  if (data.ChallengeName) {
    return {
      tokens: { accessToken: "", idToken: "", refreshToken: "", expiresIn: 0 },
      challengeName: data.ChallengeName,
      session: data.Session,
    };
  }

  // Successful auth
  const result = data.AuthenticationResult;
  return {
    tokens: {
      accessToken: result.AccessToken,
      idToken: result.IdToken,
      refreshToken: result.RefreshToken,
      expiresIn: result.ExpiresIn,
    },
  };
}

/**
 * Respond to a Cognito auth challenge (MFA code, new password, etc.)
 */
export async function cognitoRespondToChallenge(
  userPoolId: string,
  clientId: string,
  challengeName: string,
  session: string,
  responses: Record<string, string>
): Promise<CognitoAuthResult> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
    },
    body: JSON.stringify({
      ChallengeName: challengeName,
      ClientId: clientId,
      Session: session,
      ChallengeResponses: responses,
    }),
    throw: false,
  });

  const data = response.json;

  if (response.status < 200 || response.status >= 300) {
    const errorMessage = data.message || data.Message || "Challenge response failed";
    throw new Error(errorMessage);
  }

  if (data.ChallengeName) {
    return {
      tokens: { accessToken: "", idToken: "", refreshToken: "", expiresIn: 0 },
      challengeName: data.ChallengeName,
      session: data.Session,
    };
  }

  const result = data.AuthenticationResult;
  return {
    tokens: {
      accessToken: result.AccessToken,
      idToken: result.IdToken,
      refreshToken: result.RefreshToken,
      expiresIn: result.ExpiresIn,
    },
  };
}

/**
 * Associate a TOTP software token during MFA_SETUP challenge.
 * Returns the secret code the user must enter into their authenticator app.
 */
export async function cognitoAssociateSoftwareToken(
  userPoolId: string,
  session: string
): Promise<{ secretCode: string; session: string }> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.AssociateSoftwareToken",
    },
    body: JSON.stringify({
      Session: session,
    }),
    throw: false,
  });

  const data = response.json;

  if (response.status < 200 || response.status >= 300) {
    throw new Error(data.message || data.Message || "Failed to start MFA setup");
  }

  return {
    secretCode: data.SecretCode,
    session: data.Session,
  };
}

/**
 * Verify a TOTP code during MFA_SETUP to complete device registration.
 * Must be called after cognitoAssociateSoftwareToken.
 */
export async function cognitoVerifySoftwareToken(
  userPoolId: string,
  session: string,
  totpCode: string,
  friendlyDeviceName?: string
): Promise<{ session: string; status: string }> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.VerifySoftwareToken",
    },
    body: JSON.stringify({
      Session: session,
      UserCode: totpCode,
      FriendlyDeviceName: friendlyDeviceName ?? "VaultGuard",
    }),
    throw: false,
  });

  const data = response.json;

  if (response.status < 200 || response.status >= 300) {
    const msg = data.message || data.Message || "MFA verification failed";
    if ((data.__type || "").includes("CodeMismatchException")) {
      throw new Error("Invalid code. Please check your authenticator app and try again.");
    }
    throw new Error(msg);
  }

  return {
    session: data.Session,
    status: data.Status, // "SUCCESS" or "ERROR"
  };
}

/**
 * Enable TOTP MFA as the preferred method for the authenticated user.
 * Called with the access token after successful login.
 */
export async function cognitoSetUserMfaPreference(
  userPoolId: string,
  accessToken: string,
  enabled: boolean
): Promise<void> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.SetUserMFAPreference",
    },
    body: JSON.stringify({
      AccessToken: accessToken,
      SoftwareTokenMfaSettings: {
        Enabled: enabled,
        PreferredMfa: enabled,
      },
    }),
    throw: false,
  });

  if (response.status < 200 || response.status >= 300) {
    const data = response.json;
    throw new Error(data.message || data.Message || "Failed to update MFA preference");
  }
}

/**
 * Refresh Cognito tokens using a refresh token.
 */
export async function cognitoRefresh(
  userPoolId: string,
  clientId: string,
  refreshToken: string
): Promise<CognitoTokens> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    },
    body: JSON.stringify({
      AuthFlow: "REFRESH_TOKEN_AUTH",
      ClientId: clientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    }),
    throw: false,
  });

  const data = response.json;

  if (response.status < 200 || response.status >= 300) {
    // PL4: carry Cognito's error __type (e.g. NotAuthorizedException for an
    // expired/revoked refresh token or a disabled user) so callers can tell a
    // TERMINAL rejection apart from a transient network/throttling failure.
    const err = new Error(data.message || "Token refresh failed") as Error & {
      cognitoErrorType?: string;
    };
    if (typeof data.__type === "string" && data.__type) {
      err.cognitoErrorType = data.__type.split("#").pop();
    }
    throw err;
  }

  const result = data.AuthenticationResult;
  return {
    accessToken: result.AccessToken,
    idToken: result.IdToken,
    refreshToken: refreshToken, // Cognito doesn't always return a new refresh token
    expiresIn: result.ExpiresIn,
  };
}

/**
 * Revoke a Cognito refresh token (RevokeToken API). After revocation the
 * token can never mint new access/id tokens — required so logout actually
 * invalidates the credential rather than only deleting local copies (PL6:
 * a lingering data.json backup otherwise stays a working key). Requires
 * token revocation to be enabled on the app client (Cognito's default).
 */
export async function cognitoRevokeToken(
  userPoolId: string,
  clientId: string,
  refreshToken: string
): Promise<void> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.RevokeToken",
    },
    body: JSON.stringify({
      ClientId: clientId,
      Token: refreshToken,
    }),
    throw: false,
  });

  if (response.status < 200 || response.status >= 300) {
    const data = response.json;
    throw new Error(data?.message || "Token revocation failed");
  }
}

/**
 * Initiate the Cognito ForgotPassword flow.
 * Sends a verification code to the user's registered email address.
 * Silently succeeds even if the email doesn't exist (to avoid account enumeration).
 */
export async function cognitoForgotPassword(
  userPoolId: string,
  clientId: string,
  email: string
): Promise<void> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.ForgotPassword",
    },
    body: JSON.stringify({
      ClientId: clientId,
      Username: email,
    }),
    throw: false,
  });

  // Don't reveal if account exists — silently succeed
  if (response.status >= 200 && response.status < 300) {
    return;
  }

  const data = response.json;
  if (data.__type?.includes('LimitExceededException')) {
    throw new Error("Too many attempts. Please wait before trying again.");
  }
  // For all other errors, silently succeed (don't reveal account existence)
}

/**
 * Confirm a Cognito password reset using the verification code and a new password.
 * Throws descriptive errors for invalid codes, expired codes, and weak passwords.
 */
export async function cognitoConfirmForgotPassword(
  userPoolId: string,
  clientId: string,
  email: string,
  code: string,
  newPassword: string
): Promise<void> {
  const region = userPoolId.split("_")[0];
  const endpoint = `https://cognito-idp.${region}.amazonaws.com/`;

  const response = await requestUrl({
    url: endpoint,
    method: "POST",
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.ConfirmForgotPassword",
    },
    body: JSON.stringify({
      ClientId: clientId,
      Username: email,
      ConfirmationCode: code,
      Password: newPassword,
    }),
    throw: false,
  });

  if (response.status >= 200 && response.status < 300) {
    return;
  }

  const data = response.json;
  const errorType = data.__type || "";

  if (errorType.includes('CodeMismatchException')) {
    throw new Error("Invalid reset code. Please check and try again.");
  }
  if (errorType.includes('ExpiredCodeException')) {
    throw new Error("Reset code has expired. Please request a new one.");
  }
  if (errorType.includes('InvalidPasswordException')) {
    throw new Error("Password must be 12+ characters with uppercase, lowercase, numbers, and symbols.");
  }
  throw new Error(data.message || data.Message || "Password reset failed.");
}

/**
 * Initiate a password reset through the VaultGuard backend (not Cognito).
 *
 * The backend's POST /auth/forgot-password generates the reset code and sends
 * a branded email via SES, deliberately bypassing Cognito's built-in
 * ForgotPassword flow (see infrastructure/lambda/auth/handler.ts). Calling
 * Cognito's ForgotPassword directly from the plugin produced no email when the
 * pool has its native email delivery disabled — which is why the reset code
 * never arrived when triggered from Obsidian.
 *
 * The endpoint always returns a generic success (even for unknown emails) to
 * avoid account enumeration, so we surface failures only for real server
 * errors and rate limiting.
 */
export async function vaultguardForgotPassword(
  apiBaseUrl: string,
  clientId: string,
  email: string
): Promise<void> {
  const base = apiBaseUrl.replace(/\/+$/, "");
  if (!base) {
    throw new Error("API endpoint must be configured to reset your password.");
  }

  const response = await postToVaultGuardAuth(base, "/auth/forgot-password", {
    email,
    clientId,
  });

  if (response.status >= 200 && response.status < 300) {
    return;
  }

  const data = response.json ?? {};
  if (response.status === 429 || (data.__type ?? "").includes("LimitExceeded")) {
    throw new Error("Too many attempts. Please wait before trying again.");
  }
  throw new Error(data.message || data.Message || "Unable to send reset code right now. Please try again later.");
}

/**
 * Confirm a password reset via the VaultGuard backend's POST /auth/confirm-reset
 * using the emailed code and a new password. Mirrors the admin panel flow.
 */
export async function vaultguardConfirmReset(
  apiBaseUrl: string,
  clientId: string,
  email: string,
  code: string,
  newPassword: string
): Promise<void> {
  const base = apiBaseUrl.replace(/\/+$/, "");
  if (!base) {
    throw new Error("API endpoint must be configured to reset your password.");
  }

  const response = await postToVaultGuardAuth(base, "/auth/confirm-reset", {
    email,
    code,
    newPassword,
    clientId,
  });

  if (response.status >= 200 && response.status < 300) {
    return;
  }

  const data = response.json ?? {};
  const errorType = data.__type || "";
  if (errorType.includes("CodeMismatch") || response.status === 400) {
    throw new Error(data.message || "Invalid or expired reset code. Please check and try again.");
  }
  if (errorType.includes("InvalidPassword")) {
    throw new Error("Password must be 12+ characters with uppercase, lowercase, numbers, and symbols.");
  }
  throw new Error(data.message || data.Message || "Password reset failed.");
}

/**
 * Submit a recovery code to the VaultGuard backend after the user has lost
 * their TOTP device. The backend wipes the user's Cognito MFA preference on
 * success; next login routes to MFA_SETUP.
 *
 * Talks to /auth/recovery-codes/verify (no auth required, rate-limited
 * server-side). The plugin can't call this Cognito API directly — it's
 * VaultGuard-specific because Cognito has no "redeem a backup code" verb.
 */
export async function vaultguardVerifyRecoveryCode(
  apiBaseUrl: string,
  email: string,
  code: string
): Promise<void> {
  const base = apiBaseUrl.replace(/\/+$/, "");
  const response = await postToVaultGuardAuth(base, "/auth/recovery-codes/verify", {
    email,
    code,
  });

  if (response.status >= 200 && response.status < 300) {
    return;
  }

  // The server intentionally returns the same generic 400 for unknown email,
  // wrong code, and race-lost redemption. Surface a single, honest message
  // for that case; rate-limit (429) gets its own copy.
  if (response.status === 429) {
    throw new Error(
      "Too many recovery attempts. Try again in an hour or contact your administrator."
    );
  }

  let message = "Recovery failed. Please try again.";
  try {
    const data = response.json as { message?: string; error?: string } | undefined;
    if (data?.message) message = data.message;
    else if (data?.error) message = data.error;
  } catch {
    // Body wasn't JSON — fall through to the generic message.
  }
  throw new Error(message);
}
