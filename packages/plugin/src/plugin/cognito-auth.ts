/**
 * Cognito authentication using USER_PASSWORD_AUTH flow.
 * Uses Obsidian's requestUrl to bypass Electron/CORS restrictions.
 */

import { requestUrl } from "obsidian";

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
    throw new Error(data.message || "Token refresh failed");
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
  const response = await requestUrl({
    url: `${base}/auth/recovery-codes/verify`,
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ email, code }),
    throw: false,
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
