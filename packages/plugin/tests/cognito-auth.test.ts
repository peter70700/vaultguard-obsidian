import { beforeEach, describe, expect, it, vi } from "vitest";

import { requestUrl } from "obsidian";

import {
  cognitoAssociateSoftwareToken,
  cognitoConfirmForgotPassword,
  cognitoForgotPassword,
  cognitoLogin,
  cognitoRefresh,
  cognitoRespondToChallenge,
  cognitoSetUserMfaPreference,
  cognitoVerifySoftwareToken,
  devServerLogin,
  isLocalDevAuth,
  vaultguardConfirmReset,
  vaultguardForgotPassword,
} from "../src/plugin/cognito-auth";

const mockRequestUrl = vi.mocked(requestUrl);

function jsonResponse(status: number, json: unknown) {
  return {
    status,
    json,
    text: JSON.stringify(json),
    headers: { "content-type": "application/x-amz-json-1.1" },
  } as any;
}

describe("cognito-auth", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("logs in with USER_PASSWORD_AUTH and returns tokens", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
          RefreshToken: "refresh-token",
          ExpiresIn: 3600,
        },
      })
    );

    await expect(
      cognitoLogin("eu-central-1_pool", "client-123", "user@example.com", "Password123!")
    ).resolves.toEqual({
      tokens: {
        accessToken: "access-token",
        idToken: "id-token",
        refreshToken: "refresh-token",
        expiresIn: 3600,
      },
    });

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://cognito-idp.eu-central-1.amazonaws.com/",
        method: "POST",
        throw: false,
        headers: expect.objectContaining({
          "Content-Type": "application/x-amz-json-1.1",
          "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        }),
      })
    );

    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: "client-123",
      AuthParameters: {
        USERNAME: "user@example.com",
        PASSWORD: "Password123!",
      },
    });
  });

  it("returns challenge metadata when Cognito requires MFA or password reset", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        ChallengeName: "SOFTWARE_TOKEN_MFA",
        Session: "challenge-session",
      })
    );

    await expect(
      cognitoLogin("eu-central-1_pool", "client-123", "user@example.com", "Password123!")
    ).resolves.toEqual({
      tokens: {
        accessToken: "",
        idToken: "",
        refreshToken: "",
        expiresIn: 0,
      },
      challengeName: "SOFTWARE_TOKEN_MFA",
      session: "challenge-session",
    });
  });

  it.each([
    ["NotAuthorizedException", "Invalid email or password."],
    ["UserNotFoundException", "Invalid email or password."],
    ["UserNotConfirmedException", "Account not confirmed. Check your email for a verification link."],
    ["PasswordResetRequiredException", "Password reset required. Contact your administrator."],
  ])("maps login error %s to a friendly message", async (errorType, message) => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(400, { __type: errorType, message: "Original message" })
    );

    await expect(
      cognitoLogin("eu-central-1_pool", "client-123", "user@example.com", "Password123!")
    ).rejects.toThrow(message);
  });

  it("responds to auth challenges and can return another challenge", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        ChallengeName: "MFA_SETUP",
        Session: "next-session",
      })
    );

    await expect(
      cognitoRespondToChallenge(
        "eu-central-1_pool",
        "client-123",
        "NEW_PASSWORD_REQUIRED",
        "session-123",
        { USERNAME: "user@example.com", NEW_PASSWORD: "Password123!" }
      )
    ).resolves.toEqual({
      tokens: {
        accessToken: "",
        idToken: "",
        refreshToken: "",
        expiresIn: 0,
      },
      challengeName: "MFA_SETUP",
      session: "next-session",
    });

    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      ChallengeName: "NEW_PASSWORD_REQUIRED",
      ClientId: "client-123",
      Session: "session-123",
      ChallengeResponses: {
        USERNAME: "user@example.com",
        NEW_PASSWORD: "Password123!",
      },
    });
  });

  it("associates and verifies software MFA tokens", async () => {
    mockRequestUrl
      .mockResolvedValueOnce(
        jsonResponse(200, {
          SecretCode: "ABCDEF12",
          Session: "associate-session",
        })
      )
      .mockResolvedValueOnce(
        jsonResponse(200, {
          Session: "verified-session",
          Status: "SUCCESS",
        })
      );

    await expect(
      cognitoAssociateSoftwareToken("eu-central-1_pool", "mfa-session")
    ).resolves.toEqual({
      secretCode: "ABCDEF12",
      session: "associate-session",
    });

    await expect(
      cognitoVerifySoftwareToken("eu-central-1_pool", "associate-session", "123456")
    ).resolves.toEqual({
      session: "verified-session",
      status: "SUCCESS",
    });

    expect(JSON.parse(mockRequestUrl.mock.calls[1]![0].body as string)).toEqual({
      Session: "associate-session",
      UserCode: "123456",
      FriendlyDeviceName: "VaultGuard",
    });
  });

  it("surfaces invalid MFA codes with a user-friendly message", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(400, {
        __type: "CodeMismatchException",
        message: "Bad code",
      })
    );

    await expect(
      cognitoVerifySoftwareToken("eu-central-1_pool", "session-123", "123456")
    ).rejects.toThrow("Invalid code. Please check your authenticator app and try again.");
  });

  it("updates MFA preference and refreshes tokens", async () => {
    mockRequestUrl
      .mockResolvedValueOnce(jsonResponse(200, {}))
      .mockResolvedValueOnce(
        jsonResponse(200, {
          AuthenticationResult: {
            AccessToken: "new-access",
            IdToken: "new-id",
            ExpiresIn: 1800,
          },
        })
      );

    await expect(
      cognitoSetUserMfaPreference("eu-central-1_pool", "access-token", true)
    ).resolves.toBeUndefined();

    await expect(
      cognitoRefresh("eu-central-1_pool", "client-123", "refresh-token")
    ).resolves.toEqual({
      accessToken: "new-access",
      idToken: "new-id",
      refreshToken: "refresh-token",
      expiresIn: 1800,
    });
  });

  it("keeps forgot-password enumeration-safe while still rate limiting", async () => {
    mockRequestUrl
      .mockResolvedValueOnce(jsonResponse(400, { __type: "UserNotFoundException" }))
      .mockResolvedValueOnce(jsonResponse(400, { __type: "LimitExceededException" }));

    await expect(
      cognitoForgotPassword("eu-central-1_pool", "client-123", "missing@example.com")
    ).resolves.toBeUndefined();

    await expect(
      cognitoForgotPassword("eu-central-1_pool", "client-123", "user@example.com")
    ).rejects.toThrow("Too many attempts. Please wait before trying again.");
  });

  it.each([
    ["CodeMismatchException", "Invalid reset code. Please check and try again."],
    ["ExpiredCodeException", "Reset code has expired. Please request a new one."],
    [
      "InvalidPasswordException",
      "Password must be 12+ characters with uppercase, lowercase, numbers, and symbols.",
    ],
  ])("maps reset failure %s to a friendly message", async (errorType, message) => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(400, { __type: errorType, message: "Reset failed" })
    );

    await expect(
      cognitoConfirmForgotPassword(
        "eu-central-1_pool",
        "client-123",
        "user@example.com",
        "123456",
        "Password123!"
      )
    ).rejects.toThrow(message);
  });
});

describe("isLocalDevAuth", () => {
  it("is true only for the local-dev sentinel pool id", () => {
    expect(isLocalDevAuth("local-dev")).toBe(true);
  });

  it("is false for a real Cognito pool id", () => {
    expect(isLocalDevAuth("eu-central-1_pool")).toBe(false);
    expect(isLocalDevAuth("")).toBe(false);
  });
});

describe("devServerLogin", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("POSTs email/password to {base}/auth/login and returns tokens", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, {
        tokens: {
          accessToken: "dev-access",
          idToken: "dev-id",
          refreshToken: "dev-refresh",
        },
      })
    );

    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "Password123!")
    ).resolves.toEqual({
      tokens: {
        accessToken: "dev-access",
        idToken: "dev-id",
        refreshToken: "dev-refresh",
        expiresIn: 3600,
      },
    });

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "http://localhost:3000/auth/login",
        method: "POST",
        throw: false,
        headers: expect.objectContaining({ "Content-Type": "application/json" }),
      })
    );

    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      email: "user@example.com",
      password: "Password123!",
    });
  });

  it("strips a trailing slash from the base url", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, { tokens: { idToken: "dev-id" } })
    );

    await devServerLogin("http://localhost:3000///", "user@example.com", "pw");

    expect(mockRequestUrl.mock.calls[0]![0].url).toBe("http://localhost:3000/auth/login");
  });

  it("throws when the base url is empty", async () => {
    await expect(devServerLogin("", "user@example.com", "pw")).rejects.toThrow(
      "API endpoint must be configured for local dev login."
    );
    expect(mockRequestUrl).not.toHaveBeenCalled();
  });

  it("throws the server message on a non-2xx response", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(401, { message: "Bad credentials" })
    );

    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "pw")
    ).rejects.toThrow("Bad credentials");
  });

  it("falls back to data.Message then a default on a non-2xx response", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(500, { Message: "Boom" }));
    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "pw")
    ).rejects.toThrow("Boom");

    mockRequestUrl.mockResolvedValueOnce(jsonResponse(500, {}));
    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "pw")
    ).rejects.toThrow("Invalid email or password.");
  });

  it("throws when the dev server returns no id token", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, { tokens: { accessToken: "only-access" } })
    );

    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "pw")
    ).rejects.toThrow("Dev server did not return a valid session token.");
  });

  it("defaults accessToken to idToken and refreshToken to empty string", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(200, { tokens: { idToken: "dev-id" } })
    );

    await expect(
      devServerLogin("http://localhost:3000", "user@example.com", "pw")
    ).resolves.toEqual({
      tokens: {
        accessToken: "dev-id",
        idToken: "dev-id",
        refreshToken: "",
        expiresIn: 3600,
      },
    });
  });
});

describe("vaultguardForgotPassword", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("POSTs {email,clientId} to /auth/forgot-password and resolves on 2xx", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, {}));

    await expect(
      vaultguardForgotPassword("http://localhost:3000", "client-123", "user@example.com")
    ).resolves.toBeUndefined();

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "http://localhost:3000/auth/forgot-password",
        method: "POST",
        throw: false,
      })
    );
    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      email: "user@example.com",
      clientId: "client-123",
    });
  });

  it("throws when the base url is empty", async () => {
    await expect(
      vaultguardForgotPassword("", "client-123", "user@example.com")
    ).rejects.toThrow("API endpoint must be configured to reset your password.");
  });

  it("maps a 429 to a rate-limit message", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(429, {}));
    await expect(
      vaultguardForgotPassword("http://localhost:3000", "client-123", "user@example.com")
    ).rejects.toThrow("Too many attempts. Please wait before trying again.");
  });

  it("maps a LimitExceeded __type to a rate-limit message", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(400, { __type: "LimitExceededException" })
    );
    await expect(
      vaultguardForgotPassword("http://localhost:3000", "client-123", "user@example.com")
    ).rejects.toThrow("Too many attempts. Please wait before trying again.");
  });

  it("surfaces the server message for other failures", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(500, { message: "Server down" }));
    await expect(
      vaultguardForgotPassword("http://localhost:3000", "client-123", "user@example.com")
    ).rejects.toThrow("Server down");
  });
});

describe("vaultguardConfirmReset", () => {
  beforeEach(() => {
    mockRequestUrl.mockReset();
  });

  it("POSTs {email,code,newPassword,clientId} to /auth/confirm-reset and resolves on 2xx", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(200, {}));

    await expect(
      vaultguardConfirmReset(
        "http://localhost:3000",
        "client-123",
        "user@example.com",
        "123456",
        "Password123!"
      )
    ).resolves.toBeUndefined();

    expect(mockRequestUrl).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "http://localhost:3000/auth/confirm-reset",
        method: "POST",
        throw: false,
      })
    );
    expect(JSON.parse(mockRequestUrl.mock.calls[0]![0].body as string)).toEqual({
      email: "user@example.com",
      code: "123456",
      newPassword: "Password123!",
      clientId: "client-123",
    });
  });

  it("throws when the base url is empty", async () => {
    await expect(
      vaultguardConfirmReset("", "client-123", "user@example.com", "123456", "pw")
    ).rejects.toThrow("API endpoint must be configured to reset your password.");
  });

  it("maps a CodeMismatch __type to an invalid-code message", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(500, { __type: "CodeMismatchException" })
    );
    await expect(
      vaultguardConfirmReset(
        "http://localhost:3000",
        "client-123",
        "user@example.com",
        "123456",
        "pw"
      )
    ).rejects.toThrow("Invalid or expired reset code. Please check and try again.");
  });

  it("maps a 400 status to an invalid-code message", async () => {
    mockRequestUrl.mockResolvedValueOnce(jsonResponse(400, {}));
    await expect(
      vaultguardConfirmReset(
        "http://localhost:3000",
        "client-123",
        "user@example.com",
        "123456",
        "pw"
      )
    ).rejects.toThrow("Invalid or expired reset code. Please check and try again.");
  });

  it("maps an InvalidPassword __type to a password-policy message", async () => {
    mockRequestUrl.mockResolvedValueOnce(
      jsonResponse(500, { __type: "InvalidPasswordException" })
    );
    await expect(
      vaultguardConfirmReset(
        "http://localhost:3000",
        "client-123",
        "user@example.com",
        "123456",
        "weak"
      )
    ).rejects.toThrow(
      "Password must be 12+ characters with uppercase, lowercase, numbers, and symbols."
    );
  });
});
