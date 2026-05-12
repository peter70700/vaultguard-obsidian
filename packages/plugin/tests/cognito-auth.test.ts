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
