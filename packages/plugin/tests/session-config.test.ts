import { describe, expect, it } from "vitest";

import { deriveConnectionConfigFromTokenPayload } from "../src/plugin/session-config";

describe("deriveConnectionConfigFromTokenPayload", () => {
  it("extracts org, slug, pool, and client info from Cognito claims", () => {
    expect(
      deriveConnectionConfigFromTokenPayload(
        {
          iss: "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_EXAMPLE123",
          aud: "exampleclientid123",
          "custom:org": "org-example-123",
          "cognito:groups": ["org-acme", "admin"],
        },
        []
      )
    ).toEqual({
      organizationId: "org-example-123",
      orgSlug: "acme",
      cognitoUserPoolId: "eu-central-1_EXAMPLE123",
      cognitoClientId: "exampleclientid123",
    });
  });

  it("falls back to explicit roles when groups are unavailable", () => {
    expect(
      deriveConnectionConfigFromTokenPayload(
        {
          iss: "https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_EXAMPLE123/",
          aud: "client-123",
        },
        ["owner", "org-acme-corp"]
      )
    ).toEqual({
      organizationId: undefined,
      orgSlug: "acme-corp",
      cognitoUserPoolId: "eu-central-1_EXAMPLE123",
      cognitoClientId: "client-123",
    });
  });
});
