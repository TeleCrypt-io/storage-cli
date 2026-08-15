import { describe, expect, it } from "vitest";
import { withRefreshedTokens } from "../src/storage.js";
import type { Session } from "../src/profile.js";

const SESSION: Session = {
  homeserver: "https://backend.example.test",
  userId: "@alice:example.test",
  deviceId: "DEVICE",
  accessToken: "access-original",
  refreshToken: "refresh-original",
  oidcIssuer: "https://auth.example.test",
  oidcClientId: "client",
  oidcTokenEndpoint: "https://auth.example.test/token",
};

describe("OIDC session refresh persistence", () => {
  it("keeps the latest rotated refresh token when a later refresh omits one", () => {
    const rotated = withRefreshedTokens(SESSION, {
      accessToken: "access-rotated",
      refreshToken: "refresh-rotated",
    });
    const later = withRefreshedTokens(rotated, { accessToken: "access-later" });

    expect(later).toEqual({
      ...SESSION,
      accessToken: "access-later",
      refreshToken: "refresh-rotated",
    });
  });
});
