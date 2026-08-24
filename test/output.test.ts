import { describe, expect, it } from "vitest";
import { safeErrorMessage, safeOutputField } from "../src/output.js";

describe("CLI diagnostics", () => {
  it("escapes controls in human-output fields", () => {
    expect(safeOutputField("name\nnext\tvalue\u0000\u0085\u2028")).toBe(
      "name\\x0anext\\x09value\\x00\\x85\\x2028",
    );
  });
  it("keeps diagnostics on one physical line", () => {
    expect(safeErrorMessage("first\u0085second\u2028third\u2029fourth")).toBe("first second third fourth");
  });
  it("redacts JSON-style token, credential, and identifier fields", () => {
    const message = safeErrorMessage(
      '{"access_token":"access-secret","refresh_token":"refresh-secret","client_id":"client-secret","user_id":"@alice:example.test","device_id":"DEVICE-SECRET","password":"password-secret"} Bearer bearer-secret token=plain-secret',
    );

    expect(message).not.toContain("access-secret");
    expect(message).not.toContain("refresh-secret");
    expect(message).not.toContain("client-secret");
    expect(message).not.toContain("@alice:example.test");
    expect(message).not.toContain("DEVICE-SECRET");
    expect(message).not.toContain("password-secret");
    expect(message).not.toContain("bearer-secret");
    expect(message).not.toContain("plain-secret");
    expect(message).toContain("<redacted>");
  });

  it("redacts camel-case and escaped JSON-quoted secret fields", () => {
    const message = safeErrorMessage(
      '{"accessToken":"access-secret","refreshToken":"refresh-secret","clientId":"client-secret","deviceId":"device-secret","authorizationCode":"auth-secret","apiKey":"api-secret"}',
    );
    expect(message).not.toMatch(/access-secret|refresh-secret|client-secret|device-secret|auth-secret|api-secret/u);
    expect(message.match(/<redacted>/gu)?.length).toBe(6);
  });

  it("redacts client secrets and generic token fields in structured errors", () => {
    const message = safeErrorMessage('{"client_secret":"client-secret","token":"bearer-secret","private_key":"private-secret"}');
    const escaped = safeErrorMessage(String.raw`{\"client_secret\":\"escaped-secret\"}`);

    expect(message).not.toMatch(/client-secret|bearer-secret|private-secret/u);
    expect(message.match(/<redacted>/gu)?.length).toBe(3);
    expect(escaped).not.toContain("escaped-secret");
  });
});
