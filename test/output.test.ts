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
  it("retains both operation and cleanup failures in one sanitized diagnostic", () => {
    const message = safeErrorMessage(
      new AggregateError(
        [
          new Error("upload failed\naccess_token=operation-secret"),
          new AggregateError([
            new Error("snapshot failed\trefresh_token=cleanup-secret"),
            new Error("lock failed"),
          ]),
        ],
        "storage operation and cleanup failed",
      ),
    );

    expect(message).toContain("storage operation and cleanup failed");
    expect(message).toContain("upload failed");
    expect(message).toContain("snapshot failed");
    expect(message).not.toContain("operation-secret");
    expect(message).not.toContain("cleanup-secret");
    expect(message).not.toMatch(/[\r\n\t]/u);
  });
  it("retains nested aggregate diagnostics", () => {
    let failure: Error = new Error("leaf failure");
    for (let depth = 0; depth < 20; depth += 1) {
      failure = new AggregateError([failure], `level ${depth}`);
    }
    expect(safeErrorMessage(failure)).toContain("leaf failure");
    expect(safeErrorMessage(failure)).not.toContain("additional failures omitted");
  });
  it("retains error names, stacks, causes, and aggregate children", () => {
    const cause = new Error("transport failure");
    cause.name = "TransportError";
    cause.stack = "TransportError: transport failure\n    at transport";
    const failure = new Error("operation failure", { cause });
    failure.name = "OperationError";
    failure.stack = "OperationError: operation failure\n    at operation";
    const message = safeErrorMessage(
      new AggregateError([failure, new Error("cleanup failure")], "operation and cleanup failed"),
    );

    expect(message).toContain("AggregateError: operation and cleanup failed");
    expect(message).toContain("OperationError: operation failure");
    expect(message).toContain("cause: TransportError: transport failure");
    expect(message).toContain("stack: OperationError: operation failure");
    expect(message).toContain("aggregate child 1: Error: cleanup failure");
  });
  it("retains every aggregate diagnostic", () => {
    const failures = Array.from({ length: 100 }, (_, index) => new Error(`failure ${index}`));
    const message = safeErrorMessage(new AggregateError(failures, "many failures"));
    expect(message).toContain("failure 0");
    expect(message).toContain("failure 99");
    expect(message).not.toContain("additional failures omitted");
  });
  it("retains formatter failures while rendering diagnostics", () => {
    const causeFailure = new Error("cause formatter failed");
    const failure = new Error("operation failed");
    Object.defineProperty(failure, "cause", {
      configurable: true,
      get: () => {
        throw causeFailure;
      },
    });

    const message = safeErrorMessage(failure);

    expect(message).toContain("cause formatter failed");
    expect(message).toContain("cause unavailable");
  });
  it("retains recursive own properties of ordinary thrown objects", () => {
    const symbol = Symbol("diagnostic detail");
    const failure: Record<PropertyKey, unknown> = {
      visible: { nested: "detail\nwith-control" },
      access_token: "must-not-appear",
    };
    failure[symbol] = "symbol detail";
    failure["self"] = failure;

    const message = safeErrorMessage(failure);

    expect(message).toContain("visible");
    expect(message).toContain("nested");
    expect(message).toContain("detail with-control");
    expect(message).toContain("Symbol(diagnostic detail)");
    expect(message).toContain("symbol detail");
    expect(message).toContain("[cyclic diagnostic]");
    expect(message).not.toContain("must-not-appear");
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
