import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { main } from "../src/index.js";
import { sessionPath, writeSession } from "../src/profile.js";

const originalHome = process.env.TELECRYPT_IO_STORAGE_HOME;
const originalExitCode = process.exitCode;

afterEach(() => {
  if (originalHome === undefined) delete process.env.TELECRYPT_IO_STORAGE_HOME;
  else process.env.TELECRYPT_IO_STORAGE_HOME = originalHome;
  process.exitCode = originalExitCode;
  vi.restoreAllMocks();
});

describe("production CLI runtime", () => {
  it("uses the fixed loopback fixture identity without runtime overrides", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-cli-runtime-test-"));
    try {
      writeSession(
        {
          homeserver: "http://localhost:8008",
          userId: "@fixture:example.test",
          matrixServerName: "example.test",
          deviceId: "DEVICE",
          accessToken: "access-token",
          oidcIssuer: "http://localhost:8008/",
          refreshToken: "refresh-token",
          oidcClientId: "client",
          oidcTokenEndpoint: "http://localhost:8008/token",
        },
        dir,
      );
      process.env.TELECRYPT_IO_STORAGE_HOME = dir;
      const stderr: string[] = [];
      vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array, callback?: () => void) => {
        stderr.push(String(chunk));
        callback?.();
        return true;
      }) as typeof process.stderr.write);

      await main(["node", "telecrypt-io", "storage", "whoami", "--json"]);

      expect(process.exitCode).toBe(0);
      expect(stderr.join("")).toBe("");
      expect(fs.existsSync(sessionPath(dir))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
