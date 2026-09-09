import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { main } from "../src/index.js";
import { sessionPath, writeSession } from "../src/profile.js";

const originalHome = process.env.TELECRYPT_IO_STORAGE_HOME;
const originalExitCode = process.exitCode;
const directories: string[] = [];

function fixtureDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-cli-runtime-test-"));
  directories.push(directory);
  return directory;
}

afterEach(({ task }) => {
  if (originalHome === undefined) delete process.env.TELECRYPT_IO_STORAGE_HOME;
  else process.env.TELECRYPT_IO_STORAGE_HOME = originalHome;
  process.exitCode = originalExitCode;
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  if (task.result?.state === "fail") {
    process.stderr.write(
      [
        "CLI runtime unit test failed; retaining fixture directories for investigation:",
        ...pending,
      ].join("\n") + "\n",
    );
    return;
  }
  for (const directory of pending) fs.rmSync(directory, { recursive: true, force: true });
});

describe("production CLI runtime", () => {
  it("uses the fixed loopback fixture identity without runtime overrides", async () => {
    const dir = fixtureDirectory();
    writeSession(
      {
        homeserver: "http://localhost:8008",
        userId: "@fixture:localhost:8008",
        matrixServerName: "localhost:8008",
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
    console.log("preserved SDK diagnostic");

    await main(["node", "telecrypt-io", "storage", "whoami", "--json"]);

    expect(process.exitCode).toBe(0);
    expect(stderr.join("")).toContain("preserved SDK diagnostic");
    expect(fs.existsSync(sessionPath(dir))).toBe(true);
  });
});
