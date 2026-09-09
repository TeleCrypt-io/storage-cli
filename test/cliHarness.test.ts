import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const originalCliBinary = process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN;
process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN = process.execPath;
const { runCli } = await import("./harness/cli.js");
if (originalCliBinary === undefined) delete process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN;
else process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN = originalCliBinary;

const roots: string[] = [];
const originalArtifactsRoot = process.env.HARNESS_ARTIFACTS_ROOT;

function artifactRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-cli-harness-test-"));
  fs.chmodSync(root, 0o700);
  roots.push(root);
  process.env.HARNESS_ARTIFACTS_ROOT = root;
  return root;
}

function captureDirectory(root: string): string {
  const directories = fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => path.join(root, entry.name));
  expect(directories).toHaveLength(1);
  return directories[0]!;
}

function expectPrivateCapture(directory: string): void {
  expect(fs.statSync(directory).mode & 0o777).toBe(0o700);
  for (const name of ["stdout", "stderr", "status"]) {
    expect(fs.statSync(path.join(directory, name)).mode & 0o777).toBe(0o600);
  }
}

function errorText(error: unknown, seen = new Set<unknown>()): string {
  if (seen.has(error)) return "[circular diagnostic]";
  seen.add(error);
  if (error instanceof AggregateError) {
    return [String(error), ...error.errors.map((child) => errorText(child, seen))].join(" | ");
  }
  if (error instanceof Error && error.cause !== undefined) {
    return [String(error), errorText(error.cause, seen)].join(" | ");
  }
  return String(error);
}

afterEach(({ task }) => {
  if (originalArtifactsRoot === undefined) delete process.env.HARNESS_ARTIFACTS_ROOT;
  else process.env.HARNESS_ARTIFACTS_ROOT = originalArtifactsRoot;
  vi.restoreAllMocks();
  process.stderr.write(
    `CLI harness capture test ${task.result?.state === "fail" ? "failed" : "completed"}; retaining private capture roots:\n${roots.join("\n")}\n`,
  );
});

describe("CLI subprocess output capture", () => {
  it("retains complete byte streams and status for successful and failed children", async () => {
    const root = artifactRoot();
    const success = await runCli(
      ["-e", "process.stdout.write(Buffer.from([0xe2, 0x82, 0xac])); process.stderr.write('success');"],
      {},
    );
    expect(success).toMatchObject({ code: 0, stdout: "€", stderr: "success" });
    const successCapture = captureDirectory(root);
    expectPrivateCapture(successCapture);
    expect(fs.readFileSync(path.join(successCapture, "stdout"))).toEqual(Buffer.from([0xe2, 0x82, 0xac]));
    expect(fs.readFileSync(path.join(successCapture, "stderr"), "utf8")).toBe("success");
    expect(fs.readFileSync(path.join(successCapture, "status"), "utf8")).toBe("code=0\nsignal=\n");

    const failed = await runCli(
      ["-e", "process.stdout.write('failed-out'); process.stderr.write('failed-err'); process.exitCode = 7;"],
      {},
    );
    expect(failed).toMatchObject({ code: 7, stdout: "failed-out", stderr: "failed-err" });
    const failedCapture = fs.readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, entry.name))
      .find((directory) => directory !== successCapture);
    expect(failedCapture).toBeDefined();
    expectPrivateCapture(failedCapture!);
    expect(fs.readFileSync(path.join(failedCapture!, "stdout"), "utf8")).toBe("failed-out");
    expect(fs.readFileSync(path.join(failedCapture!, "stderr"), "utf8")).toBe("failed-err");
    expect(fs.readFileSync(path.join(failedCapture!, "status"), "utf8")).toBe("code=7\nsignal=\n");
  });

  it("handles short writes without losing bytes", async () => {
    const root = artifactRoot();
    const originalWriteSync = fs.writeSync;
    vi.spyOn(fs, "writeSync").mockImplementation(((fd, data, offset, length, position) => {
      const start = typeof offset === "number" ? offset : 0;
      const requested = typeof length === "number" ? length : data.byteLength;
      return originalWriteSync(fd, data, start, Math.min(requested, 1), position ?? null);
    }) as typeof fs.writeSync);

    const result = await runCli(
      ["-e", "process.stdout.write('short-write-out'); process.stderr.write('short-write-err');"],
      {},
    );
    expect(result).toMatchObject({ code: 0, stdout: "short-write-out", stderr: "short-write-err" });
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "stdout"), "utf8")).toBe("short-write-out");
    expect(fs.readFileSync(path.join(capture, "stderr"), "utf8")).toBe("short-write-err");
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("code=0\nsignal=\n");
  });

  it("aborts on a stream capture failure while retaining earlier output and status", async () => {
    const root = artifactRoot();
    const streamFailure = new Error("simulated stdout capture write failure");
    const originalWriteSync = fs.writeSync;
    vi.spyOn(fs, "writeSync").mockImplementation(((fd, data, offset, length, position) => {
      if (Buffer.isBuffer(data) && data.toString("utf8") === "abort-out") throw streamFailure;
      return originalWriteSync(fd, data, offset, length, position);
    }) as typeof fs.writeSync);

    let failure: unknown;
    try {
      await runCli(
        [
          "-e",
          "process.stderr.write('retained-before-abort'); setTimeout(() => process.stdout.write('abort-out'), 10); setInterval(() => {}, 1000);",
        ],
        {},
      );
    } catch (error) {
      failure = error;
    }
    expect(String(failure)).toContain(root);
    expect(errorText(failure)).toContain("stdout capture write failed");
    expect(String(failure)).toContain("abort-out");
    expect(String(failure)).toContain("retained-before-abort");
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "stderr"), "utf8")).toBe("retained-before-abort");
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("code=null\nsignal=SIGTERM\n");
  });

  it("aborts on a status capture failure while retaining prior output and the primary exit", async () => {
    const root = artifactRoot();
    const statusFailure = new Error("simulated status capture write failure");
    const originalWriteSync = fs.writeSync;
    vi.spyOn(fs, "writeSync").mockImplementation(((fd, data, offset, length, position) => {
      if (Buffer.isBuffer(data) && data.toString("utf8").startsWith("code=")) throw statusFailure;
      return originalWriteSync(fd, data, offset, length, position);
    }) as typeof fs.writeSync);

    let failure: unknown;
    try {
      await runCli(
        ["-e", "process.stdout.write('retained-out'); process.stderr.write('retained-err'); process.exitCode = 7;"],
        {},
      );
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).cause).toBeInstanceOf(AggregateError);
    expect(errorText(failure)).toContain("CLI test subprocess exited 7");
    expect(errorText(failure)).toContain("status capture write failed");
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "stdout"), "utf8")).toBe("retained-out");
    expect(fs.readFileSync(path.join(capture, "stderr"), "utf8")).toBe("retained-err");
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("");
  });

  it("aggregates a descriptor close failure with a non-successful child", async () => {
    const root = artifactRoot();
    const closeFailure = new Error("simulated status capture close failure");
    const originalWriteSync = fs.writeSync;
    const originalCloseSync = fs.closeSync;
    let statusDescriptor: number | undefined;
    let closeFailureThrown = false;
    vi.spyOn(fs, "writeSync").mockImplementation(((fd, data, offset, length, position) => {
      if (Buffer.isBuffer(data) && data.toString("utf8").startsWith("code=")) statusDescriptor = fd;
      return originalWriteSync(fd, data, offset, length, position);
    }) as typeof fs.writeSync);
    vi.spyOn(fs, "closeSync").mockImplementation((fd) => {
      if (fd === statusDescriptor && !closeFailureThrown) {
        closeFailureThrown = true;
        throw closeFailure;
      }
      return originalCloseSync(fd);
    });

    let failure: unknown;
    try {
      await runCli(["-e", "process.stdout.write('close-out'); process.exitCode = 9;"], {});
    } catch (error) {
      failure = error;
    } finally {
      if (statusDescriptor !== undefined) originalCloseSync(statusDescriptor);
    }
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).cause).toBeInstanceOf(AggregateError);
    expect(errorText(failure)).toContain("CLI test subprocess exited 9");
    expect(errorText(failure)).toContain("status capture close failed");
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "stdout"), "utf8")).toBe("close-out");
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("code=9\nsignal=\n");
  });

  it("decodes split UTF-8 before notifying the streaming observer", async () => {
    const root = artifactRoot();
    const observed: string[] = [];
    const result = await runCli(
      [
        "-e",
        "process.stderr.write(Buffer.from([0xf0])); setTimeout(() => process.stderr.write(Buffer.from([0x9f, 0x8c, 0x8d])), 10);",
      ],
      {},
      { onStderr: (value) => observed.push(value) },
    );
    expect(result.stderr).toBe("🌍");
    expect(observed.at(-1)).toBe("🌍");
    const capture = captureDirectory(root);
    expectPrivateCapture(capture);
    expect(fs.readFileSync(path.join(capture, "stderr"))).toEqual(Buffer.from([0xf0, 0x9f, 0x8c, 0x8d]));
  });

  it("retains a status when a child times out", async () => {
    const root = artifactRoot();
    let failure: unknown;
    try {
      await runCli(["-e", "setInterval(() => {}, 1000);"], {}, { timeoutMs: 30 });
    } catch (error) {
      failure = error;
    }
    expect(String(failure)).toContain("timed out after 30ms");
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("code=null\nsignal=SIGTERM\n");
  });

  it("finalizes capture after a synchronous child-spawn failure", async () => {
    const root = artifactRoot();
    let failure: unknown;
    try {
      await runCli(1 as unknown as string[], {});
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(Error);
    expect(String(failure)).toContain("args");
    const capture = captureDirectory(root);
    expect(fs.readFileSync(path.join(capture, "status"), "utf8")).toBe("code=null\nsignal=\n");
  });

  it("uses a private temporary capture when no artifacts root is configured", async () => {
    const previousRoot = process.env.HARNESS_ARTIFACTS_ROOT;
    const before = new Set(
      fs.readdirSync(os.tmpdir()).filter((entry) => entry.startsWith("cli-subprocess-")),
    );
    delete process.env.HARNESS_ARTIFACTS_ROOT;
    try {
      const result = await runCli(["-e", "process.stdout.write('default-capture');"], {});
      expect(result.stdout).toBe("default-capture");
    } finally {
      if (previousRoot === undefined) delete process.env.HARNESS_ARTIFACTS_ROOT;
      else process.env.HARNESS_ARTIFACTS_ROOT = previousRoot;
      const created = fs.readdirSync(os.tmpdir())
        .filter((entry) => entry.startsWith("cli-subprocess-") && !before.has(entry))
        .map((entry) => path.join(os.tmpdir(), entry));
      roots.push(...created);
    }
    const capture = roots.at(-1);
    expect(capture).toBeDefined();
    expectPrivateCapture(capture!);
    expect(fs.readFileSync(path.join(capture!, "stdout"), "utf8")).toBe("default-capture");
  });
});
