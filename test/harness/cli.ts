import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { StringDecoder } from "node:string_decoder";
import { safeErrorMessage } from "../../src/output.js";

const REPO_ROOT = process.cwd();
const TSX_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "tsx");
const CLI_ENTRY = path.join(REPO_ROOT, "test", "harness", "cliEntry.ts");
const INSTALLED_CLI = process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN;

function minimalEnvironment(overrides: Record<string, string>): NodeJS.ProcessEnv {
  const inherited: NodeJS.ProcessEnv = {};
  for (const name of ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "TERM"]) {
    const value = process.env[name];
    if (value !== undefined) inherited[name] = value;
  }
  return {
    ...inherited,
    ...overrides,
  };
}

function sanitizeOutput(value: string): string {
  return value
    .split(/\r?\n/u)
    .map((line) => safeErrorMessage(line))
    .join("\n");
}

function parseJsonLine(stream: string): Record<string, unknown> {
  const lines = stream.trim().split(/\r?\n/u).filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const parsed: unknown = JSON.parse(lines[index]);
      if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // Diagnostics may precede the final machine-readable error line.
    }
  }
  throw new SyntaxError("stream did not contain a JSON object line");
}

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunCliOptions {
  /** Test-only streaming observation, used to approve a local MAS device
   * grant after the real CLI prints its verification code. */
  onStderr?: (stderr: string) => void;
  /** Explicit stdin for commands that intentionally read it. */
  stdin?: string;
  /** Stops the child if test-only orchestration (such as local MAS approval)
   * fails. The child is waited for so it cannot leak into a later scenario. */
  abortSignal?: AbortSignal;
  /** Bounds every CLI subprocess, including failures where the child never
   * reaches its normal close path. */
  timeoutMs?: number;
}

interface CliOutputCapture {
  directory: string;
  stdout: number;
  stderr: number;
  status: number;
  failures: unknown[];
  finalized: boolean;
}

function createOutputCapture(): CliOutputCapture {
  const configuredRoot = process.env.HARNESS_ARTIFACTS_ROOT;
  const root = configuredRoot ?? os.tmpdir();
  let directory: string | undefined;
  const descriptors: number[] = [];
  try {
    directory = fs.mkdtempSync(path.join(root, "cli-subprocess-"));
    fs.chmodSync(directory, 0o700);
    const open = (name: string): number => {
      const descriptor = fs.openSync(
        path.join(directory!, name),
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
        0o600,
      );
      descriptors.push(descriptor);
      return descriptor;
    };
    const capture = {
      directory,
      stdout: open("stdout"),
      stderr: open("stderr"),
      status: open("status"),
      failures: [],
      finalized: false,
    } satisfies CliOutputCapture;
    return capture;
  } catch (error) {
    const cleanupFailures: unknown[] = [];
    for (const descriptor of descriptors) {
      try {
        fs.closeSync(descriptor);
      } catch (closeError) {
        cleanupFailures.push(new Error("CLI subprocess output capture setup close failed", { cause: closeError }));
      }
    }
    const setupFailure = new Error(
      `CLI subprocess output capture setup failed${directory ? ` at ${directory}` : ""}`,
      { cause: error },
    );
    throw cleanupFailures.length > 0
      ? new AggregateError([setupFailure, ...cleanupFailures], "CLI subprocess output capture setup failed")
      : setupFailure;
  }
}

function writeCaptureBytes(descriptor: number, chunk: Buffer): void {
  let offset = 0;
  while (offset < chunk.byteLength) {
    const written = fs.writeSync(descriptor, chunk, offset, chunk.byteLength - offset);
    if (written <= 0) throw new Error("capture write made no progress");
    offset += written;
  }
}

function captureWrite(capture: CliOutputCapture, descriptor: number, stream: string, chunk: Buffer): Error | undefined {
  try {
    writeCaptureBytes(descriptor, chunk);
  } catch (error) {
    const failure = new Error(`CLI subprocess ${stream} capture write failed`, { cause: error });
    capture.failures.push(failure);
    return failure;
  }
  return undefined;
}

function captureFinalize(capture: CliOutputCapture, code: number | null, signal: NodeJS.Signals | null): unknown[] {
  if (capture.finalized) return capture.failures;
  capture.finalized = true;
  try {
    writeCaptureBytes(
      capture.status,
      Buffer.from(`code=${code === null ? "null" : code}\nsignal=${signal ?? ""}\n`, "utf8"),
    );
  } catch (error) {
    capture.failures.push(new Error("CLI subprocess status capture write failed", { cause: error }));
  }
  for (const [stream, descriptor] of [["stdout", capture.stdout], ["stderr", capture.stderr], ["status", capture.status]] as const) {
    try {
      fs.closeSync(descriptor);
    } catch (error) {
      capture.failures.push(new Error(`CLI subprocess ${stream} capture close failed`, { cause: error }));
    }
  }
  return capture.failures;
}

function combineCaptureFailures(primary: unknown | undefined, failures: readonly unknown[]): unknown | undefined {
  const distinctFailures = failures.filter((failure, index) =>
    failure !== primary && failures.indexOf(failure) === index,
  );
  if (distinctFailures.length === 0) return primary;
  if (primary === undefined) {
    return distinctFailures.length === 1
      ? distinctFailures[0]
      : new AggregateError(distinctFailures, "CLI subprocess output capture failed");
  }
  return new AggregateError([primary, ...distinctFailures], "CLI subprocess and output capture failed");
}

function captureFailureContext(
  capture: CliOutputCapture,
  failure: unknown,
  stdout: string,
  stderr: string,
): Error {
  return new Error(
    `CLI subprocess output capture failed at ${capture.directory}\n` +
      `stdout:\n${sanitizeOutput(stdout)}\n` +
      `stderr:\n${sanitizeOutput(stderr)}`,
    { cause: failure },
  );
}

/** Spawns the CLI as a genuinely separate OS process (child_process.spawn),
 * never in-process — this is what the cross-process persistence proof and
 * every other CLI test scenario depend on. */
export function runCli(
  args: string[],
  env: Record<string, string>,
  options: RunCliOptions = {},
): Promise<CliResult> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return Promise.reject(new Error("CLI test timeout must be a positive finite number"));
  }
  return new Promise((resolve, reject) => {
    let capture: CliOutputCapture;
    try {
      capture = createOutputCapture();
    } catch (error) {
      reject(error);
      return;
    }
    const executable = INSTALLED_CLI ?? TSX_BIN;
    let child: ChildProcessWithoutNullStreams;
    try {
      const executableArgs = INSTALLED_CLI ? args : [CLI_ENTRY, ...args];
      child = spawn(executable, executableArgs, {
        env: minimalEnvironment(env),
        cwd: REPO_ROOT,
      });
    } catch (error) {
      const captureFailures = captureFinalize(capture, null, null);
      reject(combineCaptureFailures(error, captureFailures));
      return;
    }
    let abortReason: Error | undefined;
    let forceKill: ReturnType<typeof setTimeout> | undefined;
    const requestAbort = (reason?: unknown) => {
      if (abortReason) return;
      // AbortSignal listeners receive an Event as their first argument; use
      // the signal's actual reason in that case. Direct callers (the timeout
      // below) pass the Error they want propagated explicitly.
      const abortValue = reason instanceof Error ? reason : options.abortSignal?.reason;
      abortReason =
        abortValue instanceof Error ? abortValue : new Error("CLI test orchestration aborted");
      child.kill("SIGTERM");
      forceKill = setTimeout(() => child.kill("SIGKILL"), 5_000);
    };
    const timeout = setTimeout(
      () => requestAbort(new Error(`CLI test subprocess timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    if (options.abortSignal?.aborted) requestAbort();
    options.abortSignal?.addEventListener("abort", requestAbort, { once: true });
    let stdout = "";
    let stderr = "";
    const stdoutDecoder = new StringDecoder("utf8");
    const stderrDecoder = new StringDecoder("utf8");
    let childError: unknown;
    let finished = false;
    const append = (stream: "stdout" | "stderr", chunk: Buffer): void => {
      const captureFailure = captureWrite(capture, capture[stream], stream, chunk);
      if (captureFailure) requestAbort(captureFailure);
      const decoded = (stream === "stdout" ? stdoutDecoder : stderrDecoder).write(chunk);
      if (stream === "stdout") {
        stdout += decoded;
      } else {
        stderr += decoded;
        options.onStderr?.(sanitizeOutput(stderr));
      }
    };
    child.stdout.on("data", (d: Buffer) => append("stdout", d));
    child.stderr.on("data", (d: Buffer) => {
      append("stderr", d);
    });
    child.stdin.end(options.stdin ?? "");
    child.on("error", (err) => {
      childError = err;
    });
    child.on("close", (code, signal) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      options.abortSignal?.removeEventListener("abort", requestAbort);
      stdout += stdoutDecoder.end();
      const finalStderr = stderrDecoder.end();
      if (finalStderr) {
        stderr += finalStderr;
        options.onStderr?.(sanitizeOutput(stderr));
      }
      const captureFailures = captureFinalize(capture, code, signal);
      const primary = abortReason ?? childError;
      const processFailure = primary ?? (captureFailures.length > 0 && (code ?? -1) !== 0
        ? new Error(`CLI test subprocess exited ${code ?? -1}${signal ? ` (${signal})` : ""}`)
        : undefined);
      const combinedFailure = combineCaptureFailures(processFailure, captureFailures);
      if (combinedFailure) {
        reject(captureFailures.length > 0
          ? captureFailureContext(capture, combinedFailure, stdout, stderr)
          : combinedFailure);
      } else {
        // Successful stdout is the artifact under test: redacting identity
        // fields here made sharing tests pass redaction placeholders instead
        // of the actual MXID. Diagnostics remain sanitized.
        resolve({
          code: code ?? -1,
          stdout: code === 0 ? stdout : sanitizeOutput(stdout),
          stderr: sanitizeOutput(stderr),
        });
      }
    });
  });
}

/** Runs the CLI with --json and parses its machine-readable result. Successful
 * stdout is one JSON line; failure stderr may also contain diagnostics, so the
 * final JSON object line is the command result. */
export async function cliJson(
  args: string[],
  env: Record<string, string>,
  options: RunCliOptions = {},
): Promise<{ code: number; json: Record<string, unknown>; stderr: string; stdout: string }> {
  const result = await runCli([...args, "--json"], env, options);
  // On success the JSON payload is on stdout; on failure the final JSON object
  // line is on stderr (see output.ts), after any preserved diagnostics.
  const source = result.code === 0 ? result.stdout : result.stderr;
  let json: Record<string, unknown>;
  try {
    json = parseJsonLine(source);
  } catch (error) {
    throw new Error(
      `CLI output was not valid JSON (exit ${result.code})\n` +
        `args: ${JSON.stringify(args)}\nstdout: ${JSON.stringify(result.stdout)}\nstderr: ${JSON.stringify(result.stderr)}`,
      { cause: error },
    );
  }
  return { code: result.code, json, stderr: result.stderr, stdout: result.stdout };
}

/** A fresh, isolated profile directory for one simulated user/device. */
const freshProfiles = new Set<string>();
const remotelyOwnedProfiles = new Set<string>();

export function freshProfileDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `telecrypt-io-storage-${prefix}-`));
  freshProfiles.add(dir);
  return dir;
}

/** Returns every profile created by this test worker, including profiles from
 * scenarios that failed before remote cleanup could be attempted. */
export function freshProfilePaths(): string[] {
  return [...freshProfiles];
}

/** Records a profile whose successful OIDC login created remote state. */
export function markProfileForRemoteCleanup(dir: string): void {
  remotelyOwnedProfiles.add(dir);
}

/** Removes profiles after a successful functional run or explicit
 * post-investigation cleanup. A cleanup failure stops here so the current and
 * remaining profiles stay available for investigation. */
export async function cleanupFreshProfiles(): Promise<void> {
  for (const dir of freshProfiles) {
    const hasRemoteSession =
      fs.existsSync(path.join(dir, "session.json")) || fs.existsSync(path.join(dir, "login-pending.json"));
    if (remotelyOwnedProfiles.has(dir) && hasRemoteSession) {
      let result: CliResult;
      try {
        result = await runCli(["storage", "logout", "--json"], {
          TELECRYPT_IO_STORAGE_HOME: dir,
        }, { timeoutMs: 20_000 });
      } catch (error) {
        throw new Error(
          `${dir}: remote logout failed: ${safeErrorMessage(error)}`,
          { cause: error },
        );
      }
      if (result.code !== 0) {
        throw new Error(
          `${dir}: remote logout exited ${result.code}\n` +
            `stdout:\n${result.stdout}\n` +
            `stderr:\n${result.stderr}`,
        );
      }
    }
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (error) {
      throw new Error(
        `${dir}: local profile removal failed: ${safeErrorMessage(error)}`,
        { cause: error },
      );
    }
    freshProfiles.delete(dir);
    remotelyOwnedProfiles.delete(dir);
  }
}
