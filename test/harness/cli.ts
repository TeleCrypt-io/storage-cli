import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { safeErrorMessage } from "../../src/output.js";

const REPO_ROOT = process.cwd();
const TSX_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "tsx");
const CLI_ENTRY = path.join(REPO_ROOT, "test", "harness", "cliEntry.ts");
const INSTALLED_CLI = process.env.TELECRYPT_IO_STORAGE_TEST_CLI_BIN;
const MAX_CLI_OUTPUT_BYTES = 256 * 1024;

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
  return safeErrorMessage(value);
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
    const executable = INSTALLED_CLI ?? TSX_BIN;
    const executableArgs = INSTALLED_CLI ? args : [CLI_ENTRY, ...args];
    const child = spawn(executable, executableArgs, {
      env: minimalEnvironment(env),
      cwd: REPO_ROOT,
    });
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
    const append = (current: string, chunk: Buffer): string => {
      const next = current + chunk.toString();
      if (Buffer.byteLength(next, "utf8") > MAX_CLI_OUTPUT_BYTES) {
        requestAbort(new Error(`CLI test subprocess exceeded the ${MAX_CLI_OUTPUT_BYTES}-byte output limit`));
        return current;
      }
      return next;
    };
    child.stdout.on("data", (d: Buffer) => (stdout = append(stdout, d)));
    child.stderr.on("data", (d: Buffer) => {
      stderr = append(stderr, d);
      options.onStderr?.(sanitizeOutput(stderr));
    });
    child.stdin.end(options.stdin ?? "");
    child.on("error", (err) => {
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      options.abortSignal?.removeEventListener("abort", requestAbort);
      reject(abortReason ?? err);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      options.abortSignal?.removeEventListener("abort", requestAbort);
      if (abortReason) {
        reject(abortReason);
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

/** Runs the CLI with --json and parses stdout as JSON. Throws with full
 * stdout/stderr context (never silently swallowed) if stdout wasn't valid
 * JSON — a corrupted stdout contract (e.g. stray SDK log lines) is itself a
 * bug worth surfacing loudly, not a thing to work around in the test. */
export async function cliJson(
  args: string[],
  env: Record<string, string>,
  options: RunCliOptions = {},
): Promise<{ code: number; json: Record<string, unknown>; stderr: string; stdout: string }> {
  const result = await runCli([...args, "--json"], env, options);
  // On success the JSON payload is on stdout; on failure it's the
  // `{ "error": "..." }` object on stderr (see output.ts) — parse whichever
  // stream the CLI actually used, per its own contract.
  const source = result.code === 0 ? result.stdout : result.stderr;
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(source.trim());
  } catch {
    throw new Error(
      `CLI output was not valid JSON (exit ${result.code})\n` +
        `args: ${JSON.stringify(args)}\nstdout: ${JSON.stringify(result.stdout)}\nstderr: ${JSON.stringify(result.stderr)}`,
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

/** Records a profile whose successful OIDC login created remote state. */
export function markProfileForRemoteCleanup(dir: string): void {
  remotelyOwnedProfiles.add(dir);
}

/** Removes every profile created by this test worker, including profiles from
 * tests that failed partway through setup. */
export async function cleanupFreshProfiles(): Promise<void> {
  const failures: string[] = [];
  const cleaned = new Set<string>();
  for (const dir of freshProfiles) {
    let remoteCleanupSucceeded = true;
    const hasRemoteSession =
      fs.existsSync(path.join(dir, "session.json")) || fs.existsSync(path.join(dir, "login-pending.json"));
    if (remotelyOwnedProfiles.has(dir) && hasRemoteSession) {
      try {
        const result = await runCli(["storage", "logout", "--json"], {
          TELECRYPT_IO_STORAGE_HOME: dir,
        }, { timeoutMs: 20_000 });
        if (result.code !== 0) {
          remoteCleanupSucceeded = false;
          failures.push(`${dir}: remote logout did not complete`);
        }
      } catch {
        remoteCleanupSucceeded = false;
        failures.push(`${dir}: remote logout could not be attempted`);
      }
    }
    // Preserve bearer state when revocation was not confirmed so teardown can
    // be retried instead of silently orphaning remote state.
    if (!remoteCleanupSucceeded) continue;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      cleaned.add(dir);
    } catch {
      failures.push(dir);
    }
  }
  for (const dir of cleaned) {
    freshProfiles.delete(dir);
    remotelyOwnedProfiles.delete(dir);
  }
  if (failures.length > 0) {
    throw new Error(`failed to remove ${failures.length} temporary CLI profile(s)`);
  }
}
