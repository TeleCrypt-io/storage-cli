import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const REPO_ROOT = process.cwd();
const TSX_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "tsx");
const CLI_ENTRY = path.join(REPO_ROOT, "src", "index.ts");

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
}

/** Spawns the CLI as a genuinely separate OS process (child_process.spawn),
 * never in-process — this is what the cross-process persistence proof and
 * every other CLI test scenario depend on. */
export function runCli(
  args: string[],
  env: Record<string, string>,
  options: RunCliOptions = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(TSX_BIN, [CLI_ENTRY, ...args], {
      env: { ...process.env, ...env },
      cwd: REPO_ROOT,
    });
    let abortReason: Error | undefined;
    let forceKill: ReturnType<typeof setTimeout> | undefined;
    const requestAbort = () => {
      const reason = options.abortSignal?.reason;
      abortReason = reason instanceof Error ? reason : new Error("CLI test orchestration aborted");
      child.kill("SIGTERM");
      forceKill = setTimeout(() => child.kill("SIGKILL"), 5_000);
    };
    if (options.abortSignal?.aborted) requestAbort();
    options.abortSignal?.addEventListener("abort", requestAbort, { once: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString();
      options.onStderr?.(stderr);
    });
    child.stdin.end(options.stdin ?? "");
    child.on("error", (err) => {
      if (forceKill) clearTimeout(forceKill);
      options.abortSignal?.removeEventListener("abort", requestAbort);
      reject(abortReason ?? err);
    });
    child.on("close", (code) => {
      if (forceKill) clearTimeout(forceKill);
      options.abortSignal?.removeEventListener("abort", requestAbort);
      if (abortReason) {
        reject(abortReason);
      } else {
        resolve({ code: code ?? -1, stdout, stderr });
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
export function freshProfileDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `telecrypt-io-storage-${prefix}-`));
}
