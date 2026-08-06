import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { approveDeviceCodeViaHttp } from "./oidcApproval";

const REPO_ROOT = process.cwd();
const TSX_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "tsx");
const CLI_ENTRY = path.join(REPO_ROOT, "src", "index.ts");

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface RunCliOptions {
  /** Written to the child's stdin, then closed. Never include secrets in args. */
  stdin?: string;
}

export interface DeviceCodeApproval {
  username: string;
  password: string;
}

export interface CliJsonResult {
  code: number;
  json: Record<string, unknown>;
  stderr: string;
  stdout: string;
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
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? -1, stdout, stderr }));
    child.stdin.end(options.stdin);
  });
}

/**
 * Runs the real OAuth-only login command and approves the displayed device
 * code through the disposable MAS fixture. The helper deliberately parses
 * the CLI's human-facing stderr instead of reaching into product internals:
 * it proves the CLI emits a usable code and completes an actual device-code
 * grant. MAS credentials are test-fixture-only and never passed to the CLI.
 */
export function runCliWithDeviceCodeApproval(
  args: string[],
  env: Record<string, string>,
  approval: DeviceCodeApproval,
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(TSX_BIN, [CLI_ENTRY, ...args], {
      env: { ...process.env, ...env },
      cwd: REPO_ROOT,
    });
    let stdout = "";
    let stderr = "";
    let approvalPromise: Promise<void> | undefined;
    let approvalError: unknown;

    const approveDisplayedCode = () => {
      if (approvalPromise) return;
      const match = stderr.match(/and enter code:\s*([^\s]+)/i);
      if (!match) return;
      approvalPromise = approveDeviceCodeViaHttp(approval.username, approval.password, match[1]).catch(
        (error: unknown) => {
          approvalError = error;
          child.kill();
        },
      );
    };

    child.stdout.on("data", (data: Buffer) => (stdout += data.toString()));
    child.stderr.on("data", (data: Buffer) => {
      stderr += data.toString();
      approveDisplayedCode();
    });
    child.on("error", reject);
    child.on("close", async (code) => {
      try {
        if (approvalError) throw approvalError;
        if (!approvalPromise) {
          throw new Error(`CLI did not emit an OAuth device user code. stderr: ${JSON.stringify(stderr)}`);
        }
        await approvalPromise;
        if (approvalError) throw approvalError;
        resolve({ code: code ?? -1, stdout, stderr });
      } catch (error) {
        reject(error);
      }
    });
    child.stdin.end();
  });
}

function parseCliJsonResult(result: CliResult, args: string[]): CliJsonResult {
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

/** Runs the CLI with --json and parses its JSON output. Throws with full
 * stdout/stderr context (never silently swallowed) if the success/error JSON
 * stream is invalid — a corrupted output contract (e.g. stray SDK log lines)
 * is itself a bug worth surfacing loudly, not a thing to work around in tests. */
export async function cliJson(
  args: string[],
  env: Record<string, string>,
  options: RunCliOptions = {},
): Promise<CliJsonResult> {
  return parseCliJsonResult(await runCli([...args, "--json"], env, options), args);
}

/** JSON variant of runCliWithDeviceCodeApproval for functional CLI tests. */
export async function cliJsonWithDeviceCodeApproval(
  args: string[],
  env: Record<string, string>,
  approval: DeviceCodeApproval,
): Promise<CliJsonResult> {
  return parseCliJsonResult(
    await runCliWithDeviceCodeApproval([...args, "--json"], env, approval),
    args,
  );
}

/** A fresh, isolated profile directory for one simulated user/device. */
export function freshProfileDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `telecrypt-io-storage-${prefix}-`));
}
