import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const REPO_ROOT = process.cwd();
const TSX_BIN = path.join(REPO_ROOT, "node_modules", ".bin", "tsx");
const CLI_ENTRY = path.join(REPO_ROOT, "src", "cli", "index.ts");

export interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Spawns the CLI as a genuinely separate OS process (child_process.spawn),
 * never in-process — this is what the cross-process persistence proof and
 * every other CLI test scenario depend on. */
export function runCli(args: string[], env: Record<string, string>): Promise<CliResult> {
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
  });
}

/** Runs the CLI with --json and parses stdout as JSON. Throws with full
 * stdout/stderr context (never silently swallowed) if stdout wasn't valid
 * JSON — a corrupted stdout contract (e.g. stray SDK log lines) is itself a
 * bug worth surfacing loudly, not a thing to work around in the test. */
export async function cliJson(
  args: string[],
  env: Record<string, string>,
): Promise<{ code: number; json: Record<string, unknown>; stderr: string; stdout: string }> {
  const result = await runCli([...args, "--json"], env);
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
