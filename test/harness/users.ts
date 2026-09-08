import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { safeErrorMessage } from "../../src/output.js";

const execFileAsync = promisify(execFile);

/**
 * Creates a disposable local MAS user. Its password exists only so the test
 * can approve an OAuth device grant through MAS's own login form; product
 * code never receives it and the harness never calls Matrix password login.
 */
export async function registerUserInMas(username: string, password: string): Promise<void> {
  const diagnostic = (value: unknown): string => {
    let text = safeErrorMessage(value);
    for (const secret of [password, username]) {
      if (secret) text = text.split(secret).join("<redacted>");
    }
    return text;
  };
  const args = [
    "exec",
    "throwaway-mas",
    "mas-cli",
    "manage",
    "register-user",
    username,
    "--password",
    password,
    "--yes",
    "--ignore-password-complexity",
    "-c",
    "/data/config.yaml",
  ];

  // Immediately after the disposable stack starts, MAS can briefly fail to
  // resolve its Postgres hostname. Retry only that transient failure; all
  // other registration errors remain immediate failures.
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const result = await execFileAsync("podman", args, {
        timeout: 30_000,
        maxBuffer: Number.POSITIVE_INFINITY,
      });
      process.stdout.write(diagnostic(result.stdout));
      process.stderr.write(diagnostic(result.stderr));
      return;
    } catch (err) {
      const e = err as { stdout?: unknown; stderr?: unknown };
      const output = [e.stderr, e.stdout].filter((value): value is string => typeof value === "string").join("\n");
      const detail = diagnostic(err);
      process.stderr.write(`${detail}\n`);
      if (!output.includes("Temporary failure in name resolution") || attempt === 3) {
        throw new Error(`mas-cli register-user failed: ${detail}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}
