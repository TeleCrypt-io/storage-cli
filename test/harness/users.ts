import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Creates a disposable local MAS user. Its password exists only so the test
 * can approve an OAuth device grant through MAS's own login form; product
 * code never receives it and the harness never calls Matrix password login.
 */
export async function registerUserInMas(username: string, password: string): Promise<void> {
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
      await execFileAsync("podman", args);
      return;
    } catch (err) {
      const e = err as { stdout?: string; stderr?: string; message: string };
      const message = e.stderr || e.stdout || e.message;
      if (!message.includes("Temporary failure in name resolution") || attempt === 3) {
        throw new Error(`mas-cli register-user failed for "${username}": ${message}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
}
