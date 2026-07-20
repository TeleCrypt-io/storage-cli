import type { Command } from "commander";

export interface CommandResult {
  /** Machine-readable payload for --json. */
  json: Record<string, unknown>;
  /** Human-readable text for the default (non --json) output. */
  text: string;
}

function isJsonMode(command: Command): boolean {
  return Boolean((command.optsWithGlobals() as { json?: boolean }).json);
}

/**
 * Runs a command action: executes `fn`, prints its result (JSON or human
 * text) to stdout on success, or a clean `{ "error": "..." }` (JSON mode) /
 * `Error: ...` (text mode) to stderr on failure — never a raw stack trace.
 * Sets process.exitCode accordingly (0 on success, 1 on failure) rather than
 * calling process.exit() directly, so callers can do any final cleanup
 * first.
 */
export async function runAction(
  command: Command,
  fn: () => Promise<CommandResult>,
): Promise<void> {
  const json = isJsonMode(command);
  try {
    const result = await fn();
    process.stdout.write((json ? JSON.stringify(result.json) : result.text) + "\n");
    process.exitCode = 0;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(
      (json ? JSON.stringify({ error: message }) : `Error: ${message}`) + "\n",
    );
    process.exitCode = 1;
  }
}
