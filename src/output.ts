import type { Command } from "commander";
import { cancellationExitCode, commandSignal } from "./cancellation.js";

export interface CommandResult {
  /** Machine-readable payload for --json. */
  json: Record<string, unknown>;
  /** Human-readable text for the default (non --json) output. */
  text: string;
}

const MAX_OUTPUT_BYTES = 256 * 1024;
const MAX_OUTPUT_VALUES = 100_000;
const MAX_OUTPUT_DEPTH = 32;

function assertBoundedJsonValue(value: unknown): void {
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  const seen = new WeakSet<object>();
  let values = 0;
  let stringBytes = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    values += 1;
    if (values > MAX_OUTPUT_VALUES || current.depth > MAX_OUTPUT_DEPTH) {
      throw new Error("command output exceeds the structural limit");
    }
    if (typeof current.value === "string") {
      stringBytes += Buffer.byteLength(current.value, "utf8");
      if (stringBytes > MAX_OUTPUT_BYTES) throw new Error("command output exceeds the 256 KiB limit");
      continue;
    }
    if (current.value === null || typeof current.value !== "object") continue;
    if (seen.has(current.value)) throw new Error("command output contains a circular value");
    seen.add(current.value);
    for (const [key, child] of Object.entries(current.value)) {
      stringBytes += Buffer.byteLength(key, "utf8");
      if (stringBytes > MAX_OUTPUT_BYTES) throw new Error("command output exceeds the 256 KiB limit");
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

/** Escapes control characters in untrusted values embedded in human output.
 * Deliberate line breaks in command templates remain intact because callers
 * apply this only to interpolated fields. */
export function safeOutputField(value: unknown): string {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu, (character) => {
    const code = character.codePointAt(0) ?? 0;
    return `\\x${code.toString(16).padStart(2, "0")}`;
  });
}

function isJsonMode(command: Command): boolean {
  return Boolean((command.optsWithGlobals() as { json?: boolean }).json);
}

function writeLine(stream: NodeJS.WriteStream, line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error) => {
      stream.off("error", onError);
      reject(error);
    };
    stream.once("error", onError);
    stream.write(`${line}\n`, () => {
      stream.off("error", onError);
      resolve();
    });
  });
}

export function safeErrorMessage(error: unknown): string {
  const message = (error instanceof Error ? error.message : String(error)).replace(/\\(["'])/gu, "$1");
  const secretField = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?id|client[_-]?secret|user[_-]?id|device[_-]?id|authorization(?:[_-]?code)?|device[_-]?code|user[_-]?code|code[_-]?verifier|token|credential[s]?|private[_-]?key|(?:encryption|signing|password|secret|api[_-]?key|recovery[_-]?key|cookie|session)(?:[_-]?token|[_-]?key)?)$/iu;
  const quotedValue = `"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,}\\]]+`;
  const sanitized = message
    .replace(/(Bearer\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',}]+)/giu, "$1<redacted>")
    .replace(
      new RegExp(`(["'])([^"']+)\\1(\\s*[:=]\\s*)(${quotedValue})`, "giu"),
      (whole, quote: string, key: string, separator: string) =>
        secretField.test(key.replace(/\\(["'])/gu, "$1"))
          ? `${quote}${key}${quote}${separator}"<redacted>"`
          : whole,
    )
    .replace(
      new RegExp(`\\b([A-Za-z][A-Za-z0-9_-]*)\\b(\\s*[:=]\\s*)(${quotedValue})`, "giu"),
      (whole, key: string, separator: string) =>
        secretField.test(key) ? `${key}${separator}"<redacted>"` : whole,
    )
    .replace(/[\r\n\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu, " ")
    .trim();
  const bytes = Buffer.from(sanitized, "utf8");
  return bytes.length <= 4096 ? sanitized : `${bytes.subarray(0, 4096).toString("utf8")}…`;
}

/**
 * Runs a command action: executes `fn`, prints its result (JSON or human
 * text) to stdout on success, or a clean `{ "error": "..." }` (JSON mode) /
 * `Error: ...` (text mode) to stderr on failure — never a raw stack trace.
 * Sets process.exitCode accordingly (including the conventional 128+signal
 * code after cancellation) rather than terminating the process directly, so
 * callers can do any final cleanup first.
 */
export async function runAction(
  command: Command,
  fn: (signal: AbortSignal) => Promise<CommandResult>,
): Promise<void> {
  const json = isJsonMode(command);
  try {
    const result = await fn(commandSignal);
    assertBoundedJsonValue(result.json);
    if (Buffer.byteLength(result.text, "utf8") > MAX_OUTPUT_BYTES) {
      throw new Error("command output exceeds the 256 KiB limit");
    }
    const rendered = json ? JSON.stringify(result.json) : result.text;
    const safeRendered = rendered.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/gu, "?");
    if (Buffer.byteLength(safeRendered, "utf8") > MAX_OUTPUT_BYTES) {
      throw new Error("command output exceeds the 256 KiB limit");
    }
    await writeLine(process.stdout, safeRendered);
    process.exitCode = cancellationExitCode() ?? 0;
  } catch (err) {
    const message = safeErrorMessage(err);
    await writeLine(process.stderr, json ? JSON.stringify({ error: message }) : `Error: ${message}`);
    process.exitCode = cancellationExitCode() ?? 1;
  }
}
