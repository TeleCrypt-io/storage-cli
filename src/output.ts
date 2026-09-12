import type { Command } from "commander";
import { sanitizeDiagnosticText } from "@telecrypt-io/storage/core";
import { cancellationExitCode, commandSignal } from "./cancellation.js";


export interface CommandResult {
  /** Machine-readable payload for --json. */
  json: Record<string, unknown>;
  /** Human-readable text for the default (non --json) output. */
  text: string;
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

function rawErrorMessage(error: unknown): string {
  if (!(error instanceof Error)) return String(error);

  const name = error.name || "Error";
  const message = error.message || "unknown failure";
  const stack = typeof error.stack === "string" && error.stack !== `${name}: ${message}`
    ? `; stack: ${error.stack}`
    : "";
  const parts = [`${name}: ${message}${stack}`];
  const details = error as Error & { code?: unknown; errcode?: unknown; status?: unknown; statusCode?: unknown; treeId?: unknown };
  for (const key of ["code", "errcode", "status", "statusCode", "treeId"] as const) {
    const value = details[key];
    if (typeof value === "string" || typeof value === "number") parts.push(`${key}: ${value}`);
  }
  if (error.cause !== undefined) parts.push(`cause: ${rawErrorMessage(error.cause)}`);
  if (error instanceof AggregateError) {
    error.errors.forEach((child, index) => {
      parts.push(`aggregate child ${index}: ${rawErrorMessage(child)}`);
    });
  }
  return parts.join("; ");
}

export { sanitizeDiagnosticText as safeDiagnosticText };

export function safeErrorMessage(error: unknown): string {
  const rawMessage = rawErrorMessage(error);
  const message = rawMessage.replace(/\\(["'])/gu, "$1");
  return sanitizeDiagnosticText(message);
}

/**
 * Runs a command action: executes `fn`, prints its result (JSON or human
 * text) to stdout on success, or a clean `{ "error": "..." }` (JSON mode) /
 * `Error: ...` (text mode) to stderr on failure — complete secret-safe
 * diagnostic details, including error names, messages, causes, aggregate
 * children, and stacks.
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
    const rendered = json ? JSON.stringify(result.json) : result.text;
    await writeLine(process.stdout, rendered);
    process.exitCode = cancellationExitCode() ?? 0;
  } catch (err) {
    const message = safeErrorMessage(err);
    await writeLine(process.stderr, json ? JSON.stringify({ error: message }) : `Error: ${message}`);
    process.exitCode = cancellationExitCode() ?? 1;
  }
}
