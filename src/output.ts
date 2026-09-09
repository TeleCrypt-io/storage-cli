import type { Command } from "commander";
import { cancellationExitCode, commandSignal } from "./cancellation.js";

const DIAGNOSTIC_SECRET_FIELD = /^(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?id|client[_-]?secret|user[_-]?id|device[_-]?id|authorization(?:[_-]?code)?|device[_-]?code|user[_-]?code|code[_-]?verifier|token|credential[s]?|private[_-]?key|(?:[A-Za-z0-9]+[_-])?(?:encryption|signing|password|secret|api[_-]?key|recovery[_-]?key|cookie|session)(?:[_-]?token|[_-]?key)?)$/iu;
const DIAGNOSTIC_QUOTED_VALUE = `"(?:\\\\.|[^"\\\\])*"|'(?:\\\\.|[^'\\\\])*'|[^\\s,};\\]]+`;
const DIAGNOSTIC_EMAIL = /[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9-]+(?:\.[A-Z0-9-]+)+/giu;
const DIAGNOSTIC_MXID = /@[A-Z0-9._=+\-/]+:[A-Z0-9.-]+/giu;
const DIAGNOSTIC_ULID = /\b[0-9A-HJKMNP-TV-Z]{26}\b/giu;

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

interface PendingDiagnostic {
  value: unknown;
  label: string;
}

interface DiagnosticProperty {
  key: PropertyKey;
  value: unknown;
}

function isDiagnosticReference(value: unknown): value is object {
  return value !== null && (typeof value === "object" || typeof value === "function");
}

function diagnosticKey(key: PropertyKey): string {
  return String(key);
}

function diagnosticDisplayKey(key: PropertyKey): string {
  return safeOutputField(diagnosticKey(key)) || "<empty property>";
}

function diagnosticPropertyIsSecret(key: PropertyKey): boolean {
  return DIAGNOSTIC_SECRET_FIELD.test(diagnosticKey(key));
}

function readDiagnosticProperties(
  value: object,
  seen: WeakSet<object>,
): { properties: DiagnosticProperty[]; failures: string[] } {
  const properties: DiagnosticProperty[] = [];
  const failures: string[] = [];
  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch (error) {
    failures.push(`own properties unavailable: ${safePropertyFailure(error, seen)}`);
    return { properties, failures };
  }
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch (error) {
      failures.push(
        `${diagnosticDisplayKey(key)} unavailable: ${diagnosticPropertyIsSecret(key) ? "<redacted>" : safePropertyFailure(error, seen)}`,
      );
      continue;
    }
    if (!descriptor) continue;
    try {
      if ("value" in descriptor) {
        properties.push({ key, value: descriptor.value });
      } else if (typeof descriptor.get === "function") {
        properties.push({ key, value: Reflect.get(value, key) });
      } else {
        failures.push(
        `${diagnosticDisplayKey(key)} unavailable: ${diagnosticPropertyIsSecret(key) ? "<redacted>" : "accessor has no getter"}`,
        );
      }
    } catch (error) {
      failures.push(
        `${diagnosticDisplayKey(key)} unavailable: ${diagnosticPropertyIsSecret(key) ? "<redacted>" : safePropertyFailure(error, seen)}`,
      );
    }
  }
  return { properties, failures };
}

function safePropertyFailure(error: unknown, seen: WeakSet<object>): string {
  if (isDiagnosticReference(error)) {
    try {
      return rawErrorMessage(error, seen);
    } catch {
      return "unknown property failure";
    }
  }
  try {
    return String(error);
  } catch {
    return "unknown property failure";
  }
}

function formatterFailure(error: unknown, seen?: WeakSet<object>): string {
  if (seen && isDiagnosticReference(error) && seen.has(error)) return "[cyclic diagnostic formatter failure]";
  try {
    const detail = rawErrorMessage(error);
    return detail || "unknown diagnostic formatter failure";
  } catch {
    return "unknown diagnostic formatter failure";
  }
}

function appendDiagnosticProperties(
  pending: PendingDiagnostic[],
  label: string,
  inspection: { properties: DiagnosticProperty[]; failures: string[] },
  skip: ReadonlySet<PropertyKey>,
): void {
  const { properties, failures } = inspection;
  for (let index = properties.length - 1; index >= 0; index -= 1) {
    const property = properties[index]!;
    if (skip.has(property.key)) continue;
    const key = diagnosticDisplayKey(property.key);
    pending.push({
      value: diagnosticPropertyIsSecret(property.key) ? "<redacted>" : property.value,
      label: `${label}${key}: `,
    });
  }
  for (let index = failures.length - 1; index >= 0; index -= 1) {
    pending.push({ value: failures[index], label: `${label}` });
  }
}

function rawErrorMessage(error: unknown, seen = new WeakSet<object>()): string {
  const messages: string[] = [];
  const pending: PendingDiagnostic[] = [{ value: error, label: "" }];
  while (pending.length > 0) {
    const { value: current, label } = pending.pop()!;
    if (isDiagnosticReference(current)) {
      if (seen.has(current)) {
        messages.push(`${label}[cyclic diagnostic]`);
        continue;
      }
      seen.add(current);
    } else {
      try {
        messages.push(`${label}${String(current)}`);
      } catch {
        messages.push(`${label}unknown diagnostic value`);
      }
      continue;
    }
    try {
      if (current instanceof Error) {
        const name = current.name || "Error";
        const message = current.message || "unknown failure";
        const stack = typeof current.stack === "string" ? current.stack : "";
        const stackSuffix = stack !== "" && stack !== `${name}: ${message}` ? `; stack: ${stack}` : "";
        messages.push(`${label}${name}: ${message}${stackSuffix}`);
        const skip = new Set<PropertyKey>(["name", "message", "stack", "cause"]);
        if (current instanceof AggregateError) skip.add("errors");
        const nested: PendingDiagnostic[] = [];
        let cause: unknown;
        try {
          cause = current.cause;
        } catch (causeError) {
          messages.push(`${label}cause unavailable: ${formatterFailure(causeError, seen)}`);
        }
        if (cause !== undefined) nested.push({ value: cause, label: `${label}cause: ` });
        if (current instanceof AggregateError) {
          let children: unknown;
          try {
            children = current.errors;
          } catch (childrenError) {
            messages.push(`${label}aggregate children unavailable: ${formatterFailure(childrenError, seen)}`);
            continue;
          }
          if (Array.isArray(children)) {
            for (let index = children.length - 1; index >= 0; index -= 1) {
              nested.push({ value: children[index], label: `${label}aggregate child ${index}: ` });
            }
          } else {
            messages.push(`${label}aggregate children: [invalid]`);
          }
        }
        appendDiagnosticProperties(nested, label, readDiagnosticProperties(current, seen), skip);
        for (let index = nested.length - 1; index >= 0; index -= 1) pending.push(nested[index]!);
      } else {
        const inspection = readDiagnosticProperties(current, seen);
        if (inspection.properties.length === 0 && inspection.failures.length === 0) {
          messages.push(`${label}${isDiagnosticReference(current) ? "object { }" : String(current)}`);
        } else {
          messages.push(`${label}object`);
          const nested: PendingDiagnostic[] = [];
          appendDiagnosticProperties(nested, label, inspection, new Set<PropertyKey>());
          for (let index = nested.length - 1; index >= 0; index -= 1) pending.push(nested[index]!);
        }
      }
    } catch (formatError) {
      messages.push(`${label}diagnostic formatting failed: ${formatterFailure(formatError, seen)}`);
    }
  }
  return messages.join("; ");
}

export function safeDiagnosticText(value: string): string {
  return value
    .replace(/(Bearer\s+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s"',}]+)/giu, "$1<redacted>")
    .replace(
      new RegExp(`(["'])([^"']+)\\1(\\s*[:=]\\s*)(${DIAGNOSTIC_QUOTED_VALUE})`, "giu"),
      (whole, quote: string, key: string, separator: string) =>
        DIAGNOSTIC_SECRET_FIELD.test(key.replace(/\\(["'])/gu, "$1"))
          ? `${quote}${key}${quote}${separator}"<redacted>"`
          : whole,
    )
    .replace(
      new RegExp(`\\b([A-Za-z][A-Za-z0-9_-]*)\\b(\\s*[:=]\\s*)(${DIAGNOSTIC_QUOTED_VALUE})`, "giu"),
      (whole, key: string, separator: string) =>
        DIAGNOSTIC_SECRET_FIELD.test(key) ? `${key}${separator}"<redacted>"` : whole,
    )
    .replace(DIAGNOSTIC_EMAIL, "<redacted>")
    .replace(DIAGNOSTIC_MXID, "<redacted>")
    .replace(DIAGNOSTIC_ULID, "<redacted>")
    .replace(/[\r\n\u0000-\u001f\u007f-\u009f\u2028\u2029]/gu, " ")
    .trim();
}

export function safeErrorMessage(error: unknown): string {
  const rawMessage = rawErrorMessage(error);
  const message = rawMessage.replace(/\\(["'])/gu, "$1");
  return safeDiagnosticText(message);
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
    const safeRendered = rendered.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029]/gu, "?");
    await writeLine(process.stdout, safeRendered);
    process.exitCode = cancellationExitCode() ?? 0;
  } catch (err) {
    const message = safeErrorMessage(err);
    await writeLine(process.stderr, json ? JSON.stringify({ error: message }) : `Error: ${message}`);
    process.exitCode = cancellationExitCode() ?? 1;
  }
}
