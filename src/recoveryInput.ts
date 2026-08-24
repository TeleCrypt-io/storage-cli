import { StorageError } from "@telecrypt-io/storage/core";
import { runWithAbortRace } from "./cancellation.js";

export const MAX_RECOVERY_KEY_BYTES = 16 * 1024;

function promptOutput(value: string): void {
  process.stderr.write(value);
}

export function requireRecoveryKey(value: string): string {
  const recoveryKey = value.replace(/[\r\n]+$/u, "");
  if (!recoveryKey) throw new StorageError("recovery key was empty");
  if (
    Buffer.byteLength(recoveryKey, "utf8") > MAX_RECOVERY_KEY_BYTES ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(recoveryKey)
  ) {
    throw new StorageError("recovery key contains unsupported characters");
  }
  return recoveryKey;
}

/** Reads a piped recovery key only when the caller selected that explicit
 * non-interactive interface. Keeping this separate from the command line
 * prevents a recovery key being retained in shell history or process lists. */
export async function readRecoveryKeyFromStdin(
  signal: AbortSignal,
  stdin: NodeJS.ReadStream = process.stdin,
): Promise<string> {
  if (stdin.isTTY) {
    throw new StorageError("--key-stdin requires a piped recovery key; omit it for the hidden prompt");
  }

  const interrupted = new StorageError("recovery key input interrupted");
  const onAbort = () => {
    try {
      stdin.destroy();
    } catch {
      // Preserve the cancellation result if stdin is already closed.
    }
  };
  if (signal.aborted) throw interrupted;
  signal.addEventListener("abort", onAbort, { once: true });
  const reading = (async (): Promise<string> => {
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of stdin) {
      if (signal.aborted) throw interrupted;
      const data = Buffer.from(chunk);
      length += data.length;
      if (length > MAX_RECOVERY_KEY_BYTES) throw new StorageError("recovery key input is unexpectedly large");
      chunks.push(data);
    }
    if (signal.aborted) throw interrupted;
    return requireRecoveryKey(Buffer.concat(chunks).toString("utf8"));
  })();
  // A non-cooperative stream may leave its async iterator pending after
  // destroy(); consume its late rejection when the abort race returns.
  reading.catch(() => undefined);
  try {
    return await runWithAbortRace(() => reading, signal, interrupted);
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

/** Prompts on a TTY without echoing the recovery key. The stream and output
 * sink are injectable so EOF/close cleanup can be tested without replacing
 * process-global stdin or stderr. */
export async function promptForRecoveryKey(
  signal: AbortSignal,
  stdin: NodeJS.ReadStream = process.stdin,
  write: (value: string) => void = promptOutput,
): Promise<string> {
  if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
    throw new StorageError("recovery key requires a TTY prompt or explicit --key-stdin input");
  }

  return new Promise((resolve, reject) => {
    const wasRaw = stdin.isRaw;
    const chars: string[] = [];
    let byteLength = 0;
    let rawModeEnabled = false;
    let settled = false;

    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("close", onClose);
      signal.removeEventListener("abort", onAbort);
      let restoreError: unknown;
      try {
        if (rawModeEnabled || stdin.isRaw) stdin.setRawMode(wasRaw ?? false);
      } catch (err) {
        restoreError = err;
      } finally {
        stdin.pause();
      }
      write("\n");
      if (error) reject(error);
      else if (restoreError) reject(restoreError);
      else {
        try {
          resolve(requireRecoveryKey(chars.join("")));
        } catch (err) {
          reject(err);
        }
      }
    };
    const onData = (data: Buffer | string) => {
      for (const char of data.toString()) {
        if (char === "\r" || char === "\n") {
          finish();
          return;
        }
        if (char === "\u0003") {
          finish(new StorageError("recovery key input interrupted"));
          return;
        }
        if (char === "\u0004") {
          finish(new StorageError("recovery key input ended before a key was entered"));
          return;
        }
        if (char === "\b" || char === "\u007f") {
          const removed = chars.pop();
          if (removed) byteLength -= Buffer.byteLength(removed, "utf8");
          continue;
        }
        byteLength += Buffer.byteLength(char, "utf8");
        if (byteLength > MAX_RECOVERY_KEY_BYTES) {
          finish(new StorageError("recovery key input is unexpectedly large"));
          return;
        }
        chars.push(char);
      }
    };
    const onAbort = () => finish(new StorageError("recovery key input interrupted"));
    const onEnd = () => finish(new StorageError("recovery key input ended before a key was entered"));
    const onClose = () => finish(new StorageError("recovery key input closed before a key was entered"));

    try {
      if (signal.aborted) {
        onAbort();
        return;
      }
      write("Recovery Key: ");
      stdin.setRawMode(true);
      rawModeEnabled = true;
      stdin.on("data", onData);
      stdin.once("end", onEnd);
      stdin.once("close", onClose);
      signal.addEventListener("abort", onAbort, { once: true });
      // Attach every listener before resuming: a TTY/fixture stream may emit
      // input or EOF synchronously from resume().
      stdin.resume();
    } catch (err) {
      finish(err as Error);
    }
  });
}

export function readRecoveryKey(useStdin: boolean, signal: AbortSignal): Promise<string> {
  return useStdin ? readRecoveryKeyFromStdin(signal) : promptForRecoveryKey(signal);
}
