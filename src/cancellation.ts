import { StorageError } from "@telecrypt-io/storage/core";
import { throwCombinedFailures } from "./failure.js";

/** One controller is shared by the command and all SDK-backed work it starts.
 * Signal handlers only request cancellation; cleanup remains in each action's
 * `finally` block and the process exit code is set after output drains. */
const commandController = new AbortController();
type SupportedSignal = "SIGHUP" | "SIGINT" | "SIGTERM";
let receivedSignal: SupportedSignal | undefined;
let installed = false;

const SIGNAL_EXIT_CODES: Readonly<Record<SupportedSignal, number>> = {
  SIGHUP: 129,
  SIGINT: 130,
  SIGTERM: 143,
};

/** The grace period bounds cleanup that belongs to the current operation. */
export const CANCELLATION_JOIN_GRACE_MS = 5_000;

export type PromiseSettlement<T> =
  | { status: "fulfilled"; value: T }
  | { status: "rejected"; error: unknown }
  | { status: "timeout" };

export function settlePromiseWithin<T>(
  operation: Promise<T>,
  graceMs = CANCELLATION_JOIN_GRACE_MS,
): Promise<PromiseSettlement<T>> {
  if (!Number.isFinite(graceMs) || graceMs < 0) {
    return Promise.reject(new Error("cancellation grace period must be finite and non-negative"));
  }
  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (result: PromiseSettlement<T>): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(result);
    };
    operation.then(
      (value) => finish({ status: "fulfilled", value }),
      (error) => finish({ status: "rejected", error }),
    );
    timer = setTimeout(() => finish({ status: "timeout" }), graceMs);
  });
}

/** Runs one operation behind a caller-owned abort boundary. */
export function runWithAbortRace<T>(
  operation: () => Promise<T>,
  signal: AbortSignal,
  abortError: Error,
): Promise<T> {
  if (signal.aborted) return Promise.reject(abortError);

  let rejectAbort!: (error: Error) => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = reject;
  });
  const onAbort = (): void => rejectAbort(abortError);
  const request = Promise.resolve().then(() => {
    if (signal.aborted) throw abortError;
    return operation();
  });
  signal.addEventListener("abort", onAbort, { once: true });
  return Promise.race([request, aborted]).finally(() => {
    signal.removeEventListener("abort", onAbort);
  });
}

/** Stops a readable response body within the cleanup deadline. */
export async function cancelReadableStreamReaderWithinBound<T>(
  reader: ReadableStreamDefaultReader<T>,
): Promise<void> {
  const cancellation = Promise.resolve().then(() => reader.cancel());
  const settlement = await settlePromiseWithin(cancellation);
  if (settlement.status === "rejected") throw settlement.error;
  if (settlement.status === "timeout") {
    throw new StorageError("response body cancellation timed out");
  }
}

/** Races one body read against its abort signal. The read and its rejection
 * remain observed after the abort wins, while reader cancellation is bounded
 * independently so releaseLock/finally cleanup cannot hang on a bad stream. */
export async function readReadableStreamChunkWithAbort<T>(
  reader: ReadableStreamDefaultReader<T>,
  signal: AbortSignal,
  abortError: Error,
): Promise<ReadableStreamReadResult<T>> {
  if (signal.aborted) {
    try {
      await cancelReadableStreamReaderWithinBound(reader);
    } catch (cleanupError) {
      throwCombinedFailures(abortError, true, [cleanupError], "response read cancellation failed");
    }
    throw abortError;
  }

  let rejectAbort!: (error: Error) => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = reject;
  });
  const onAbort = (): void => {
    rejectAbort(abortError);
  };
  signal.addEventListener("abort", onAbort, { once: true });

  const read = Promise.resolve().then(() => {
    if (signal.aborted) throw abortError;
    return reader.read();
  });
  try {
    return await Promise.race([read, aborted]);
  } catch (error) {
    try {
      await cancelReadableStreamReaderWithinBound(reader);
    } catch (cleanupError) {
      throwCombinedFailures(error, true, [cleanupError], "response read cancellation failed");
    }
    throw error;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

export const commandSignal = commandController.signal;

export function installCancellationHandlers(): () => void {
  if (installed) return () => {};
  installed = true;
  const handlers: Array<[SupportedSignal, () => void]> = [];
  for (const signal of Object.keys(SIGNAL_EXIT_CODES) as SupportedSignal[]) {
    const handler = () => {
      receivedSignal = receivedSignal ?? signal;
      if (!commandController.signal.aborted) {
        commandController.abort(new StorageError("operation cancelled"));
      }
    };
    handlers.push([signal, handler]);
    process.once(signal, handler);
  }
  return () => {
    for (const [signal, handler] of handlers) process.off(signal, handler);
    installed = false;
  };
}

export function cancellationExitCode(): number | undefined {
  return receivedSignal === undefined ? undefined : SIGNAL_EXIT_CODES[receivedSignal];
}
