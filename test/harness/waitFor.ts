import { settlePromiseWithin } from "../../src/cancellation.js";

export async function waitFor<T>(
  check: (signal: AbortSignal) => T | Promise<T>,
  opts?: { timeoutMs?: number; intervalMs?: number; label?: string },
): Promise<T> {
  const timeoutMs = opts?.timeoutMs ?? 10000;
  const intervalMs = opts?.intervalMs ?? 200;
  const label = opts?.label;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new Error("waitFor timeout and interval must be positive finite numbers");
  }

  const timeoutError = new Error(
    label ? `waitFor timed out after ${timeoutMs}ms: ${label}` : `waitFor timed out after ${timeoutMs}ms`,
  );
  const controller = new AbortController();
  let rejectDeadline!: (error: Error) => void;
  const deadlinePromise = new Promise<never>((_resolve, reject) => { rejectDeadline = reject; });
  const timer = setTimeout(() => {
    controller.abort(timeoutError);
    rejectDeadline(timeoutError);
  }, timeoutMs);
  try {
    while (true) {
      const checkPromise = Promise.resolve().then(() => check(controller.signal));
      checkPromise.catch(() => undefined);
      let result: T;
      try {
        result = await Promise.race([checkPromise, deadlinePromise]);
      } catch (error) {
        if (controller.signal.aborted) {
          // Give a timed-out check a bounded opportunity to reap its process or
          // request before the next scenario reuses its profile or fixture.
          // settlePromiseWithin also consumes a late rejection if it ignores
          // its signal.
          await settlePromiseWithin(checkPromise);
          throw timeoutError;
        }
        throw error;
      }
      if (result) return result;
      let intervalTimer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          new Promise<void>((resolve) => {
            intervalTimer = setTimeout(resolve, intervalMs);
          }),
          deadlinePromise,
        ]);
      } finally {
        if (intervalTimer !== undefined) clearTimeout(intervalTimer);
      }
    }
  } finally {
    clearTimeout(timer);
    controller.abort();
  }
}
