export function throwCombinedFailures(
  primary: unknown,
  hasPrimary: boolean,
  cleanupFailures: unknown[],
  message: string,
): never {
  const failures = hasPrimary ? [primary, ...cleanupFailures] : cleanupFailures;
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, message);
  throw new Error("internal cleanup failure aggregation error");
}

export function attemptCleanup(cleanupFailures: unknown[], cleanup: () => void): void {
  try {
    cleanup();
  } catch (error) {
    cleanupFailures.push(error);
  }
}

export function withCause<T extends Error>(error: T, cause: unknown): T {
  Object.defineProperty(error, "cause", {
    configurable: true,
    enumerable: false,
    value: cause,
    writable: true,
  });
  return error;
}
