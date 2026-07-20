export async function waitFor<T>(
  check: () => T | Promise<T>,
  opts?: { timeoutMs?: number; intervalMs?: number; label?: string },
): Promise<T> {
  const timeoutMs = opts?.timeoutMs ?? 10000;
  const intervalMs = opts?.intervalMs ?? 200;
  const label = opts?.label;

  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const result = await Promise.resolve(check());
    if (result) return result;
    await new Promise((r) => setTimeout(r, intervalMs));
  }

  const msg = label
    ? `waitFor timed out after ${timeoutMs}ms: ${label}`
    : `waitFor timed out after ${timeoutMs}ms`;
  throw new Error(msg);
}
