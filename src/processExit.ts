const NORMAL_EXIT_GRACE_MS = 5_000;

export type ExitProcess = NodeJS.Process & {
  exit: (code?: number) => never;
};

/** Let Node exit naturally when work is drained, with a bounded fallback for
 * SDK sockets or timers that remain alive after command cleanup. */
export function scheduleBoundedNormalExit(
  exitCode: number,
  processLike: ExitProcess = process as ExitProcess,
  graceMs = NORMAL_EXIT_GRACE_MS,
): boolean {
  const fallback = setTimeout(() => processLike.exit(exitCode), graceMs);
  // An unreferenced timer does not delay a normally drained process, but it
  // still fires if an SDK socket or timer keeps the event loop alive. This
  // uses only supported Node APIs.
  fallback.unref();
  return true;
}
