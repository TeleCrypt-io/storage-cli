import {
  readReadableStreamChunkWithAbort,
  runWithAbortRace,
} from "../../src/cancellation.js";

async function readText(response: Response, signal: AbortSignal): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  const abortError = new Error("Synapse versions response read cancelled");
  let failure: unknown;
  try {
    while (true) {
      const next = await readReadableStreamChunkWithAbort(reader, signal, abortError);
      if (next.done) break;
      chunks.push(next.value);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Synapse versions response read failed";
    failure = new Error(
      `${message}; complete body before failure:\n${Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8")}`,
      { cause: error },
    );
  } finally {
    try {
      reader.releaseLock();
    } catch (cleanupError) {
      failure = failure === undefined
        ? cleanupError
        : new AggregateError(
          [failure, cleanupError],
          "Synapse versions response read and reader cleanup failed",
          { cause: failure },
        );
    }
  }
  if (failure !== undefined) throw failure;
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
}

export async function setup(): Promise<void> {
  // Use a normal timer so fake-timer tests exercise the same deadline as the
  // fixture setup. AbortSignal.timeout() uses an internal timer that test
  // frameworks cannot reliably advance.
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  const signal = controller.signal;
  try {
    let res: Response;
    try {
      res = await runWithAbortRace(
        () => fetch("http://localhost:8008/_matrix/client/versions", {
          redirect: "error",
          signal,
        }),
        signal,
        new Error("Synapse versions request cancelled"),
      );
    } catch (error) {
      throw new Error(
        [
          "Synapse not reachable at http://localhost:8008",
          "",
          "  Start the shared fixture from the Storage SDK repository first.",
          "",
        ].join("\n"),
        { cause: error },
      );
    }

    const responseText = await readText(res, signal);
    if (!res.ok) {
      throw new Error(
        `Synapse versions request returned HTTP ${res.status}; complete response body:\n${responseText}`,
      );
    }
    let body: { versions?: string[] };
    try {
      body = JSON.parse(responseText) as { versions?: string[] };
    } catch (error) {
      throw new Error(`Synapse versions response is not JSON; complete response body:\n${responseText}`, {
        cause: error,
      });
    }
    if (!body.versions) {
      throw new Error(
        "Synapse responded but response has no versions field — is this a Matrix server?",
      );
    }
  } finally {
    clearTimeout(timeout);
  }
}
