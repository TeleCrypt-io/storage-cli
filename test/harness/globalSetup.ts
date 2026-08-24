import {
  cancelReadableStreamReaderWithinBound,
  readReadableStreamChunkWithAbort,
  runWithAbortRace,
} from "../../src/cancellation.js";

const MAX_RESPONSE_BYTES = 64 * 1024;

async function readBoundedText(response: Response, signal: AbortSignal): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    Number.isSafeInteger(Number(declaredLength)) &&
    Number(declaredLength) > MAX_RESPONSE_BYTES
  ) {
    throw new Error("Synapse versions response exceeds the output limit");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const abortError = new Error("Synapse versions response read cancelled");
  let readFailed = false;
  try {
    while (true) {
      const next = await readReadableStreamChunkWithAbort(reader, signal, abortError);
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await cancelReadableStreamReaderWithinBound(reader);
        throw new Error("Synapse versions response exceeds the output limit");
      }
      chunks.push(next.value);
    }
  } catch (error) {
    readFailed = true;
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch (error) {
      if (!readFailed) throw error;
    }
  }
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
    const res = await runWithAbortRace(
      () => fetch("http://localhost:8008/_matrix/client/versions", {
        redirect: "error",
        signal,
      }),
      signal,
      new Error("Synapse versions request cancelled"),
    ).catch(() => null);

    if (!res || !res.ok) {
      throw new Error(
        [
          "Synapse not reachable at http://localhost:8008",
          "",
          "  Start the shared fixture from the Storage SDK repository first.",
          "",
        ].join("\n"),
      );
    }

    const responseText = await readBoundedText(res, signal);
    const body = JSON.parse(responseText) as { versions?: string[] };
    if (!body.versions) {
      throw new Error(
        "Synapse responded but response has no versions field — is this a Matrix server?",
      );
    }
  } finally {
    clearTimeout(timeout);
  }
}
