import { afterEach, describe, expect, it, vi } from "vitest";
import { setup } from "./harness/globalSetup.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("functional fixture setup response handling", () => {
  it("abort-races a hung versions request itself", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
      vi.stubGlobal("fetch", fetchMock);

      const pending = setup();
      const failure = expect(pending).rejects.toThrow("Synapse not reachable");
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("abort-races a hung versions body and bounds reader cancellation", async () => {
    vi.useFakeTimers();
    try {
      let cancelCalled = false;
      const body = new ReadableStream<Uint8Array>({
        cancel: () => {
          cancelCalled = true;
          return new Promise<void>(() => {});
        },
      });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(body)));

      const pending = setup();
      const failure = expect(pending).rejects.toThrow("Synapse versions response read cancelled");
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(cancelCalled).toBe(true);

      await vi.advanceTimersByTimeAsync(5_000);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
