import { describe, expect, it, vi } from "vitest";
import { waitFor } from "./harness/waitFor.js";

describe("acceptance wait helper", () => {
  it("bounds a check that ignores cancellation after the deadline", async () => {
    vi.useFakeTimers();
    try {
      const pending = waitFor(() => new Promise<null>(() => {}), { timeoutMs: 10 });
      const failure = expect(pending).rejects.toThrow("waitFor timed out after 10ms");
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
    } finally {
      vi.useRealTimers();
    }
  });

  it("clears an in-flight interval timer when the deadline wins", async () => {
    vi.useFakeTimers();
    try {
      const pending = waitFor(() => false, { timeoutMs: 10, intervalMs: 1_000 });
      const failure = expect(pending).rejects.toThrow("waitFor timed out after 10ms");
      await vi.advanceTimersByTimeAsync(10);
      await failure;
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
