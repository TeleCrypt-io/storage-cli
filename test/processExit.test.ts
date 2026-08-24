import { describe, expect, it, vi } from "vitest";
import { scheduleBoundedNormalExit, type ExitProcess } from "../src/processExit.js";

describe("bounded normal exit", () => {
  it("uses an unreferenced supported timer as the bounded fallback", () => {
    vi.useFakeTimers();
    try {
      const processLike = { exit: vi.fn() } as unknown as ExitProcess;
      expect(scheduleBoundedNormalExit(7, processLike, 25)).toBe(true);
      vi.advanceTimersByTime(24);
      expect(processLike.exit).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1);
      expect(processLike.exit).toHaveBeenCalledWith(7);
    } finally {
      vi.useRealTimers();
    }
  });
});
