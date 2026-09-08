import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
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

describe("CLI functional fixture cleanup source", () => {
  it("stops at the first profile cleanup failure with complete diagnostics", () => {
    const source = fs.readFileSync(new URL("./harness/cli.ts", import.meta.url), "utf8");

    expect(source).toContain("for (const dir of freshProfiles)");
    expect(source).toContain("post-investigation cleanup");
    expect(source).not.toContain("const failures: string[]");
    expect(source).not.toContain("const cleaned = new Set<string>");
    expect(source).toMatch(
      /if \(result\.code !== 0\) \{\s*throw new Error\([\s\S]*stdout:\\n\$\{result\.stdout\}[\s\S]*stderr:\\n\$\{result\.stderr\}/u,
    );
    expect(source).toMatch(
      /fs\.rmSync\(dir,[\s\S]*freshProfiles\.delete\(dir\);[\s\S]*remotelyOwnedProfiles\.delete\(dir\);/u,
    );
  });
});
