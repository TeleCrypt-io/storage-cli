import { EventEmitter } from "node:events";
import { describe, expect, it } from "vitest";
import { promptForRecoveryKey, readRecoveryKeyFromStdin } from "../src/recoveryInput.js";

class FakeTty extends EventEmitter {
  readonly isTTY = true;
  isRaw = false;
  paused = false;
  resumed = false;
  emitOnResume?: "data" | "end" | "close";

  setRawMode(raw: boolean): this {
    this.isRaw = raw;
    return this;
  }

  resume(): this {
    this.resumed = true;
    if (this.emitOnResume === "data") this.emit("data", "recovery-key\n");
    if (this.emitOnResume === "end") this.emit("end");
    if (this.emitOnResume === "close") this.emit("close");
    return this;
  }

  pause(): this {
    this.paused = true;
    return this;
  }
}

describe("hidden recovery-key prompt input", () => {
  it.each([
    ["Ctrl-D", "data", "\u0004", "recovery key input ended before a key was entered"],
    ["end", "end", undefined, "recovery key input ended before a key was entered"],
    ["close", "close", undefined, "recovery key input closed before a key was entered"],
  ])("rejects %s deterministically and removes its listeners", async (_label, event, value, message) => {
    const stdin = new FakeTty();
    const pending = promptForRecoveryKey(
      new AbortController().signal,
      stdin as unknown as NodeJS.ReadStream,
      () => {},
    );
    stdin.emit(event, value);

    await expect(pending).rejects.toThrow(message);
    expect(stdin.isRaw).toBe(false);
    expect(stdin.resumed).toBe(true);
    expect(stdin.paused).toBe(true);
    expect(stdin.listenerCount("data")).toBe(0);
    expect(stdin.listenerCount("end")).toBe(0);
    expect(stdin.listenerCount("close")).toBe(0);
  });

  it("installs listeners before resume can synchronously emit input", async () => {
    const stdin = new FakeTty();
    stdin.emitOnResume = "data";

    await expect(promptForRecoveryKey(
      new AbortController().signal,
      stdin as unknown as NodeJS.ReadStream,
      () => {},
    )).resolves.toBe("recovery-key");
    expect(stdin.isRaw).toBe(false);
    expect(stdin.paused).toBe(true);
    expect(stdin.listenerCount("data")).toBe(0);
    expect(stdin.listenerCount("end")).toBe(0);
    expect(stdin.listenerCount("close")).toBe(0);
  });
});

describe("piped recovery-key input", () => {
  it("returns promptly when a non-cooperative stdin ignores cancellation", async () => {
    const controller = new AbortController();
    const stdin = new EventEmitter() as EventEmitter & {
      isTTY: false;
      destroyed: boolean;
      destroy: () => void;
      [Symbol.asyncIterator]: () => AsyncIterator<Buffer>;
    };
    stdin.isTTY = false;
    stdin.destroyed = false;
    stdin.destroy = () => {
      stdin.destroyed = true;
    };
    stdin[Symbol.asyncIterator] = () => ({
      next: () => new Promise<IteratorResult<Buffer>>(() => {}),
    });

    const pending = readRecoveryKeyFromStdin(controller.signal, stdin as unknown as NodeJS.ReadStream);
    controller.abort(new Error("cancelled by test"));

    await expect(pending).rejects.toThrow("recovery key input interrupted");
    expect(stdin.destroyed).toBe(true);
  });
});
