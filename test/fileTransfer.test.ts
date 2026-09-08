import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readBoundedInput, writeDownload } from "../src/fileTransfer.js";
import { MAX_MEDIA_FILE_BYTES } from "../src/limits.js";

const directories: string[] = [];

afterEach(({ task }) => {
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  if (task.result?.state === "fail") {
    process.stderr.write(
      [
        "CLI file-transfer unit test failed; retaining fixture directories for investigation:",
        ...pending,
      ].join("\n") + "\n",
    );
    return;
  }
  for (const directory of pending) fs.rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-file-transfer-"));
  directories.push(value);
  return value;
}

describe("bounded file transfer paths", () => {
  it("accepts an exact 128 MiB source and rejects the next byte", () => {
    const dir = directory();
    const source = path.join(dir, "exact.bin");
    fs.writeFileSync(source, Buffer.alloc(0));
    fs.truncateSync(source, MAX_MEDIA_FILE_BYTES);

    expect(readBoundedInput(source)).toHaveLength(MAX_MEDIA_FILE_BYTES);

    const oversized = path.join(dir, "oversized.bin");
    fs.writeFileSync(oversized, Buffer.alloc(0));
    fs.truncateSync(oversized, MAX_MEDIA_FILE_BYTES + 1);
    expect(() => readBoundedInput(oversized)).toThrow("input file exceeds the 128 MiB limit");
  });

  it("writes downloads without imposing a second media-size limit", () => {
    const dir = directory();
    const destination = path.join(dir, "exact.bin");
    writeDownload(destination, Buffer.alloc(MAX_MEDIA_FILE_BYTES));
    expect(fs.statSync(destination).size).toBe(MAX_MEDIA_FILE_BYTES);

    const oversized = path.join(dir, "oversized.bin");
    writeDownload(oversized, Buffer.alloc(MAX_MEDIA_FILE_BYTES + 1));
    expect(fs.existsSync(oversized)).toBe(true);
  });

  it("reads through a stable descriptor and writes an atomic destination", () => {
    const dir = directory();
    const source = path.join(dir, "source.txt");
    const destination = path.join(dir, "nested", "destination.txt");
    fs.mkdirSync(path.dirname(destination));
    fs.writeFileSync(source, "source bytes");

    expect(readBoundedInput(source).toString()).toBe("source bytes");
    writeDownload(destination, Buffer.from("download bytes"));
    expect(fs.readFileSync(destination, "utf8")).toBe("download bytes");
  });

  it("rejects a same-size in-place source mutation during the read", () => {
    const dir = directory();
    const source = path.join(dir, "source.txt");
    fs.writeFileSync(source, "source bytes");
    const originalReadSync = fs.readSync;
    let firstRead = true;
    const readArgs = (...args: [number, NodeJS.ArrayBufferView, number, number, number | null]) => {
      const count = originalReadSync(...args);
      if (firstRead && args[4] === null) {
        firstRead = false;
        const writer = fs.openSync(source, "r+");
        try {
          fs.writeSync(writer, Buffer.from("changed byte"), 0, "changed byte".length, 0);
        } finally {
          fs.closeSync(writer);
        }
      }
      return count;
    };
    vi.spyOn(fs, "readSync").mockImplementation(readArgs as typeof fs.readSync);

    expect(() => readBoundedInput(source)).toThrow("input file changed while it was being read");
  });

  it("closes the parent descriptor when destination setup rejects the name", () => {
    const dir = directory();
    const openSync = vi.spyOn(fs, "openSync");
    const closeSync = vi.spyOn(fs, "closeSync");

    expect(() => writeDownload(`${dir}/.`, Buffer.from("download bytes"))).toThrow(
      "file path must name a regular file",
    );

    const opened = openSync.mock.results
      .filter((result) => result.type === "return")
      .map((result) => result.value);
    const parentFd = opened.at(-1);
    expect(parentFd).toBeDefined();
    expect(closeSync).toHaveBeenCalledWith(parentFd);
  });

  it("preserves the read failure and every descriptor cleanup failure", () => {
    const dir = directory();
    const source = path.join(dir, "oversized.bin");
    fs.writeFileSync(source, Buffer.alloc(0));
    fs.truncateSync(source, MAX_MEDIA_FILE_BYTES + 1);
    const originalCloseSync = fs.closeSync;
    let closeCalls = 0;
    vi.spyOn(fs, "closeSync").mockImplementation((fd) => {
      closeCalls += 1;
      if (closeCalls === 3 || closeCalls === 4) {
        originalCloseSync(fd);
        throw new Error(`close failure ${closeCalls}`);
      }
      return originalCloseSync(fd);
    });

    let failure: unknown;
    try {
      readBoundedInput(source);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors.map(String)).toEqual([
      "StorageError: input file exceeds the 128 MiB limit",
      "Error: close failure 3",
      "Error: close failure 4",
    ]);
  });

  it("does not hide a replacement-descriptor close failure", () => {
    const dir = directory();
    const source = path.join(dir, "source.txt");
    fs.writeFileSync(source, "source bytes");
    const originalCloseSync = fs.closeSync;
    let closeCalls = 0;
    vi.spyOn(fs, "closeSync").mockImplementation((fd) => {
      closeCalls += 1;
      if (closeCalls <= 2) {
        originalCloseSync(fd);
        throw new Error(`close failure ${closeCalls}`);
      }
      return originalCloseSync(fd);
    });

    let failure: unknown;
    try {
      readBoundedInput(source);
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors.map(String)).toEqual([
      "Error: close failure 1",
      "Error: close failure 2",
    ]);
  });

  it("preserves the write failure and every independent cleanup failure", () => {
    const dir = directory();
    const destination = path.join(dir, "download.bin");
    const originalCloseSync = fs.closeSync;
    let closeCalls = 0;
    vi.spyOn(fs, "closeSync").mockImplementation((fd) => {
      closeCalls += 1;
      if (closeCalls === 3 || closeCalls === 4) {
        originalCloseSync(fd);
        throw new Error(`close failure ${closeCalls}`);
      }
      return originalCloseSync(fd);
    });
    vi.spyOn(fs, "writeFileSync").mockImplementation(() => {
      throw new Error("write failure");
    });
    const originalRmSync = fs.rmSync;
    vi.spyOn(fs, "rmSync").mockImplementation(((target, options) => {
      const result = originalRmSync(target, options);
      if (typeof target === "string" && target.includes(".download.bin-")) {
        throw new Error("temporary cleanup failure");
      }
      return result;
    }) as typeof fs.rmSync);

    let failure: unknown;
    try {
      writeDownload(destination, Buffer.from("download bytes"));
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).errors.map(String)).toEqual([
      "Error: write failure",
      "Error: close failure 3",
      "Error: temporary cleanup failure",
      "Error: close failure 4",
    ]);
  });

  it("fails closed when a parent component is a symlink", () => {
    const dir = directory();
    const real = path.join(dir, "real");
    const linked = path.join(dir, "linked");
    fs.mkdirSync(real);
    fs.symlinkSync(real, linked);
    const source = path.join(linked, "source.txt");
    fs.writeFileSync(path.join(real, "source.txt"), "source bytes");

    expect(() => readBoundedInput(source)).toThrow(/safe file operations|input file could not be opened/);
  });

  it("refuses every existing destination without changing its target", () => {
    const dir = directory();
    const real = path.join(dir, "real.txt");
    const destination = path.join(dir, "destination.txt");
    fs.writeFileSync(real, "keep");
    fs.symlinkSync(real, destination);

    expect(() => writeDownload(destination, Buffer.from("replace"))).toThrow(
      "download destination already exists",
    );
    expect(fs.readFileSync(real, "utf8")).toBe("keep");

    fs.rmSync(destination);
    fs.writeFileSync(destination, "existing");
    expect(() => writeDownload(destination, Buffer.from("replace"))).toThrow(
      "download destination already exists",
    );
    expect(fs.readFileSync(destination, "utf8")).toBe("existing");
  });
});
