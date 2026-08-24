import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readBoundedInput, writeBoundedDownload } from "../src/fileTransfer.js";
import { MAX_MEDIA_FILE_BYTES } from "../src/limits.js";

const directories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
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

  it("accepts an exact 128 MiB download and rejects an oversized result before touching disk", () => {
    const dir = directory();
    const destination = path.join(dir, "exact.bin");
    writeBoundedDownload(destination, Buffer.alloc(MAX_MEDIA_FILE_BYTES));
    expect(fs.statSync(destination).size).toBe(MAX_MEDIA_FILE_BYTES);

    expect(() => writeBoundedDownload(
      path.join(dir, "oversized.bin"),
      { byteLength: MAX_MEDIA_FILE_BYTES + 1 } as Uint8Array,
    )).toThrow("download exceeds the 128 MiB limit");
    expect(fs.existsSync(path.join(dir, "oversized.bin"))).toBe(false);
  });

  it("reads through a stable descriptor and writes an atomic destination", () => {
    const dir = directory();
    const source = path.join(dir, "source.txt");
    const destination = path.join(dir, "nested", "destination.txt");
    fs.mkdirSync(path.dirname(destination));
    fs.writeFileSync(source, "source bytes");

    expect(readBoundedInput(source).toString()).toBe("source bytes");
    writeBoundedDownload(destination, Buffer.from("download bytes"));
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

    expect(() => writeBoundedDownload(destination, Buffer.from("replace"))).toThrow(
      "download destination already exists",
    );
    expect(fs.readFileSync(real, "utf8")).toBe("keep");

    fs.rmSync(destination);
    fs.writeFileSync(destination, "existing");
    expect(() => writeBoundedDownload(destination, Buffer.from("replace"))).toThrow(
      "download destination already exists",
    );
    expect(fs.readFileSync(destination, "utf8")).toBe("existing");
  });
});
