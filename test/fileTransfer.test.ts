import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readBoundedInput, writeDownload } from "../src/fileTransfer.js";
import { MAX_MEDIA_FILE_BYTES } from "@telecrypt-io/storage/core";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) fs.rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const value = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-file-transfer-"));
  directories.push(value);
  return value;
}

describe("CLI file transfers", () => {
  it("reads upload files and enforces the 128 MiB product limit", () => {
    const dir = directory();
    const source = path.join(dir, "source.txt");
    fs.writeFileSync(source, "upload bytes");
    expect(readBoundedInput(source)).toEqual(Buffer.from("upload bytes"));

    const oversized = path.join(dir, "oversized.bin");
    fs.writeFileSync(oversized, Buffer.alloc(0));
    fs.truncateSync(oversized, MAX_MEDIA_FILE_BYTES + 1);
    expect(() => readBoundedInput(oversized)).toThrow("input file exceeds the 128 MiB limit");
  });

  it("reads an empty file", () => {
    const source = path.join(directory(), "empty.txt");
    fs.writeFileSync(source, "");
    expect(readBoundedInput(source)).toEqual(Buffer.alloc(0));
  });

  it("writes a download atomically without replacing an existing destination", () => {
    const dir = directory();
    const destination = path.join(dir, "download.txt");
    writeDownload(destination, Buffer.from("download bytes"));
    expect(fs.readFileSync(destination, "utf8")).toBe("download bytes");

    expect(() => writeDownload(destination, Buffer.from("replacement"))).toThrow(
      "download destination already exists",
    );
    expect(fs.readFileSync(destination, "utf8")).toBe("download bytes");
  });
});
