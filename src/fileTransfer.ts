import fs from "node:fs";
import * as path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { StorageError } from "@telecrypt-io/storage/core";
import { MAX_MEDIA_FILE_BYTES } from "./profile.js";

const DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const PROC_FD_ROOT = "/proc/self/fd";

function securePathError(): StorageError {
  return new StorageError("safe file operations require Linux /proc/self/fd support");
}

/** Opens every directory component without following a path symlink. Node has
 * no openat(2) wrapper; on Linux, a proc-fd path gives the same stable
 * directory anchor for the remaining operations. Other topologies fail closed
 * instead of claiming that a pathname walk is race-free. */
function openSecureDirectory(directory: string): number {
  if (process.platform !== "linux" || !fs.existsSync(PROC_FD_ROOT)) throw securePathError();
  const resolved = path.resolve(directory);
  if (path.parse(resolved).root !== "/") throw securePathError();

  let fd = fs.openSync("/", DIRECTORY_FLAGS);
  try {
    for (const component of resolved.split("/").filter(Boolean)) {
      const next = fs.openSync(path.join(PROC_FD_ROOT, String(fd), component), DIRECTORY_FLAGS);
      fs.closeSync(fd);
      fd = next;
    }
    return fd;
  } catch (error) {
    try {
      fs.closeSync(fd);
    } catch {
      // Preserve the fail-closed result if cleanup itself also fails.
    }
    if (error instanceof StorageError) throw error;
    throw securePathError();
  }
}

function anchoredPath(directoryFd: number, name: string): string {
  if (!name || name === "." || name === ".." || name.includes("/")) {
    throw new StorageError("file path must name a regular file");
  }
  return path.join(PROC_FD_ROOT, String(directoryFd), name);
}

function metadataChanged(before: fs.Stats, after: fs.Stats): boolean {
  return (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mode !== after.mode ||
    before.mtimeMs !== after.mtimeMs ||
    before.ctimeMs !== after.ctimeMs
  );
}

/** Reads a bounded regular file through an anchored descriptor. The second
 * pass catches same-size in-place mutation that inode/size checks cannot see. */
export function readBoundedInput(filePath: string): Buffer {
  const parentFd = openSecureDirectory(path.dirname(filePath));
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      anchoredPath(parentFd, path.basename(filePath)),
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile()) throw new StorageError("input path must be a regular file");
    if (opened.size > MAX_MEDIA_FILE_BYTES) throw new StorageError("input file exceeds the 128 MiB limit");

    const data = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, null);
      if (count === 0) throw new StorageError("input file changed while it was being read");
      offset += count;
    }

    const digest = createHash("sha256").update(data).digest();
    const verifyHash = createHash("sha256");
    const scratch = Buffer.allocUnsafe(Math.min(1024 * 1024, Math.max(1, opened.size)));
    let position = 0;
    while (position < opened.size) {
      const count = fs.readSync(fd, scratch, 0, Math.min(scratch.length, opened.size - position), position);
      if (count === 0) throw new StorageError("input file changed while it was being read");
      verifyHash.update(scratch.subarray(0, count));
      position += count;
    }

    const final = fs.fstatSync(fd);
    if (metadataChanged(opened, final) || !digest.equals(verifyHash.digest())) {
      throw new StorageError("input file changed while it was being read");
    }
    return data;
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw new StorageError("input file could not be opened");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    fs.closeSync(parentFd);
  }
}

export function writeBoundedDownload(destination: string, bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_MEDIA_FILE_BYTES) throw new StorageError("download exceeds the 128 MiB limit");
  const parentFd = openSecureDirectory(path.dirname(destination));
  let fd: number | undefined;
  const name = path.basename(destination);
  const temporaryName = `.${name}-${process.pid}-${randomUUID()}.tmp`;
  const temporary = anchoredPath(parentFd, temporaryName);
  const target = anchoredPath(parentFd, name);
  try {
    try {
      fs.lstatSync(target);
      throw new StorageError("download destination already exists; choose a new path");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    try {
      // Same-directory hard linking provides atomic create-if-absent
      // semantics. rename(2) would silently overwrite a file created after
      // the preflight check.
      fs.linkSync(temporary, target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new StorageError("download destination already exists; choose a new path");
      }
      throw error;
    }
    fs.rmSync(temporary);
    fs.fsyncSync(parentFd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.rmSync(temporary);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    fs.closeSync(parentFd);
  }
}
