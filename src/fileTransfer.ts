import fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { StorageError } from "@telecrypt-io/storage/core";
import { attemptCleanup, throwCombinedFailures, withCause } from "./failure.js";
import { MAX_MEDIA_FILE_BYTES } from "./limits.js";

const DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const PROC_FD_ROOT = ["/proc/self/fd", "/dev/fd"].find((candidate) => fs.existsSync(candidate));

function securePathError(): StorageError {
  return new StorageError("safe file operations require a file-descriptor filesystem");
}

/** Opens every directory component without following a path symlink. Node has
 * no openat(2) wrapper; a proc-fd or dev-fd path gives the same stable
 * directory anchor for the remaining operations. */
function openSecureDirectory(directory: string): number {
  if (!PROC_FD_ROOT) throw securePathError();
  const resolved = path.resolve(directory);
  if (path.parse(resolved).root !== "/") throw securePathError();

  let fd: number | undefined = fs.openSync("/", DIRECTORY_FLAGS);
  let fdCloseAttempted = false;
  let primaryError: unknown;
  let hasPrimary = false;
  const cleanupFailures: unknown[] = [];
  try {
    for (const component of resolved.split("/").filter(Boolean)) {
      const currentFd = fd!;
      const next = fs.openSync(path.join(PROC_FD_ROOT, String(currentFd), component), DIRECTORY_FLAGS);
      fdCloseAttempted = true;
      try {
        fs.closeSync(currentFd);
      } catch (error) {
        primaryError = error;
        hasPrimary = true;
        attemptCleanup(cleanupFailures, () => fs.closeSync(next));
        break;
      }
      fd = undefined;
      fd = next;
      fdCloseAttempted = false;
    }
  } catch (error) {
    primaryError = error instanceof StorageError ? error : withCause(securePathError(), error);
    hasPrimary = true;
  }
  if (!hasPrimary && fd !== undefined) return fd;

  if (fd !== undefined && !fdCloseAttempted) attemptCleanup(cleanupFailures, () => fs.closeSync(fd!));
  throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "secure directory cleanup failed");
}

function anchoredPath(directoryFd: number, name: string): string {
  if (!name || name === "." || name === ".." || name.includes("/")) {
    throw new StorageError("file path must name a regular file");
  }
  if (!PROC_FD_ROOT) throw securePathError();
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

/** Reads a bounded regular file through an anchored descriptor. */
export function readBoundedInput(filePath: string): Buffer {
  const parentFd = openSecureDirectory(path.dirname(filePath));
  let fd: number | undefined;
  let result: Buffer | undefined;
  let primaryError: unknown;
  let hasPrimary = false;
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

    const final = fs.fstatSync(fd);
    if (metadataChanged(opened, final)) {
      throw new StorageError("input file changed while it was being read");
    }
    result = data;
  } catch (error) {
    hasPrimary = true;
    primaryError = error instanceof StorageError
      ? error
      : withCause(new StorageError("input file could not be opened"), error);
  }
  const cleanupFailures: unknown[] = [];
  if (fd !== undefined) attemptCleanup(cleanupFailures, () => fs.closeSync(fd!));
  attemptCleanup(cleanupFailures, () => fs.closeSync(parentFd));
  if (hasPrimary || cleanupFailures.length > 0) {
    throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "input file cleanup failed");
  }
  return result!;
}

export function writeDownload(destination: string, bytes: Uint8Array): void {
  const parentFd = openSecureDirectory(path.dirname(destination));
  let fd: number | undefined;
  let fdCloseAttempted = false;
  let temporary: string | undefined;
  let primaryError: unknown;
  let hasPrimary = false;
  try {
    const name = path.basename(destination);
    const temporaryName = `.${name}-${process.pid}-${randomUUID()}.tmp`;
    temporary = anchoredPath(parentFd, temporaryName);
    const target = anchoredPath(parentFd, name);
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
    fdCloseAttempted = true;
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
  } catch (error) {
    hasPrimary = true;
    primaryError = error;
  }
  const cleanupFailures: unknown[] = [];
  if (fd !== undefined && !fdCloseAttempted) attemptCleanup(cleanupFailures, () => fs.closeSync(fd!));
  if (temporary !== undefined) {
    attemptCleanup(cleanupFailures, () => {
      try {
        fs.rmSync(temporary!);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    });
  }
  attemptCleanup(cleanupFailures, () => fs.closeSync(parentFd));
  if (hasPrimary || cleanupFailures.length > 0) {
    throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "download cleanup failed");
  }
}
