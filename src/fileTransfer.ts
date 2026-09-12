import fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { MAX_MEDIA_FILE_BYTES, StorageError } from "@telecrypt-io/storage/core";
import { withCause } from "./failure.js";

/** Read an upload input, enforcing the product's media-size limit. */
export function readBoundedInput(filePath: string): Buffer {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) throw new StorageError("input path must be a regular file");
    if (stat.size > MAX_MEDIA_FILE_BYTES) {
      throw new StorageError("input file exceeds the 128 MiB limit");
    }
    const bytes = fs.readFileSync(filePath);
    if (bytes.length > MAX_MEDIA_FILE_BYTES) {
      throw new StorageError("input file exceeds the 128 MiB limit");
    }
    return bytes;
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw withCause(new StorageError("input file could not be opened"), error);
  }
}

/** Install a download atomically, leaving any existing destination untouched. */
export function writeDownload(destination: string, bytes: Uint8Array): void {
  const directory = path.dirname(destination);
  const name = path.basename(destination);
  if (!name || name === "." || name === "..") {
    throw new StorageError("download destination must name a file");
  }
  const temporary = path.join(directory, `.${name}-${randomUUID()}.tmp`);
  try {
    fs.writeFileSync(temporary, bytes, { flag: "wx", mode: 0o600 });
    try {
      // The temporary file is on the same filesystem. Linking it into place
      // makes installation atomic and refuses to replace an existing path.
      fs.linkSync(temporary, destination);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new StorageError("download destination already exists; choose a new path");
      }
      throw error;
    }
  } catch (error) {
    if (error instanceof StorageError) throw error;
    throw withCause(new StorageError("download could not be written"), error);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}
