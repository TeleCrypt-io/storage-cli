import fs from "node:fs";
import { execFileSync } from "node:child_process";

const REQUIRED_ROOT_FILES = [
  "package/CLI.md",
  "package/LICENSE",
  "package/README.md",
  "package/THIRD-PARTY-LICENSES.txt",
  "package/package.json",
];

const REQUIRED_DIST_FILES = [
  "package/dist/cancellation.d.ts", "package/dist/cancellation.js",
  "package/dist/cryptoSnapshot.d.ts", "package/dist/cryptoSnapshot.js",
  "package/dist/fileTransfer.d.ts", "package/dist/fileTransfer.js",
  "package/dist/index.d.ts", "package/dist/index.js",
  "package/dist/limits.d.ts", "package/dist/limits.js",
  "package/dist/loginTransaction.d.ts", "package/dist/loginTransaction.js",
  "package/dist/logout.d.ts", "package/dist/logout.js",
  "package/dist/oidc.d.ts", "package/dist/oidc.js",
  "package/dist/output.d.ts", "package/dist/output.js",
  "package/dist/processExit.d.ts", "package/dist/processExit.js",
  "package/dist/profile.d.ts", "package/dist/profile.js",
  "package/dist/recoveryInput.d.ts", "package/dist/recoveryInput.js",
  "package/dist/storage.d.ts", "package/dist/storage.js",
  "package/dist/topology.d.ts", "package/dist/topology.js",
];

const SUPPORTED_LICENSE_NAMES = new Set([
  "LICENSE",
  "LICENCE",
  "COPYING",
  "license",
  "LICENSE.md",
  "LICENSE-MIT",
]);
const MAX_ARCHIVE_ENTRIES = 100_000;
const MAX_ARCHIVE_PATH_BYTES = 4096;
const MAX_INVENTORY_BYTES = 1_048_576;
const MAX_LICENSE_BYTES = 1_048_576;
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024;
const MAX_TAR_LISTING_BYTES = 64 * 1024 * 1024;
const TAR_TIMEOUT_MS = 30_000;
const EXACT_SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]{86}==$/u;
export const FORBIDDEN_RELEASE_MARKERS = [
  "test/harness",
  "test/functional",
  "CliRuntimeOptions",
  "activeRuntime",
  "TELECRYPT_IO_STORAGE_TEST_FIXTURE",
  "TELECRYPT_IO_STORAGE_TEST_MATRIX_SERVER_NAME",
  "TELECRYPT_IO_STORAGE_NO_BROWSER",
  "TELECRYPT_IO_STORAGE_DEBUG",
];

function sorted(values) {
  return [...values].sort();
}

function directChildren(archive, directory) {
  return archive.filter((entry) => {
    if (!entry.startsWith(directory) || entry.endsWith("/")) return false;
    return !entry.slice(directory.length).includes("/");
  });
}

/**
 * Checks the archive member that carries a dependency's license. The path
 * validator below can only see names; this check is deliberately separate so
 * a caller validating a real tarball also proves that the member is a regular,
 * bounded, non-empty file.
 */
export function validateLicenseContent(name, content, metadata = { type: "file", size: content?.byteLength }) {
  if (!SUPPORTED_LICENSE_NAMES.has(name)) throw new Error(`unsupported license filename: ${name}`);
  if (!metadata || metadata.type !== "file") throw new Error(`license member is not a regular file: ${name}`);
  if (!Number.isSafeInteger(metadata.size) || metadata.size < 1 || metadata.size > MAX_LICENSE_BYTES) {
    throw new Error(`license member has invalid bounded size: ${name}`);
  }
  if (!Buffer.isBuffer(content)) throw new Error(`license member content is not bytes: ${name}`);
  if (content.byteLength !== metadata.size || content.byteLength < 1 || content.byteLength > MAX_LICENSE_BYTES) {
    throw new Error(`license member content size is invalid: ${name}`);
  }
  return true;
}

function readTarLicense(archivePath, memberPath) {
  const name = memberPath.slice(memberPath.lastIndexOf("/") + 1);
  const listing = execFileSync("tar", ["-tvzf", archivePath, "--numeric-owner", "--full-time", "--", memberPath], {
    encoding: "utf8",
    maxBuffer: 256 * 1024,
    timeout: TAR_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const lines = listing.trimEnd().split(/\r?\n/u).filter(Boolean);
  if (lines.length !== 1) throw new Error(`license member is missing or ambiguous: ${memberPath}`);
  // GNU tar's numeric-owner/full-time form has stable fields through the
  // timestamp; the filename itself is already bound by the requested member.
  const match = /^(-[-rwxstST]{9})\s+\d+\/\d+\s+(\d+)\s+\d{4}-\d\d-\d\d\s+\S+\s+/u.exec(lines[0]);
  if (!match) throw new Error(`license member metadata is not regular: ${memberPath}`);
  const content = execFileSync("tar", ["-xOzf", archivePath, "--", memberPath], {
    maxBuffer: MAX_LICENSE_BYTES + 1,
    timeout: TAR_TIMEOUT_MS,
    stdio: ["ignore", "pipe", "pipe"],
  });
  validateLicenseContent(name, content, { type: "file", size: Number(match[2]) });
}

const TAR_MEMBER_LINE = /^([-d][-rwxstST]{9})\s+\d+\/\d+\s+(\d+)\s+\d{4}-\d\d-\d\d\s+\S+\s+(.+)$/u;

/**
 * Validates a bounded GNU tar verbose listing against the expected npm
 * archive paths. The listing is the only place where member types and
 * uncompressed sizes are available, so this check rejects symlinks, devices,
 * duplicate members, oversized members, and aggregate extraction bombs.
 */
export function validateArchiveListing(listing, expectedArchive) {
  if (typeof listing !== "string" || Buffer.byteLength(listing, "utf8") > MAX_TAR_LISTING_BYTES) {
    throw new Error("tar listing is invalid or exceeds the bounded length");
  }
  if (!Array.isArray(expectedArchive) || expectedArchive.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error("expected archive inventory is invalid or too large");
  }
  const expected = new Set(expectedArchive);
  if (expected.size !== expectedArchive.length) throw new Error("expected archive inventory has duplicates");
  const lines = listing.trimEnd().split(/\r?\n/u).filter(Boolean);
  if (lines.length === 0 || lines.length > MAX_ARCHIVE_ENTRIES) throw new Error("tar archive has an invalid member count");
  const seen = new Set();
  let totalBytes = 0;
  for (const line of lines) {
    const match = TAR_MEMBER_LINE.exec(line);
    if (!match) throw new Error("tar archive contains a non-regular or malformed member");
    const size = Number(match[2]);
    const memberPath = match[3];
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_ARCHIVE_MEMBER_BYTES) {
      throw new Error(`tar archive member exceeds the bounded size: ${memberPath}`);
    }
    totalBytes += size;
    if (!Number.isSafeInteger(totalBytes) || totalBytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES) {
      throw new Error("tar archive exceeds the aggregate uncompressed size bound");
    }
    if (!expected.has(memberPath) || seen.has(memberPath)) {
      throw new Error(`tar archive member inventory is not exact: ${memberPath}`);
    }
    seen.add(memberPath);
  }
  if (seen.size !== expected.size) throw new Error("tar archive is missing an expected member");
  return true;
}

/**
 * Validates the license members in an actual npm archive after path and
 * lockfile validation have produced the deterministic inventory.
 */
export function validateArchiveLicenseFiles(archivePath, inventory, expectedArchive) {
  if (typeof archivePath !== "string" || archivePath.length === 0) throw new Error("archive path is required");
  const archiveSize = fs.statSync(archivePath).size;
  if (!Number.isSafeInteger(archiveSize) || archiveSize < 1 || archiveSize > MAX_ARCHIVE_BYTES) {
    throw new Error("archive size is invalid or exceeds the bounded length");
  }
  if (typeof inventory !== "string" || Buffer.byteLength(inventory, "utf8") > MAX_INVENTORY_BYTES) {
    throw new Error("license inventory is invalid or unbounded");
  }
  if (expectedArchive !== undefined) {
    const listing = execFileSync("tar", ["-tvzf", archivePath, "--numeric-owner", "--full-time"], {
      encoding: "utf8",
      maxBuffer: MAX_TAR_LISTING_BYTES,
      timeout: TAR_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    validateArchiveListing(listing, expectedArchive);
  }
  const lines = inventory.split(/\r?\n/u).filter(Boolean);
  if (lines.length === 0) throw new Error("license inventory is empty");
  for (const line of lines) {
    const fields = line.split("\t");
    if (fields.length !== 4 || !fields[3].startsWith("package/")) throw new Error("license inventory framing is invalid");
    readTarLicense(archivePath, fields[3]);
  }
  return true;
}

/**
 * Reads every source-owned regular member from the real release tarball and
 * rejects local harness paths or test-only runtime markers in its bytes. This
 * binds the source/test separation to the artifact rather than relying only
 * on the package file allowlist.
 */
export function validateArchiveSourceContent(archivePath, expectedArchive) {
  if (typeof archivePath !== "string" || archivePath.length === 0) throw new Error("archive path is required");
  if (!Array.isArray(expectedArchive) || expectedArchive.length > MAX_ARCHIVE_ENTRIES) {
    throw new Error("expected archive inventory is invalid or too large");
  }
  const sourceMembers = expectedArchive.filter(
    (memberPath) => typeof memberPath === "string" && memberPath.startsWith("package/") &&
      !memberPath.endsWith("/") && !memberPath.startsWith("package/node_modules/"),
  );
  for (const memberPath of sourceMembers) {
    const content = execFileSync("tar", ["-xOzf", archivePath, "--", memberPath], {
      maxBuffer: MAX_ARCHIVE_MEMBER_BYTES + 1,
      timeout: TAR_TIMEOUT_MS,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const text = content.toString("utf8");
    for (const marker of FORBIDDEN_RELEASE_MARKERS) {
      if (text.includes(marker)) throw new Error(`forbidden test marker in release member: ${memberPath}`);
    }
  }
  return true;
}

/**
 * Validates the exact source-owned archive paths and the direct license file
 * owned by every lockfile package that npm bundles. Returns the deterministic
 * third-party inventory lines for publication.
 */
export function validateArchiveEntries(archiveInput, lock) {
  if (!Array.isArray(archiveInput)) throw new Error("archive manifest must be an array");
  if (archiveInput.length > MAX_ARCHIVE_ENTRIES) throw new Error("archive contains too many entries");
  const rawArchive = archiveInput.map((entry) => {
    if (
      typeof entry !== "string" ||
      entry.length === 0 ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(entry) ||
      entry.includes("\\") ||
      entry.startsWith("/")
    ) {
      throw new Error("invalid archive path type or framing");
    }
    if (Buffer.byteLength(entry, "utf8") > MAX_ARCHIVE_PATH_BYTES) throw new Error("archive path exceeds the bounded length");
    const parts = entry.split("/");
    const body = parts.at(-1) === "" ? parts.slice(1, -1) : parts.slice(1);
    if (
      (body.length === 0 && entry !== "package/") ||
      body.some((part) => part === "" || part === "." || part === "..") ||
      entry.includes("//")
    ) {
      throw new Error("unsafe archive path");
    }
    return entry;
  });
  if (new Set(rawArchive).size !== rawArchive.length) throw new Error("duplicate archive path");
  const archive = sorted(rawArchive.filter((entry) => entry !== "package/"));
  for (const directory of rawArchive.filter((entry) => entry.endsWith("/") && entry !== "package/")) {
    if (!archive.some((entry) => !entry.endsWith("/") && entry.startsWith(directory))) {
      throw new Error(`empty unexpected archive directory: ${directory}`);
    }
  }
  if (archive.some((entry) => /(^|\/)oidcWindowPolyfill(?:[./]|$)/u.test(entry))) {
    throw new Error("obsolete OIDC window shim is present in the release archive");
  }
  const rootFiles = archive.filter((entry) => entry.startsWith("package/") && !entry.slice("package/".length).includes("/"));
  if (JSON.stringify(rootFiles) !== JSON.stringify(REQUIRED_ROOT_FILES)) {
    throw new Error(`unexpected package root files: ${rootFiles.join(", ")}`);
  }
  const distFiles = archive.filter((entry) => entry.startsWith("package/dist/") && !entry.endsWith("/"));
  if (JSON.stringify(distFiles) !== JSON.stringify(REQUIRED_DIST_FILES)) {
    throw new Error(`unexpected compiled archive files: ${distFiles.join(", ")}`);
  }
  const allowedSourceFiles = new Set([...REQUIRED_ROOT_FILES, ...REQUIRED_DIST_FILES]);
  const unexpectedSourceFiles = archive.filter((entry) =>
    !entry.endsWith("/") && !entry.startsWith("package/node_modules/") && !allowedSourceFiles.has(entry));
  if (unexpectedSourceFiles.length > 0) {
    throw new Error(`unexpected source-owned archive files: ${unexpectedSourceFiles.join(", ")}`);
  }
  if (!lock || typeof lock !== "object" || !lock.packages || typeof lock.packages !== "object") {
    throw new Error("lockfile package inventory is invalid");
  }
  const bundled = Object.entries(lock.packages)
    .filter(([name, entry]) => name.startsWith("node_modules/") && entry?.inBundle === true)
    .sort(([left], [right]) => left.localeCompare(right));
  if (bundled.length === 0) throw new Error("lockfile has no bundled runtime package inventory");

  const bundledNames = new Set(bundled.map(([name]) => name));
  for (const archivePath of archive) {
    const relative = archivePath.slice("package/".length).replace(/\/$/u, "");
    const segments = relative.split("/");
    for (let index = 0; index < segments.length; index += 1) {
      if (segments[index] !== "node_modules") continue;
      const packageSegments = segments[index + 1]?.startsWith("@")
        ? segments.slice(index, index + 3)
        : segments.slice(index, index + 2);
      if (packageSegments.length < 2 || packageSegments.at(-1) === undefined) {
        throw new Error(`invalid bundled package path: ${archivePath}`);
      }
      const packageName = packageSegments.join("/");
      if (!bundledNames.has(packageName)) {
        throw new Error(`unexpected bundled package path: ${archivePath}`);
      }
      index += packageSegments.length - 1;
    }
  }

  const inventory = [];
  const missing = [];
  for (const [name, entry] of bundled) {
    const directory = `package/${name}/`;
    const children = directChildren(archive, directory);
    const licenses = children.filter((entryPath) => SUPPORTED_LICENSE_NAMES.has(entryPath.slice(directory.length)));
    const packageName = entry.name ?? name.slice("node_modules/".length);
    const packageVersion = entry.version;
    const tarballName = typeof packageName === "string" && packageName.startsWith("@")
      ? packageName.slice(packageName.indexOf("/") + 1)
      : packageName;
    let registryResolved = false;
    try {
      const resolved = new URL(entry.resolved);
      registryResolved =
        resolved.protocol === "https:" &&
        resolved.hostname === "registry.npmjs.org" &&
        resolved.port === "" &&
        resolved.username === "" &&
        resolved.password === "" &&
        resolved.search === "" &&
        resolved.hash === "" &&
        typeof packageVersion === "string" &&
        typeof tarballName === "string" &&
        resolved.pathname === `/${packageName}/-/${tarballName}-${packageVersion}.tgz`;
    } catch {
      registryResolved = false;
    }
    const integrity = typeof entry.integrity === "string" && EXACT_SHA512_INTEGRITY.test(entry.integrity);
    if (
      licenses.length !== 1 ||
      !children.includes(`${directory}package.json`) ||
      typeof packageName !== "string" ||
      (entry.name !== undefined && packageName !== name.slice("node_modules/".length)) ||
      typeof packageVersion !== "string" ||
      packageVersion.trim() === "" ||
      typeof entry.license !== "string" ||
      entry.license.trim() === "" ||
      !registryResolved ||
      !integrity ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(String(packageName)) ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(packageVersion) ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(entry.license)
    ) {
      missing.push(`${name} (registry provenance, integrity, or own license/package metadata missing or ambiguous)`);
      continue;
    }
    inventory.push(`${packageName}\t${packageVersion}\t${entry.license}\t${licenses[0]}`);
  }
  if (missing.length > 0) throw new Error(`bundled packages missing own license files: ${missing.join(", ")}`);
  return `${inventory.join("\n")}\n`;
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const [archivePath, lockPath, inventoryPath, tarballPath] = process.argv.slice(2);
  if (!archivePath || !lockPath || !inventoryPath) throw new Error("usage: validateReleaseArchive.mjs ARCHIVE_CONTENTS LOCKFILE INVENTORY");
  const archive = fs.readFileSync(archivePath, "utf8").split(/\r?\n/u).filter(Boolean);
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  const inventory = validateArchiveEntries(archive, lock);
  if (Buffer.byteLength(inventory, "utf8") > MAX_INVENTORY_BYTES) throw new Error("third-party inventory exceeds the bounded length");
  fs.writeFileSync(inventoryPath, inventory, { encoding: "utf8", mode: 0o600 });
  if (tarballPath) {
    validateArchiveLicenseFiles(tarballPath, inventory, archive);
    validateArchiveSourceContent(tarballPath, archive);
  }
}
