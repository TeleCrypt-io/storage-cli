import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const PACKAGE_NAME = "@telecrypt-io/storage";
const MAX_TARBALL_BYTES = 128 * 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES = 131_072;
const SRI_SHA512 = /^sha512-[A-Za-z0-9+/]{86}==$/u;
const EXACT_SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;

function readBoundedJson(path, label) {
  let stat;
  try {
    stat = fs.statSync(path);
  } catch (error) {
    throw new Error(`${label} cannot be read: ${error.message}`);
  }
  if (!stat.isFile() || stat.size > MAX_PACKAGE_JSON_BYTES) {
    throw new Error(`${label} exceeds the bounded JSON input`);
  }
  try {
    return JSON.parse(fs.readFileSync(path, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function exactRegistryUrl(name, version) {
  const tarballName = name.slice(name.indexOf("/") + 1);
  return `https://registry.npmjs.org/${name}/-/${tarballName}-${version}.tgz`;
}

/**
 * Verifies the consumer-side registry-byte contract. The exact SDK release's
 * own provenance verifier is the authority for the release commit binding;
 * this small consumer-side check only binds the downloaded bytes and package
 * identity to this lockfile. npm's legacy `gitHead` field is intentionally not
 * used because it is neither present nor authoritative for the accepted npm
 * provenance publication.
 */
export function verifySdkPackageBinding(tarballPath, lock, expectedVersion) {
  if (typeof tarballPath !== "string" || tarballPath.length === 0) throw new Error("SDK tarball path is required");
  if (typeof expectedVersion !== "string" || !EXACT_SEMVER.test(expectedVersion)) {
    throw new Error("SDK package version is not exact semver");
  }
  const entry = lock?.packages?.[`node_modules/${PACKAGE_NAME}`];
  if (!entry || entry.version !== expectedVersion || (entry.name !== undefined && entry.name !== PACKAGE_NAME)) {
    throw new Error("lockfile does not select the expected SDK package version");
  }
  const resolved = exactRegistryUrl(PACKAGE_NAME, expectedVersion);
  if (entry.resolved !== resolved || typeof entry.integrity !== "string" || !SRI_SHA512.test(entry.integrity)) {
    throw new Error("lockfile SDK package provenance or integrity is not exact");
  }

  const stat = fs.statSync(tarballPath);
  if (!stat.isFile() || stat.size < 1 || stat.size > MAX_TARBALL_BYTES) {
    throw new Error("SDK tarball is not a bounded regular file");
  }
  const bytes = fs.readFileSync(tarballPath);
  const actualIntegrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  if (actualIntegrity !== entry.integrity) throw new Error("SDK tarball bytes do not match package-lock integrity");

  let packageJson;
  try {
    const text = execFileSync("tar", ["-xOzf", tarballPath, "--", "package/package.json"], {
      encoding: "utf8",
      maxBuffer: MAX_PACKAGE_JSON_BYTES + 1,
      timeout: 30_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (Buffer.byteLength(text, "utf8") > MAX_PACKAGE_JSON_BYTES) throw new Error("package metadata is too large");
    packageJson = JSON.parse(text);
  } catch {
    throw new Error("SDK tarball package metadata is invalid or unavailable");
  }
  if (
    !packageJson ||
    packageJson.name !== PACKAGE_NAME ||
    packageJson.version !== expectedVersion
  ) {
    throw new Error("SDK registry package identity is not exact");
  }
  return true;
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const [tarballPath, lockPath, version] = process.argv.slice(2);
  if (!tarballPath || !lockPath || !version) {
    throw new Error("usage: verifySdkPackage.mjs SDK_TARBALL PACKAGE_LOCK VERSION");
  }
  verifySdkPackageBinding(tarballPath, readBoundedJson(lockPath, "package lockfile"), version);
}
