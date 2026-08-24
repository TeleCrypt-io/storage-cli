const MAX_IDENTITY_BYTES = 64 * 1024;
const COMMIT = /^(?!0{40}$)[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

function parseIdentity(text, keys) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_IDENTITY_BYTES) {
    throw new Error("release identity is missing or exceeds the bounded length");
  }
  if (!text.endsWith("\n")) throw new Error("release identity must end with one newline");
  const normalized = text.replace(/\r?\n$/u, "");
  const lines = normalized.split(/\r?\n/u);
  if (lines.length !== keys.length || normalized === "") throw new Error("release identity framing is invalid");
  const values = new Map();
  for (const line of lines) {
    const separator = line.indexOf("=");
    if (separator < 1 || values.has(line.slice(0, separator))) throw new Error("release identity framing is invalid");
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!keys.includes(key) || value === "" || /[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
      throw new Error("release identity framing is invalid");
    }
    values.set(key, value);
  }
  if (values.size !== keys.length || keys.some((key) => !values.has(key))) {
    throw new Error("release identity keys are incomplete");
  }
  return Object.fromEntries(values);
}

export function validateSourceIdentity(text, expected) {
  const values = parseIdentity(text, ["tag_ref", "tag_object", "tag_commit", "remote_main", "archive_sha256"]);
  for (const key of Object.keys(expected)) {
    if (values[key] !== expected[key]) throw new Error(`source identity mismatch: ${key}`);
  }
  for (const key of ["tag_object", "tag_commit", "remote_main"]) {
    if (!COMMIT.test(values[key])) throw new Error(`source identity is not a full commit: ${key}`);
  }
  if (!SHA256.test(values.archive_sha256)) throw new Error("source identity archive hash is not a SHA-256 value");
  return values;
}

export function validateSdkIdentity(text, expected) {
  const values = parseIdentity(text, ["tag_ref", "tag_object", "tag_commit", "version"]);
  if (values.tag_ref !== expected.tagRef || values.version !== expected.version) {
    throw new Error("SDK identity does not match the expected fixture release");
  }
  for (const key of ["tag_object", "tag_commit"]) {
    if (!COMMIT.test(values[key])) throw new Error(`SDK identity is not a full commit: ${key}`);
  }
  return values;
}

export function isConfirmedNotFound(status, stderr) {
  if (status !== 1 || typeof stderr !== "string" || Buffer.byteLength(stderr, "utf8") > MAX_IDENTITY_BYTES) return false;
  const lines = stderr.trim().split(/\r?\n/u).filter(Boolean);
  return lines.length === 1 && /^gh:\s+.+\(HTTP 404\)$/u.test(lines[0]);
}

function validateReleaseShape(release, expected) {
  if (!release || typeof release !== "object") throw new Error("GitHub Release response is not an object");
  if (
    release.tag_name !== expected.tag || release.name !== expected.tag ||
    release.prerelease !== false || release.draft !== expected.draft ||
    (expected.immutable !== undefined && release.immutable !== expected.immutable)
  ) throw new Error("GitHub Release identity or state is not exact");
  if (!Array.isArray(release.assets) || release.assets.length !== 1) {
    throw new Error("GitHub Release must contain exactly one archive asset");
  }
  const [asset] = release.assets;
  if (
    asset?.name !== expected.archiveName || asset.state !== "uploaded" ||
    asset.size !== expected.size || asset.digest !== expected.digest
  ) throw new Error("GitHub Release archive asset does not match the tested bytes");
  return true;
}

export function classifyExistingDraft(release, expected) {
  if (!release || typeof release !== "object") throw new Error("GitHub Release response is not an object");
  if (release.tag_name !== expected.tag || release.name !== expected.tag || release.prerelease !== false || release.draft !== true) {
    throw new Error("an existing published, prerelease, or mismatched Release cannot be reused");
  }
  if (!Array.isArray(release.assets) || release.assets.length > 1) throw new Error("existing draft has unexpected assets");
  if (release.assets.length === 0) return "draft-empty";
  validateReleaseShape(release, { ...expected, draft: true });
  return "draft-exact";
}

export function validateDraft(release, expected) {
  return validateReleaseShape(release, { ...expected, draft: true });
}

export function validatePublished(release, expected) {
  return validateReleaseShape(release, { ...expected, draft: false, immutable: true });
}
