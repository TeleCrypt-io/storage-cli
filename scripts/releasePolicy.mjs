const MAX_IDENTITY_BYTES = 64 * 1024;
const MAX_RELEASE_LIST_BYTES = 1_048_576;
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

function validateReleaseListEntry(release, seenIds) {
  if (!release || typeof release !== "object" || Array.isArray(release) ||
      !Number.isSafeInteger(release.id) || release.id < 1 || typeof release.tag_name !== "string" || release.tag_name === "") {
    throw new Error("GitHub Release list entry is invalid");
  }
  if (seenIds.has(release.id)) throw new Error("duplicate GitHub Release ID");
  seenIds.add(release.id);
  return release;
}

export function parseReleaseList(text) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_RELEASE_LIST_BYTES) {
    throw new Error("GitHub Release list is missing or exceeds the bounded length");
  }
  if (text === "") return [];
  if (!text.endsWith("\n")) throw new Error("GitHub Release list pagination is incomplete");
  const lines = text.split(/\r?\n/u);
  if (lines.at(-1) === "") lines.pop();
  if (lines.length === 0 || lines.some((line) => line === "")) throw new Error("GitHub Release list pagination is incomplete");
  const seenIds = new Set();
  return lines.map((line) => {
    let encoded;
    try {
      encoded = JSON.parse(line);
    } catch {
      throw new Error("GitHub Release list pagination is incomplete");
    }
    let release = encoded;
    if (typeof encoded === "string") {
      try {
        release = JSON.parse(encoded);
      } catch {
        throw new Error("GitHub Release list pagination is incomplete");
      }
    }
    return validateReleaseListEntry(release, seenIds);
  });
}

export function findReleaseByTag(releases, tag) {
  if (!Array.isArray(releases) || typeof tag !== "string" || tag === "") {
    throw new Error("release list or tag is invalid");
  }
  const seenIds = new Set();
  const entries = releases.map((release) => validateReleaseListEntry(release, seenIds));
  const matches = entries.filter((release) => release.tag_name === tag);
  if (matches.length > 1) throw new Error("multiple Releases match the expected tag");
  return matches[0] ?? null;
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
