import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import {
  classifyExistingDraft,
  isConfirmedNotFound,
  validateDraft,
  validatePublished,
  validateSdkIdentity,
  validateSourceIdentity,
} from "../scripts/releasePolicy.mjs";
import { verifySdkPackageBinding } from "../scripts/verifySdkPackage.mjs";

const tag = "storage-cli-v1.2.3";
const archive = `${tag}.tgz`;
const digest = `sha256:${"a".repeat(64)}`;
const commit = "b".repeat(40);
const sourceIdentity = `tag_ref=refs/tags/${tag}\ntag_object=${"c".repeat(40)}\ntag_commit=${commit}\nremote_main=${commit}\narchive_sha256=${"f".repeat(64)}\n`;
const sdkIdentity = `tag_ref=refs/tags/v0.5.0\ntag_object=${"d".repeat(40)}\ntag_commit=${"e".repeat(40)}\nversion=0.5.0\n`;

function release(overrides = {}) {
  return {
    tag_name: tag,
    name: tag,
    draft: true,
    prerelease: false,
    immutable: false,
    assets: [{ name: archive, state: "uploaded", size: 12, digest }],
    ...overrides,
  };
}

const expected = { tag, archiveName: archive, size: 12, digest };

function makeSdkArchive(packageJson) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "storage-sdk-binding-adversarial-"));
  const packageDirectory = path.join(directory, "package");
  const archivePath = path.join(directory, "storage-sdk.tgz");
  fs.mkdirSync(packageDirectory);
  fs.writeFileSync(path.join(packageDirectory, "package.json"), JSON.stringify(packageJson));
  execFileSync("tar", ["-czf", archivePath, "-C", directory, "package"]);
  const integrity = `sha512-${createHash("sha512").update(fs.readFileSync(archivePath)).digest("base64")}`;
  return { directory, archivePath, integrity };
}

function sdkLock(integrity, overrides = {}) {
  return {
    packages: {
      "node_modules/@telecrypt-io/storage": {
        version: "0.5.0",
        resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.0.tgz",
        integrity,
        ...overrides,
      },
    },
  };
}

test("source and SDK identity files are exact and bounded", () => {
  assert.deepEqual(validateSourceIdentity(sourceIdentity, {
    tag_ref: `refs/tags/${tag}`,
    tag_object: "c".repeat(40),
    tag_commit: commit,
    remote_main: commit,
    archive_sha256: "f".repeat(64),
  }).tag_commit, commit);
  assert.equal(validateSdkIdentity(sdkIdentity, { tagRef: "refs/tags/v0.5.0", version: "0.5.0" }).version, "0.5.0");
  assert.throws(() => validateSourceIdentity(`${sourceIdentity}extra=x\n`, {}), /framing|keys/u);
  assert.throws(() => validateSourceIdentity(sourceIdentity.replace(/archive_sha256=f+/u, "archive_sha256=bad"), {}), /hash/u);
  assert.throws(() => validateSdkIdentity(sdkIdentity.replace(/version=0.5.0/u, "version=0.5.1"), {
    tagRef: "refs/tags/v0.5.0",
    version: "0.5.0",
  }), /fixture/u);
  assert.throws(
    () => validateSourceIdentity(sourceIdentity.replace(new RegExp(`${commit}(?=\\nremote_main)`), "0".repeat(40)), {}),
    /commit/u,
  );
  assert.throws(
    () => validateSdkIdentity(sdkIdentity.replace(/e{40}(?=\nversion)/u, "0".repeat(40)), {
      tagRef: "refs/tags/v0.5.0",
      version: "0.5.0",
    }),
    /commit/u,
  );
  assert.throws(() => validateSourceIdentity(sourceIdentity.replace(/\n$/u, " "), {}), /newline/u);
});

test("the SDK consumer contract requires exact registry bytes bound to the annotated tag", () => {
  const sdkCommit = "1".repeat(40);
  const lock = {
    packages: {
      "node_modules/@telecrypt-io/storage": {
        name: "@telecrypt-io/storage",
        version: "0.5.0",
        resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.0.tgz",
        integrity: "",
      },
    },
  };
  assert.throws(() => verifySdkPackageBinding("/unavailable/sdk.tgz", lock, sdkCommit, "0.5.0"), /integrity/u);
  assert.throws(() => verifySdkPackageBinding("/unavailable/sdk.tgz", lock, "not-a-commit", "0.5.0"), /commit/u);
});

test("the SDK consumer contract accepts a normal npm v3 lock entry without name", () => {
  const sdkCommit = "2".repeat(40);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "storage-sdk-binding-test-"));
  try {
    const packageDirectory = path.join(directory, "package");
    const archivePath = path.join(directory, "storage-0.5.0.tgz");
    fs.mkdirSync(packageDirectory);
    fs.writeFileSync(
      path.join(packageDirectory, "package.json"),
      JSON.stringify({ name: "@telecrypt-io/storage", version: "0.5.0", gitHead: sdkCommit }),
    );
    execFileSync("tar", ["-czf", archivePath, "-C", directory, "package"]);
    const integrity = `sha512-${createHash("sha512").update(fs.readFileSync(archivePath)).digest("base64")}`;
    const lock = {
      packages: {
        "node_modules/@telecrypt-io/storage": {
          version: "0.5.0",
          resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.0.tgz",
          integrity,
          inBundle: true,
          license: "BUSL-1.1",
        },
      },
    };
    assert.equal(verifySdkPackageBinding(archivePath, lock, sdkCommit, "0.5.0"), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the SDK consumer contract rejects malformed package, lock, bytes, version, and tag identities", () => {
  const sdkCommit = "3".repeat(40);
  const validMetadata = { name: "@telecrypt-io/storage", version: "0.5.0", gitHead: sdkCommit };
  const fixtures = [];
  const valid = makeSdkArchive(validMetadata);
  fixtures.push(valid);
  try {
    assert.equal(verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), sdkCommit, "0.5.0"), true);

    for (const packageJson of [
      { ...validMetadata, name: "@telecrypt-io/not-storage" },
      { ...validMetadata, version: "0.5.1" },
      { ...validMetadata, gitHead: "4".repeat(40) },
    ]) {
      const malformed = makeSdkArchive(packageJson);
      fixtures.push(malformed);
      assert.throws(
        () => verifySdkPackageBinding(malformed.archivePath, sdkLock(malformed.integrity), sdkCommit, "0.5.0"),
        /bound/u,
      );
    }

    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity, { name: "@telecrypt-io/not-storage" }), sdkCommit, "0.5.0"),
      /lockfile/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(
        valid.archivePath,
        sdkLock(valid.integrity, { resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.1.tgz" }),
        sdkCommit,
        "0.5.0",
      ),
      /provenance/u,
    );

    const differentBytes = makeSdkArchive({ ...validMetadata, gitHead: "5".repeat(40) });
    fixtures.push(differentBytes);
    assert.throws(
      () => verifySdkPackageBinding(differentBytes.archivePath, sdkLock(valid.integrity), sdkCommit, "0.5.0"),
      /bytes/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), sdkCommit, "01.2.3"),
      /semver/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), "0".repeat(40), "0.5.0"),
      /commit/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), "not-a-commit", "0.5.0"),
      /commit/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), "6".repeat(40), "0.5.0"),
      /bound/u,
    );
  } finally {
    for (const fixture of fixtures) fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("the packaged CLI keeps only its minimum Node engine constraint", () => {
  const packageJson = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(packageJson.engines?.node, ">=22.23.2");
});

test("only one bounded GitHub 404 is considered a missing Release", () => {
  assert.equal(isConfirmedNotFound(1, "gh: Not Found (HTTP 404)\n"), true);
  assert.equal(isConfirmedNotFound(124, "gh: Not Found (HTTP 404)\n"), false);
  assert.equal(isConfirmedNotFound(1, "timeout\ngh: Not Found (HTTP 404)\n"), false);
  assert.equal(isConfirmedNotFound(1, "gh: Forbidden (HTTP 403)\n"), false);
});

test("draft reuse accepts only an empty or exact one-asset draft", () => {
  assert.equal(classifyExistingDraft({ ...release(), assets: [] }, expected), "draft-empty");
  assert.equal(classifyExistingDraft(release(), expected), "draft-exact");
  assert.throws(() => classifyExistingDraft(release({ draft: false }), expected), /cannot be reused/u);
  assert.throws(() => classifyExistingDraft(release({ assets: [{}, {}] }), expected), /unexpected assets/u);
  assert.throws(() => classifyExistingDraft(release({ assets: [{ ...release().assets[0], digest: "sha256:bad" }] }), expected), /asset/u);
});

test("draft and published state checks require exact immutable asset identity", () => {
  assert.equal(validateDraft(release(), expected), true);
  assert.equal(validatePublished(release({ draft: false, immutable: true }), expected), true);
  assert.throws(() => validatePublished(release({ draft: false, immutable: false }), expected), /state/u);
  assert.throws(() => validateDraft(release({ assets: [] }), expected), /exactly one/u);
});
