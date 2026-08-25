import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  classifyExistingDraft,
  findReleaseByTag,
  isConfirmedNotFound,
  parseReleaseList,
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
const sdkIdentity = `tag_ref=refs/tags/v0.5.10\ntag_object=${"d".repeat(40)}\ntag_commit=${"e".repeat(40)}\nversion=0.5.10\n`;

function release(overrides = {}) {
  return {
    id: 123,
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
        version: "0.5.10",
        resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.10.tgz",
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
  assert.equal(validateSdkIdentity(sdkIdentity, { tagRef: "refs/tags/v0.5.10", version: "0.5.10" }).version, "0.5.10");
  assert.throws(() => validateSourceIdentity(`${sourceIdentity}extra=x\n`, {}), /framing|keys/u);
  assert.throws(() => validateSourceIdentity(sourceIdentity.replace(/archive_sha256=f+/u, "archive_sha256=bad"), {}), /hash/u);
  assert.throws(() => validateSdkIdentity(sdkIdentity.replace(/version=0.5.10/u, "version=0.5.11"), {
    tagRef: "refs/tags/v0.5.10",
    version: "0.5.10",
  }), /fixture/u);
  assert.throws(
    () => validateSourceIdentity(sourceIdentity.replace(new RegExp(`${commit}(?=\\nremote_main)`), "0".repeat(40)), {}),
    /commit/u,
  );
  assert.throws(
    () => validateSdkIdentity(sdkIdentity.replace(/e{40}(?=\nversion)/u, "0".repeat(40)), {
      tagRef: "refs/tags/v0.5.10",
      version: "0.5.10",
    }),
    /commit/u,
  );
  assert.throws(() => validateSourceIdentity(sourceIdentity.replace(/\n$/u, " "), {}), /newline/u);
});

test("the SDK consumer contract requires exact registry bytes", () => {
  const lock = {
    packages: {
      "node_modules/@telecrypt-io/storage": {
        name: "@telecrypt-io/storage",
        version: "0.5.10",
        resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.10.tgz",
        integrity: "",
      },
    },
  };
  assert.throws(() => verifySdkPackageBinding("/unavailable/sdk.tgz", lock, "0.5.10"), /integrity/u);
});

test("the SDK consumer contract accepts a normal npm v3 lock entry without name or gitHead", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "storage-sdk-binding-test-"));
  try {
    const packageDirectory = path.join(directory, "package");
    const archivePath = path.join(directory, "storage-0.5.10.tgz");
    fs.mkdirSync(packageDirectory);
    fs.writeFileSync(
      path.join(packageDirectory, "package.json"),
      JSON.stringify({ name: "@telecrypt-io/storage", version: "0.5.10" }),
    );
    execFileSync("tar", ["-czf", archivePath, "-C", directory, "package"]);
    const integrity = `sha512-${createHash("sha512").update(fs.readFileSync(archivePath)).digest("base64")}`;
    const lock = {
      packages: {
        "node_modules/@telecrypt-io/storage": {
          version: "0.5.10",
          resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.10.tgz",
          integrity,
          inBundle: true,
          license: "BUSL-1.1",
        },
      },
    };
    assert.equal(verifySdkPackageBinding(archivePath, lock, "0.5.10"), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the SDK consumer contract rejects malformed package, lock, bytes, and version identities", () => {
  const validMetadata = { name: "@telecrypt-io/storage", version: "0.5.10" };
  const fixtures = [];
  const valid = makeSdkArchive(validMetadata);
  fixtures.push(valid);
  try {
    assert.equal(verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), "0.5.10"), true);

    for (const packageJson of [
      { ...validMetadata, name: "@telecrypt-io/not-storage" },
      { ...validMetadata, version: "0.5.11" },
    ]) {
      const malformed = makeSdkArchive(packageJson);
      fixtures.push(malformed);
      assert.throws(
        () => verifySdkPackageBinding(malformed.archivePath, sdkLock(malformed.integrity), "0.5.10"),
        /identity/u,
      );
    }

    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity, { name: "@telecrypt-io/not-storage" }), "0.5.10"),
      /lockfile/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(
        valid.archivePath,
        sdkLock(valid.integrity, { resolved: "https://registry.npmjs.org/@telecrypt-io/storage/-/storage-0.5.11.tgz" }),
        "0.5.10",
      ),
      /provenance/u,
    );

    const differentBytes = makeSdkArchive({ ...validMetadata, marker: "different" });
    fixtures.push(differentBytes);
    assert.throws(
      () => verifySdkPackageBinding(differentBytes.archivePath, sdkLock(valid.integrity), "0.5.10"),
      /bytes/u,
    );
    assert.throws(
      () => verifySdkPackageBinding(valid.archivePath, sdkLock(valid.integrity), "01.2.3"),
      /semver/u,
    );
  } finally {
    for (const fixture of fixtures) fs.rmSync(fixture.directory, { recursive: true, force: true });
  }
});

test("the SDK CLI verifier bounds its lockfile input", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "storage-sdk-binding-lock-bound-"));
  try {
    const lockPath = path.join(directory, "package-lock.json");
    fs.writeFileSync(lockPath, `${JSON.stringify({ packages: {} })}${"x".repeat(131_072)}`);
    assert.throws(
      () => execFileSync(process.execPath, [
        fileURLToPath(new URL("../scripts/verifySdkPackage.mjs", import.meta.url)),
        "/unavailable/sdk.tgz",
        lockPath,
        "0.5.10",
      ], { encoding: "utf8", stdio: "pipe" }),
      /bounded JSON input/u,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("the release workflow performs npm signature verification before SDK provenance binding", () => {
  const workflow = fs.readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  const audit = workflow.indexOf("npm audit signatures");
  const consumer = workflow.indexOf("scripts/verifySdkPackage.mjs");
  const provenance = workflow.indexOf("storage-sdk/scripts/verify-npm-provenance.mjs");
  assert.ok(audit >= 0 && consumer >= 0 && provenance >= 0 && audit < consumer && consumer < provenance);
  assert.doesNotMatch(workflow, /gitHead/u);
  assert.match(workflow, /SDK_REF: v0\.5\.10/u);
  assert.match(workflow, /if test "\$status" = 0; then\s+return 1\s+fi\s+return "\$status"/u);
});

test("the release workflow discovers drafts through complete paginated list records", () => {
  const workflow = fs.readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  assert.match(workflow, /api --paginate --jq '\.\[\] \| @json'/u);
  assert.match(workflow, /parseReleaseList/u);
  assert.match(workflow, /Number\.isSafeInteger\(release\.id\)/u);
  assert.match(workflow, /release_resource_endpoint/u);
  assert.match(workflow, /api --method POST[\s\S]+https:\/\/uploads\.github\.com\/\$\{release_resource_endpoint\}\/assets/u);
  assert.doesNotMatch(workflow, /release upload/u);
  assert.doesNotMatch(workflow, /releases\/tags/u);
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

test("release list discovery selects one exact tag and rejects ambiguity", () => {
  assert.equal(findReleaseByTag([], tag), null);
  assert.deepEqual(findReleaseByTag([{ id: 456, tag_name: "other" }, release()], tag), release());
  assert.throws(() => findReleaseByTag([release(), { ...release(), id: 456 }], tag), /multiple Releases/u);
  assert.throws(() => findReleaseByTag({}, tag), /release list/u);
  assert.throws(() => findReleaseByTag([{ ...release(), id: "123" }], tag), /list entry/u);
});

test("release list parsing is bounded and fails closed on incomplete pagination", () => {
  const encoded = [release(), { ...release(), id: 456, tag_name: "other" }]
    .map((entry) => JSON.stringify(JSON.stringify(entry))).join("\n");
  assert.deepEqual(parseReleaseList(`${encoded}\n`), [release(), { ...release(), id: 456, tag_name: "other" }]);
  const raw = [release(), { ...release(), id: 456, tag_name: "other" }].map((entry) => JSON.stringify(entry)).join("\n");
  assert.deepEqual(parseReleaseList(`${raw}\n`), [release(), { ...release(), id: 456, tag_name: "other" }]);
  assert.deepEqual(parseReleaseList(""), []);
  assert.throws(() => parseReleaseList("{}"), /incomplete/u);
  assert.throws(() => parseReleaseList("x".repeat(1_048_577)), /bounded/u);
  assert.throws(() => parseReleaseList(`${encoded.slice(0, -3)}\n`), /incomplete/u);
  assert.throws(() => parseReleaseList(`${JSON.stringify(JSON.stringify(release()))}\n${JSON.stringify(JSON.stringify(release()))}\n`), /duplicate/u);
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
