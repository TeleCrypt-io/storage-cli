import { describe, expect, it } from "vitest";
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import * as os from "node:os";
import * as path from "node:path";
import { releaseVersionForTag, isCommit } from "../scripts/verifyReleaseSource.mjs";
import {
  validateArchiveEntries,
  validateArchiveListing,
  validateArchiveSourceContent,
  validateLicenseContent,
} from "../scripts/validateReleaseArchive.mjs";

const root = [
  "package/", "package/CLI.md", "package/LICENSE", "package/README.md",
  "package/THIRD-PARTY-LICENSES.txt", "package/package.json",
];
const dist = [
  "cancellation.d.ts", "cancellation.js", "cryptoSnapshot.d.ts", "cryptoSnapshot.js", "index.d.ts", "index.js",
  "fileTransfer.d.ts", "fileTransfer.js", "limits.d.ts", "limits.js", "loginTransaction.d.ts", "loginTransaction.js", "logout.d.ts", "logout.js",
  "oidc.d.ts", "oidc.js", "output.d.ts", "output.js", "processExit.d.ts", "processExit.js", "profile.d.ts", "profile.js",
  "recoveryInput.d.ts", "recoveryInput.js", "storage.d.ts", "storage.js", "topology.d.ts", "topology.js",
].map((name) => `package/dist/${name}`);

function archiveFor(packageFiles: string[] = ["package/node_modules/dep/LICENSE", "package/node_modules/dep/package.json"]): string[] {
  return [...root, ...dist, "package/node_modules/dep/", ...packageFiles];
}

function lock() {
  return {
    packages: {
      "node_modules/dep": {
        inBundle: true,
        name: "dep",
        version: "1.0.0",
        license: "MIT",
        resolved: "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz",
        integrity: `sha512-${"A".repeat(86)}==`,
      },
    },
  };
}

describe("release source and archive invariants", () => {
  it("accepts only exact release versions and full commit IDs", () => {
    expect(releaseVersionForTag("storage-cli-v1.2.3")).toBe("1.2.3");
    expect(releaseVersionForTag("storage-cli-v0.0.0")).toBe("0.0.0");
    expect(releaseVersionForTag("storage-cli-v01.2.3")).toBeNull();
    expect(releaseVersionForTag("storage-cli-v1.2")).toBeNull();
    expect(isCommit("a".repeat(40))).toBe(true);
    expect(isCommit("A".repeat(40))).toBe(false);
    expect(isCommit("a".repeat(39))).toBe(false);
    expect(isCommit("0".repeat(40))).toBe(false);
  });

  it("requires the exact source-owned archive paths and runtime inventory", () => {
    const inventory = validateArchiveEntries(archiveFor(), lock());
    expect(inventory).toBe("dep\t1.0.0\tMIT\tpackage/node_modules/dep/LICENSE\n");
    expect(() => validateArchiveEntries([...archiveFor(), "package/dist/extra.js"], lock())).toThrow(/unexpected compiled/u);
    expect(() => validateArchiveEntries([...archiveFor(), "package/node_modules/dep/../escape"], lock())).toThrow(/unsafe archive path/u);
  });

  it("requires registry provenance, integrity, and each bundled package license", () => {
    const missingLicense = archiveFor().filter((entry) => entry !== "package/node_modules/dep/LICENSE");
    expect(() => validateArchiveEntries(missingLicense, lock())).toThrow(/own license/u);
    const untrusted = lock();
    untrusted.packages["node_modules/dep"].resolved = "git+https://github.com/example/dep.git";
    expect(() => validateArchiveEntries(archiveFor(), untrusted)).toThrow(/registry provenance/u);
    const badIntegrity = lock();
    badIntegrity.packages["node_modules/dep"].integrity = "sha1-not-accepted";
    expect(() => validateArchiveEntries(archiveFor(), badIntegrity)).toThrow(/registry provenance/u);
    const alternatePort = lock();
    alternatePort.packages["node_modules/dep"].resolved = "https://registry.npmjs.org:444/dep/-/dep-1.0.0.tgz";
    expect(() => validateArchiveEntries(archiveFor(), alternatePort)).toThrow(/registry provenance/u);
  });

  it("accepts the exact license filename variants used by bundled registry packages", () => {
    for (const filename of ["license", "LICENSE.md", "LICENSE-MIT"]) {
      const inventory = validateArchiveEntries(
        archiveFor([`package/node_modules/dep/${filename}`, "package/node_modules/dep/package.json"]),
        lock(),
      );
      expect(inventory).toBe(`dep\t1.0.0\tMIT\tpackage/node_modules/dep/${filename}\n`);
    }
  });

  it("accepts only exact, regular, bounded, non-empty license members", () => {
    expect(validateLicenseContent("LICENSE", Buffer.from("MIT\n"))).toBe(true);
    expect(validateLicenseContent("LICENCE", Buffer.from("MIT\n"))).toBe(true);
    expect(validateLicenseContent("COPYING", Buffer.from("MIT\n"))).toBe(true);
    expect(validateLicenseContent("license", Buffer.from("MIT\n"))).toBe(true);
    expect(validateLicenseContent("LICENSE.md", Buffer.from("MIT\n"))).toBe(true);
    expect(validateLicenseContent("LICENSE-MIT", Buffer.from("MIT\n"))).toBe(true);
    expect(() => validateLicenseContent("LICENSE.txt", Buffer.from("MIT\n"))).toThrow(/unsupported/u);
    expect(() => validateLicenseContent("LICENSE", Buffer.alloc(0))).toThrow(/size/u);
    expect(() => validateLicenseContent("LICENSE", Buffer.alloc(1_048_577))).toThrow(/size/u);
    expect(() => validateLicenseContent("LICENSE", Buffer.from("MIT\n"), { type: "symlink", size: 4 })).toThrow(/regular/u);
    expect(() => validateLicenseContent("LICENSE", Buffer.from("MIT\n"), { type: "file", size: 3 })).toThrow(/size/u);
  });

  it("rejects duplicate, malformed, obsolete, and non-package archive members", () => {
    expect(() => validateArchiveEntries([...archiveFor(), "package/README.md"], lock())).toThrow(/duplicate/u);
    expect(() => validateArchiveEntries([...archiveFor(), "package\\escape"], lock())).toThrow(/invalid archive path/u);
    expect(() => validateArchiveEntries([...archiveFor(), "package/dist/oidcWindowPolyfill.js"], lock())).toThrow(/obsolete OIDC/u);
    expect(() => validateArchiveEntries([...archiveFor(), "other/file"], lock())).toThrow(/unexpected source-owned/u);
    expect(() => validateArchiveEntries([...archiveFor(), "package/test/harness/cliEntry.js"], lock())).toThrow(/unexpected source-owned/u);
  });

  it("requires exact regular tar members with bounded extraction sizes", () => {
    const listing = [
      "drwxr-xr-x 0/0 0 2026-08-24 00:00:00 package/",
      "-rw-r--r-- 0/0 4 2026-08-24 00:00:00 package/file",
    ].join("\n");
    expect(validateArchiveListing(`${listing}\n`, ["package/", "package/file"])).toBe(true);
    expect(() => validateArchiveListing(
      "lrwxrwxrwx 0/0 0 2026-08-24 00:00:00 package/file -> target\n",
      ["package/file"],
    )).toThrow(/non-regular/u);
    expect(() => validateArchiveListing(listing, ["package/", "package/other"])).toThrow(/exact|missing/u);
  });

  it("rejects test harness code and identity override markers from real archives", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-release-archive-test-"));
    try {
      fs.mkdirSync(path.join(dir, "package", "dist"), { recursive: true });
      const archivePath = path.join(dir, "release.tgz");
      const member = "package/dist/index.js";
      fs.writeFileSync(path.join(dir, member), "export const production = true;\n");
      execFileSync("tar", ["-czf", archivePath, "-C", dir, "package"]);
      expect(validateArchiveSourceContent(archivePath, [member])).toBe(true);

      for (const marker of [
        "TELECRYPT_IO_STORAGE_TEST_FIXTURE",
        "test/harness/cliEntry.ts",
        "CliRuntimeOptions",
        "activeRuntime",
        "TELECRYPT_IO_STORAGE_NO_BROWSER",
        "TELECRYPT_IO_STORAGE_DEBUG",
      ]) {
        fs.writeFileSync(path.join(dir, member), `${marker}\n`);
        execFileSync("tar", ["-czf", archivePath, "-C", dir, "package"]);
        expect(() => validateArchiveSourceContent(archivePath, [member])).toThrow(/forbidden test marker/u);
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
