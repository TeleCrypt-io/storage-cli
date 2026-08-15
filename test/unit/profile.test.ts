import { afterEach, describe, expect, it, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  ensureProfileDir,
  validatePrivateFile,
  writePrivateFileAtomic,
} from "../../src/profile.js";

const createdDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-profile-unit-"));
  createdDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of createdDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("profile private-path validation", () => {
  it("rejects profile directories with group or other permissions", () => {
    const dir = makeTempDir();
    fs.chmodSync(dir, 0o755);

    expect(() => ensureProfileDir(dir)).toThrow(/permissions are too broad/);
  });

  it("rejects symbolic links and wrong file types", () => {
    const dir = makeTempDir();
    const regularFile = path.join(dir, "regular");
    const link = path.join(dir, "link");
    fs.writeFileSync(regularFile, "secret", { mode: 0o600 });
    fs.symlinkSync(regularFile, link);

    expect(() => validatePrivateFile(link, "session file")).toThrow(/not a symbolic link/);
    expect(() => validatePrivateFile(dir, "session file")).toThrow(/regular file/);
    expect(() => ensureProfileDir(regularFile)).toThrow(/regular directory/);
  });

  it("rejects files whose owner is not the current user", () => {
    const target = path.join(makeTempDir(), "session.json");
    fs.writeFileSync(target, "secret", { mode: 0o600 });
    const actualUid = fs.lstatSync(target).uid;
    vi.spyOn(process, "getuid").mockReturnValue(actualUid + 1);

    expect(() => validatePrivateFile(target, "session file")).toThrow(/not owned by the current user/);
  });
});

describe("writePrivateFileAtomic", () => {
  it("creates a 0600 file and leaves no temporary file behind", () => {
    const dir = path.join(makeTempDir(), "profile");
    const target = path.join(dir, "session.json");

    writePrivateFileAtomic(target, "first secret");

    expect(fs.readFileSync(target, "utf8")).toBe("first secret");
    expect(fs.lstatSync(target).mode & 0o777).toBe(0o600);
    expect(fs.lstatSync(dir).mode & 0o777).toBe(0o700);
    expect(fs.readdirSync(dir)).toEqual(["session.json"]);
  });

  it("refuses to replace an existing insecure file", () => {
    const dir = makeTempDir();
    const target = path.join(dir, "session.json");
    fs.writeFileSync(target, "old secret", { mode: 0o600 });
    fs.chmodSync(target, 0o644);

    expect(() => writePrivateFileAtomic(target, "new secret")).toThrow(/permissions are too broad/);
    expect(fs.readFileSync(target, "utf8")).toBe("old secret");
  });
});
