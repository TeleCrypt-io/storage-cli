import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const LICENSE_FILES = new Set([
  "LICENSE",
  "LICENCE",
  "COPYING",
  "license",
  "LICENSE.md",
  "LICENSE-MIT",
]);

export function generateThirdPartyLicenses(lock, modulesDirectory = "node_modules") {
  const packages = lock?.packages;
  if (!packages || typeof packages !== "object") throw new Error("package lock is invalid");

  const bundled = Object.entries(packages)
    .filter(([name, entry]) => name.startsWith("node_modules/") && entry?.inBundle === true)
    .sort(([left], [right]) => left.localeCompare(right));
  if (bundled.length === 0) throw new Error("package lock has no bundled dependencies");

  const rows = bundled.map(([lockPath, entry]) => {
    const relativePath = lockPath.slice("node_modules/".length);
    const packageName = entry.name ?? relativePath;
    if (!entry.version || !entry.license) throw new Error(`dependency metadata is missing for ${packageName}`);
    const files = fs.readdirSync(path.join(modulesDirectory, relativePath));
    const licenses = files.filter((file) => LICENSE_FILES.has(file));
    if (!files.includes("package.json") || licenses.length !== 1) {
      throw new Error(`expected one package manifest and license file for ${packageName}`);
    }
    return `${packageName}\t${entry.version}\t${entry.license}\tpackage/${relativePath}/${licenses[0]}`;
  });
  return `${rows.join("\n")}\n`;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [lockPath, modulesDirectory, outputPath] = process.argv.slice(2);
  if (!lockPath || !modulesDirectory || !outputPath) {
    throw new Error("usage: generateThirdPartyLicenses.mjs LOCKFILE NODE_MODULES OUTPUT");
  }
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  fs.writeFileSync(outputPath, generateThirdPartyLicenses(lock, modulesDirectory), "utf8");
}
