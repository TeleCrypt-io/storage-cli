import { readFileSync } from "node:fs";

const EXPECTED = {
  "@telecrypt-io/storage": "0.5.11",
  "matrix-js-sdk": "42.2.0",
};
const SRI = /^sha512-[A-Za-z0-9+/]{86}==$/u;

const packageJson = JSON.parse(readFileSync("package.json", "utf8"));
const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
const root = lock?.packages?.[""];
if (!root || root.name !== packageJson.name || root.version !== packageJson.version) {
  throw new Error("package-lock.json root does not match package.json");
}

for (const [name, version] of Object.entries(EXPECTED)) {
  const entry = lock.packages?.[`node_modules/${name}`];
  const tarball = name.startsWith("@") ? name.slice(name.indexOf("/") + 1) : name;
  const resolved = `https://registry.npmjs.org/${name}/-/${tarball}-${version}.tgz`;
  if (
    packageJson.dependencies?.[name] !== version ||
    root.dependencies?.[name] !== version ||
    entry?.version !== version ||
    entry.resolved !== resolved ||
    !SRI.test(entry.integrity ?? "")
  ) {
    throw new Error(`${name} is not the exact locked ${version} registry artifact`);
  }
}

console.log("exact consumer dependency manifest and lock identities passed");
