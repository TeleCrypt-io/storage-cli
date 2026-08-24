const RELEASE_TAG = /^storage-cli-v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$/u;
const COMMIT = /^(?!0{40}$)[0-9a-f]{40}$/u;

export function releaseVersionForTag(tag) {
  return typeof tag === "string" ? RELEASE_TAG.exec(tag)?.[1] ?? null : null;
}

export function isCommit(value) {
  return typeof value === "string" && COMMIT.test(value);
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).href === import.meta.url) {
  const [tag, commit] = process.argv.slice(2);
  if (!releaseVersionForTag(tag) || !isCommit(commit)) {
    throw new Error("usage: verifyReleaseSource.mjs storage-cli-vX.Y.Z COMMIT");
  }
}
