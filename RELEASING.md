# Releasing `storage-cli`

`storage-cli` is distributed only as an immutable GitHub Release artifact. It is **not**
published to the NPM registry and needs no NPM token, Trusted Publisher, or package settings.

Each release contains:

- `storage-cli-vX.Y.Z.tgz`: compiled CLI, bundled lockfile-resolved production dependencies, and
  the generated `THIRD-PARTY-LICENSES.txt` inventory with each bundled package's license file.

The release workflow does not generate a provenance attestation. Release integrity is established
by the immutable annotated tag, the exact tested archive digest, and the immutable Release asset
checks described below.

The archive can be installed directly with the standard Node installer:

```sh
npm install -g --ignore-scripts https://github.com/TeleCrypt-io/storage-cli/releases/download/storage-cli-vX.Y.Z/storage-cli-vX.Y.Z.tgz
```

The package bundles its runtime dependencies, including the exact storage-library version. The
installer therefore does not need to resolve packages from the NPM registry. The supported runtime
is Linux with Node.js `>=22.23.2`; release verification uses that exact pinned Node.js version and the bundled npm `10.9.8`.

## Release flow

1. Set the exact semver version in `package.json` and commit it.
2. Verify `main` through the ordinary GitHub Actions workflow.
3. Create and push a fresh annotated tag whose version exactly matches the manifest:

   ```sh
   git tag -a storage-cli-vX.Y.Z -m "Release storage-cli-vX.Y.Z"
   git push origin storage-cli-vX.Y.Z
   ```

4. Before creating the tag, an operator with repository-administration access verifies that **immutable releases are enabled** and that the repository has one active ruleset targeting **all tags**, with no bypasses or exclusions, which forbids both tag updates and tag deletion. Record those two repository prerequisites in the Harness release evidence. The Actions token intentionally has no administration authority and does not attempt these settings queries. GitHub Actions then checks that the tag and manifest agree, runs `npm ci --ignore-scripts`, lint, unit tests, and build once, and packages the compiled output with bundled dependencies. Hosted Actions never runs Harness or functional acceptance scenarios; run those scenarios only from the local operator checkout against the disposable fixture.
   The archive validator also requires every bundled lockfile
   package to have an HTTPS `registry.npmjs.org` tarball URL matching its exact package/version,
   SHA-512 integrity, package metadata, and a direct license file.
   For the SDK specifically, the consumer release gate also downloads the exact registry tarball
   selected by the lockfile, recomputes its SHA-512 bytes, and requires the published package
   metadata `gitHead` to equal the checked annotated SDK tag commit. That final binding remains
   deliberately deferred until the SDK 0.5 artifact and its release-workflow evidence exist.
5. Only after all checks pass, the publish job downloads the tested archive and revalidates the exact
   remote annotated tag object, peeled commit, tag ref, and authoritative current `main` tip immediately before
   every Release mutation. Git and GitHub transport configuration is isolated to canonical HTTPS
   endpoints. The recorded SDK release tag object and commit are also revalidated at publication.
   It creates one exact draft when none exists, uploads the archive, and verifies
   the draft's one asset and digest. A rerun may reuse only that same exact draft and asset; an
   existing published, prerelease, mismatched, or altered Release is rejected. The workflow then
   publishes the verified draft and checks the non-draft, non-prerelease immutable Release and its
   one archive asset against the tested bytes. The archive's extracted license inventory must also
   match the lockfile-derived inventory byte for byte.

Never replace, delete, or rebuild a release archive. A correction requires a new source commit,
new semver version, and a fresh annotated `storage-cli-v*` tag.

No release is currently eligible: the release gate requires the exact published, immutable
`@telecrypt-io/storage` `0.5.0` / `matrix-js-sdk` `42.2.0` binding, while the manifest and lockfile
remain on their available exact releases. Do not manufacture dependency metadata or claim release
readiness while those exact registry and Release identities are unavailable.
