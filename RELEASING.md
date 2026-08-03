# Releasing `storage-cli`

`storage-cli` is distributed only as an immutable GitHub Release artifact. It is **not**
published to the NPM registry and needs no NPM token, Trusted Publisher, or package settings.

Each release contains:

- `storage-cli-vX.Y.Z.tgz`: compiled CLI plus bundled, lockfile-resolved production dependencies;
- `SHA256SUMS`: SHA-256 checksum for that archive.
- a GitHub build-provenance attestation for the archive.

The archive can be installed directly with the standard Node installer:

```sh
npm install -g https://github.com/TeleCrypt-io/storage-cli/releases/download/storage-cli-vX.Y.Z/storage-cli-vX.Y.Z.tgz
```

The package bundles its runtime dependencies, including the exact storage-library version. The
installer therefore does not need to resolve packages from the NPM registry. Node 22.14 through
22.x is required.

## Release flow

1. Set the exact semver version in `package.json` and commit it.
2. Verify `main` through the ordinary GitHub Actions workflow.
3. Create and push a fresh immutable tag whose version exactly matches the manifest:

   ```sh
   git tag storage-cli-vX.Y.Z
   git push origin storage-cli-vX.Y.Z
   ```

4. GitHub Actions checks that the tag and manifest agree, runs `npm ci`, lint, and build once,
   packages the compiled output with bundled dependencies, and performs an **offline** global
   installation check of that archive.
5. Only after all checks pass, the workflow creates the GitHub Release and attaches the archive
   and checksum. The release tag is the complete deployment and rollback identity.

Never replace, delete, or rebuild a release archive. A correction requires a new source commit,
new semver version, and a fresh immutable `storage-cli-v*` tag.
