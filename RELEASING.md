# Releasing Halos

A release is one annotated `vX.Y.Z` (or `vX.Y.Z-rc.N`) tag on `main`. Everything after the tag
is automated by `.github/workflows/release.yml`; a human only decides *when*.

## Cut a release

1. Land a PR on `main` that moves the `CHANGELOG.md` entries under `## [X.Y.Z] - YYYY-MM-DD`
   (an rc may use its own `## [X.Y.Z-rc.N]` section or the `## [X.Y.Z]` one it soaks for).
   `main` is protected; nothing pushes to it directly.
2. From an up-to-date, clean `main` checkout:

   ```sh
   scripts/release.sh --dry-run v0.2.0-rc.1   # every check, nothing pushed
   scripts/release.sh v0.2.0-rc.1             # same checks, then tag + push (asks first; --yes skips)
   ```

   Preflight: on `main`, clean tree, `HEAD == origin/main`, tag is strict SemVer and unused (and an
   rc's final is not already out), a non-empty CHANGELOG section, the latest `ci` run on `main` is
   green for `HEAD`, `go test ./...`, and `goreleaser check` (only the known `brews` deprecation is
   tolerated). It pushes the tag only, never a branch.
3. Watch the run (Actions > release). It fails loudly; a green `verify` job is the release being done.

## What the workflow does

| Job | Does | Permissions |
|---|---|---|
| `gate` | Tag is strict SemVer and on `main`; a final tag has `HOMEBREW_TAP_TOKEN` (fails, never skips); CHANGELOG section exists; `go vet`, `go test -race ./...` | `contents: read` |
| `web` | Builds the console with no credentials (`npm ci --ignore-scripts`) | `contents: read` |
| `release` | GoReleaser with the CHANGELOG section as notes: archives, deb/rpm/apk, syft SBOMs, `checksums.txt` + cosign Sigstore bundle, signed multi-arch images on `ghcr.io/dshakes/{halo-server,halo-proxy,halo-shadow,kong-halo}`, Homebrew + Scoop (final only). Then GitHub build provenance attestations for every archive | `contents`, `packages`, `id-token`, `attestations: write` |
| `verify` | From published artifacts only: `cosign verify-blob` on `checksums.txt`, one archive's sha256, `gh attestation verify` on it, `cosign verify` on all four images at `:X.Y.Z`, `install.sh --version` then `halo version`, and (final) `Formula/halo.rb` + `halo.json` are at `X.Y.Z` | read only |

`release-drift.yml` (daily, and on every push to `main`) fails if the tap formula or Scoop manifest
is not at the latest final release (`v0.1.1` is the first final it checks against).

Runs share one `release` concurrency group and are never cancelled mid-publish.

## Release candidates

- An rc tag (`vX.Y.Z-rc.N`) builds and signs everything, publishes a GitHub *prerelease*, pushes
  `:X.Y.Z-rc.N` images but never moves `:latest`, and does not touch the tap or bucket.
- Soak: the final is tagged on a commit that ran as an rc for at least 48 hours on a canary ring
  with no open P0/P1. Any code change after the rc means a new rc; a CHANGELOG-only PR does not.

## Re-run

Actions > release > Run workflow: choose the **tag** under "Use workflow from" and set `tag` to it.
The installers pin the signing identity to `release.yml@refs/tags/<tag>`, so the gate refuses a run
started from a branch. A re-run finishes a partial release: it rebuilds and re-signs, replaces
existing assets (`replace_existing_artifacts`) and re-pushes images and tap/bucket at the same
version. Builds are not bit-reproducible, so re-run before announcing, not after.

## Secrets and repos

| Name | Purpose |
|---|---|
| `GITHUB_TOKEN` | built in: release, ghcr.io, cosign + attestation OIDC |
| `HOMEBREW_TAP_TOKEN` | PAT, contents:write on `dshakes/homebrew-tap` and `dshakes/scoop-bucket`. Required for final tags (the gate fails without it) |
| `dshakes/homebrew-tap` | `Formula/halo.rb`, written by GoReleaser |
| `dshakes/scoop-bucket` | `halo.json`, written by GoReleaser |

## Automated vs manual

Automated: everything above. Manual: the CHANGELOG PR, choosing the tag, the soak, and **winget**.
GoReleaser only writes the winget manifest to `dist/winget`; build it from a checkout of the tag
(`goreleaser release --clean --skip=publish,sign,sbom,docker`) and open a PR on
`microsoft/winget-pkgs` by hand.

Local dry run of the build (no publish, signing, SBOM or Docker):
`goreleaser release --snapshot --clean --skip=publish,sign,sbom,docker`

## Roll back (yank) a release

Never delete or move the tag: installers, attestations and image signatures are bound to it.

1. Withdraw it: `gh release edit vX.Y.Z --prerelease` (drops "Latest", keeps the assets for anyone
   pinned to it) or `gh release delete vX.Y.Z` (assets gone; `install.sh --version vX.Y.Z` fails).
2. Homebrew/Scoop: revert the GoReleaser commit in `dshakes/homebrew-tap` and `dshakes/scoop-bucket`
   (`git revert <sha>`). `release-drift` then checks them against the new latest final.
3. Images: point `:latest` back at the previous version, for each of the four images:
   `docker buildx imagetools create -t ghcr.io/dshakes/halo-server:latest ghcr.io/dshakes/halo-server:<prev>`.
   The `:X.Y.Z` tags stay.
4. Say why in the release notes (and a security advisory if it is a security fix).

Signatures and attestations stay valid: they prove where the artifacts came from, not that they are
fit to use. Withdrawn means not offered, not unsigned. Ship the fix as a new version; never reuse one.

## Known issue

`goreleaser check` reports `brews` as deprecated (exit 2) in GoReleaser v2. The release is
unaffected; `scripts/release.sh` tolerates exactly that deprecation.
