# Releasing Halos

Releases are cut by pushing a `vX.Y.Z` tag. `.github/workflows/release.yml` then runs
GoReleaser (`.goreleaser.yaml`) and publishes:

- GitHub Release with archives for `halo`, `halod`, `halo-shadow`, `halo-server`, `halo-proxy`
  (darwin/linux/windows, amd64/arm64) and `halo-kong` (linux), plus `checksums.txt`
- deb/rpm/apk packages for `halo` and `halod`
- SBOMs (syft) and keyless cosign signatures for the checksums and images. `checksums.txt` is signed
  as a Sigstore bundle, `checksums.txt.sigstore.json` (cosign v3), which `install.sh`/`install.ps1` verify
- multi-arch images on `ghcr.io/dshakes/{halo-server,halo-proxy,halo-shadow,kong-halo}`, signed with cosign
- Homebrew formula (`dshakes/homebrew-tap`) and Scoop manifest (`dshakes/scoop-bucket`)
- winget manifest, written to `dist/winget` only; submit it to `microsoft/winget-pkgs` by hand

## Steps

1. Move `CHANGELOG.md` entries from Unreleased under the new version heading; merge to `main`.
2. Tag the merge commit and push the tag (needs a human; the tag is the release gate):
   `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`
3. Watch the `release` workflow. A tag with a prerelease suffix (`v1.0.0-rc.1`) builds everything
   but is published as a GitHub prerelease, does not move the `latest` image tag, and GoReleaser does
   not push the tap/bucket manifests.

Re-run for an existing tag: Actions > release > Run workflow, choosing the tag itself under "Use workflow
from" and setting `tag` to it. The installers pin the signing identity to
`release.yml@refs/tags/<tag>`, so a run started from a branch produces a signature they reject.

Dry run on a laptop (no publish, signing, SBOM or Docker):
`goreleaser release --snapshot --clean --skip=publish,sign,sbom,docker`

## Secrets

| Secret | Required | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | built in | GitHub Release, ghcr.io push, cosign OIDC (job permissions: `contents`, `packages`, `id-token` write) |
| `HOMEBREW_TAP_TOKEN` | optional | PAT with contents:write on `dshakes/homebrew-tap` and `dshakes/scoop-bucket` |

If `HOMEBREW_TAP_TOKEN` is unset or empty, `.goreleaser.yaml` sets `skip_upload: true` for brew and
scoop: the release succeeds and the manifests are only written to `dist/` (not uploaded as release
assets). Publish them by hand or add the secret and re-run the workflow.

The web console is built in a separate job with no credentials (`npm ci --ignore-scripts`); the
release job downloads `web/dist` and sets `HALO_WEB_PREBUILT=1`.

## Known issue

`goreleaser check` reports `brews` as deprecated (exit 2) in current GoReleaser v2. The release
itself is unaffected; migrate to `homebrew_casks` or keep `brews` for Linux Homebrew deliberately.
