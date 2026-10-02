---
title: "ADR-0008: Signed ring pointers and verified artifacts"
description: Rings are served by signed pointers with seq and expiry; CLIs install from hash-pinned artifacts, never from shell scripts.
status: accepted
date: 2026-09-30
---

# ADR-0008: Signed ring pointers and verified artifacts

- Status: accepted (refines ADR-0005)
- Date: 2026-09-30

## Context and problem statement

ADR-0005 signed releases and treated ring tags as convenience pointers. Building the agent showed two gaps:

1. A signed release does not authenticate the *ring to release mapping*. A registry operator can retag `ring-ga` to an older, validly signed release (rollback attack), to a release built for another ring or org, or freeze a ring forever.
2. `halod` runs as root. The manifest carried an `installCommand` (`curl | bash`, `npm install -g` with lifecycle scripts) and file paths chosen by the release. The signing key alone would then give arbitrary code execution and arbitrary file write as root.

## Decision drivers

- A compromised registry must not be able to roll clients back or freeze them silently.
- The signing key should be necessary but not sufficient for root-level damage.
- Rollback must remain a normal, fast operation.
- No new runtime dependency on the device.

## Considered options

1. Keep tags; rely on `halod` refusing older releases by version comparison.
2. Full TUF (root, targets, snapshot, timestamp roles, threshold keys).
3. "TUF-lite": one signed pointer per ring with `org`, `ring`, `digest`, `seq` and expiry; hash-pinned install artifacts; a fixed path allowlist in `halod`.

## Decision outcome

Chosen: **option 3**.

- Each ring has a signed pointer stored as an OCI artifact at tag `ring-<name>.pointer`, signed with a domain-separated statement. `halod` verifies it, checks `org` and `ring` against its config, refuses a `seq` lower than the last applied for that ring, refuses an expired pointer (7-day TTL), then fetches the release by content digest, and verifies the release signature.
- `seq = max(previous + 1, unix time)` (see the addendum for the signer-side rule). Rollback is a new pointer with a higher `seq` naming an older digest. `halo release refresh` re-signs a pointer on a schedule (daily) to keep it fresh.
- The release manifest carries verified install artifacts (https URL, exact size, sha256 or npm sha512 integrity) per OS and architecture. `halod` streams them under a size cap, refuses non-https redirects, checks the hash, and only then places them. npm tarballs install with `--ignore-scripts` and empty npmrc files using a root-owned Node. The legacy `installCommand` runs only with `allowShellInstall: true`.
- `halod` may write only under fixed per-harness directories, with a 0644 mode ceiling, and verifies that its config, key, token, state and their ancestors are root-owned and free of user-planted symlinks before it starts.
- The primary signer must be ed25519. cosign is an optional co-signature.

### Consequences

- Good: a registry compromise cannot replay an older release or serve one for another ring or org, and freezing is bounded by the expiry.
- Good: the signing key alone cannot write arbitrary files as root or run install scripts.
- Bad: **pointers must be refreshed at least weekly** or every client stops updating. This is an operational duty (see the production deployment guide).
- Bad: there is no threshold signing. Rotation overlaps keys (`pubkeys`) and a compromised key is blocked per device with `revokedKeys`, but there is no registry-side revocation list.
- Bad: paths and harness binaries are hard-coded in `halod`; adding a harness means changing the agent (Copilot CLI is rendered but not yet in the allowlist).

## Alternatives not chosen

Full TUF was deferred: its role and threshold machinery is more than the current threat model needs. If org-scale key custody requires it, the pointer format can be wrapped later.

## Addendum 2026-09-30: signer-side continuity

The pointer checks above protect the device. They did not protect the signer: `refresh` and `promote` took "what the registry serves" as input, so a registry that served an old, validly signed pointer got it re-signed with a higher `seq` and a fresh expiry, and `halod`'s anti-rollback accepted the result. A security review found this and a related gap: `promote` read the source ring from the unauthenticated `ring-<name>` tag, and `rollback --to <version>` trusted the `v<version>` tag.

### Decision

- **Promote follows the source ring's signed pointer.** `halo release promote` reads `--from-ring`'s pointer, verifying signature, ring, org, expiry and state continuity, fetches the release it names and checks the digest. The `ring-<from>` tag is never the source.
- **Rollback requires a version match.** `halo rollback --to <version>` refuses a release whose signed manifest does not carry that version. `--to sha256:<digest>` is the OCI **manifest** digest (content-addressed).
- **Refresh refuses expired pointers.** An expired pointer may be a replay; recovery is an explicit `halo rollback --to <version>`.
- **Signer state file.** `publish`, `promote`, `refresh` and `rollback` record the last pointer written per registry repo and ring (`seq`, `digest`, `issuedAt`) in `$XDG_STATE_HOME/halos/pointers.json` (`--state-file`). A served pointer with a lower `seq`, the same `seq` and another digest, or missing where one was written, is refused. The new `seq` is `max(served + 1, recorded + 1, unix now)`. The file is written atomically after the pointer is pushed; if the save fails after the push, the command reports that the pointer was published but the state was not updated. A missing file is empty state, but a served pointer the state has no record of is refused unless the operator adopts it explicitly (`--adopt-existing`) or pins it (`--expect-digest`), so an evicted CI cache cannot silently switch replay protection off; an unparseable file blocks signing.
- **`--expect-digest sha256:<release digest>`** on `refresh`, `promote` and `rollback` refuses unless the release involved is that one. It is the stateless guard for CI.
- **Visibility.** Before each signature the CLI prints `Signing ring X → version V (digest D, seq S)` to stderr.

### Consequences

- Good: a registry cannot launder an old pointer through the signer, and a retagged `v` or `ring-` tag cannot steer promote or rollback.
- Bad: **stateless CI has a gap.** A fresh runner has no state file, so the replay check is inert unless the file is cached between runs (the example workflow does this) or `--expect-digest` is passed. A missing file is empty state, but a served pointer with no record is refused unless the operator passes `--expect-digest` or `--adopt-existing`, so cache eviction is not silent; `--adopt-existing` trusts the served pointer, so that run has no replay protection (an unparseable file blocks signing). Prefer `--expect-digest` in CI.
- Bad: one signer per state file; there is no locking, and two signers with separate files do not see each other's writes.
- Bad: an expired ring needs a human-chosen `halo rollback --to <version>` instead of an automatic refresh.

## Addendum 2026-10-02: harness paths come from the adapter, not the agent

The consequence "paths and harness binaries are hard-coded in `halod`; adding a harness means changing the agent (Copilot CLI is rendered but not yet in the allowlist)" is superseded. `halod` derives the write allowlist, binary name and installer kind from each adapter's `harness.Meta`, so a new adapter is in the allowlist as soon as it registers, and Copilot CLI is covered (`cmd/halod` `TestHalodKnowsEveryHarness`). The allowlist stays fixed per release of `halod` (it is compiled in), which is the property the decision needs: the release signing key still cannot choose paths.

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Signed pointer at `ring-<name>.pointer`, domain-separated statement, `org`, `ring`, `digest`, `seq`, expiry | `internal/bundle/pointer.go` (`Pointer`, `PointerTag`, `signPointer`, `ReadPointer`) | `pointer_test.go` `TestPointerTamperedPayload`, `TestPointerCrossRingAndForeignKey`, `TestWriteRefusesForeignOrg` | Done |
| `halod` verifies org, ring, `seq` monotonic, 7-day expiry; fetches by digest; verifies release signature | `cmd/halod/agent.go` (`cycle`, state `Pointers[ring].Seq`); `bundle.PullRing` | `cmd/halod` `TestPointerFreshness` (replay, expiry, foreign org), `TestRefusesUnverified` | Done |
| `seq = max(previous + 1, unix now)`; rollback is a new pointer with higher `seq` | `internal/bundle/pointer.go` `writePointer` | `continuity_test.go` `TestPointerSeqIsMaxOfServedPlusOneAndNow`; `bundle_test.go` `TestImmutableVersionTagAndRollback` | Done |
| `halo release refresh` re-signs on a schedule | `cmd/halo/cmd_release.go` (`refresh`); `.github/workflows/refresh-pointers.yml.example`; [production deployment](/halos/guides/production-deployment/) (daily, alert on two failures) | `TestRefreshRefusesReplayedPointer`, `TestRefreshRefusesExpiredPointer`; `cmd/halo` `TestReleaseRegistryRetagAttack` | Done |
| Verified install artifacts (https, size, sha256 / npm sha512) per OS and arch | `internal/release` (`Artifact`), `cmd/halod/install.go` (`download`: size cap, no non-https redirect, hash check before placing) | `cmd/halod` `TestDownloadRefusals`, `TestInstallBadHashRejected`, `TestApplyInstallDriftAndRemoval` | Done |
| npm tarballs with `--ignore-scripts`, empty npmrc, root-owned Node | `cmd/halod/install.go` (`npmInstall`) | `TestNpmInstallArgs` | Done |
| Legacy `installCommand` only with `allowShellInstall: true` | `cmd/halod/agent.go` | `TestLegacyShellInstallGated` | Done |
| Fixed per-harness write directories, 0644 ceiling | `cmd/halod/paths.go` `allowedPath`; `agent.go` mode check with paths from `harness.Meta` | `TestAllowedPath`, `TestApplyRefusesUnsafeTargets`, `TestStrictWindowsPath`, `TestHalodKnowsEveryHarness` | Done (see addendum) |
| Preflight: config, key, token, state and ancestors root-owned, no user symlinks | `cmd/halod/main.go` `preflight` | `TestOwnershipPreflight`, `TestCheckACEs` (Windows) | Done |
| Primary signer ed25519; cosign optional co-signature; `halod` never runs cosign | `bundle.Signer`; `cmd/halod` verifies ed25519 only | `pointer_test.go` `TestPublishSignerRules`; `bundle_test.go` `TestCosignShellsOut` | Done |
| Key rotation overlap (`pubkeys`) and per-device `revokedKeys` | `cmd/halod/config.go`, `agent.go` (keyring) | `TestKeyringRotationAndRevocation` | Done |
| Pointers refreshed at least weekly (operational duty) | documented with a ready workflow; `halod` warns from 24 h before expiry | `TestPointerFreshness` (expiry refused) | Done |
| Promote follows the source ring's signed pointer, never the tag | `bundle.PromoteRing` (`Source`) | `continuity_test.go` `TestPromoteRollbackIgnoreRetaggedTags`; `TestReleaseRegistryRetagAttack` | Done |
| Rollback requires a version match; `--to sha256:` is the manifest digest | `cmd_release.go` (`rollback`), `bundle.RollbackRing` | `TestReleaseRegistryRetagAttack` ("rollback to retagged version") | Done |
| Refresh refuses expired pointers | `bundle.RefreshRing` | `TestRefreshRefusesExpiredPointer` | Done |
| Signer state file: atomic save, lower/equal-seq refusal, unknown pointer needs `--adopt-existing` or `--expect-digest`, unparseable blocks, save failure after push is reported | `internal/bundle/state.go`; `PublishRing` with `PointerOptions.State` | `TestPointerStateCheck`, `TestContinuityUnknownPointerNeedsAdoption`, `TestPointerStateSaveFailureReportsPublished`; `TestReleaseRegistryRetagAttack` (stateless `--expect-digest`, `--adopt-existing`) | Done |
| `--expect-digest` on refresh, promote, rollback | `cmd_release.go` | `TestReleaseRegistryRetagAttack` ("expect-digest mismatch") | Done |
| `Signing ring X → version V (digest D, seq S)` on stderr before each signature | `cmd_release.go:100` | `cmd_release_test.go` `TestReleaseRegistryRetagAttack` (asserts the stderr line) | Done |
| No threshold signing; no registry-side revocation | accepted limitation, documented in the security model | n/a | Accepted |
