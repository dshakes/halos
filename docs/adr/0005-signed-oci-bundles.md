---
title: "ADR-0005: Signed OCI bundles"
description: Releases are OCI artifacts signed with cosign; consumers refuse unsigned bundles.
status: accepted
date: 2026-09-30
---

# ADR-0005: Signed OCI bundles

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

`halod` applies configuration as root on developer machines, and that configuration can lock permissions, MCP servers and hooks. A tampered bundle is a remote-code-execution vector (a hook is a shell command). We need integrity, provenance and a distribution channel that orgs already operate.

## Decision drivers

- Verifiable provenance; fail closed.
- Reuse existing registries, auth and mirroring.
- Immutable, content-addressed identity (needed by ADR-0002).

## Considered options

1. Plain tarballs on object storage with checksums.
2. OCI artifacts (ORAS) signed with cosign (ed25519 key or keyless), ring tags as mutable pointers to immutable digests.
3. TUF-based repository.

## Decision outcome

Chosen: **option 2**. `halo release publish` pushes the bundle to an OCI registry and signs the digest. `halod`, the Dev Container Feature and MDM exporters verify before applying and refuse unsigned or mismatched bundles. Ring tags are convenience; the digest is authoritative. TUF (rollback and freeze protections) is a possible later hardening.

### Consequences

- Good: works with any OCI registry; digest identity is free; cosign tooling and SBOM story are mature.
- Bad: key management is now critical (see the security model); a keyless setup depends on an OIDC issuer.
- Bad: without TUF, a registry compromise could replay an older, validly signed release; `halod` mitigates by refusing to move to a release older than its current one unless explicitly told to roll back.

## Update (2026-09-30): superseded in part by ADR-0008

The primary signature is now an ed25519 key (`halod` verifies only ed25519 and never runs cosign as root); cosign is an optional co-signature. Ring tags are no longer trusted at all: each ring is served by a signed pointer with `seq` and expiry, which is the freeze and rollback protection this ADR deferred to "TUF later". The "refuse to move to an older release" mitigation above is now enforced by the pointer `seq`. See [ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/).

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| `halo release publish` pushes an OCI artifact and signs the digest | `cmd/halo/cmd_release.go` (`publish`); `internal/bundle/bundle.go` (`PublishRing`, ORAS push, ed25519 signature) | `bundle_test.go` `TestPublishPullRoundTrip`, `TestImmutableVersionTagAndRollback`; `cmd/halo` `TestKeysBuildPublishPlanRollback` | Done |
| `halod` verifies before applying; refuses unsigned or mismatched bundles | `cmd/halod/agent.go` (`cycle`); `bundle.PullRing` | `cmd/halod` `TestRefusesUnverified`, `TestInstallBadHashRejected`; `bundle_test.go` `TestPullRejects` | Done |
| Dev Container Feature and MDM exporters verify and refuse unsigned bundles | `features/halos/install.sh` (pinned `halod` runs the same verification); `internal/delivery/devcontainer`, `internal/delivery/mdm` refuse an unverified release at export | `devcontainer_test.go` `TestExportRefusals`; `mdm_test.go` `TestUnverifiedRefused` | Done |
| Ring tags are convenience; the digest is authoritative | superseded by signed pointers ([ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/)); tags are never trusted | `bundle_test.go` `TestPromoteRollbackIgnoreRetaggedTags`; `cmd/halo` `TestReleaseRegistryRetagAttack` | Superseded (stronger) |
| Refuse to move to an older release unless explicitly rolled back | pointer `seq` anti-rollback (`cmd/halod/agent.go`, `halod` state) | `cmd/halod` `TestPointerFreshness` | Done (via ADR-0008) |
| cosign as optional co-signature; ed25519 primary | `internal/bundle/bundle.go` (`Signer`, cosign shell-out) | `TestPublishSignerRules`, `TestCosignShellsOut` | Done |
| Key management documented | [security model](/halos/concepts/security-model/), [production deployment](/halos/guides/production-deployment/) (`umask 077`, rotation via `pubkeys`, `revokedKeys`) | `cmd/halod` `TestKeyringRotationAndRevocation` | Done |
| TUF as later hardening | not adopted; ADR-0008's pointer (`seq`, expiry, org and ring binding) covers freeze and rollback | `bundle` `TestPointerCrossRingAndForeignKey`, `TestRefreshRefusesExpiredPointer` | Superseded by ADR-0008 |
