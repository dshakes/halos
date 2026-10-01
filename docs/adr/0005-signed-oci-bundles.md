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
