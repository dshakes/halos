---
title: "ADR-0018: Org hierarchy and delegated policy"
description: A Unit kind adds business units and teams with delegated owners and overlays. The org baseline's security fields can only be tightened, and unit overlays ship inside the signed ring release.
status: accepted
date: 2026-10-21
---

# ADR-0018: Org hierarchy and delegated policy

## Context and problem statement

The policy model is one flat org: rings point at profiles, and profiles share settings through a single `extends` chain. A large org with many business units ends up with one of two problems. Either every BU-specific change goes through the central platform team, or BUs get write access to the shared profiles and can weaken the security baseline by accident. Neither scales to hundreds of teams. How do business units and teams own their own settings without being able to loosen what the org enforces?

## Decision drivers

- Keep `halos.dev/v1` frozen: the change has to be additive (ADR-0012).
- The central security baseline (permissions, sandbox, MCP denylist, telemetry, egress) must not be weakened by a delegated owner, and CI has to be able to prove it.
- Ring and experiment assignment stay in `internal/assign` (invariant 3). A hierarchy must not create a second assignment mechanism that drifts from it.
- Delegation has to map onto how policy repos are already governed: pull requests with code-owner review.
- Validate and release build must stay fast at 150+ units.

## Considered options

1. **A `Unit` kind that overlays the ring's profile, with enforced fields checked at validate time and unit files shipped inside the ring release.**
2. **Per-unit rings.** Units become rings with group membership. This reuses existing machinery, but the ring then carries two meanings (rollout stage and org placement), and the number of rings becomes BUs × stages.
3. **Multiple `extends` (profile mixins) plus CODEOWNERS on profile files.** This needs no new kind, but nothing stops a mixin from loosening a field, and membership stays tied to rings.
4. **Separate channels per unit**, like client-axis experiment variants (ADR-0010). The release count would be (variants + 1) × (units + 1) per ring, and every release would need its own signed pointer.

## Decision outcome

Chosen: **option 1**.

- **Kind.** `Unit` (`apiVersion: halos.dev/v1`) has `parent`, `owners` (CODEOWNERS owners), `members` (`groups`, `users`) and `overlay`. The overlay is the profile subset a unit may change: `models`, `permissions`, `mcp`, `hooks`, `telemetry`, `egress`, `instructions`, `env`. Harness pins and overrides stay central.
- **Placement.** A user's unit is the deepest one whose selector, and every ancestor's, matches the user's id or IdP groups. Equal depth goes to the lexically smaller name. Rings and variants are unchanged and still resolve through `internal/assign`.
- **Merge order.** The profile `extends` chain (root first), then ancestor overlays (root first), then the unit's own. Deny lists and hooks union, MCP servers are added, other lists replace, `env` and `telemetry.attributes` merge per key, and instructions are appended.
- **Enforced fields.** `policy.Loosenings` defines the security baseline: permission mode and sandbox (ranked), the bypass, sandbox-required, managed-only and telemetry switches, deny/ask/denied lists (no drops), allow and egress lists (no additions), telemetry destination and prompt logging (unchanged), inherited env keys and telemetry attributes (unchanged), and `models.allowed` while `models.enforce` is set (a subset). `halo validate` checks every unit against its parent's effective config, on every shipped profile (ring profiles and running client-axis variants). Each loosening is an error at `units[<name>].overlay.<field>`. The effective config must also pass the profile checks and built-in guardrails the base passes.
- **Delegation.** A unit lives in its own directory. Unit directories may hold only Unit documents, and a unit nested in another unit's directory must be its descendant. `halo units codeowners` renders CODEOWNERS from the units. Branch protection with code-owner review and a required `halo validate` turns that into delegated, baseline-safe merges.
- **Delivery.** Each release (ring and variant) lists every unit in its signed manifest: the selector, plus the files its effective config renders differently from the release, as whole files. Toggle deltas cannot express a narrowed list or a new non-JSON file, so units don't use them. `halod` picks the unit with `policy.MatchUnit`, using the subject and groups from the ring endpoint, writes the unit's files in place of the release's own, then merges toggle fragments.
- **Explain.** `halo explain --user U --groups G` shows the ring, variant, unit chain and every effective field, with the layer (`profile <name>` or `unit <name>`) that set it.

## Consequences

- Good: units own their overlays without central review, and CI rejects any loosening with the exact field path.
- Good: no new assignment path, no new channels or pointers. A rollback re-points the ring, and every unit moves with it.
- Good: additive to v1. A policy without units loads, validates and builds byte-for-byte the same releases (`Manifest.Units` and `Org.Units` are omitted when empty).
- Bad: release size grows with the number of units whose effective config differs. Blobs are content-addressed, so identical files are stored once. Measured at 50 units × 3 levels, validate takes about 11 ms (`BenchmarkValidateLargeOrg`) and a release build about 5 ms with a fake adapter (`BenchmarkBuildLargeOrg`).
- Bad: a unit that adds an MCP server needs its host in the baseline's egress allowlist, because adding an egress domain is a loosening. The central team has to allow the host first.
- Neutral: a device without groups (ring pinned in `halod.yaml`, or no halo-server) gets no unit. The gateway does not enforce unit model allowlists; it enforces aliases as before, and the unit's narrower `models.allowed` is enforced in the rendered client config.
- Skew: `halo` and `halo-server` must be new enough to decode `kind: Unit` before a repo uses it, because decoding is strict. An older `halod` ignores `units` in the manifest and applies the release's own files, which is the baseline, never something looser.

## More information

- `internal/policy/unit.go` (`Unit`, `MatchUnit`, `EffectiveProfile`, `Loosenings`, `ExplainEffective`, `CodeOwners`), `internal/release/units.go`, `cmd/halod/toggles.go`, `cmd/halo/cmd_units.go`.
- [Org hierarchy](/halos/concepts/org-hierarchy/), [Compatibility](/halos/reference/compatibility/).
