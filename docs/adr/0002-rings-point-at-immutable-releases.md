---
title: "ADR-0002: Rings point at immutable releases"
description: Rings are pointers to content-addressed releases, so promotion and rollback are pointer moves.
status: accepted
date: 2026-09-30
---

# ADR-0002: Rings point at immutable releases

- Status: accepted
- Date: 2026-09-30

## Context and problem statement

If a ring is defined as "profile X at HEAD", then a merge to the policy repo changes what every member of that ring runs, with no record of what exactly was running yesterday. Rollback becomes "revert and hope".

## Decision drivers

- Reproducibility and auditability.
- Rollback that does not require rebuilding anything.
- Ability to prove which bytes a client ran.

## Considered options

1. Rings track a git branch or profile at HEAD.
2. Rings point at an immutable, content-addressed release digest (`Ring.release`); `Profile` is the source, `Release` is the artifact.

## Decision outcome

Chosen: **option 2**. `halo release publish` compiles a profile plus pinned harness versions into a release identified by digest. `Ring.release` pins a ring to a digest. When empty, the ring builds from its profile (development convenience only). Promotion is a PR that changes the pointer; rollback re-points to the previous digest.

### Consequences

- Good: rollback is O(1) and needs no compilation; clients report the digest they run.
- Good: the diff between rings is a diff between two releases.
- Bad: an extra publish step; ring pointers in git create PR churn (accepted, it is the audit trail).

## Addendum 2026-10-02: publish honours the pin; ring diffs use `halo plan`

- **A pinned ring is never rebuilt from its profile.** `halo release publish --ring R` refuses when `R` sets `release:` to a different digest, and says how to re-point it (`halo rollback --ring R --to <version> --expect-digest <pin>`) or to clear the pin. Before this, publish ignored the pin.
- **There is no `halo release diff`.** The diff between two releases is `halo plan --ring R --release-version V --against <tar | registry ring tag>`, which pulls the baseline release and runs `release.Diff`.

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Publish compiles profile plus pinned harness versions into a digest-identified release | `cmd/halo/cmd_release.go` (`publish`), `release.BuildRing`, `bundle.PublishRing` | `cmd/halo` `TestKeysBuildPublishPlanRollback` | Done |
| `Ring.release` pins a ring; empty builds from profile | `cmd/halo/root.go` `refusePinned`; `internal/gateway/decision.go` reports the pinned release | `TestKeysBuildPublishPlanRollback` (publish over a pinned ring fails) | Done (was Missing) |
| Promotion is a PR moving the pointer; rollback re-points without a rebuild | `internal/promote/pr.go` `PlanPromote`, `PlanRollback`; `cmd_release.go` `rollback` | `promote_test.go` `TestPlanAndApply`, `TestOpenPRNeverMerges`; `TestKeysBuildPublishPlanRollback` | Done |
| Clients report the digest they run | `cmd/halod/agent.go` (`Status.Digest`); `internal/server/server.go`; OTEL `halo.release` | `test/uat/k8s`; `test/uat` `TestCLIs` | Done |
| A ring diff is a diff between two releases | `halo plan --against` (`cmd_release.go`, `release.Diff`) | `TestKeysBuildPublishPlanRollback` | Done (as `halo plan`, see addendum) |
