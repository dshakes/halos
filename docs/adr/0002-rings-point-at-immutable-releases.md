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
