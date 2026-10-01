# Governance

Halos is an Apache-2.0 project with a lightweight, maintainer-led model. It is intended to move to a neutral foundation or org if adoption warrants it.

## Roles

- **Contributors**: anyone who opens an issue, PR, ADR or doc fix.
- **Reviewers**: contributors with a track record in an area (for example a harness adapter); may approve PRs in that area.
- **Maintainers**: own the roadmap, releases and the merge button. Listed in `MAINTAINERS` (to be added with the first external maintainer).

## Decisions

- Routine changes: one maintainer approval and green CI.
- **Load-bearing changes** (new language, broken invariant, new trust boundary, policy schema break) require an [ADR](docs/adr/) and approval from two maintainers, or one maintainer plus a 5 business day comment window if only one exists.
- Disagreements: seek consensus in the PR or ADR; if none, maintainers vote by simple majority, with the ADR author abstaining.

## Invariants

These hold regardless of who is proposing the change:

- Releases are signed; consumers refuse unsigned bundles.
- Promotion is never automatic. A human merges the PR that moves a ring pointer.
- Halos never emits `bypassPermissions` or `danger-full-access`.

Changing an invariant requires an ADR that supersedes the relevant one.

## Becoming a maintainer

Sustained, high-quality contributions plus nomination by an existing maintainer and no objection from others within 7 days.

## Conduct and security

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [SECURITY.md](SECURITY.md).
