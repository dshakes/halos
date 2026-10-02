---
title: "ADR-0011: halos.dev/v1 is the stable policy API"
description: The policy kinds and fields freeze as halos.dev/v1; v1alpha1 keeps loading with identical semantics and a deprecation warning until halos.dev/v2.
status: accepted
date: 2026-10-02
---

# ADR-0011: halos.dev/v1 is the stable policy API

## Context and problem statement

Every policy document has said `apiVersion: halos.dev/v1alpha1` since the first commit, and the docs said it "may change until v1". GA needs a version that operators can build on: one whose meaning doesn't shift under a policy repo, a CI pipeline or a signed release. What does GA promise about the policy API, and how do existing repos get there?

## Decision drivers

- Existing v1alpha1 repos must keep loading and producing the same configs. Upgrading the binaries must not break a policy repo.
- Migration must be mechanical, reviewable as a diff, and keep the operator's comments and layout.
- Breaking a field after GA costs far more than leaving an imperfect name. Renames need a strong reason.
- `halo`, `halo-server`, `halo-proxy` and `halod` upgrade on different schedules. The skew rules have to be explicit.

## Considered options

1. **Promote the v1alpha1 schema to v1 as-is, with v1alpha1 as a deprecated alias.** No conversion code. `halo migrate` rewrites only the `apiVersion` value.
2. **Use GA to rename and restructure fields, converting v1alpha1 to v1.** This gives cleaner names, but the conversion layer has to be maintained until v2 and every doc, example and user repo changes.
3. **Keep `v1alpha1` and declare it stable.** Nothing changes, but the version name says "unstable" forever.

## Decision outcome

Chosen: **option 1**. Every kind (`Halos`, `Gateway`, `Profile`, `Ring`, `Experiment`, `Toggle`, `Rollout`) and every field freezes as it is. A review found nothing misnamed or experimental enough to justify a break. `policy.APIVersion` is now `halos.dev/v1`, and `policy.APIVersionV1Alpha1` is accepted at load time. A v1alpha1 document is normalised to v1 in memory, so it validates, compiles and renders exactly as before. `Validate` reports one warning per file still on v1alpha1, naming `halo migrate`.

`halo migrate --policy-dir DIR [--dry-run]` rewrites the top-level `apiVersion` of every document in place. It uses `internal/yamledit` byte splices, so comments, quoting and other documents in the same file are untouched. Running it again changes nothing. `halo init` and the intent commands write v1. `schemas/*.schema.json` describe v1, and the frozen v1alpha1 schemas stay under `schemas/v1alpha1/`.

Deprecation policy: a deprecated version or field warns for at least one minor release before anything else happens, and it is removed only in the next major API version (`halos.dev/v2`). See [Compatibility](/halos/reference/compatibility/).

## Consequences

- Good: no conversion layer. v1 and v1alpha1 are the same Go types, so equivalence is enforced by construction.
- Good: operators migrate with one reviewable commit, or never until v2.
- Bad: names we might prefer now are frozen until v2.
- Neutral: the compiled snapshot carries each document's `apiVersion`. The first release built after upgrading gets a new content digest even when the policy is otherwise unchanged. Releases are content-addressed, so this is a new release, not a mutation.
- Skew: an older `halo` or `halo-server` (v1alpha1-only) rejects v1 documents. Upgrade the binaries that read policy YAML before running `halo migrate`. `halo-proxy` and `halod` don't read policy YAML: they consume the snapshot (`halos.dev/snapshot/v1`) and release manifests (`schemaVersion: 1`), and those formats are unchanged.

## More information

- `internal/policy/types.go` (`APIVersion`, `APIVersionV1Alpha1`), `internal/policy/load.go` (`checkAPIVersion`), `internal/intent/migrate.go`.
- [Compatibility and deprecation policy](/halos/reference/compatibility/).
