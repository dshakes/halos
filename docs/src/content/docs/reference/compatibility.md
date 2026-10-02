---
title: Compatibility
description: What halos.dev/v1 guarantees, how deprecations work, and which binary versions can run together.
---

`apiVersion: halos.dev/v1` is the stable policy API. This page covers what it promises, how anything in it can be deprecated, and how `halo`, `halod`, `halo-server` and `halo-proxy` (and `halo-kong`) can run at different versions. The decision record is [ADR-0012](/halos/adr/0012-policy-api-v1/).

## v1 guarantees

For every release in the `halos.dev/v1` line:

- **Kinds and fields are frozen.** `Halos` (`halos.yaml`), `Gateway`, `Profile`, `Ring`, `Experiment`, `Toggle` and `Rollout` keep every field name, type and meaning listed in the [policy schema](/halos/reference/policy-schema/). No field is renamed, removed, retyped or given a new meaning within v1.
- **Same policy, same output.** A policy that validates without errors keeps validating, and it renders to the same harness configs and gateway behaviour. Exceptions: a guardrail fix for a security issue, or a harness vendor changing its own config format. Both are listed in the [changelog](https://github.com/dshakes/halos/blob/main/CHANGELOG.md).
- **Additions are optional.** New fields and kinds can arrive in a minor release. They are optional and default to the old behaviour. Decoding is strict, so a policy that uses a new field needs a `halo` and `halo-server` at least as new as that field (see [version skew](#version-skew)).
- **Invariants hold.** Rendered configs never contain `bypassPermissions` or `danger-full-access`, unsupported settings warn rather than drop, and releases are immutable and content-addressed.
- **Schemas are published.** `schemas/*.schema.json` describe v1. The frozen v1alpha1 schemas stay in `schemas/v1alpha1/`.

New warnings can appear in a minor release. They never turn into errors within v1, except for the security exception above.

## halos.dev/v1alpha1

`halos.dev/v1alpha1` is deprecated. It still loads, with **exactly** the semantics of v1: the two versions decode into the same types, and a v1alpha1 document is treated as v1 in memory. `halo validate` reports one warning per file that still uses it:

```
warning profiles/base.yaml  apiVersion halos.dev/v1alpha1 is deprecated; it reads as halos.dev/v1 with identical semantics until halos.dev/v2. Run `halo migrate --policy-dir .`
```

To migrate:

```sh
halo migrate --policy-dir . --dry-run   # review the diff
halo migrate --policy-dir .             # rewrite in place
halo validate --policy-dir .
```

`halo migrate` changes only the top-level `apiVersion` value of each document. Comments, quoting, key order and the other documents in a multi-document file stay byte for byte the same. Running it again is a no-op. It runs on overlay directories too (directories without a `halos.yaml`).

The compiled snapshot records each document's `apiVersion`. The first release you build after migrating gets a new content digest even though nothing else changed. That is a new release, not a change to an old one.

## Deprecation policy

- A deprecated version, kind or field **warns** (in `halo validate`, CI and the MCP `validate` tool) for **at least one minor release** before anything else changes.
- It is **removed only in the next major API version** (`halos.dev/v2`). Within v1 a deprecated form keeps loading with its documented meaning.
- Every deprecation has a mechanical migration (`halo migrate` or a documented edit) and an entry in the changelog.
- `halos.dev/v2`, if it ever ships, comes with a `halo migrate` path from v1 and its own entry on this page.

## Version skew

Each binary reads a different artifact, and each artifact has its own version:

| Binary | Reads | Version it checks |
|---|---|---|
| `halo` (CLI, CI, MCP server) | policy YAML | `apiVersion` (`halos.dev/v1`, `halos.dev/v1alpha1`) |
| `halo-server` | policy YAML (`--policy-dir`) | `apiVersion` |
| `halo-proxy`, `halo-kong` | compiled snapshot (`halo gateway compile`) | `halos.dev/snapshot/v1` |
| `halod` | signed release bundles and ring pointers | manifest `schemaVersion: 1` |

Rules:

- **Policy YAML.** `halo` and `halo-server` releases before v1 support accept only `halos.dev/v1alpha1`, and they reject v1 documents with `apiVersion "halos.dev/v1" not supported`. Upgrade every `halo` that reads the repo (laptops, CI, the MCP server) and `halo-server` **before** running `halo migrate`. Newer binaries read both versions, so upgrading first is always safe.
- **Snapshots.** `halo-proxy` and `halo-kong` accept any snapshot with `version: halos.dev/snapshot/v1`, whichever `apiVersion` the source documents used. An older proxy ignores snapshot fields it doesn't know, so a policy that relies on a new gateway feature needs the proxy upgraded first.
- **Releases.** `halod` reads manifests with `schemaVersion: 1`, and the policy `apiVersion` doesn't affect them. A `halod` older than the release format it is given fails verification and keeps its last-good config. It never applies a partial release.
- **Recommended upgrade order:** `halod` and the traffic plane (`halo-proxy` or `halo-kong`), then `halo-server`, then the `halo` CLI in CI and on laptops, then `halo migrate` in the policy repo.
