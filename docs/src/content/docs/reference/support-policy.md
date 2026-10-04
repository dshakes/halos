---
title: Support and versioning policy
description: What a version number promises, which versions are supported, the order to upgrade the binaries in, and when a release reaches end of life.
---

## Versioning

Halos follows [SemVer](https://semver.org/). One git tag `vX.Y.Z` (or `vX.Y.Z-rc.N`) builds every binary — `halo`, `halod`, `halo-server`, `halo-proxy`, `halo-shadow`, `halo-kong` — and the container images, from the same commit (`.github/workflows/release.yml`); `halo version` prints it. There is no separate version per component: "Halos 1.4.2" means all of them at 1.4.2.

What a version number covers, and what breaking means for each surface:

| Surface | Compatibility promise |
|---|---|
| CLI commands and flags (`halo`, `halod`) | Minor releases add; only a major release removes or changes meaning. Deprecated flags keep working for one minor release and print a warning |
| HTTP API (`/api/v1/...`) | Path-versioned. Fields are added in minors; a field is never removed or retyped under `/v1` |
| Policy files (`apiVersion: halos.dev/v1`) | Stable: every kind and field is frozen; fields are only added. A deprecated field warns for at least one minor and is removed only in `halos.dev/v2`. `halos.dev/v1alpha1` still loads with a warning until v2. Details in [Compatibility](/halos/reference/compatibility/) |
| Release bundles and ring pointers | `schemaVersion: 1` (`internal/release/release.go:60`). A reader refuses a schema it does not know (`release.go:274`) and keeps last-good; a new schema version is a major release |
| Kill list, fleet report and mirror payloads | Fields only ever added. `halo-shadow` decodes mirror jobs strictly (`internal/shadow/server.go`), which is why it upgrades before `halo-proxy` (below) |
| Helm chart | Its own SemVer in `Chart.yaml` (`version`), tracking `appVersion`. A values key is renamed only in a chart major; `values.schema.json` checks types and the replica pins but does not reject unknown keys, so read the chart CHANGELOG entry before a major |
| Prometheus metric names and labels | Treated as API: renamed only in a major |
| Go module `github.com/dshakes/halos` | `internal/` only; nothing is importable, nothing is promised |

While the major is 0, a minor release may contain a breaking change; it is called out at the top of its CHANGELOG section with the word **Breaking**. Release candidates (`-rc.N`) publish as GitHub prereleases and never move the `latest` image tag.

## Supported versions

This is the commitment from `v0.1.1` on. It is a policy, not something the code enforces; it is listed here so you can hold us to it.

- The **latest minor** receives features and fixes.
- The **previous minor** receives security and data-loss fixes. While the major is 0, that window is **90 days** after the newer minor ships; from 1.0 it is **6 months**, or until the next minor, whichever is longer. The shorter 0.x window is honest about a young project that ships minors often.
- Patch releases are cumulative: `1.4.3` supersedes `1.4.2` on the day it ships. We do not backport to a patch you skipped.
- A security fix is released as a patch on every supported minor at once, with a GitHub Security Advisory.
- `rc` builds are supported until the final tag ships, then not at all.
- A release that could not complete publishing (for example `v0.1.0`, which has no Homebrew formula, Scoop manifest or provenance attestation) is not a supported version; the next patch is, and the CHANGELOG names the replacement.

| Version | Status | Supported until |
|---|---|---|
| 0.1.x | current | the 0.2 minor ships, then 90 days of security fixes |
| 0.1.0 | superseded by 0.1.1 (incomplete publish) | — |
| 0.1.0-rc.1, rc.2 | prerelease | — |

Harness CLIs (Claude Code, Codex, Gemini CLI, Copilot CLI) are not ours to support. The versions a Halos release was exercised against are in the [harness matrix](/halos/reference/harness-matrix/) (`make uat-clis` runs them on every PR). A newer CLI that changes its config format is a Halos **minor**, not a patch, because the adapter's rendered bytes change.

## Upgrade order

Clients tolerate an older server; servers tolerate older clients; the one strict reader is `halo-shadow`. Upgrade in this order and nothing is ever talking to something it does not understand:

1. **`halo-server`** — serves the API, kill list and portal that everything else consumes. Single replica with `Recreate`: plan a short console outage (gateways and `halod` are unaffected, see [operations](/halos/guides/operations/#what-is-highly-available-and-what-is-not)). Back up `--data-dir` first.
2. **`halo-shadow`** — before the proxy, because it rejects mirror jobs with fields it does not know; a newer proxy against an older shadow shows up as `halo_proxy_shadow_failed_total`, not as client errors.
3. **`halo-proxy`** / **`halo-kong`** — rolling, zero client errors with the chart defaults (verified under load by `make uat-k8s`). Recompile the policy snapshot with the new `halo gateway compile` only after every proxy runs the new version.
4. **`halod`** — it does not self-update; ship it the way it was installed: the MDM package, a Dev Container Feature or Coder template rebuild, and the portal's `halodURL`/`halodSHA256` for machines that enroll from now on. Old `halod` keeps reading new pointers as long as `schemaVersion` is unchanged, so this step can lag by weeks.
5. **`halo`** (CI and operators) — last, so the releases it publishes are never newer than the agents that must verify them.

Within one minor the order does not matter; across a major, the CHANGELOG says if it changes. Rolling back follows the reverse order, and a `halo-server` rollback restores the `--data-dir` backup taken in step 1 only if the newer version wrote a format the older one cannot replay (the CHANGELOG says so when it does; append-only JSONL with ignored unknown fields is the default).

## End of life

A minor is end of life the day its support window above closes. After that: no fixes, no advisories, images stay on GHCR but are not rebuilt for base-image CVEs. The CHANGELOG records the EOL date next to the version. An EOL `halod` keeps working — it verifies releases with the public key and nothing expires it — but a ring pointer it cannot parse means it stops updating and stays on last-good, which is the fail-safe behaviour and also how you will notice.
