---
title: "halo upgrade start"
description: "Roll a CLI version out: build and publish the candidate (no ring moves) and write its phased rollout"
---

Roll a CLI version out: build and publish the candidate (no ring moves) and write its phased rollout

Writes rollouts/&lt;tool>-&lt;version>.yaml from the rollout preset (ring0, a guardrailed canary ramp,
then ring by ring to GA), its client-axis experiment and treatment profile. It builds the candidate
release (the treatment profile for the GA ring), pushes and signs it as v&lt;tool>-&lt;version> with no
pointer, publishes the treatment on its experiment channel, and fills change.release with its
digest and baseline.release with the digest the GA ring serves. Nothing reaches a device until
a human merges the rollout and advances it. --no-publish computes the same digest offline and
prints the `halo upgrade publish` command to push it later. --registry/--key default to
HALO_REGISTRY / HALO_KEY.

## Usage

```console
halo upgrade start <tool> <version> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--adopt-existing` |  | bool | false | trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache); without it such a pointer is refused unless --expect-digest names it |
| `--baseline` |  | string |  | override: rollback digest (default: the release the GA ring's signed pointer serves) |
| `--cosign-key` |  | string |  | cosign key reference (file or KMS URI); co-signs alongside --key |
| `--cosign-keyless` |  | bool | false | cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log |
| `--dry-run` |  | bool | false | print the diff instead of writing (nothing is published) |
| `--key` |  | string |  | ed25519 private key PEM (create one with: halo keys generate) |
| `--no-artifacts` |  | bool | false | skip resolving vendor install artifacts (offline builds); halod will not install CLIs without them unless allowShellInstall |
| `--no-publish` |  | bool | false | write the files with the locally computed digest; push later with `halo upgrade publish` |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--release` |  | string |  | override: digest of an already published candidate release (skips build and publish) |
| `--release-version` |  | string |  | candidate release version label (default &lt;tool>-&lt;version>) |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo upgrade`](/halos/reference/cli/upgrade/)
