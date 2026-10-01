---
title: "halo upgrade publish"
description: "Rebuild and push the candidate release a `halo upgrade start` rollout names (no ring pointer moves)"
---

Rebuild and push the candidate release a `halo upgrade start` rollout names (no ring pointer moves)

For rollouts written with --no-publish (e.g. from a laptop; run this in CI after merge). The rebuilt
release must have exactly the rollout's change.release digest, else nothing is pushed.

## Usage

```console
halo upgrade publish <rollout> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--adopt-existing` |  | bool | false | trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache); without it such a pointer is refused unless --expect-digest names it |
| `--cosign-key` |  | string |  | cosign key reference (file or KMS URI); co-signs alongside --key |
| `--cosign-keyless` |  | bool | false | cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log |
| `--key` |  | string |  | ed25519 private key PEM (create one with: halo keys generate) |
| `--no-artifacts` |  | bool | false | skip resolving vendor install artifacts (offline builds); halod will not install CLIs without them unless allowShellInstall |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo upgrade`](/halos/reference/cli/upgrade/)
