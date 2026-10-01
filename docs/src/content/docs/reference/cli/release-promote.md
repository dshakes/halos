---
title: "halo release promote"
description: "Point --to-ring at the release --from-ring's signed pointer names; experiment channels stay with the ring they were built for"
---

Point --to-ring at the release --from-ring's signed pointer names; experiment channels stay with the ring they were built for

The source release is taken from --from-ring's signed pointer (signature, ring, org, expiry and
--state-file continuity checked), never from the unauthenticated ring-&lt;name> tag.

## Usage

```console
halo release promote [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--adopt-existing` |  | bool | false | trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache); without it such a pointer is refused unless --expect-digest names it |
| `--cosign-key` |  | string |  | cosign key reference (file or KMS URI); co-signs alongside --key |
| `--cosign-keyless` |  | bool | false | cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log |
| `--expect-digest` |  | string |  | refuse unless --from-ring serves this release digest (sha256:...) |
| `--from-ring` |  | string |  | source ring (required) |
| `--key` |  | string |  | ed25519 private key PEM (create one with: halo keys generate) |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |
| `--to-ring` |  | string |  | destination ring (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo release`](/halos/reference/cli/release/)
