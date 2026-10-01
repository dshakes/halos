---
title: "halo rollback"
description: "Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest)"
---

Point a ring (and its experiment channels) back at an earlier signed release (version or manifest digest)

--to &lt;version> resolves tag v&lt;version> and refuses the release unless its signed manifest
carries that version (a retagged v-tag is refused); --to sha256:&lt;manifest digest> is content-addressed.

## Usage

```console
halo rollback [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--adopt-existing` |  | bool | false | trust pointers the registry already serves that the state file has no record of (first run, or an evicted CI cache); without it such a pointer is refused unless --expect-digest names it |
| `--cosign-key` |  | string |  | cosign key reference (file or KMS URI); co-signs alongside --key |
| `--cosign-keyless` |  | bool | false | cosign keyless (Fulcio+Rekor): uploads the release digest to the public transparency log |
| `--expect-digest` |  | string |  | refuse unless --to names this release digest (sha256:...) |
| `--key` |  | string |  | ed25519 private key PEM (create one with: halo keys generate) |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--ring` |  | string |  | ring to roll back (required) |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |
| `--to` |  | string |  | release version or sha256 manifest digest (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
