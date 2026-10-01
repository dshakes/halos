---
title: "halo release publish"
description: "Build, sign and push a ring release (and its client-axis experiment channels); tags v<version> and ring-<ring>"
---

Build, sign and push a ring release (and its client-axis experiment channels); tags v&lt;version> and ring-&lt;ring>

## Usage

```console
halo release publish [flags]
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
| `--release-version` |  | string |  | release version, becomes tag v&lt;version> (required) |
| `--ring` |  | string |  | ring to publish (required) |
| `--state-file` |  | string |  | signer state file recording the last pointer written per registry repo and ring; a registry serving an older pointer (replay) is refused. Default $XDG_STATE_HOME/halos/pointers.json (~/.local/state/halos/pointers.json). CI: cache this file between runs |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo release`](/halos/reference/cli/release/)
