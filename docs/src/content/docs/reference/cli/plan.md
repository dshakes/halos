---
title: "halo plan"
description: "Diff the release a ring would get against a previous release"
---

Diff the release a ring would get against a previous release

## Usage

```console
halo plan [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--against` |  | string |  | release.tar or registry ref host/org/name[:tag] (required) |
| `--cosign-key` |  | string |  | cosign public key reference to verify with |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--pubkey` |  | string |  | ed25519 public key PEM to verify with |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--release-version` |  | string | 0.0.0-dev | release version label |
| `--ring` |  | string |  | ring to plan (required) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
