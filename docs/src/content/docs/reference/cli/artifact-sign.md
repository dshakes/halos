---
title: "halo artifact sign"
description: "Sign an artifact's digest with an ed25519 key (base64 signature for supplyChain.artifacts[].signature.file)"
---

Sign an artifact's digest with an ed25519 key (base64 signature for supplyChain.artifacts[].signature.file)

## Usage

```console
halo artifact sign <path> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--key` |  | string |  | ed25519 private key PEM (halo keys generate) |
| `--out` | `-o` | string |  | write the signature here instead of stdout |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo artifact`](/halos/reference/cli/artifact/)
