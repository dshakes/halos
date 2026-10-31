---
title: "halo keys"
description: "Signing key management"
---

Signing key management

## Usage

```console
halo keys
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo keys generate`](/halos/reference/cli/keys-generate/) | Generate an ed25519 signing key pair (PEM) |
| [`halo keys public`](/halos/reference/cli/keys-public/) | Export the public key (PEM) and key id of a signing key: file://, awskms:// or exec:// |

## Parent

[`halo`](/halos/reference/cli/)
