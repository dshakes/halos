---
title: "halo artifact"
description: "Digest, scan and sign agent extension artifacts (skills, plugins, hooks, commands, agents; ADR-0028)"
---

Digest, scan and sign agent extension artifacts (skills, plugins, hooks, commands, agents; ADR-0028)

## Usage

```console
halo artifact
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
| [`halo artifact digest`](/halos/reference/cli/artifact-digest/) | Print the artifact digest of a file or directory, to pin it in supplyChain.artifacts[].digest |
| [`halo artifact scan`](/halos/reference/cli/artifact-scan/) | Run the supply-chain static scan over a file or directory (exit 2 on findings) |
| [`halo artifact sign`](/halos/reference/cli/artifact-sign/) | Sign an artifact's digest with an ed25519 key (base64 signature for supplyChain.artifacts[].signature.file) |

## Parent

[`halo`](/halos/reference/cli/)
