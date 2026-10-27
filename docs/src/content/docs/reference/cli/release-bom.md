---
title: "halo release bom"
description: "Print and verify a release's CycloneDX AI-BOM (or --provenance, its in-toto SLSA provenance)"
---

Print and verify a release's CycloneDX AI-BOM (or --provenance, its in-toto SLSA provenance)

A local release.tar is checked against the release.tar.bom.cdx.json and release.tar.intoto.json
that `halo release build` wrote beside it (not signed). A registry ref is pulled with --pubkey or
--cosign-key: the release signature, the attestation signature and their content must all verify.

## Usage

```console
halo release bom <release.tar | host/org/name:tag> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--cosign-key` |  | string |  | cosign public key reference to verify with |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--provenance` |  | bool | false | print the provenance instead of the BOM |
| `--pubkey` |  | string |  | ed25519 public key PEM to verify with |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo release`](/halos/reference/cli/release/)
