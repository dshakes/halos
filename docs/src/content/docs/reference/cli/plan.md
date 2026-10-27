---
title: "halo plan"
description: "Diff the release each ring (or --ring) would get against a previous release, and with --diff who is affected"
---

Diff the release each ring (or --ring) would get against a previous release, and with --diff who is affected

Without --ring every ring is planned. --diff &lt;git ref> diffs against the policy at that ref (the
releases it builds, unless --against is set) and previews the impact: how many users, devices and
agents change ring, experiment variant or effective settings, by org unit, with examples. The
population is halo-server's enrolled fleet with --server (or HALO_SERVER) and HALO_SESSION, else a
policy-only estimate. Assignment uses the same hashing as the fleet (internal/assign).

## Usage

```console
halo plan [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--against` |  | string |  | release.tar or registry ref host/org/name[:tag] (default: the --diff policy's release, else none: the first release) |
| `--cosign-key` |  | string |  | cosign public key reference to verify with |
| `--diff` |  | string |  | git ref of the policy to compare with (e.g. main): release diffs from it, plus the impact preview |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--pubkey` |  | string |  | ed25519 public key PEM to verify with |
| `--registry` |  | string |  | registry repo, e.g. ghcr.io/acme/halos |
| `--release-version` |  | string | 0.0.0-dev | release version label |
| `--ring` |  | string |  | ring to plan (default: every ring) |
| `--server` |  | string |  | halo-server base URL (or HALO_SERVER) for the impact preview over the enrolled fleet; session from HALO_SESSION |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo`](/halos/reference/cli/)
