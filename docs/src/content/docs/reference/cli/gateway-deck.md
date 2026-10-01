---
title: "halo gateway deck"
description: "Generate the decK declarative config (kong.yml) for Kong + halo-kong"
---

Generate the decK declarative config (kong.yml) for Kong + halo-kong

## Usage

```console
halo gateway deck [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--groups-header` |  | string |  | header carrying IdP groups |
| `--halo-shadow-token` |  | string |  | halo-shadow auth token |
| `--halo-shadow-url` |  | string |  | halo-shadow URL for shadow traffic |
| `--identity-header` |  | string |  | identity header (default: org gateway.auth.identityHeader) |
| `--killswitch-url` |  | string |  | halo-server kill-switch URL; token and pubkey are emitted as &#123;vault://env/halo-killswitch-*} refs |
| `--out` | `-o` | string | - | output file ('-' = stdout) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--policy-path` |  | string |  | snapshot path inside the Kong container |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo gateway`](/halos/reference/cli/gateway/)
