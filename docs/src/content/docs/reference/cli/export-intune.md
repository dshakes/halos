---
title: "halo export intune"
description: "Intune PowerShell script writing the Claude Code registry policy"
---

Intune PowerShell script writing the Claude Code registry policy

## Usage

```console
halo export intune
```

## Flags

None.

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--download-url` |  | string |  | https halod download URL (&#123;os}/&#123;arch} substituted; jamf/intune) |
| `--halod-sha256` |  | stringSlice | [] | sha256 of the halod binary as &lt;os>/&lt;arch>=&lt;hex>; repeatable or comma-separated |
| `--org` |  | string |  | org name; pins the org the ring's signed pointer must carry (required with --ring) |
| `--out` |  | string | halo-export | output directory |
| `--output` |  | string | text | output format: text\|json |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--pubkey` |  | string |  | ed25519 public key PEM: verifies the release and is embedded inline (required) |
| `--registry` |  | string |  | registry repo the release is pulled from (required) |
| `--ring` |  | string |  | ring to export (required for jamf/intune) |

## Parent

[`halo export`](/halos/reference/cli/export/)
