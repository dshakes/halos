---
title: "halo export"
description: "Export a signed release for a delivery channel"
---

Export a signed release for a delivery channel

## Usage

```console
halo export
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--download-url` |  | string |  | https halod download URL (&#123;os}/&#123;arch} substituted; jamf/intune) |
| `--halod-sha256` |  | stringSlice | [] | sha256 of the halod binary as &lt;os>/&lt;arch>=&lt;hex>; repeatable or comma-separated |
| `--org` |  | string |  | org name; pins the org the ring's signed pointer must carry (required with --ring) |
| `--out` |  | string | halo-export | output directory |
| `--plain-http` |  | bool | false | use HTTP instead of HTTPS (local registries) |
| `--pubkey` |  | string |  | ed25519 public key PEM: verifies the release and is embedded inline (required) |
| `--registry` |  | string |  | registry repo the release is pulled from (required) |
| `--ring` |  | string |  | ring to export (required for jamf/intune) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Commands

| Command | Description |
|---|---|
| [`halo export devcontainer`](/halos/reference/cli/export-devcontainer/) | Dev Container Feature source with org defaults baked in |
| [`halo export intune`](/halos/reference/cli/export-intune/) | Intune PowerShell script writing the Claude Code registry policy |
| [`halo export jamf`](/halos/reference/cli/export-jamf/) | Jamf/Kandji .mobileconfig plus halod postinstall |

## Parent

[`halo`](/halos/reference/cli/)
