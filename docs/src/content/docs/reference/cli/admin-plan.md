---
title: "halo admin plan"
description: "Render vendorAdmin's consoles from policy and diff them against the live settings (read-only)"
---

Render vendorAdmin's consoles from policy and diff them against the live settings (read-only)

Renders the console settings of every vendor under halos.yaml vendorAdmin from one ring's profile and, for vendors with a public read API (gemini, copilot), reads the live settings and diffs them. Credentials come from --&lt;vendor>-token-file or the environment variable --&lt;vendor>-token-env names (default HALO_ADMIN_&lt;VENDOR>_TOKEN), never from policy. Exit 0 in sync, 2 on drift, 1 when a console could not be read. Writes nothing.

## Usage

```console
halo admin plan [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--copilot-base-url` |  | string |  | copilot API base URL (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--copilot-token-env` |  | string | HALO_ADMIN_COPILOT_TOKEN | environment variable holding the copilot API credential |
| `--copilot-token-file` |  | string |  | file holding the copilot API credential (read once, never logged) |
| `--gemini-base-url` |  | string |  | gemini API base URL (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--gemini-token-env` |  | string | HALO_ADMIN_GEMINI_TOKEN | environment variable holding the gemini API credential |
| `--gemini-token-file` |  | string |  | file holding the gemini API credential (read once, never logged) |
| `--offline` |  | bool | false | render only: do not read the live consoles (no credentials needed, no drift check) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo admin`](/halos/reference/cli/admin/)
