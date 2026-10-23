---
title: "halo admin apply"
description: "Write the drifted settings of vendors with a public write API, after showing the diff"
---

Write the drifted settings of vendors with a public write API, after showing the diff

Runs plan, prints it, asks for confirmation (or --yes) and writes the drifted settings that have a public write API (gemini logging and release channel, copilot content exclusion). It refuses the whole run if a change it would write loosens a control the console has now, if a console resource Halos does not own governs the same target, or if a change would emit bypassPermissions or danger-full-access. Just before writing it re-reads each console and aborts that vendor if it changed since the confirmed plan. Read-only and manual settings are listed for a human. Prints an apply record with one result per change for the audit trail.

## Usage

```console
halo admin apply [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--copilot-base-url` |  | string |  | copilot API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--copilot-token-env` |  | string | HALO_ADMIN_COPILOT_TOKEN | environment variable holding the copilot API credential |
| `--copilot-token-file` |  | string |  | file holding the copilot API credential (read once, never logged) |
| `--gemini-base-url` |  | string |  | gemini API base URL: https, or http to a loopback host only (default the vendor's; e.g. a GitHub Enterprise Server API) |
| `--gemini-token-env` |  | string | HALO_ADMIN_GEMINI_TOKEN | environment variable holding the gemini API credential |
| `--gemini-token-file` |  | string |  | file holding the gemini API credential (read once, never logged) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--yes` |  | bool | false | apply without the interactive confirmation |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo admin`](/halos/reference/cli/admin/)
