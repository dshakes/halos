---
title: "halo admin"
description: "Sync vendor admin consoles (Claude, ChatGPT/Codex, Gemini, Copilot, Cursor) with policy (ADR-0025)"
---

Sync vendor admin consoles (Claude, ChatGPT/Codex, Gemini, Copilot, Cursor) with policy (ADR-0025)

## Usage

```console
halo admin
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
| [`halo admin apply`](/halos/reference/cli/admin-apply/) | Write the drifted settings of vendors with a public write API, after showing the diff |
| [`halo admin export`](/halos/reference/cli/admin-export/) | Write the console artifacts and manual steps for every vendorAdmin vendor |
| [`halo admin plan`](/halos/reference/cli/admin-plan/) | Render vendorAdmin's consoles from policy and diff them against the live settings (read-only) |

## Parent

[`halo`](/halos/reference/cli/)
