---
title: "halo enable hook"
description: "Enable a hook (--event and --command)"
---

Enable a hook (--event and --command)

## Usage

```console
halo enable hook <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--command` |  | string |  | command to run |
| `--dry-run` |  | bool | false | print the diff instead of writing |
| `--event` |  | string |  | PreToolUse \| PostToolUse \| SessionStart \| Stop \| UserPromptSubmit |
| `--expires` |  | string |  | toggle expiry YYYY-MM-DD (default: 90 days) |
| `--for` |  | string | all | all (profile change) \| &lt;ring> \| N% \| group:&lt;name> \| user:&lt;id> (a toggle) |
| `--matcher` |  | string |  | tool matcher, e.g. Edit\|Write |
| `--owner` |  | string |  | toggle owner (default: first identity.adminGroups entry) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo enable`](/halos/reference/cli/enable/)
