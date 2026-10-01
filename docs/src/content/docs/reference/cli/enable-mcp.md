---
title: "halo enable mcp"
description: "Enable an MCP server (--url or --command)"
---

Enable an MCP server (--url or --command)

## Usage

```console
halo enable mcp <name> [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--command` |  | string |  | command line of a local (stdio) server |
| `--dry-run` |  | bool | false | print the diff instead of writing |
| `--expires` |  | string |  | toggle expiry YYYY-MM-DD (default: 90 days) |
| `--for` |  | string | all | all (profile change) \| &lt;ring> \| N% \| group:&lt;name> \| user:&lt;id> (a toggle) |
| `--header` |  | stringArray | [] | request header Name=value (use $&#123;VAR} for secrets; repeatable) |
| `--owner` |  | string |  | toggle owner (default: first identity.adminGroups entry) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--url` |  | string |  | https URL of a remote server |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo enable`](/halos/reference/cli/enable/)
