---
title: "halo onboard verify"
description: "Run each installed CLI headless (claude -p, codex exec, gemini -p, copilot -p) and check the reply"
---

Run each installed CLI headless (claude -p, codex exec, gemini -p, copilot -p) and check the reply

One short model call per CLI, through whatever endpoint its config points at. Skipped when the CLI
is missing or no credential variable is set; a CLI that is logged in (OAuth, keychain) needs
--assume-auth because halo cannot see that. Output is redacted.

## Usage

```console
halo onboard verify [harness...] [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--assume-auth` |  | bool | false | run even when no credential variable is set (the CLI is logged in) |
| `--dry-run` |  | bool | false | print the commands instead of running them |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--timeout` |  | duration | 2m0s | per-CLI timeout |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo onboard`](/halos/reference/cli/onboard/)
