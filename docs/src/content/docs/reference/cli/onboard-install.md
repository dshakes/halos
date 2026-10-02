---
title: "halo onboard install"
description: "Render a ring's managed config for this OS and show exactly what lands where; --apply writes it"
---

Render a ring's managed config for this OS and show exactly what lands where; --apply writes it

Managed config lives in admin-owned paths (e.g. /Library/Application Support/ClaudeCode on macOS,
/etc on Linux), so --apply usually needs sudo; --root DIR stages the same tree under DIR. A file that
differs is backed up once to &lt;file>.halos-backup. Idempotent: a second --apply writes nothing.

## Usage

```console
halo onboard install [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--apply` |  | bool | false | write the files (default: dry run) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--ring` |  | string |  | ring to install (default: the GA ring) |
| `--root` |  | string |  | write under this directory instead of the real paths |
| `--show` |  | bool | false | include each file's contents |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo onboard`](/halos/reference/cli/onboard/)
