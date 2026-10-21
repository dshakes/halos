---
title: "halo ci config"
description: "Write one harness's managed config for a headless run from the ring's release"
---

Write one harness's managed config for a headless run from the ring's release

Renders the ring's release (the same bundle laptops get) and writes only
--harness's files under --out, mirroring absolute paths (use --out / as root
to install them where the harness reads managed settings). Nothing interactive
is added and no permission-bypass mode is ever written: in headless runs
(claude -p, codex exec, gemini -p) a tool the profile does not allow is denied,
so grant job-specific tools with the harness's own flag (claude --allowedTools)
within the profile's deny rules.

## Usage

```console
halo ci config [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--harness` |  | string |  | harness: claude-code \| codex \| gemini-cli \| copilot-cli (required) |
| `--os` |  | string | host OS | target OS: darwin\|linux\|windows |
| `--out` |  | string |  | output root (required; / installs in place) |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--release-version` |  | string | 0.0.0-ci | release version label stamped into config |
| `--ring` |  | string |  | ring whose release to render (env HALO_RING, set by `halo ci token`) |

## Global flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--output` |  | string | text | output format: text\|json |

## Parent

[`halo ci`](/halos/reference/cli/ci/)
