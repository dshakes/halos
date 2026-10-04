---
title: Writing a harness adapter
description: Add support for a new CLI by implementing render and the capability declaration.
---

An adapter lives in `internal/harness/<name>/` and does two things: **render** a `Profile` into the harness's native config (returning files and warnings), and **declare capabilities** (`Capabilities()`), which `halo harnesses` prints and the docs matrix mirrors. Existing adapters: `claudecode`, `codex`, `gemini`, `copilot`.

## Steps

1. **Research and cite.** For every matrix row, find the vendor doc or run the CLI and record the evidence in `internal/harness/FACTS.md` (with the source URL). Rows you cannot verify are listed under "Still UNVERIFIED", never guessed.
2. **Declare capabilities** you actually render: version pin, model lock, MCP allowlist, hooks lock, permissions, gateway, headers, telemetry, instructions. Emit a warning for every profile field you cannot render (`hutil.WarnUnsupported`); never drop one silently. If the CLI cannot pin its own version, warn that `halod` enforces.
3. **Implement render**: `Profile` (plus `Gateway` and release info) to files, at the documented managed paths for each OS. Merge `HarnessSpec.Overrides` last, and list the override keys you accept in `allowedOverrides` in `internal/policy/guardrails.go` (a harness with no entry accepts no overrides). Publish `Meta()` (`internal/harness/harness.go:116`: `Binary`, `Installer`, `ManagedDirs`, `ManagedFiles`) and register the package in `internal/harness/all`; `halod` derives its path allowlist and binaries from it, or it will refuse to apply the files.
4. **Golden tests and release check**: rendered output matches fixtures under `testdata/`; add a case to `internal/release/check.go` so the parsed output is verified for `bypassPermissions`, `danger-full-access` and the profile's lock settings.
5. **Smoke test** in a container: install the pinned CLI, apply the output, confirm the CLI loads it (`--version`, a doctor-style command) and that an out-of-range version refuses to start (if the CLI supports it).
6. **Eval driver**: headless invocation for `halo eval` and event parsing for telemetry normalization.
7. **Docs**: update the [harness matrix](/halos/reference/harness-matrix/) and [metrics mapping](/halos/reference/metrics/).

## Rollout

New harness: `canary` starting at ring0 with the matrix complete, golden tests green and evals passing. Rollback: disable the harness in the profile.

## Rules

- Never emit a permissive mode (`bypassPermissions`, `danger-full-access` or equivalents), including via overrides (AGENTS.md invariant 1).
- Fail closed when a required key is uncertain.
- Cross-check the adapter's claims in the docs: a docs/code disagreement is a bug.
