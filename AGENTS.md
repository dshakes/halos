# AGENTS.md

Halos: OSS Go control plane for AI coding CLIs (Claude Code, Codex, Gemini). Policy repo -> signed releases -> rollout rings -> experiments -> eval-gated promotion. CLI is `halo`. Module `github.com/dshakes/halos`. This file is the source of truth for contributors' agents; `CLAUDE.md` points here.

## Commands

```
make build        # halo halod halo-shadow halo-server into bin/
make test         # go test -race ./...
make lint         # golangci-lint run ./...
make vuln         # govulncheck
make docs         # docs site (npm)
go vet ./...
go test -race ./internal/<pkg>/...   # run on every package you touch
```

Before finishing: `gofmt -l .` empty, `go build ./... && go vet ./... && go test -race <touched pkgs>`. Never run `go mod tidy` without being asked. Report any check you could not run as UNVERIFIED.

## Package map

- `cmd/halo` CLI (cobra). `cmd/halod` fleet agent. `cmd/halo-server` API + console. `cmd/halo-shadow` shadow mirror. `cmd/halo-kong` gateway plugin.
- `internal/policy` types, loader, validation, ring/experiment resolution.
- `internal/harness/{claudecode,codex,gemini,copilot}` adapters: render config + capability matrix.
- `internal/release` build/diff of release bundles; `internal/bundle` OCI push/pull + signing.
- `internal/assign` deterministic hashing. `internal/gateway`, `internal/identity`, `internal/server`, `internal/shadow`.
- `internal/eval` replay evals + scorecards. `internal/stats` mSPRT/bootstrap. `internal/promote` verdicts, promotion/rollback plans, PRs.
- `internal/mcpserver` MCP server behind `halo mcp serve`. `plugins/claude-code` Claude Code plugin. `schemas/` JSON Schemas. `examples/acme-corp` example policy repo.

## Invariants (do not break; flag rather than bend)

1. Never emit `bypassPermissions` or `danger-full-access` in any rendered config, ring or profile.
2. Adapters warn, never silently drop: an unsupported setting produces a warning in the release manifest.
3. `internal/assign` is the single source of hashing for ring and variant assignment. Do not reimplement it.
4. Client-supplied `x-halo-*` headers are stripped at the gateway; cohort comes from the authenticated identity only.
5. No auto-merge, no auto-promote. Promotion opens a PR and a human merges. Auto-rollback is the only automatic direction.
6. Releases are immutable and content-addressed; rings point at releases; rollback means re-pointing.
7. Never hand-edit generated code or `go.sum`; never commit secrets.

## Agentic operation (MCP)

`halo mcp serve --policy-dir DIR [--allow-writes] [--clickhouse URL] [--server URL]` serves read tools (status, validate, plan, release_build, render_preview, whoami, list_rings, list_experiments, show_experiment, harness_matrix, explain_release_diff, eval_scorecard, wait_for, list_rollouts, rollout_status, analyze_experiment when ClickHouse is set; kill_switch_status, fleet_status, audit_tail when `--server` and `HALO_SESSION` are set), resources (`halos://policy/<path>`, `halos://schema/<kind>`, `halos://guide/autopilot`) and prompts (`autopilot` is the full lifecycle with its human gates). Write tools (`start|pause|conclude_experiment`, `propose_promotion`, `propose_rollback`, `propose_rollout_advance|rollback`, `kill_switch`, `eval_run`) exist only with `--allow-writes` (the last two are registered always and preview without it), default to `dry_run`, require a `reason`, and only commit to a local branch, open a PR, or post to halo-server's reversible kill list. Every tool answers with `next_steps`: the next call or the exact human command at a gate. No tool publishes releases, retags registry rings, merges, or pushes to main: a human owns every irreversible step. Do not add one.

### Onboarding a user or a company

Follow `plugins/claude-code/skills/halos-onboard/SKILL.md` (Claude Code: `/halos:halo-onboard`; Codex: `$halos-onboard`; Gemini CLI and Copilot CLI: the `onboard` MCP prompt, or read the skill file). Three paths: try it (`halo quickstart`), my machine (`halo doctor` -> `halo onboard local` -> `install` -> `proxy` -> `verify`), my company (`halo onboard company` -> validate/plan/eval -> PR). The MCP tools `doctor`, `detect_harnesses`, `init_policy`, `local_install`, `local_proxy`, `verify_harness` and `onboard_company` mirror those commands; every one with a side effect (writing files, or `verify_harness` spawning a CLI that spends the human's credentials) defaults to `dry_run` and refuses `dry_run: false` without `--allow-writes`. Show every write as a dry run and wait for a yes; never print or ask for a credential value; stop before publish, enroll, push, merge or deploy.

### Driving Halos from Codex

See `.codex/README.md` for the config snippet. Follow the same flow as the Claude plugin's `halos-rollout` skill (`plugins/claude-code/skills/`): edit YAML -> `validate` -> `plan` -> eval -> start experiment in ring1 -> `analyze_experiment` -> `propose_promotion`, stopping for human approval before starting and before promoting.
