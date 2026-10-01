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

`halo mcp serve --policy-dir DIR [--allow-writes] [--clickhouse URL]` serves read tools (validate, plan, render_preview, whoami, list_rings, list_experiments, show_experiment, harness_matrix, explain_release_diff, eval_scorecard, analyze_experiment when ClickHouse is set), resources (`halos://policy/<path>`, `halos://schema/<kind>`) and prompts. Write tools (`start|pause|conclude_experiment`, `propose_promotion`, `propose_rollback`) exist only with `--allow-writes`, default to `dry_run`, require a `reason` recorded in the commit message, and only commit to a local branch or open a PR. No tool publishes releases, retags registry rings, merges, or pushes to main: a human owns every irreversible step. Do not add one.

### Driving Halos from Codex

See `.codex/README.md` for the config snippet. Follow the same flow as the Claude plugin's `halos-rollout` skill (`plugins/claude-code/skills/`): edit YAML -> `validate` -> `plan` -> eval -> start experiment in ring1 -> `analyze_experiment` -> `propose_promotion`, stopping for human approval before starting and before promoting.
