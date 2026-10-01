# acme-corp example policy repo

A complete Halos policy repo for a fictional org whose traffic flows
CLI -> Kong (`https://ai.acme.example`) -> custom auth API gateway -> internal
orchestrator -> AWS Bedrock (application inference profiles), with a direct
Anthropic upstream for experiments.

| Path | Kind | What it shows |
|------|------|---------------|
| `halos.yaml` | root | Org name |
| `gateway.yaml` | Gateway | Model aliases (`sonnet`, `opus`, `haiku`, `codex-default`, `gemini-default`), upstreams, `acme-token` auth helper, `x-acme-user` identity header |
| `profiles/base.yaml` | Profile | Org defaults: telemetry on, bypass disabled, secrets denied, managed hooks/MCP only, egress allowlist, org instructions |
| `profiles/engineering.yaml` | Profile | `extends: base`; pins claude-code, codex, gemini-cli |
| `profiles/engineering-next.yaml` | Profile | `extends: engineering`; newer CLI pins |
| `rings/` | Ring | ring0 (IdP group `ai-platform`) -> ring1 5% -> ring2 25% -> ring3 default (GA) |
| `experiments/opus-5-5-canary.yaml` | Experiment | Traffic-axis canary: new Opus route for 5% of ring1 |
| `experiments/claude-cli-2.1.3xx-ab.yaml` | Experiment | Client-axis A/B of a CLI upgrade |
| `experiments/sonnet-next-shadow.yaml` | Experiment | Shadow: 5% of first-turn requests mirrored to a candidate |

All experiments use mSPRT stopping with the `halo.*` metrics
(`halo.task.success`, `halo.cost.usd_per_session`, `halo.api.error_rate`,
`halo.edit.accept_rate`, `halo.latency.p95_ms`).

Each file carries a `yaml-language-server` comment pointing at `schemas/` for
IDE autocomplete. ARNs, hostnames and versions are illustrative.
Check it with `halo validate examples/acme-corp` (or `policy.Load` + `Validate`).
