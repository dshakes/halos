# regulated

A locked-down policy for restricted codebases: strict permissions, no web, egress-limited MCP, audit hooks, one region.

## Who this is for

Banks, health and public-sector teams where AI use must be auditable, data must stay in one region and every access change needs review.

## What it enforces

- Bedrock in `eu-west-1` only; two models, `models.enforce: true`.
- `WebFetch`, `WebSearch`, `curl`, `wget`, `ssh`, `scp`, `nc` and key/secret reads are denied; `git push` and `rm` ask.
- `sandbox: workspace-write` with `sandboxRequired: true`: Claude refuses to start if the sandbox is missing.
- MCP and hooks are managed-only: one internal MCP server, an audit hook on every Bash call and a DLP hook on prompts.
- Telemetry on, `logPrompts: false`. Egress is an explicit internal allowlist.
- Self-service is off; the rollout needs human approval for the pilot and GA steps.
- The only harness override is `companyAnnouncements`, which the override allowlist permits.

## Tree

```
regulated/
  halos.yaml, gateway.yaml                 identity, selfService off, one Bedrock upstream
  profiles/base.yaml, engineering.yaml     the restrictions above
  rings/ring0-security.yaml, ring1-pilot.yaml (5%), ring2-ga.yaml
  rollouts/settings-change.yaml            draft, approval gates after the security ring
```

## Adopt it

```bash
cp -r examples/regulated my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
halo render --policy-dir my-policy --ring ring2-ga --os linux --out /tmp/rendered
```

Read `/tmp/rendered/etc/claude-code/managed-settings.json` before shipping. Replace the `regulated.example` hosts, ARNs and hook paths. Halos renders config; it does not install the hook binaries.
