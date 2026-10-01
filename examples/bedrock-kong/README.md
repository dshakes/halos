# bedrock-kong

Claude Code through Kong (`halo-kong` plugin), your auth gateway and an orchestrator to Amazon Bedrock.

## Who this is for

Enterprises that already front model traffic with Kong and an orchestrator that owns the AWS identity. `engine: kong` is set because `halo-kong` does not sign SigV4 and uses each route's first target.

## Tree

```
bedrock-kong/
  halos.yaml                           OIDC identity verified at the gateway
  gateway.yaml                         engine kong, `orchestrator` upstream, sonnet/opus/haiku -> inference profile ARNs
  profiles/base.yaml                   managed-only MCP and hooks, denies, telemetry, egress allowlist
  profiles/engineering.yaml            extends base, pins claude-code
  rings/ring0-platform.yaml            ai-platform group
  rings/ring1-canary.yaml              10%, opt-in
  rings/ring2-ga.yaml                  default
  toggles/github-mcp.yaml              GitHub MCP for 10% of the canary ring, killable without a release
  rollouts/engineering-settings.yaml   draft blue-green rollout with approval gates
```

## Adopt it

```bash
cp -r examples/bedrock-kong my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
halo gateway compile --policy-dir my-policy -o policy.json
halo gateway deck --policy-dir my-policy --policy-path /etc/kong/policy.json -o kong.yml
halo rollout plan engineering-settings-example --policy-dir my-policy
```

Replace the ARNs with your inference profiles and the `corp.example` hosts with yours. The rollout digests are placeholders; `halo release build` produces real ones. Walkthrough: the Bedrock via Kong guide.
