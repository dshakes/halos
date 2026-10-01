# codex-heavy

Codex as the primary harness, talking the `openai-responses` wire through `halo-proxy` to OpenAI, with Azure OpenAI as failover.

## Who this is for

Teams standardising on Codex CLI that want the provider keys held by the proxy, a failover to an Azure deployment, and the same rings and toggles Claude Code users get.

## Tree

```
codex-heavy/
  halos.yaml                        OIDC identity
  gateway.yaml                      `openai` + `azure-openai` upstreams (env-var credentials), codex-default / codex-mini
  profiles/base.yaml                model allowlist, no-bypass, managed MCP, telemetry, egress
  profiles/engineering.yaml         extends base, pins codex 0.99.0
  rings/ring0-platform.yaml, ring1-early.yaml (15%, opt-in), ring2-ga.yaml
  toggles/docs-mcp-early.yaml       extra MCP server for half of the early ring
```

## Adopt it

```bash
cp -r examples/codex-heavy my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
halo gateway routes --policy-dir my-policy --user you@example.com
```

Set `OPENAI_API_KEY` and `AZURE_OPENAI_API_KEY` in the `halo-proxy` environment; policy only names the variables. For Azure, `model` is your deployment name. Replace `example-resource` and the `codex.example` hosts.
