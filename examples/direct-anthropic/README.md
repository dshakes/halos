# direct-anthropic

Claude Code straight to Anthropic through `halo-proxy`. No cloud provider, no orchestrator.

## Who this is for

Teams that buy Claude directly, want the org Anthropic key to live only on the proxy host, and want model routing, rings and traffic canaries on top.

## Tree

```
direct-anthropic/
  halos.yaml                         OIDC identity (any IdP)
  gateway.yaml                       engine halo-proxy, one `anthropic` upstream, sonnet/opus/haiku aliases
  profiles/base.yaml                 model allowlist, no-bypass, sandbox, secret denies, telemetry, egress
  profiles/engineering.yaml          extends base, pins claude-code
  rings/ring0-platform.yaml          platform group
  rings/ring1-ga.yaml                everyone else
  experiments/opus-new-snapshot.yaml draft 5% traffic canary of a newer Opus snapshot
```

## Adopt it

```bash
cp -r examples/direct-anthropic my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
halo gateway routes --policy-dir my-policy --user you@example.com
```

Run `halo-proxy` with the Anthropic key in its own environment; clients never hold one. The experiment is `status: draft`: nothing is exposed until a human starts it with `halo exp start`.
