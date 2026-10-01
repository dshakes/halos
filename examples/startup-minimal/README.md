# startup-minimal

The smallest useful Halos policy repo: one profile, two rings, one gateway alias.

## Who this is for

A small team on Claude Code and a direct Anthropic key that wants pinned CLI versions, a model allowlist, a few secret-file denies and usage telemetry, without running much infrastructure.

## Tree

```
startup-minimal/
  halos.yaml            org name (no identity provider yet)
  gateway.yaml          halo-proxy -> api.anthropic.com, alias `sonnet`
  profiles/default.yaml claude-code 2.1.280, deny .env and ~/.ssh, telemetry on
  rings/canary.yaml     the founder plus anyone who opts in
  rings/ga.yaml         everyone else (the default ring)
```

## Adopt it

```bash
cp -r examples/startup-minimal my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
```

Then replace `startup.example` with your domain and the canary user with your own, point `baseURL` at your `halo-proxy`, and add an `identity:` block once you have an OIDC provider. Telemetry has no `otlpEndpoint` here; add one when you have a collector.
