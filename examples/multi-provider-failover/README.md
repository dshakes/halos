# multi-provider-failover

One model alias backed by Anthropic, Amazon Bedrock and Google Vertex, with weighted tiers and automatic failover.

## Who this is for

Teams that cannot afford a single provider outage or rate limit stopping every developer, or that want to move traffic between providers as a policy change instead of a client change.

## Tree

```
multi-provider-failover/
  halos.yaml                              OIDC identity
  gateway.yaml                            three upstreams; `sonnet` and `opus` as priority tiers
  profiles/base.yaml, engineering.yaml    model allowlist, no-bypass, telemetry, egress
  rings/ring0-platform.yaml, ring1-ga.yaml
  experiments/sonnet-bedrock-first.yaml   draft A/B: Bedrock-first vs. the 70/30 default
```

## How the routes behave

- `sonnet`: tier 0 splits 70/30 between Anthropic and Bedrock (sticky per user and session); Vertex is tier 1 and only used if tier 0 fails.
- `opus`: strict order Anthropic, then Bedrock, then Vertex.
- Failover happens on a connect error, 5xx or 429, before any byte streams to the client.

## Adopt it

```bash
cp -r examples/multi-provider-failover my-policy
halo validate --policy-dir my-policy      # OK: policy valid (0 warnings)
halo gateway routes --policy-dir my-policy --user you@example.com --session s1
```

Credentials are not in policy: `halo-proxy` signs Bedrock with its own AWS identity, uses Google ADC for Vertex, and holds the Anthropic key itself. Replace the project, ARNs and Vertex model ids with yours. Multi-target routes are `halo-proxy` only; with `engine: kong` validation warns.
