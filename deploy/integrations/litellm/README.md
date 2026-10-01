# LiteLLM  (UNVERIFIED: written from LiteLLM's documented config format, not run)

**A. halo-proxy in front (recommended)** - clients -> halo-proxy -> LiteLLM -> providers.
LiteLLM keeps doing provider translation, keys, budgets; halo-proxy adds verified cohort assignment,
model rewrite and shadow mirroring.

```sh
halo-proxy --policy policy.json --next-hop http://litellm:4000 --forward-auth
```

`--forward-auth` is needed only if LiteLLM authenticates the same bearer token (e.g. via its JWT auth /
SSO); otherwise omit it and give LiteLLM a master key via `upstreamHeaders` on the policy upstream.
The policy's model routes must name models LiteLLM knows: halo-proxy rewrites `sonnet` -> the route's
`model`, so define those names under `model_list[].model_name` (`litellm-config.yaml`).

**B. LiteLLM as a policy upstream** - keep LiteLLM as the front door and have it forward to
halo-proxy for the Anthropic-format models (LiteLLM `anthropic/...` with `api_base: http://halo-proxy:8088`),
or point a policy upstream at LiteLLM (`kind: openai`, `url: http://litellm:4000`) and let halo-proxy
run standalone. In B the caller's JWT must reach halo-proxy (`forward` it) or use `trusted_header` +
`trustedProxyCIDRs`.
