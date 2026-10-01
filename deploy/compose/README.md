# Halos traffic-plane quickstart

```
curl -> Kong OSS (db-less) + halo-kong Go plugin :8080   (verifies the bearer JWT itself)
     -> orch-mock | anthropic-mock                     (fake upstreams, echo model + headers)
     -> halo-shadow :8090 gets async mirrors of sampled first-turn requests
mock-idp :8081  demo OIDC issuer (discovery + JWKS + GET /token)
```

Identity is **verified, never trusted**: `halo-kong` checks the caller's JWT against the IdP's JWKS
(issuer/audience come from `Identity` in `policy.json`), so Kong may sit *before* your auth gateway
and client-supplied `x-acme-*` / `x-halo-*` headers cannot influence the cohort.

```sh
docker compose up -d --build          # HALO_PORT / HALO_IDP_PORT if 8080 / 8081 are taken
TOK=$(curl -s 'localhost:8081/token?user=alice@acme.com&groups=ai-platform')
curl -s localhost:8080/v1/messages \
  -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -H 'x-claude-code-session-id: s1' \
  -H 'x-halo-ring: ring3-ga' \                       # spoof attempt: overwritten by the gateway
  -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
```

**No Kong?** `docker compose -f docker-compose.halo-proxy.yml up -d --build` runs the same demo with
`halo-proxy` (cmd/halo-proxy) in place of Kong: clients -> halo-proxy -> upstreams.
(VERIFIED: halo-proxy variant. UNVERIFIED: the Kong variant was not built/run after the JWT change.)

The reply text shows the upstream, the rewritten model (`sonnet` -> `us.anthropic...`) and the
`x-halo-ring/release/experiment/variant` headers the upstream received.

| Try | Expect |
|---|---|
| token for `alice@acme.com`, groups `ai-platform` | ring `ring0-harness-team`, model routed via `orch` |
| token for `bob@acme.com`, groups `eng` | ring1/GA; 50% of users land in the `direct` canary (anthropic-mock, dated model id) |
| add `-d '{..."stream":true...}'` with `curl -N` | SSE arrives incrementally |
| `POST /model/sonnet/invoke` | path rewritten to the Bedrock model id |
| `POST /v1/responses` | OpenAI Responses body, model rewritten |
| no / forged / expired token | halo-kong: default routing, ring `unknown` (halo-proxy: 401) |
| `-d '{"model":"gpt-4o",...}'` (not a policy alias) | 403 with an Anthropic-shaped `permission_error`; never forwarded |
| `POST /v1/messages/batches` | 404 at Kong (exact routes), 403 at halo-proxy |
| `curl -H 'X-Halo-Shadow-Token: dev-only-token' localhost:8090/metrics` | `halo_shadow_mirrored_total` etc. (token required; port bound to 127.0.0.1) |
| `docker compose exec halo-shadow tail /data/pairs.jsonl` | control/candidate pairs for the judge |

`sonnet-next-shadow` samples 100% here (`sampleRate: 1`) so you see pairs immediately; halo-shadow
stops at a $5 estimated spend (default $50; each job reserves its worst-case estimate before it is
sent). halo-shadow reads the same `policy.json` and resolves control/candidate upstreams itself: a mirror
job names only experiment + variant, so the halo-shadow token can't be used to aim halo-shadow (or its
per-upstream credentials, `-upstream-headers`) at an arbitrary URL.

Change `policy.json` (it is hot-reloaded by mtime, ~1s) to move users between rings or variants.
After editing routes/upstreams regenerate Kong's config: `go run ./deploy/compose/gen` then
`docker compose restart kong`. `kong.yml` holds only the Kong vault reference
`{vault://env/halo-shadow-token}`; the demo value `dev-only-token` is in Kong's environment
(`HALO_SHADOW_TOKEN`, passed through nginx by `KONG_NGINX_MAIN_ENV`), so the Admin API never shows it.

Kong must run with `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m`: halo-kong needs the whole body in
memory to enforce the model allowlist, and a body Kong spooled to disk is answered 413 (never
forwarded un-inspected). Generated routes are `https`-only unless `kong.Options.AllowHTTP` (this
demo sets it because Kong listens on plain http).
