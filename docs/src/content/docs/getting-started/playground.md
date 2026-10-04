---
title: Playground
description: The whole Halos stack in one command, seeded with the acme-corp policy repo, a mock IdP and mock models.
---

The playground runs every Halos component on Docker with a seeded policy repo: the console and self-service portal behind an OIDC login, `halo-proxy`, `halo-shadow`, mock model upstreams and the evidence plane (collector, ClickHouse, Grafana). Nothing talks to a real model provider or cloud account. It is **dev only**: the IdP signs in anyone, and every key and token is generated at start and deleted on teardown.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/request-path-light.svg" alt="A coding CLI calls halo-proxy, which verifies the caller's identity, resolves ring, experiment and toggle, rewrites the model and forwards to the upstream." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/request-path-dark.svg" alt="A coding CLI calls halo-proxy, which verifies the caller's identity, resolves ring, experiment and toggle, rewrites the model and forwards to the upstream." width="880" />

## Start it

**With `halo` [installed](/halos/getting-started/install/)** (Docker and git on the machine):

```sh
halo quickstart          # clones a Halos checkout into ~/.cache/halos/src if needed, then runs make demo
halo quickstart down     # later: stop it and delete its volumes
```

**In the browser:** [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/dshakes/halos). The dev container builds `bin/` and puts it on `PATH`; run `make demo` in its terminal and open the forwarded **Halos console** port (**UNVERIFIED**: not yet run in a real Codespace).

**From a checkout** (Docker with Compose v2.20+, Go to build `bin/`):

```sh
make demo                # make demo-down removes it
```

A one-shot `seed` container copies `examples/acme-corp` plus a small overlay (`deploy/compose/demo/policy`: mock IdP issuer, mock upstreams, the shadow experiment running at 100%), generates throwaway keys, publishes a signed release per ring to a local `registry:2` and compiles `policy.json`. When everything is healthy it prints:

| What | URL |
|---|---|
| Console + portal | `http://localhost:18080` (Sign in, pick a demo user) |
| Mock IdP (OIDC) | `http://localhost:18081/.well-known/openid-configuration` |
| halo-proxy (model API) | `http://localhost:18088/v1/messages` |
| halo-shadow metrics | `http://localhost:18090/metrics` |
| Grafana | `http://localhost:13000` (`admin` / `halo-dev-only`) |

| Demo user | Groups | Lands in |
|---|---|---|
| `alice@acme.com` | `ai-platform` | `ring0-harness-team`, admin |
| `bob@acme.com` | `eng` | `ring2-early` (claude-cli A/B, sonnet shadow) |
| `mallory@acme.com` | `eng` | `ring1-canary` (opus-5-5 canary) |
| `dave@acme.com` | `eng` | `ring3-ga` |

The seeded repo is `examples/acme-corp`, a full-mode repo with every document written out so each feature has something to show. Your own repo would usually start as one file: `halo init` writes a [simple-mode](/halos/concepts/simple-mode/) `halos.yaml`, and `halo explain --policy-dir examples/simple` shows what the `examples/simple` file expands to.

The seeded repo has three running experiments, the `opus-5-5-upgrade` rollout active at step `canary-5`, and three toggles, including `sonnet-next-route` (ring0's `sonnet` goes to the next model).

## Try this

1. **Sign in.** Open the console, click Sign in and choose `alice@acme.com`. The mock IdP runs a real authorization-code + PKCE flow, so the console sees exactly what it would from Okta or Entra. The same flow with curl:

   ```text
   GET /auth/login            -> 302 http://localhost:18081/authorize?...&code_challenge_method=S256
   GET /authorize&user=alice  -> 302 http://localhost:18080/auth/callback?code=...&state=...
   GET /auth/callback         -> 302 http://localhost:18080/
   GET /api/v1/me             alice@acme.com ['ai-platform'] admin=True ring=ring0-harness-team
   GET /api/v1/experiments    claude-cli-2.1.3xx-ab running, opus-5-5-canary running, sonnet-next-shadow running
   GET /api/v1/rollouts       opus-5-5-upgrade active canary-5 (plus two drafts)
   ```

2. **Call the model API as three users.** Each token comes from the mock IdP; a spoofed `x-halo-ring: ring3-ga` header is ignored because the cohort comes from the verified token.

   ```sh
   TOK=$(curl -s 'localhost:18081/token?user=bob@acme.com&groups=eng')
   curl -s localhost:18088/v1/messages -H "Authorization: Bearer $TOK" \
     -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
     -H 'x-halo-ring: ring3-ga' \
     -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
   ```

   ```text
   alice sonnet:  served-by=anthropic model=claude-sonnet-5-5  x-halo-ring:ring0-harness-team
   bob sonnet:    served-by=orch model=us.anthropic.claude-sonnet-4-5-v1:0  x-halo-experiment:claude-cli-2.1.3xx-ab x-halo-ring:ring2-early x-halo-variant:control
   mallory opus:  served-by=orch model=us.anthropic.claude-opus-4-1-v1:0  x-halo-experiment:opus-5-5-canary x-halo-ring:ring1-canary x-halo-variant:control
   no token:      {"error":{"type":"unauthorized","message":"invalid or missing credentials"}}
   ```

   Alice's `sonnet` goes to the next model because the `sonnet-next-route` toggle targets ring0.

3. **Kill the toggle.** On the console's **Toggles** page (as alice), kill `sonnet-next-route` (or `halo toggle kill` with her session cookie). halo-proxy polls the signed kill list every 2s here, so alice's next request falls back to the default route with no release and no policy PR:

   ```text
   POST /api/v1/toggles/sonnet-next-route/kill    -> 200
   alice sonnet:  served-by=orch model=us.anthropic.claude-sonnet-4-5-v1:0
   POST /api/v1/toggles/sonnet-next-route/unkill  -> 200
   alice sonnet:  served-by=anthropic model=claude-sonnet-5-5
   ```

4. **Watch the shadow.** Only first-turn requests that carry a session id are mirrored (Claude Code sends `x-claude-code-session-id`, Codex `session_id`), so add that header to Bob's call. The mirror goes to the candidate route; users only ever see the primary reply.

   ```sh
   curl -s localhost:18088/v1/messages -H "Authorization: Bearer $TOK" -H 'x-claude-code-session-id: demo-1' \
     -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
     -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
   ```

   ```text
   $ curl -s localhost:18090/metrics
   halo_shadow_mirrored_total 1
   halo_shadow_spend_usd 0.001092
   halo_shadow_budget_usd 5
   ```

5. **See the evidence.** halo-proxy exports `halo.gateway.*` metrics to the collector every 5s. Grafana's **Halos: fleet and experiments** dashboard reads them from ClickHouse.

6. **Manage a feature toggle.** Open **Toggles** in the console, pick `github-mcp`, and try **Who gets it?** with a user and groups. **Kill** needs a reason and reaches `halo-proxy` at its next poll (every 2 s in the playground). **Propose change** (for example, ramp the rule to 25%) validates the edit and opens a "PR". In the playground that PR is only a **local branch**: the stack has no GitHub, so `halo-server` pushes `halos/toggle-...` to a bare repo on the `policy-repo` volume and a stub `gh` prints where it landed. Nothing merges, and the served policy does not change. Inspect it with `docker run --rm -v halos-demo_policy-repo:/repo --entrypoint git halos-demo/halo-server -C /repo/remote.git branch`.

## Tear down

```sh
make demo-down    # stops every container and deletes the volumes (keys, releases, data)
```

## Troubleshooting

- **A port is taken.** Every host port binds to `127.0.0.1` and is overridable: `HALO_DEMO_CONSOLE_PORT`, `HALO_DEMO_IDP_PORT`, `HALO_DEMO_PROXY_PORT`, `HALO_DEMO_SHADOW_METRICS_PORT`, and for the evidence plane `HALO_OBS_GRAFANA_PORT`, `HALO_OBS_CH_HTTP_PORT`, `HALO_OBS_OTLP_*_PORT`. Pass the same values to `make demo-down`.
- **A service never got healthy.** The script names it; `docker compose -f deploy/compose/docker-compose.demo.yml logs <service>` shows why. `seed` failing usually means the registry was not reachable.
- **Login loops back to the IdP.** The console's redirect URI and the IdP's browser URL are derived from the ports above (`HALO_DEMO_CONSOLE_URL`, `HALO_DEMO_IDP_URL` override them). In a Codespace the script uses the forwarded `https://<codespace>-<port>.app.github.dev` URLs.
- **Start over.** `make demo-down && make demo` reseeds from scratch.
