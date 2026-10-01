---
title: Gateway headers
description: The x-halo-* headers stamped by halo-proxy and halo-kong, and the spoofing rules.
---

Headers owned by the gateway (from `internal/gateway/decision.go`):

| Header | Value | Set by |
|---|---|---|
| `x-halo-ring` | Ring name, or `unknown` if there is no verified identity or no ring matched | `halo-proxy` / `halo-kong` |
| `x-halo-release` | Release digest of the ring, if the ring's `release` is set | `halo-proxy` / `halo-kong` |
| `x-halo-experiment` | Active A/B or canary experiment the request is in, if any. Never set for a [killed](#killed-experiments) experiment | `halo-proxy` / `halo-kong` |
| `x-halo-variant` | Variant name within that experiment. Never set for a killed experiment | `halo-proxy` / `halo-kong` |
| `x-halo-killswitch` | The literal `misconfigured`, set only when `halo-kong`'s kill-switch config is invalid (bad key, missing token, cleartext URL without `killswitch_allow_insecure_in_cluster`). While present, kills are **not** being enforced by that plugin; alert on it. Traffic is not blocked | `halo-kong` |

## Rules

1. **Everything under `x-halo-` is owned by the gateway.** Every client-supplied `x-halo-*` header is discarded before anything is computed, even if the host's header list was truncated.
2. The cohort is derived from the identity the gateway **verified**: the caller's OIDC JWT (issuer, audience, expiry), or, in `trusted_header` mode, headers set by a proxy whose address is in `trustedProxyCIDRs`. It is never taken from a client-provided value. No verified identity means ring `unknown`, default routing and no experiments.
3. The configured identity and groups headers are removed from the forwarded request once the subject is derived. In `trusted_header` mode a request carrying either header twice is a 400. The identity header may not be an `x-halo-*` name.
4. Upstream services (auth gateway, orchestrator) may trust `x-halo-*` only if they are unreachable except through the gateway.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/header-stripping-light.svg" alt="The client sends a forged x-halo-ring header; the gateway deletes every x-halo header, verifies the JWT for user and groups, decides ring, release, experiment and variant, then sets x-halo stamps on the upstream request." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/header-stripping-dark.svg" alt="The client sends a forged x-halo-ring header; the gateway deletes every x-halo header, verifies the JWT for user and groups, decides ring, release, experiment and variant, then sets x-halo stamps on the upstream request." width="760" />

The stamps go on the **upstream request**. They are not added to the response the client receives.

## Killed experiments

When an experiment is on the gateway's [kill list](/halos/concepts/experiments/#kill-switch), the gateway treats it as not running: the request gets control routing, is not mirrored, and carries **no** `x-halo-experiment` or `x-halo-variant` header. The ring and release stamps are unaffected. Downstream analysis that groups by these headers therefore sees killed traffic as un-experimented, which is the point: nothing is attributed to a treatment that is switched off. The effect lasts until the experiment is unkilled, not until the gateway's next policy snapshot.

## Errors

Rejections are rendered in the caller's wire format so the CLI prints the reason: 403 for a model that is not a policy alias or for the batches API, 404 for an unknown model endpoint, 413 for an oversize or unreadable body, 401 for a failed JWT (unless `allowAnonymous`), 503 while the policy is not loaded or when `trusted_header` has no CIDR pin.

## Shadow authentication

The gateway posts jobs to `halo-shadow` with `X-Halo-Shadow-Token` so only the gateway can enqueue mirrors. A job names only an experiment and variant; `halo-shadow` resolves the upstreams from its own policy copy and replays with its own credentials. Client credentials are never forwarded.

## Client-side headers

For Claude Code, `ANTHROPIC_CUSTOM_HEADERS` can carry release stamping from the client, but these are informational: the gateway ignores and overwrites `x-halo-*`. Codex provider config supports `http_headers`. Gemini CLI and Copilot CLI cannot set custom request headers through managed settings. Claude Code also sends `x-claude-code-session-id`, which the shadow sampler uses to keep a whole session in or out of a mirror.

## Try it

Run the [quickstart](/halos/getting-started/quickstart/) and send a forged header:

```bash
TOK=$(curl -s 'localhost:8081/token?user=alice@acme.com&groups=ai-platform')
curl -s localhost:8080/v1/messages -H "Authorization: Bearer $TOK" -H 'x-halo-ring: ring3-ga' \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' -H 'x-claude-code-session-id: s1' \
  -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'
```

The demo upstream echoes the headers it received: `x-halo-ring:ring0-harness-team`, not `ring3-ga`.
