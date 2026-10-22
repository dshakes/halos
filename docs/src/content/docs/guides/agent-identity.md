---
title: Agent identity and delegation
description: Give subagents, background agents and A2A callers a credential of their own that acts for a person or pipeline, bounded by policy, attributed in audit and telemetry, and charged to the root's budgets.
---

When an agent spawns a subagent or calls a remote agent, it should not hand over its own credential. Halos mints a **delegated credential** instead ([ADR-0024](/halos/adr/0024-agent-identity-and-delegation/)):

- The subject stays the **root principal**: the human or CI workload the chain started from. Ring, toggles, posture gates and budgets are the root's, so an agent cannot leave a budget, skip a posture gate or pick a different experiment arm.
- The agents form an RFC 8693 `act` chain, for example `planner>reviewer`. It is audited on every exchange and stamped on every model call (`x-halo-actor`, `halo.actor.*`).
- Policy decides which agents may act, how deep, for how long, and which models and tools they may use. Every child's scope is equal to or narrower than its parent's.

## Policy

```yaml
# halos.yaml
agents:
  maxDepth: 2            # an agent and one subagent (default 2, at most 5)
  maxTTLSeconds: 900     # never longer than the parent's remaining lifetime
  experiments: false     # agents get control routing and no shadow (default)
  allowedModels: [sonnet, haiku]
  deniedTools: [Bash, web_search]
  actors:
    - name: planner
      harnesses: [claude-code]
    - name: reviewer
      models: [haiku]      # narrows allowedModels for this agent
    - name: release-bot
      groups: [ai-platform] # only for roots in this group
```

An `actor_id` that is not listed is refused. `actor_harness` and `actor_session` are labels the caller asserts, recorded for audit and correlation, never a control: they may hold only `A-Z a-z 0-9 . _ : -` (64 and 256 bytes), and anything else is a 400 before anything is audited.

`deniedTools` names function tools (matched ignoring case) and hosted tools. A hosted tool, one the provider runs or builds in, counts by its type: `web_search_20250305` and `web_search_preview` (Anthropic, OpenAI), `codeExecution`, `googleSearch` and `urlContext` (Gemini), a Bedrock `systemTool` name, and `mcp:<server>` for a remote MCP server (Anthropic `mcp_servers`, OpenAI `mcp` tools). A deny entry matches a hosted tool as a prefix ignoring case and underscores, so `web_search` denies every version of it, `code_execution` denies `codeExecution`, and `mcp` denies every MCP server. Profiles and units may lower the depth (`agents.maxDepth`) and narrow the remote agents (`agents.remote: [names]`). `halo validate` reports a unit that raises the depth or adds a remote agent as a loosening.

## Mint a delegated credential

The parent is the human's `halo_session` (the console cookie, also used as `HALO_SESSION`), a workload credential from `halo ci token`, or another delegated credential:

```sh
curl -fsS https://halo.acme.example/api/v1/token/exchange \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token="$HALO_SESSION" \
  -d subject_token_type=urn:halos:params:oauth:token-type:session \
  -d actor_id=planner -d actor_harness=claude-code -d actor_session="$SESSION_ID" \
  -d scope="model:sonnet"
```

The response is RFC 8693 (`access_token`, `expires_in`, ...) plus `subject`, `ring`, `actors` and `models`. Give the subagent `access_token` as its gateway bearer, the same way as a [workload credential](/halos/guides/ci-and-cloud-agents/). The subagent delegates further by sending that token as `subject_token` with `subject_token_type=urn:ietf:params:oauth:token-type:jwt` and its own `actor_id`.

Refused, with the reason, and audited as `agent.token.denied`:

- A depth over the root's limit, or an agent already in the chain (a cycle).
- A model outside the parent's scope, `allowedModels` or the actor's `models`, or an empty intersection.
- A `group:` the parent does not hold. Narrowing groups is refused too: groups decide the ring, toggles and group budgets, so narrow models instead.
- An `expires_in` longer than `maxTTLSeconds` or the parent's remaining lifetime (any size: a 400, never a 500).
- A revoked session or a SCIM-deactivated root (audited with the root and the parent's `jti`).
- A policy that cannot be resolved for the root (a 503, audited).

A forged, malformed or expired parent is a 400 that is logged, not audited, and spends the client IP's failed-authentication budget. Delegation and egress share a budget of their own, separate from CI token exchange; policy refusals never spend it.

## At the gateway

`halo-proxy` and `halo-kong` verify the credential with the same workload public key as workload credentials (`identity.workloadPubkeyFile` / `workload_pubkey`). On every model call they apply the current policy and refuse with a 400 `agent_not_permitted` when:

- any agent of the chain was removed from `actors`, or lists `groups` the root no longer holds;
- the chain is deeper than `maxDepth`, or than the root's profile and unit `maxDepth`;
- the model is outside the credential scope, `allowedModels` or the `models` of any actor in the chain;
- the request declares a `deniedTools` tool;
- `deniedTools` is set and the request's tools cannot be read: a body nested too deeply, malformed tool declarations, or a request shape the gateway has no tool reader for.

The gateway reads tools from Anthropic Messages and `count_tokens` (`tools[]`, `mcp_servers[]`), OpenAI Responses (`tools[]`), Gemini `generateContent`, `streamGenerateContent` and `countTokens` (`functionDeclarations` and `function_declarations`, built-in tool keys), and Bedrock invoke and Converse (`tools[]`, `toolConfig.tools[]`, `additionalModelRequestFields.tools`). Keys are matched ignoring case and underscores, and duplicate keys all count.

With a SCIM directory, an agent of a deprovisioned user gets a 403, like the user. Client copies of `x-halo-actor` and `x-halo-actor-depth` are discarded. Metrics carry `halo.actor.agent` and `halo.actor.depth`. Spans also carry `halo.actor.chain` and `gen_ai.agent.name`.

## Remote agents (A2A)

List the [A2A](https://a2a-protocol.org) agents members may call, pin each AgentCard, and say who may call it:

```yaml
agents:
  remote:
    - name: billing
      cardURL: https://agents.billing.example/.well-known/agent-card.json
      digest: sha256:4f1c...            # from `halo agents verify`
      jwksURL: https://agents.billing.example/.well-known/jwks.json  # or publicKey: PEM
      skills: [lookup-invoice]
      rings: [ring3-ga]
      units: [payments]
```

```sh
halo agents verify https://agents.billing.example/.well-known/agent-card.json        # prints the digest to pin
halo agents verify --policy-dir . https://agents.billing.example/.well-known/agent-card.json  # checks the pins; exit 1 on drift
```

`verify` fetches over https only, with no redirect off the host, at most 256 KB, and a timeout. It refuses loopback, private and link-local addresses unless `--allow-private`, and always refuses IPv6 transition addresses that embed an IPv4 address (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`). A card with invalid UTF-8 or a lone surrogate escape has no digest, the card's fields are read by exact key (`SKILLS` is not `skills`), and card text is printed with control characters escaped. With a pinned key or JWKS, the card's JWS signature (A2A section 8.4) must verify. Run it in CI: a changed card fails until someone updates the pin in a reviewed PR.

Ring releases list the agents their members may call, with the pinned digests, signed with the release. No coding CLI has a system-level A2A allowlist setting, so each harness gets a release warning. Gemini CLI reads remote agents from per-user `.gemini/agents/*.md` files; `experimental.enableAgents: false` in `harnesses.gemini-cli.overrides` turns off all its subagents.

To enforce the allowlist, have the egress proxy in front of your agents ask halo-server before each A2A call:

```sh
curl -fsS https://halo.acme.example/api/v1/agents/egress \
  -H "Authorization: Bearer $DELEGATED_OR_WORKLOAD_TOKEN" \
  -d '{"url":"https://agents.billing.example/a2a/v1","skill":"lookup-invoice"}'
# {"allow":true,"agent":"billing","digest":"sha256:4f1c...","reason":"allowed","ring":"ring3-ga"}
```

The decision uses the root's ring, unit and profile from the verified credential, re-checks every agent of the chain and the root's profile and unit `maxDepth`, and is audited. An allow is fail closed: when `agent.egress.allow` cannot be recorded the answer is a 500, never an allow. A refusal (`agent.egress.deny`) is best-effort; a failed append increments `halo_server_audit_append_errors_total`. A human root whose sessions were revoked after it authenticated, or who was deprovisioned, gets a 403. An expired agent credential gets a 401 but does not spend the IP's failure budget: long agent runs outlive their credentials, and only a holder of the signing key can produce one.

## Limits

- A delegated credential cannot be revoked on its own. It dies at `exp` (at most `maxTTLSeconds`), when any agent of its chain leaves `actors`, or when its root is deprovisioned.
- The gateway has no session revocation list. Revoking a human's sessions stops their agents' exchanges and egress decisions at once, and their model calls when the credential expires.
- The egress API is advisory until a proxy enforces it.
