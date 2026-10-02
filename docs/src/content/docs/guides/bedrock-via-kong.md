---
title: Bedrock via Kong
description: Route Claude Code through Kong, your auth gateway and orchestrator to Amazon Bedrock, with rings and model aliases.
---

:::caution[What was and was not run]
The `deploy/compose` demo runs Kong OSS with `halo-kong` end to end against **mock** upstreams, and `halo gateway deck` output passes `kong config parse`. **UNVERIFIED:** real Kong Enterprise or Konnect, and real Amazon Bedrock. The `halo-kong` plugin does not sign requests (SigV4): in this topology Bedrock sits behind your orchestrator. To sign from Halos instead, use `halo-proxy` ([direct Bedrock](/halos/concepts/stack-agnostic/#direct-bedrock-sigv4-in-halo-proxy)).
:::

This is the topology Halos was designed for: Kong, then your auth gateway, then an orchestrator, then Bedrock.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/bedrock-kong-light.svg" alt="Claude Code calls Kong with halo-kong, then your auth gateway, then an orchestrator that signs with SigV4 for Amazon Bedrock." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/bedrock-kong-dark.svg" alt="Claude Code calls Kong with halo-kong, then your auth gateway, then an orchestrator that signs with SigV4 for Amazon Bedrock." width="760" />

Because Claude Code does not fetch server-managed settings on this path, configuration must be delivered by [file, MDM or environment](/halos/concepts/delivery/). You can equally run `halo-proxy` in place of the plugin; see [stack-agnostic](/halos/concepts/stack-agnostic/).

## 1. Describe the identity and the gateway

Identity is verified from the caller's OIDC JWT, so Kong may sit before your auth gateway. In `halos.yaml`:

```yaml
identity:
  issuer: https://acme.okta.com/oauth2/default
  audience: halos-gateway
```

Then the gateway document:

```yaml
apiVersion: halos.dev/v1
kind: Gateway
name: acme
baseURL: https://ai.acme.example
protocols: {claude-code: anthropic-messages}
auth:
  helperCommand: acme-sso-token --audience halos-gateway
  ttlSeconds: 900
models:
  sonnet: {upstream: orchestrator, model: us.anthropic.claude-sonnet-4-5-v1:0}
upstreams:
  orchestrator: {url: https://orchestrator.internal.acme.example, kind: orchestrator}
```

`auth.helperCommand` becomes Claude Code's `apiKeyHelper`: it must print a token whose `aud` matches `identity.audience`. `auth.identityHeader` is only needed for `trusted_header` mode.

## 2. What the Claude Code adapter renders

Run `halo render --policy-dir examples/acme-corp --ring ring1-canary --os linux --out /tmp/rendered` and read `/tmp/rendered/etc/claude-code/managed-settings.json`. It carries:

- `env.ANTHROPIC_BASE_URL` pointing at the gateway,
- `env.ANTHROPIC_CUSTOM_HEADERS` for release stamping (informational; the gateway overwrites `x-halo-*`),
- `requiredMinimumVersion` / `requiredMaximumVersion` pinning the ring's CLI,
- `availableModels` and `enforceAvailableModels` from `models`,
- `allowManagedHooksOnly`, `allowManagedMcpServersOnly`, `disableBypassPermissionsMode` from the profile,
- OTEL env with `OTEL_RESOURCE_ATTRIBUTES` carrying `halo.ring`, `halo.release` and `halo.harness`.

## 3. Compile the policy and generate Kong config

```bash
halo gateway compile --policy-dir examples/acme-corp -o policy.json         # the snapshot halo-kong loads
halo gateway deck --policy-dir examples/acme-corp \
  --policy-path /etc/kong/policy.json \
  --halo-shadow-url http://halo-shadow:8090 -o kong.yml               # decK declarative config
deck gateway sync kong.yml
```

The generated config uses exact regex routes (so `/v1/messages/batches` cannot bypass the model allowlist), https-only routes, and a Kong vault reference for the shadow token. Run Kong with `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m` and `KONG_NGINX_MAIN_ENV=HALO_SHADOW_TOKEN`. `deploy/compose/` has a working Dockerfile and `kong.yml`.

## 4. Verify

Use a real token from your IdP:

```bash
curl -s https://ai.acme.example/v1/messages -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \
  -d '{"model":"sonnet","max_tokens":16,"messages":[{"role":"user","content":"ping"}]}'
```

**Check:** the request succeeds; asking for an alias not in `models` returns 400 `invalid_request_error`; and a forged `x-halo-ring` does not change the ring your orchestrator sees. The compose demo reproduces all three against mocks.

## 5. Kill switch (optional)

Give `halo-kong` the signed kill list from `halo-server` and a rollback verdict or an admin click takes effect in seconds instead of after a PR merge. `halo gateway deck --killswitch-url https://<halo-server>/api/v1/gateway/killswitch` generates `killswitch_url`, `killswitch_token` and `killswitch_pubkey` (the last two as the vault references below); `killswitch_allow_insecure_in_cluster` is never generated, add it by hand if you need it.

| Field | Meaning |
|---|---|
| `killswitch_url` | `https://<halo-server>/api/v1/gateway/killswitch`. Empty disables the kill switch |
| `killswitch_token` | The gateway bearer token (`halo-server --gateway-token-file`). A literal or a Kong env-vault reference such as `{vault://env/halo-killswitch-token}` |
| `killswitch_pubkey` | ed25519 **public** key PEM matching `halo-server --killswitch-key-file` (`killswitch.pub` from `halo keys generate --name killswitch`). A literal or `{vault://env/halo-killswitch-pubkey}` |
| `killswitch_allow_insecure_in_cluster` | Default `false`. `killswitch_url` must be `https://` unless it targets loopback or this is `true`, because the bearer token travels on every poll. Set it only for a trusted in-cluster URL |

```yaml
plugins:
  - name: halo-kong
    config:
      policy_path: /etc/kong/policy.json
      killswitch_url: https://halo.acme.example/api/v1/gateway/killswitch
      killswitch_token: "{vault://env/halo-killswitch-token}"
      killswitch_pubkey: "{vault://env/halo-killswitch-pubkey}"
```

Vault references resolve from the plugin server's environment, so export `HALO_KILLSWITCH_TOKEN` and `HALO_KILLSWITCH_PUBKEY` to Kong and list them in `KONG_NGINX_MAIN_ENV` alongside `HALO_SHADOW_TOKEN`. The plugin polls every 10 seconds. Killed experiments are treated as not running (control routing, no shadow, no `x-halo-experiment` or `x-halo-variant`). On a failed fetch it keeps the last list; until its first successful fetch nothing is killed. An invalid config (bad key, missing token, cleartext URL) does **not** block traffic, but it is loud: the plugin logs `halo-kong: killswitch config invalid; kill switch not (re)configured, killed experiments may keep running` at ERROR at most once a minute and adds `x-halo-killswitch: misconfigured` to the upstream request (client copies are cleared first). Alert on that header; while it is present, kills are not being enforced.

**Check:** kill an experiment (`POST /api/v1/experiments/<name>/kill` as an admin), wait one poll interval, and send a request as a user in that experiment: the upstream sees no `x-halo-experiment` header. Semantics, failure policy and the wire format: [experiments](/halos/concepts/experiments/#kill-switch), [API reference](/halos/reference/api/#kill-switch). The same settings for `halo-proxy` are in its [README](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/README.md#kill-switch).

## 6. Posture and version gates (optional)

Rings with `posture` or `versionGate` set to `warn` or `enforce` (default `warn`) are checked on every model call ([gateway gates](/halos/concepts/delivery/#gateway-gates)). The version gate needs no config. For the posture gate, point the plugin at `halo-server`:

| Field | Meaning |
|---|---|
| `posture_url` | `https://<halo-server>/api/v1/gateway/posture`. Empty disables the posture gate |
| `posture_token` | The gateway bearer token, a literal or `{vault://env/halo-gateway-token}` |
| `posture_allow_insecure_in_cluster` | Default `false`; as `killswitch_allow_insecure_in_cluster` |

Verdicts are cached per user for 1 minute and kept for 15 minutes while `halo-server` is unreachable; after that the posture is unknown and the request passes. Enforce answers 403 in the CLI's wire format. Warn-mode failures and unknown posture pass, are logged at NOTICE, and tag the upstream request `x-halo-gate` (for example `version=warn,posture=unknown`; client copies are cleared first). An invalid posture config is logged at ERROR and leaves the posture gate off.
