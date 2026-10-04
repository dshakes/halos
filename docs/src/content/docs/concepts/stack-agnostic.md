---
title: Stack-agnostic traffic plane
description: halo-proxy deploy modes, the kill switch, the gateway and provider integrations, direct Bedrock with SigV4, and what has and has not been run.
---

The traffic plane does five things for every model call: verify the caller, assign a ring and variant, rewrite the model alias, stamp `x-halo-*` headers, and mirror sampled first turns. `halo-proxy` does all five as one static Go binary that works with any gateway (or none), any OIDC identity provider, and any provider that speaks `anthropic-messages`, `openai-responses` or Bedrock invoke/converse paths, and it can sign Bedrock requests itself. The `halo-kong` plugin runs the same decision code inside Kong.

## Deploy modes

<img class="diagram dark:sl-hidden" src="/halos/diagrams/topologies-light.svg" alt="a. Edge: clients to halo-proxy with --next-hop to your existing gateway, then the provider. b. Behind a gateway: clients to your gateway, then halo-proxy, then the provider. c. Standalone: clients to halo-proxy to the providers." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/topologies-dark.svg" alt="a. Edge: clients to halo-proxy with --next-hop to your existing gateway, then the provider. b. Behind a gateway: clients to your gateway, then halo-proxy, then the provider. c. Standalone: clients to halo-proxy to the providers." width="760" />

| | (a) edge | (b) behind a gateway | (c) standalone |
|---|---|---|---|
| Identity | JWT (default): the client's token is what `halo-proxy` sees | `trusted_header` with `trustedProxyCIDRs` = the gateway's addresses, **or** JWT if the gateway forwards `Authorization` | JWT |
| Upstream | `nextHop: http://kong:8000` | policy upstreams (or `defaultUpstream`) | policy upstreams plus `upstreamHeaders` for provider keys |
| `forwardAuth` | `true` if the gateway behind must authenticate the same token | usually `false` | `false`; inject provider credentials via `upstreamHeaders` |
| Client IP | sees the real client | sees only the gateway | real client |

Pick (a) when the existing gateway must stay authoritative for auth and rate limits and you can change client base URLs to `halo-proxy`. Pick (b) when clients must keep hitting the gateway; there the gateway must **overwrite** the identity header and `halo-proxy` must be unreachable except from it. Model rewriting happens in every mode, including `--next-hop`: the next hop receives the *upstream* model id, not the alias.

## Running halo-proxy

```bash
halo gateway compile --policy-dir policy-repo -o policy.json                    # hot-reloaded by halo-proxy (~1s)
halo-proxy --policy policy.json --listen :8088                     # (c), issuer from the policy
halo-proxy --policy policy.json --next-hop http://kong:8000 --forward-auth   # (a)
halo-proxy --config halo-proxy.yaml
```

Precedence: defaults, then YAML (`--config` or `HALO_PROXY_CONFIG`), then env `HALO_PROXY_<FLAG>` (for example `HALO_PROXY_HALO_SHADOW_TOKEN`), then flags. Unknown YAML keys are errors.

```yaml
listen: ":8088"
policy: /etc/halos/policy.json
nextHop: ""                  # (a): forward everything here
defaultUpstream: ""          # for paths the policy has no route for (for example /v1/models)
forwardAuth: false           # keep client Authorization / x-api-key on the forwarded request
upstreamHeaders:             # per policy upstream name; ${ENV} expanded
  anthropic: {x-api-key: "${ANTHROPIC_API_KEY}", anthropic-version: "2023-06-01"}
identity:
  mode: ""                   # jwt | trusted_header | none
  issuer: ""                 # default: policy identity.issuer
  audience: ""               # default: policy identity.audience / clientID
  userClaim: ""              # default email
  groupsClaim: ""            # default groups
  identityHeader: ""         # trusted_header only
  groupsHeader: ""
  trustedProxyCIDRs: []
  allowAnonymous: false
shadow: {url: "", token: "", maxBytes: 1048576}
maxBodyBytes: 33554432       # 32 MiB; larger => 413
readHeaderTimeout: 10s
readTimeout: 5m              # request only; responses are never time-limited
idleTimeout: 2m
upstreamHeaderTimeout: 10m   # wait for response headers; then the stream is unbounded
shutdownTimeout: 30s         # graceful drain of in-flight streams
```

Each YAML key has a flag of the same intent (`--listen`, `--policy`, `--next-hop`, `--default-upstream`, `--forward-auth`, `--identity-mode`, `--issuer`, `--audience`, `--identity-header`, `--groups-header`, `--trusted-proxy-cidrs`, `--allow-anonymous`, `--halo-shadow-url`, `--halo-shadow-token`, `--max-body-bytes`, `--read-timeout`, `--upstream-header-timeout`, `--shutdown-timeout`). Run `halo-proxy --help` for defaults.

### Behavior worth knowing

- **Identity.** With an issuer known (flag or policy) the default mode is `jwt`. Failed verification returns 401 unless `allowAnonymous`, in which case the caller gets default routing and ring `unknown` (useful when the token is an opaque API key meant for the next hop). With no issuer, no CIDRs and no explicit mode, `halo-proxy` fails closed with 503.
- **Model allowlist fails closed**, 413 on oversize bodies, batches API 400. See [security model](/halos/concepts/security-model/#model-allowlist-fails-closed).
- **Streaming is never buffered**: SSE and AWS eventstream stay incremental; there are no retries (a retried LLM call is a duplicated bill).
- **Client credentials** (`Authorization`, `x-api-key`) are stripped unless `forwardAuth: true`, and are never included in shadow jobs.
- **Endpoints:** the public `listen` address serves only proxied model calls and `GET /v1/models` (passthrough); every other path is 404. `GET /healthz` (503 until a policy snapshot loads) and `GET /metrics` live on a separate unauthenticated admin listener, `--admin-listen` / `adminListen` (default `127.0.0.1:9090`, empty disables); in Kubernetes set `:9090` and restrict it with a NetworkPolicy. Metrics (Prometheus: `halo_proxy_requests_total{ring,variant,status}`, TTFB and duration histograms, auth-failure and shadow counters). Access log is one JSON line per request with no bodies, headers or user ids.
- TLS: `halo-proxy` serves plain HTTP; terminate TLS in front of it.

### Kill switch

`halo-proxy` (and `halo-kong`) poll `halo-server`'s signed kill list and treat killed experiments as not running: control routing, no mirroring, no experiment headers. Configure it with `killSwitch.url`, `tokenFile` and `pubkeyFile` (flags `--killswitch-*`); all three are required together. A failed fetch keeps the last list, and a gateway that never fetched one kills nothing. Full behavior: [experiments](/halos/concepts/experiments/#kill-switch) and the [halo-proxy README](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/README.md#kill-switch).

### Per-request telemetry

With `--telemetry-otlp-endpoint` (YAML `telemetry`), `halo-proxy` exports `halo.gateway.requests` and `halo.gateway.latency_ms` over OTLP/HTTP with the ring, variant and model it assigned. No prompts, headers, user ids or session ids are exported; the per-unit key is a salted hash. These feed `halo.api.error_rate` and `halo.latency.*` for experiments, and are the only online source for traffic-axis ones. See [evidence plane](/halos/concepts/evidence-plane/).

## Integrations

Starting points in `deploy/integrations/`, not turnkey deployments. Files marked "generated" come from `internal/gateway/adapters`; edit the templates and run `go test ./internal/gateway/adapters -update`.

| Stack | What is provided | Checked | UNVERIFIED |
|---|---|---|---|
| **Kong** (OSS, Enterprise, Konnect) | Route to `halo-proxy` (`kong.yml`, no plugin server), or the `halo-kong` plugin (`halo gateway deck`) | `kong config parse` (3.8, db-less) OK, run by hand when the template was written and not part of CI; the `deploy/compose` demo runs Kong OSS + `halo-kong` end to end; `make uat-kong` runs Kong OSS 3.9.3 + `halo-kong` in CI (32 checks, `test/uat/KONG-REPORT.md`) | Live traffic through the route-to-`halo-proxy` template; **Kong Enterprise and Konnect** |
| **Envoy / Istio** | Static bootstrap with route `timeout: 0s` and `stream_idle_timeout` | `envoy --mode validate` (v1.32) OK, run by hand, not part of CI | Live traffic |
| **nginx** | `location` with `proxy_buffering off`, HTTP/1.1, long timeouts; `proxy_pass` without a URI so encoded Bedrock paths survive | `nginx -t` OK, run by hand, not part of CI | Live traffic |
| **AWS API Gateway** | HTTP API to VPC link to internal ALB to `halo-proxy` (`openapi.yaml`) | nothing | Everything: not imported into AWS. HTTP APIs cap integration time and do not stream; verify quotas before routing agent traffic through it |
| **LiteLLM** | `halo-proxy` in front of LiteLLM (`--next-hop`), or LiteLLM as a policy upstream | nothing | Everything: written from LiteLLM's documented config, not run |

Kong specifics worth keeping if you hand-edit the generated config: exact regex routes (prefix routes would let `/v1/messages/batches` bypass the allowlist), `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m` (otherwise bodies spool to disk and are answered 413), https-only routes, and the shadow token as a Kong vault reference (`{vault://env/halo-shadow-token}` plus `KONG_NGINX_MAIN_ENV=HALO_SHADOW_TOKEN`). A literal token is refused by the generator. If a Kong auth plugin hides the `Authorization` header, either forward it or use `trusted_header` with the CIDR pin. Never put Kong in front of an auth gateway and trust its `x-*-user` header: it is client-controlled there.

## Model routes and failover

Clients ask for a stable **alias** (`sonnet`, `opus`, `default`); the Gateway document decides where it goes. A route is one `{upstream, model}`, or a list of `targets` grouped into **priority tiers** (lower first). Within a tier, `weight` splits traffic with a pick that is sticky per user and harness session (hashed by `internal/assign`), and the rest of the tier is the failover order. Later tiers are tried only after earlier ones fail.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/route-failover-light.svg" alt="A model alias resolves to priority tiers. Within tier 0 a weighted pick, sticky per user and session, goes first and the rest of the tier follows. On a connect error, 5xx or 429, before any byte reaches the client, halo-proxy tries the next target, then the next tier." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/route-failover-dark.svg" alt="A model alias resolves to priority tiers. Within tier 0 a weighted pick, sticky per user and session, goes first and the rest of the tier follows. On a connect error, 5xx or 429, before any byte reaches the client, halo-proxy tries the next target, then the next tier." width="760" />

```yaml
# examples/acme-corp/gateway.yaml (excerpt)
models:
  opus:
    targets:
      - upstream: bedrock-use1        # priority 0: primary
        model: arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/p7q2opus41bb
        timeoutSeconds: 30            # connect + response headers; streams are not time-limited
      - upstream: anthropic-direct    # priority 1: failover
        model: claude-opus-4-1-20250805
        priority: 1
  default:
    targets:                          # 90/10 split, sticky per user + session
      - {upstream: anthropic-direct, model: claude-sonnet-4-5-20250929, weight: 90}
      - {upstream: anthropic-direct, model: claude-opus-4-1-20250805, weight: 10}
```

`halo-proxy` moves to the next target on a connect error, a 5xx or a 429. Failover happens inside the round trip, before any response byte reaches the client: once a stream starts, it is never retried. Per-target circuit breakers skip a target after `route.breakerFailures` consecutive failures (default 5) and probe it again after `route.breakerCooldown` (default 30s). `route.maxAttempts` caps tries per request (default 3). These settings live in the `halo-proxy` config, not in policy. A target whose upstream kind cannot serve the client's wire is skipped for that client.

See exactly what a user would hit:

```console
$ halo gateway routes --user alice@acme.com --session s-42 --policy-dir examples/acme-corp
Routes for user "alice@acme.com" session "s-42"
ALIAS           ORDER  UPSTREAM                KIND          MODEL                                                                               WEIGHT  PRIORITY  TIMEOUT  NOTES
default         1      anthropic-direct        anthropic     claude-opus-4-1-20250805                                                            10      0         -        <- hit when healthy; skipped by gemini-cli
default         2      anthropic-direct        anthropic     claude-sonnet-4-5-20250929                                                          90      0         -        skipped by gemini-cli
opus            1      bedrock-use1            bedrock       arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/p7q2opus41bb   -       0         30s      <- hit when healthy; skipped by codex,gemini-cli
opus            2      anthropic-direct        anthropic     claude-opus-4-1-20250805                                                            -       1         -        skipped by gemini-cli
```

Output trimmed to two aliases; the NOTES column is verbatim (gemini-cli has no usable target for `default` or `opus` here). Without `--user`, weighted tiers are shown in policy order. A model upgrade or a provider move is a one-line policy change; [toggles](/halos/concepts/toggles/) and canary experiments can switch a route for a cohort first.

## Providers

A policy **upstream** is a named backend with a `kind`; a **model route** maps a stable alias to one or more `{upstream, model}` targets. Same-wire kinds only get the model swapped. `halo-proxy` translates three cases (`internal/gateway/translate.go`), and skips any target whose kind cannot serve the client's wire.

| `kind` | Serves clients speaking | What `halo-proxy` does |
|---|---|---|
| `orchestrator` | any (including `gemini`) | Pass-through to your own LLM gateway; it handles provider auth |
| `anthropic` | any (use with `anthropic-messages`) | Pass-through; auth via `upstreamHeaders` |
| `bedrock` | `bedrock-invoke`, `anthropic-messages` | SigV4 with its own AWS identity (below). `anthropic-messages` is translated to `invoke` / `invoke-with-response-stream`, and the event stream is converted back to SSE |
| `vertex` | `anthropic-messages` | Translated to `rawPredict` / `streamRawPredict` with the model in the path. Needs `project` and `region` (`us-east5` or `global`); the URL is derived. Token from Google ADC: a service-account key file or the metadata server (GKE workload identity, GCE, Cloud Run) |
| `openai` | any (use with `openai-responses`) | Pass-through; bearer key from `credential.env` or `credential.file` |
| `azure-openai` | `openai-responses` | Rewritten to `/openai/v1/responses`, or `/openai/responses?api-version=` when `apiVersion` is set; `model` is the deployment. `credential` is required |
| `gemini` | `gemini` | Pass-through of `/v1beta/models/{model}:{generateContent,streamGenerateContent,countTokens}` (alias in the path is rewritten). Optional `credential` (env or file) is sent as `x-goog-api-key`; with a credential the host must be `generativelanguage.googleapis.com` or an `upstreamHosts` entry |

Credentials never come from policy values or the client: client `Authorization`, `x-api-key`, `api-key`, `x-goog-api-key` and `Proxy-Authorization` are dropped even with `forwardAuth`. Credentialed kinds must use https on the provider's own domain (`*.googleapis.com`, `api.openai.com`, `*.openai.azure.com`, ...) or an exact `upstreamHosts` entry; other hosts are never sent a credential. `count_tokens` has no Bedrock or Vertex equivalent and is skipped for them. `halo-kong` does not translate or fail over: it routes each alias to its first target ([verified in a real Kong](#halo-kong-in-a-real-kong-verified-on-kong-oss-393)).

**Gemini CLI.** gemini-cli cannot send `Authorization` to a custom base URL; it sends `GEMINI_API_KEY` as `x-goog-api-key`. On the `gemini` wire only, `halo-proxy` takes the Halos credential (the developer's OIDC JWT) from `x-goog-api-key`, verifies it exactly like a bearer token, and strips it (and any `?key=`) before forwarding. On every other wire that header is not a credential. The `gemini` adapter renders `GEMINI_API_KEY="$(sh -c '<gateway.auth.helperCommand>')"` into the login-shell profile, so the token is minted at shell start and never written to disk; it is short-lived, so open a new shell when it expires. `vertex` does not serve Gemini models yet (`halo validate` warns when no harness can use a target). `halo-kong` does not accept `x-goog-api-key` as identity.

Translations are covered by fixture tests. The `provider-smoke` workflow calls Anthropic and OpenAI nightly (scheduled runs on 2026-10-02 and 2026-10-03 passed); Bedrock, Vertex, Azure OpenAI and the Gemini API are **UNVERIFIED** against real accounts (their smoke jobs run once secrets are set).

### Direct Bedrock (SigV4 in halo-proxy)

Point Claude Code at `halo-proxy` in Bedrock mode. `halo-proxy` verifies the developer's JWT, rewrites the alias to the real model or inference-profile ARN, then signs the request with **its own** AWS identity. The developer needs no AWS credentials.

**1. Policy.** Declare a `bedrock` upstream and an alias (region comes from the host, or is set explicitly for a custom or VPC endpoint host):

```yaml
protocols: {claude-code: bedrock-invoke}     # renders the Bedrock env below
upstreams:
  bedrock: {url: "https://bedrock-runtime.us-east-1.amazonaws.com", kind: bedrock}
  bedrock-vpce: {url: "https://bedrock.corp.example", kind: bedrock, region: eu-west-1}   # custom DNS name: also needs signHosts (step 4)
models:
  sonnet: {upstream: bedrock, model: "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"}
```

**2. Claude Code environment.** With `protocols: {claude-code: bedrock-invoke}` the adapter renders these into managed settings; set them by hand otherwise:

```bash
export CLAUDE_CODE_USE_BEDROCK=1
export ANTHROPIC_BEDROCK_BASE_URL=https://halo-proxy.internal.example.com   # gateway.baseURL
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1      # the CLI sends no SigV4; halo-proxy signs
export ANTHROPIC_MODEL=sonnet               # a policy alias, not a Bedrock id
```

Claude Code still needs its Halos JWT: `gateway.auth.helperCommand` becomes `apiKeyHelper`, and the token's `aud` must match `identity.audience`.

**3. Credentials for halo-proxy.** The AWS SDK default chain, resolved on first use and refreshed before expiry: environment (`AWS_ACCESS_KEY_ID` and friends), shared config or SSO (`AWS_PROFILE`), web identity (**EKS IRSA** or **Pod Identity**), ECS task role, EC2 instance profile. On EKS, annotate the `halo-proxy` service account with the IAM role. Grant it `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on the models and inference profiles named in policy. Credentials are never logged.

**4. Region and host rules.** `halo-proxy` signs only when the upstream is `kind: bedrock`, a region is known, **and** the host is allowed to receive the gateway's signature. The region is either `region` (validated, for example `us-east-1`; only allowed on `kind: bedrock`) or derived from a `bedrock-runtime[-fips].<region>` host label. The host must end in `.amazonaws.com`, `.amazonaws.com.cn` or `.api.aws`, or be listed in the `signHosts` setting of `halo-proxy`'s config (exact hostnames, for example a private VPC endpoint DNS name):

```yaml
# halo-proxy config (not policy)
signHosts: [bedrock.corp.example]
```

A region on any other host gets `502 bad_upstream` ("policy upstream host is not allowed for signing") and an error log naming the host, so a policy change cannot send AWS credentials to a third party. `nextHop` and `defaultUpstream` are never signed. A malformed region also gives `502 bad_upstream`.

**5. Backward compatibility.** A `kind: bedrock` upstream on a non-AWS host where no region can be derived and none is set (an orchestrator or a SigV4 sidecar) is forwarded **unsigned**, exactly as before. Existing orchestrator setups need no change.

**What is signed.** SigV4, service `bedrock`, computed after the model rewrite over the final method, escaped path, host, `Content-Type`, `x-amz*` headers and the SHA-256 of the final body. The caller's `Authorization`, `x-api-key` and **all** `x-amz*` / `x-amzn*` headers are always dropped before the gateway sets its own, even with `forwardAuth: true`, so a client cannot smuggle a header into the signature. Paths: `invoke`, `invoke-with-response-stream`, `converse`, `converse-stream`; the `application/vnd.amazon.eventstream` response streams through unbuffered.

**No credentials** gives `502 upstream_auth_error` and nothing is forwarded unsigned.

**Check:** `halo validate` passes with the upstream, `halo-proxy` starts, and a request with a valid JWT for alias `sonnet` reaches Bedrock with an `Authorization: AWS4-HMAC-SHA256 ...` header. Verified with fixed-key tests (an AWS SigV4 test-suite vector plus a fake Bedrock that recomputes the signature). **UNVERIFIED:** real AWS Bedrock, IRSA and Pod Identity on a real cluster, and VPC endpoints.

## halo-kong in a real Kong (verified on Kong OSS 3.9.3)

`make uat-kong` runs `halo-kong` as a Go plugin server inside the official `kong` 3.9.3 image (pinned by digest, db-less, declarative config from `halo gateway deck`), against two mock model upstreams and a `halo-server` for the signed kill list. Every row below is asserted against the live gateway; see `test/uat/KONG-REPORT.md` for the evidence. **Kong Enterprise is UNVERIFIED.**

**Verified:** a valid JWT is routed, the alias rewritten and ring/release stamped; a missing, forged or wrong-audience token is a 401; caller credential headers never reach the upstream; spoofed `x-halo-*` and identity headers are stripped; an unknown model is a 400 and never reaches an upstream; non-model paths get Kong's 404; sticky canary assignment matches the library for every user; a traffic toggle applies to its cohort only; concurrent canaries on different aliases each claim only their own alias; the kill switch (experiments and toggles) takes effect within the plugin's 10 s poll and un-kill restores; an unusable kill-switch key keeps traffic flowing and is flagged `x-halo-killswitch: misconfigured`; Kong's `/status` and Prometheus metrics count the traffic.

**Settings that matter** (each one was a failure mode in a real Kong):

- **Plugin server env.** Kong passes the plugin server only the variables in nginx's main-context `env` list, and `nginx_main_env` is a single setting. Chain several with `; env `: `KONG_NGINX_MAIN_ENV="HALO_SHADOW_TOKEN; env HALO_KILLSWITCH_TOKEN; env HALO_KILLSWITCH_PUBKEY"`. Listing only one variable leaves the others unset and shows up as `x-halo-killswitch: misconfigured`. `halo gateway deck` prints this in the file header.
- **Kill switch over plain http.** An in-cluster `halo-server` Service is http: generate with `halo gateway deck --killswitch-url http://... --killswitch-allow-insecure-in-cluster` (sets the plugin's `killswitch_allow_insecure_in_cluster`). Without it, the generator refuses a non-https URL.
- **Secure defaults, the same as halo-proxy.** With JWT identity (an issuer is configured), a model call with a missing, forged, wrong-audience or garbage token gets `401 authentication_error` with `WWW-Authenticate: Bearer realm="halos"` and never reaches an upstream. The caller's `Authorization`, `x-api-key`, `api-key`, `x-goog-api-key` and `Proxy-Authorization` are removed before the upstream, so the developer's IdP token never reaches a provider; add the provider credential in Kong (for example `request-transformer` with a vault reference). Opt out explicitly, only when an auth gateway or orchestrator behind Kong needs them: `halo gateway deck --allow-unverified` (plugin `allow_unverified`: unverified callers are routed anonymously, ring `unknown`, no experiments) and `--forward-client-credentials` (plugin `forward_client_credentials`). Each opt-out prints a warning and a `# WARNING:` line in the generated file. In `trusted_header` mode the auth gateway that sets the identity header decides, so unverified callers are not refused by the plugin.
- **Prometheus.** Kong's per-request series (`kong_http_requests_total`, including the plugin's own 400/401 answers) are off by default; enable `status_code_metrics` on the `prometheus` plugin.

**Limits, as documented and as observed:** a multi-target route uses only its first target; there is no failover (an unreachable first target is a Kong 503 and the second target is never tried); there is no wire translation (a `bedrock` target receives the Anthropic path and body with only the model swapped, unsigned); the Gemini wire is not served (no Kong route, 404). Use `halo-proxy` for any of these.

Also not included: mTLS or SPIFFE identity, per-user rate limiting. (Failover across route targets is above; a single-target route is not retried.)
