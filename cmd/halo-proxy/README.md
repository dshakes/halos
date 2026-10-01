# halo-proxy

Stack-agnostic Halos traffic plane. One static Go binary that sits on the
request path and, for every model call:

1. **verifies the caller** (OIDC JWT via the IdP's discovery + JWKS, or identity
   headers from a trusted proxy) - client-supplied identity is never trusted;
2. assigns the **ring / experiment variant** (`gateway.PrepareVerified`);
3. **rewrites the model** (JSON `model` or Bedrock `/model/{id}/` path);
4. **mirrors** eligible first-turn requests to halo-shadow;
5. stamps `x-halo-ring|release|experiment|variant` (all client `x-halo-*` are dropped first);
6. forwards to the policy's upstream, or to a single `--next-hop`, streaming the
   response with no buffering (`FlushInterval: -1`; SSE and AWS eventstream stay incremental).
   `kind: bedrock` upstreams on AWS are **SigV4-signed** by halo-proxy (see below).

Works with any gateway (Kong, LiteLLM, Envoy, nginx, AWS API Gateway) or none,
any OIDC IdP, and any provider that speaks `anthropic-messages`,
`openai-responses` or Bedrock invoke/converse paths.

## Deploy modes

```
(a) edge        clients -> halo-proxy --next-hop=<existing gateway> -> provider
(b) behind      clients -> <existing gateway> -> halo-proxy -> provider
(c) standalone  clients -> halo-proxy -> providers
```

| | (a) edge | (b) behind a gateway | (c) standalone |
|---|---|---|---|
| Identity | JWT (default). The client's token is what halo-proxy sees. | `trusted_header` with `trustedProxyCIDRs` = the gateway's addresses, **or** JWT if the gateway forwards `Authorization`. | JWT |
| Upstream | `nextHop: http://kong:8000` | policy upstreams (or `defaultUpstream`) | policy upstreams + `upstreamHeaders` for provider keys |
| `forwardAuth` | `true` if the gateway behind must authenticate the same token | usually `false` | `false` (inject provider credentials via `upstreamHeaders`) |
| Client IP | sees the real client (sets `X-Forwarded-For`) | sees only the gateway; trust its XFF yourself | real client |

Pick (a) when the existing gateway must stay authoritative for auth/rate limits and you
can change client base URLs to halo-proxy. Pick (b) when clients must keep hitting the
gateway. In (b) the gateway must **overwrite** the identity header and halo-proxy must
be unreachable except from it (`trustedProxyCIDRs` enforces this at the socket level).

Model rewriting happens in every mode, including `--next-hop`: the next hop
receives the *upstream* model id, not the alias.

## Identity

| `identity.mode` | Behaviour |
|---|---|
| `jwt` (default when `identity.issuer` is set here or in the org policy) | Bearer JWT from `Authorization: Bearer` or `x-api-key`. Issuer discovery + JWKS cached and refetched on unknown `kid` (key rotation). Checks `iss`, `aud`, `exp`, `nbf`. Algorithms limited to RS256 / ES256 / EdDSA; `none` and `HS*` are rejected. User = `userClaim` (default `email`), groups = `groupsClaim` (default `groups`; array or comma-separated string). Missing groups is allowed. |
| `trusted_header` | `identityHeader` / `groupsHeader` are honoured only if the TCP peer is inside `trustedProxyCIDRs`. Without CIDRs it fails closed (503) rather than trusting headers. |
| `none` | No verification; everyone is anonymous (default routing, no experiments). |

Issuer/audience/claims default to `Org.Identity` in the policy snapshot. Failed
verification returns **401** unless `identity.allowAnonymous: true` (useful when
the token is an opaque API key meant for the next hop: the caller then gets
default routing, ring `unknown`). With no issuer and no CIDRs configured and no explicit
`mode`, halo-proxy fails closed with 503 rather than trusting headers.

## Run

```sh
halo gateway compile ./policy-repo > policy.json      # policy.Compile output; hot-reloaded (~1s)
halo-proxy --policy policy.json --listen :8088                        # (c), issuer from policy
halo-proxy --policy policy.json --next-hop http://kong:8000 --forward-auth   # (a)
halo-proxy --config halo-proxy.yaml
```

Precedence: defaults < YAML (`--config`/`HALO_PROXY_CONFIG`) < env `HALO_PROXY_<FLAG>` (e.g.
`HALO_PROXY_HALO_SHADOW_TOKEN`) < flags. Unknown YAML keys are errors.

```yaml
listen: ":8088"
adminListen: "127.0.0.1:9090" # /healthz + /metrics only; "" disables
policy: /etc/halos/policy.json
nextHop: ""                  # (a): forward everything here
defaultUpstream: ""          # for paths the policy has no route for (e.g. /v1/models)
forwardAuth: false           # keep client Authorization / x-api-key on the forwarded request
upstreamHeaders:             # per policy upstream name; ${ENV} expanded
  anthropic: {x-api-key: "${ANTHROPIC_API_KEY}", anthropic-version: "2023-06-01"}
identity:
  mode: ""                   # jwt | trusted_header | none
  issuer: ""                 # default: policy identity.issuer
  audience: ""               # default: policy identity.audience / clientID
  userClaim: ""              # default email
  groupsClaim: ""            # default groups
  identityHeader: ""         # trusted_header
  groupsHeader: ""
  trustedProxyCIDRs: []
  allowAnonymous: false
shadow: {url: "", token: "", maxBytes: 1048576}
maxBodyBytes: 33554432       # 32 MiB; larger => 413
readHeaderTimeout: 10s
readTimeout: 5m              # request only; responses are never time-limited
idleTimeout: 2m
upstreamHeaderTimeout: 10m   # wait for response headers; then the stream is unbounded
shutdownTimeout: 30s         # graceful drain of in-flight streams on SIGTERM/SIGINT
```

## Behaviour worth knowing

- **Oversize bodies get 413**, never a silent skip of the rewrite. Model-call bodies
  are read fully (needed to inspect/rewrite); other bodies stream through bounded by the same limit.
- **Model allowlist fails closed.** Only exact model-call paths are accepted
  (`/v1/messages`, `/v1/messages/count_tokens`, `/v1/responses`,
  `/model/{id}/invoke[-with-response-stream]|converse[-stream]`); any other path under those
  prefixes (after unescaping/cleaning) is 404, `/v1/messages/batches*` is 403, and a model that is
  not a policy alias (including an unparseable body) is 403 with an Anthropic- / OpenAI- /
  Bedrock-shaped error so the CLI prints the reason. Nothing rejected is forwarded.
- `count_tokens` is routed and rewritten like `/v1/messages` but never mirrored.
- The configured identity/groups headers and every `x-halo-*` are **removed** from the forwarded
  request once the subject is derived; in `trusted_header` mode a request carrying either header
  twice is a 400.
- Client `Authorization` / `x-api-key` are **stripped** unless `forwardAuth: true`;
  they are never included in shadow jobs (only `anthropic-version|beta`, `openai-beta`).
- **Admin endpoints** (on `adminListen` only, unauthenticated): `GET /healthz` (503 until a policy snapshot loads), `GET /metrics`
  (Prometheus text: `halo_proxy_requests_total{ring,variant,status}`,
  `halo_proxy_upstream_ttfb_seconds` and `halo_proxy_request_duration_seconds` histograms,
  auth-failure and shadow counters). The public `listen` address serves proxied
  model calls and `/v1/models` only; every other path is a 404. In Kubernetes set
  `adminListen: ":9090"` so the kubelet can probe it, and restrict it with a NetworkPolicy.
- **Access log:** one JSON `slog` line per request (method, path without query, status,
  bytes, duration, ttfb, ring, variant, upstream). No bodies, headers, or user ids.
- Mirroring is sampled by the policy's shadow experiments (first-turn only) and never
  blocks the request; a full queue drops jobs (`halo_proxy_shadow_dropped_total`). A shadow job
  carries only experiment, variant, protocol, method, path, allowlisted headers and body;
  halo-shadow resolves both upstreams from its own copy of the policy (run it with `-policy`).
- **Direct Bedrock (SigV4).** See [Bedrock without an orchestrator](#bedrock-without-an-orchestrator).
- HTTP/2 to TLS upstreams is negotiated automatically; compression is passed through untouched.
- Behind a load balancer, terminate TLS in front of halo-proxy; it serves plain HTTP.

## Bedrock without an orchestrator

Point Claude Code at halo-proxy in Bedrock mode; halo-proxy verifies the developer (JWT),
rewrites the alias to the real model / inference-profile ARN, then signs with **its own** AWS
identity:

```sh
export CLAUDE_CODE_USE_BEDROCK=1
export ANTHROPIC_BEDROCK_BASE_URL=https://halo-proxy.internal.example.com
export CLAUDE_CODE_SKIP_BEDROCK_AUTH=1   # the CLI sends no SigV4; halo-proxy signs
export ANTHROPIC_MODEL=sonnet            # a policy alias, not a Bedrock id
# Claude Code still needs its halo JWT: apiKeyHelper / ANTHROPIC_AUTH_TOKEN from `gateway.auth.helperCommand`.
```

```yaml
# halo-proxy config: only for hosts that are not AWS endpoints
signHosts: [bedrock.corp.example]
```

```yaml
# policy Gateway document
upstreams:
  bedrock: {url: "https://bedrock-runtime.us-east-1.amazonaws.com", kind: bedrock}   # region from host
  bedrock-vpce: {url: "https://bedrock.corp.example", kind: bedrock, region: eu-west-1}  # custom host => set region
models:
  sonnet: {upstream: bedrock, model: "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"}
```

- **When it signs:** `kind: bedrock`, a region is known (`region` set, or a
  `bedrock-runtime[-fips].<region>` host label), **and** the host is an AWS endpoint:
  it ends in `.amazonaws.com`, `.amazonaws.com.cn` or `.api.aws`, or it is listed in `signHosts`
  (exact hostnames in this config, e.g. a private VPC endpoint DNS name). A region on any other
  host is `502 bad_upstream` (logged with the host) so credentials never reach a third party.
  A `kind: bedrock` upstream on a non-AWS host with no derivable region (an orchestrator or SigV4
  sidecar) is forwarded unsigned, exactly as before. `nextHop` / `defaultUpstream` are never signed.
- **What is signed:** SigV4, service `bedrock`, computed **after** the model rewrite over the
  final method, escaped path (`/model/arn%3A.../invoke`), host, `Content-Type`, `x-amz*`
  headers and the SHA-256 of the final body. Other headers are left unsigned so intermediaries can't
  break the signature. Client `Authorization`, `x-api-key` and **every** `x-amz*` / `x-amzn*` header
  are always dropped before halo-proxy sets its own (even with `forwardAuth: true`).
- **Paths:** `invoke`, `invoke-with-response-stream`, `converse`, `converse-stream`. The
  `application/vnd.amazon.eventstream` response is passed through unbuffered.
- **Credentials:** the AWS SDK default chain, resolved on first use: env (`AWS_ACCESS_KEY_ID`...),
  shared config / SSO (`AWS_PROFILE`), web identity (EKS IRSA / Pod Identity), ECS task role,
  EC2 instance profile (IMDS). Short-lived credentials are cached and refreshed before expiry.
  Grant the role `bedrock:InvokeModel` + `bedrock:InvokeModelWithResponseStream` on the
  models / inference profiles in the policy. Credentials are never logged.
- **No credentials** => `502 upstream_auth_error` ("halo-proxy has no AWS credentials to sign
  the Bedrock request"); nothing is forwarded unsigned. A malformed `region` => `502 bad_upstream`.
- Verified with fixed-key tests (AWS SigV4 test-suite vector + a fake Bedrock that re-computes the
  signature). **Not verified against real AWS** in CI.

## Kill switch

halo-proxy can poll halo-server's signed kill list and treat killed experiments as **not running**:
control routing, no shadow mirroring, and no `x-halo-experiment` / `x-halo-variant` stamp. It takes
effect at the next poll (default 10s), with no policy PR or snapshot roll-out.

```yaml
killSwitch:
  url: https://halo.internal.example.com/api/v1/gateway/killswitch   # empty disables
  tokenFile: /run/secrets/halo-gateway-token     # halo-server --gateway-token-file
  pubkeyFile: /etc/halos/killswitch.pub          # public half of halo-server --killswitch-key-file
  interval: 10s
  allowInsecureInCluster: false                  # default; see below
```

Flags (env `HALO_PROXY_<FLAG>`): `--killswitch-url`, `--killswitch-token-file`, `--killswitch-pubkey-file`,
`--killswitch-interval`. `url`, `tokenFile` and `pubkeyFile` must be set together; a partial config is a
startup error.

- **Verified, not trusted.** The list is an ed25519 signature (domain `halo-killswitch-v1\n`) over a JSON
  payload `{version, experiments, issuedAt}`. The key is the dedicated kill-switch key, never the release key.
  A list is rejected if `issuedAt` is more than 10 minutes old or more than 1 minute in the future, or is not
  **strictly newer** than the list already held (so a replayed older envelope cannot undo a kill).
- **Failure policy.** A failed fetch or verification keeps the last accepted list (a kill never lapses because
  halo-server is down). Before the first successful fetch nothing is killed and the policy snapshot's
  `status` fields decide. Kills do not expire; they are lifted only by an explicit unkill on halo-server.
  Failures are logged on the transition (failing, recovered), not every interval.
- The token is sent as `Authorization: Bearer`; redirects are not followed. Because of that, `url` must be
  `https://` unless it targets loopback or `allowInsecureInCluster: true` (a trusted in-cluster Service URL
  with no TLS listener); otherwise startup fails.
- Client-axis experiments change profiles on machines, which the gateway cannot reach: a kill stops their
  gateway-side routing and mirroring only.

Server side and operations: `cmd/halo-server/README.md`; design: ADR-0009.

## Telemetry (gateway evidence)

```yaml
telemetry:
  otlpEndpoint: http://otel-collector:4319   # the collector's gateway receiver; empty disables
  tokenFile: /run/secrets/halo-otlp-token    # same value as the collector's HALO_OTLP_GATEWAY_TOKEN
  protocol: http/protobuf                    # or http/json
  interval: 10s                              # minimum 1s
```

Flags (env `HALO_PROXY_<FLAG>`): `--telemetry-otlp-endpoint`, `--telemetry-token-file`, `--telemetry-protocol`,
`--telemetry-interval`, `--telemetry-unit-salt-file`. `halo-proxy` exports `halo.gateway.*` per-request metrics;
the `halo.unit` attribute is `HMAC-SHA256(salt, verified subject)`, never a client id. Use the **same salt file on
every replica** so one user stays one unit (no salt means a random per-process one; there is no inline flag, flags
leak via `ps`). The collector accepts these only on its authenticated gateway receiver (`:4319`, bearer token);
without `tokenFile` the collector answers 401. Only this gateway-sourced evidence may trip the controller's kill
switch. Generate the collector with `halo telemetry collector-config` ([evidence plane](https://halos-dev.github.io/halos/concepts/evidence-plane/#evidence-trust)).

## Not included

**Google Vertex AI.** halo-proxy does not route Vertex `:rawPredict` / `:streamRawPredict` paths
(the model allowlist rejects them), so it neither routes nor signs them; use LiteLLM or another translator
as the upstream. Also not included: mTLS/SPIFFE identity, per-user rate limiting, retries (a retried LLM
call is a duplicated bill).
