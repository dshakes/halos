# Provider upstream templates  (UNVERIFIED: no provider accounts were available)

A policy *upstream* is a base URL; a *model route* maps a stable alias to `{upstream, model}`.
halo-proxy joins the upstream's path prefix with the request path and can inject credentials per
upstream (`upstreamHeaders`, `${ENV}` expanded). halo-proxy does **not** translate wire protocols.
It SigV4-signs `kind: bedrock` upstreams on AWS hosts (below); it signs nothing else.

| Provider | Works with halo-proxy directly? | Notes |
|---|---|---|
| Bedrock via your orchestrator | yes | Orchestrator does SigV4 and speaks Anthropic/Bedrock paths. `kind: orchestrator`. |
| Anthropic API | yes | `x-api-key` + `anthropic-version` via `upstreamHeaders`. |
| Azure AI Foundry (Claude) | likely | Anthropic-compatible endpoint under a path prefix; auth header per your Foundry setup. Confirm endpoint + header in Azure docs. |
| OpenAI-compatible (OpenAI, Azure OpenAI, vLLM, ...) | yes for `/v1/responses` | Needs the Responses API on the target. `Authorization: Bearer` (OpenAI/vLLM) or `api-key` (Azure OpenAI). |
| Google Vertex (Claude) | **no** | Vertex puts the model in the URL and uses `anthropic_version` in the body: a different wire format. Put LiteLLM (or another translator) in front and use it as the upstream. |
| Bedrock direct | **yes (halo-proxy)** | `kind: bedrock`, URL `https://bedrock-runtime.<region>.amazonaws.com` (or any host + `region:`). halo-proxy signs with SigV4 after the model rewrite using the AWS default credential chain (env, SSO/profile, IRSA, ECS/EC2 role); no orchestrator or sidecar needed. Clients: `CLAUDE_CODE_USE_BEDROCK=1`, `ANTHROPIC_BEDROCK_BASE_URL=<halo-proxy>`, `CLAUDE_CODE_SKIP_BEDROCK_AUTH=1`. See `cmd/halo-proxy/README.md#bedrock-without-an-orchestrator`. halo-kong / halo-shadow still do **not** sign: behind Kong, keep the orchestrator or a SigV4 sidecar (a `kind: bedrock` sidecar URL without `region` is forwarded unsigned). Unverified against real AWS. |

`gateway-upstreams.yaml` = the policy fragment; `halo-proxy-upstream-auth.yaml` = matching halo-proxy config fragment.
