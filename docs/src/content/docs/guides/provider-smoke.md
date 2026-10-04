---
title: Provider smoke
description: The nightly workflow that runs halo-proxy against real model providers, and exactly which secrets enable which provider.
---

`.github/workflows/provider-smoke.yml` runs nightly (05:17 UTC) and on `workflow_dispatch`. For each
provider it starts a real `halo-proxy` (compiled policy, one upstream) and checks:

1. a non-streaming call with a tiny prompt and `max_tokens` 16;
2. one SSE stream, with the wire's start and end events present;
3. the response shape (Anthropic message, OpenAI Responses object, Gemini candidates + usage);
4. the gateway `/metrics`: `halo_proxy_upstream_attempts_total{provider="<kind>",outcome="ok"}` and
   `halo_proxy_requests_total{...status="200"}` both reach 2.

Each provider is its own matrix entry. When its secrets are absent the gate step writes a notice and the
rest of the job is skipped: the run stays green. Today only Anthropic and OpenAI have secrets set (scheduled runs on 2026-10-02 and 2026-10-03 passed for both); Gemini, Azure OpenAI, Bedrock and Vertex skip until their secrets are set. Everything else in CI is unaffected, because the test sits
behind the `providers` build tag and `go test ./...` never compiles it.

## Secrets

Repository secrets (Settings, Secrets and variables, Actions). A provider runs only when **all** of its
names are set.

| Provider | Secret names | How halo-proxy gets it |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY` | `upstreamHeaders` `x-api-key: ${ANTHROPIC_API_KEY}` |
| `openai` (Responses API) | `OPENAI_API_KEY` | policy `credential: {env: OPENAI_API_KEY}` |
| `gemini` (Gemini API) | `GEMINI_API_KEY` | policy `credential: {env: GEMINI_API_KEY}` |
| `azure-openai` | `AZURE_OPENAI_KEY`, `AZURE_OPENAI_ENDPOINT` (`https://<resource>.openai.azure.com`), `AZURE_OPENAI_DEPLOYMENT` | policy `credential: {env: AZURE_OPENAI_KEY}`; the deployment name is the model |
| `bedrock` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` | halo-proxy SigV4 via the AWS default chain |
| `vertex` | `GOOGLE_APPLICATION_CREDENTIALS_JSON` (service-account key JSON) | written to a `0600` file in `$RUNNER_TEMP`, exposed as `GOOGLE_APPLICATION_CREDENTIALS` (Google ADC) |

Keys are read from the environment only and never logged or written to disk (the proxy config keeps the
literal `${ENV}` placeholder). The Bedrock role needs `bedrock:InvokeModel` and
`bedrock:InvokeModelWithResponseStream`; the Vertex service account needs `roles/aiplatform.user`.

OIDC role assumption for Bedrock is not wired: it needs a pinned `aws-actions/configure-aws-credentials`
step, which this repo does not use yet. The test itself works with any credentials in the AWS default chain.

## Models

Cheapest models by default, overridable with repository **variables** (Actions, Variables):

| Variable | Default |
|---|---|
| `HALO_SMOKE_ANTHROPIC_MODEL` | `claude-haiku-4-5` |
| `HALO_SMOKE_OPENAI_MODEL` | `gpt-4.1-nano` |
| `HALO_SMOKE_GEMINI_MODEL` | `gemini-2.5-flash-lite` |
| `HALO_SMOKE_BEDROCK_MODEL` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| `HALO_SMOKE_VERTEX_MODEL` | `claude-haiku-4-5@20251001` |
| `HALO_SMOKE_VERTEX_REGION` | `us-east5` |
| `HALO_SMOKE_VERTEX_PROJECT` | `project_id` from the key file |

Azure uses `AZURE_OPENAI_DEPLOYMENT`. Model ids drift; a nightly 404 usually means a default needs bumping.

## Run it locally

```sh
ANTHROPIC_API_KEY=... go test -tags providers -count=1 -v -run 'TestProviderSmoke/anthropic$' ./test/providers/...
```

With no credentials set every provider reports SKIP.
