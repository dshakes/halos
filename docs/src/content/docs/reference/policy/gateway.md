---
title: "Gateway"
description: "How harness traffic reaches models: public URL, auth, model aliases and upstreams."
---

How harness traffic reaches models: public URL, auth, model aliases and upstreams.

Generated from `schemas/gateway.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1 |  | Document version. |
| `auth` | object | yes |  |  |  | How clients obtain a credential for the auth gateway. |
| `auth.helperCommand` | string |  |  |  |  | Command that prints a short-lived token (Claude apiKeyHelper, Codex env_key source, ...). |
| `auth.identityHeader` | string |  |  |  |  | Header the auth gateway sets with the verified user id. |
| `auth.ttlSeconds` | integer |  |  |  | minimum 0 | Token lifetime in seconds. |
| `baseURL` | string | yes |  |  | format uri | What clients are pointed at (Kong's public listener). |
| `engine` | string |  |  | halo-proxy, kong, external |  | Data plane enforcing this policy (default halo-proxy). external is a gateway Halos does not run (your own API gateway): clients are rendered with each alias's provider model id. Multi-target routes (weights, failover) run only in halo-proxy; halo-kong and external use each route's first target. |
| `kind` | string | yes |  | const Gateway |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `models` | object | yes |  |  |  | Stable alias (what clients request) to upstream target. |
| `models.*` | object |  |  |  |  | Route for a model alias: either upstream+model, or an ordered/weighted list of targets (not both). |
| `models.*.model` | string |  |  |  |  | Provider model id or Bedrock inference profile ARN. |
| `models.*.targets` | array of object |  |  |  | minItems 1 | Provider targets in routing order. |
| `models.*.targets[]` | object |  |  |  |  | One provider target. Targets sharing a priority form a tier: weights split traffic within it (sticky per identity+session) and the rest of the tier is the failover order; later tiers are tried only after earlier ones fail (connect error, 5xx or 429, before any response byte). |
| `models.*.targets[].model` | string | yes |  |  |  | Provider model id, Bedrock inference profile ARN, or Azure deployment name. |
| `models.*.targets[].priority` | integer |  |  |  | minimum 0 | Failover tier, lowest first (default 0). |
| `models.*.targets[].timeoutSeconds` | integer |  |  |  | minimum 0 | Connect plus response-header timeout for this target; streams are not time-limited afterwards. |
| `models.*.targets[].upstream` | string |  |  |  |  | Name of an entry in gateway.upstreams. Required unless engine is external. |
| `models.*.targets[].weight` | number |  |  |  | minimum 0 | Relative share of traffic within the priority tier. |
| `models.*.upstream` | string |  |  |  |  | Name of an entry in gateway.upstreams. Required unless engine is external. |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `protocols` | object |  |  |  |  | Wire protocol per harness name. |
| `protocols.*` | string |  |  | anthropic-messages, bedrock-invoke, openai-responses, gemini |  |  |
| `upstreams` | object |  |  |  |  | Named backends. |
| `upstreams.*` | object |  |  |  |  | A backend. |
| `upstreams.*.apiVersion` | string |  |  |  |  | api-version query for kind azure-openai; empty uses the versionless /openai/v1 surface. |
| `upstreams.*.credential` | object |  |  |  |  | Where halo-proxy reads the provider key (kinds openai, azure-openai): an environment variable name or a file path, never the secret itself. |
| `upstreams.*.credential.env` | string |  |  |  |  | Environment variable on the halo-proxy host. |
| `upstreams.*.credential.file` | string |  |  |  |  | Secret file path on the halo-proxy host. |
| `upstreams.*.credential.scheme` | string |  |  | api-key, bearer |  | Header style: api-key (default for azure-openai) or bearer (default for openai). |
| `upstreams.*.kind` | string | yes |  | orchestrator, anthropic, bedrock, vertex, openai, azure-openai, gemini |  | Backend type. vertex: Anthropic models on Google Vertex AI (ADC auth). azure-openai: Azure OpenAI Responses (credential required). |
| `upstreams.*.project` | string |  |  |  |  | Google Cloud project id (kind vertex). |
| `upstreams.*.region` | string |  |  |  | pattern ^([a-z]&#123;2}(-[a-z]+)+-[0-9]+\|[a-z]+-[a-z]+[0-9]+\|global)$ | AWS SigV4 region for kind bedrock (default: parsed from a bedrock-runtime.&lt;region>.amazonaws.com host); Google Cloud region (e.g. us-east5, or global) for kind vertex. |
| `upstreams.*.serves` | array |  |  |  |  | Kind orchestrator only: the client wires this upstream answers. Validate warns about a harness routed to an orchestrator that does not declare its wire. |
| `upstreams.*.serves[]` |  |  |  | anthropic-messages, bedrock-invoke, openai-responses, gemini |  |  |
| `upstreams.*.url` | string |  |  |  | format uri | Base URL of the backend (optional for kind vertex: derived from region). |

## Constraints

- `models.*`: exactly one of `model` or `targets`
- `upstreams.*.credential`: exactly one of `env` or `file`
