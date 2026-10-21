---
title: "Halos root"
description: "The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`."
---

The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`.

Generated from `schemas/halos.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string |  |  | const halos.dev/v1 |  | Document version. |
| `gateway` | string |  |  |  | format uri | Simple mode: the gateway base URL clients are pointed at. |
| `gatewayEngine` | string |  |  | halo-proxy, kong, external |  | Simple mode: what serves gateway: halo-proxy (default), kong, or external (your own API gateway; clients are sent provider model ids). |
| `identity` | object |  |  |  |  | The org's OIDC provider (any compliant IdP: Okta, Entra ID, Google, Keycloak, Ping, Auth0...). Used by the portal, halo-proxy / halo-kong and enrollment. |
| `identity.adminGroups` | array of string |  |  |  |  | Groups that may approve requests and manage experiments in the portal. |
| `identity.adminGroups[]` | string |  |  |  |  |  |
| `identity.audience` | string |  |  |  |  | Audience expected in gateway bearer tokens; defaults to clientID. |
| `identity.clientID` | string |  |  |  |  | OAuth client id used by the portal. |
| `identity.groupsClaim` | string |  |  |  |  | JWT claim holding the user's groups (default "groups"). |
| `identity.issuer` | string |  |  |  | format uri | OIDC issuer URL; discovery is fetched from &lt;issuer>/.well-known/openid-configuration. |
| `identity.userClaim` | string |  |  |  |  | JWT claim holding the user id (default "email"). |
| `kind` | string |  |  | const Halos |  | Document kind. |
| `models` | object |  |  |  |  | Simple mode: model alias -> provider model id, or a list of ids in failover order. An id may be prefixed &lt;provider>/ (required with provider multi). The default alias is required. |
| `models.*` |  |  |  |  |  |  |
| `org` | string | yes |  |  | minLength 1 | Organisation name. |
| `provider` |  |  |  |  |  | Simple mode: where models run. A name, or a mapping with its settings. |
| `rollout` |  |  |  | fast, standard, careful |  | Simple mode: rollout preset (rings and step template; default standard). |
| `safety` |  |  |  | strict, standard, relaxed |  | Simple mode: safety preset (default standard). No preset bypasses permissions. |
| `selfService` | object |  |  |  |  | The developer portal (kiosk). |
| `selfService.catalog` | array of object |  |  |  |  | MCP servers developers may request that aren't in their profile yet. |
| `selfService.catalog[]` | object |  |  |  |  |  |
| `selfService.catalog[].command` | array of string |  |  |  |  |  |
| `selfService.catalog[].command[]` | string |  |  |  |  |  |
| `selfService.catalog[].headers` | object |  |  |  |  |  |
| `selfService.catalog[].headers.*` | string |  |  |  |  |  |
| `selfService.catalog[].name` | string | yes |  |  |  |  |
| `selfService.catalog[].url` | string |  |  |  | format uri |  |
| `selfService.enabled` | boolean |  |  |  |  | Turn the portal's self-service features on. |
| `selfService.enrollmentTTLSeconds` | integer |  |  |  | minimum 1 | Lifetime of one-time laptop bootstrap tokens (default 900). |
| `selfService.launchers` | array |  |  |  |  | Launchers offered to developers. |
| `selfService.launchers[]` |  |  |  | devcontainer, codespaces, coder, laptop |  |  |
| `selfService.requestable` | array |  |  |  |  | Kinds of access developers may request (approval opens a policy PR). |
| `selfService.requestable[]` |  |  |  | mcp-server, model, ring-opt-in, harness |  |  |
| `team` | array of string |  |  |  |  | Simple mode: ring0 members, IdP groups or user ids (containing @). Default: identity.adminGroups, else &lt;org>-ai-platform. |
| `team[]` | string |  |  |  | minLength 1 |  |
| `telemetry` | string |  |  |  | format uri | Simple mode: OTLP/HTTP endpoint. Telemetry is always on. |
| `tools` | object |  |  |  |  | Simple mode: harnesses to enable, each pinned to an exact CLI version: a bare version, or &#123;version, model} where model is a models alias the tool starts on instead of default. |
| `tools.*` |  |  |  |  |  |  |
| `workloads` | object |  |  |  |  | Workload identity federation for headless CI / cloud agents (ADR-0023): halo-server exchanges a token from a trusted OIDC issuer for a short-lived gateway credential when a rule matches its claims. |
| `workloads.audience` | string | yes |  |  | minLength 1 | aud the CI token must carry (e.g. halos); an issuer may override it. |
| `workloads.experiments` | boolean |  |  |  |  | Enroll workloads in experiments and shadows like humans (default false: control routing). |
| `workloads.issuers` | array of object | yes |  |  | minItems 1 | Trusted OIDC issuers, e.g. GitHub Actions https://token.actions.githubusercontent.com, GitLab https://gitlab.com, Buildkite https://agent.buildkite.com, CircleCI https://oidc.circleci.com/org/&lt;org-id>, Google https://accounts.google.com. |
| `workloads.issuers[]` | object |  |  |  |  |  |
| `workloads.issuers[].audience` | string |  |  |  | minLength 1 | Overrides workloads.audience for this issuer (CircleCI's default aud is the organization id). |
| `workloads.issuers[].name` | string | yes |  |  | minLength 1 | Name rules refer to. |
| `workloads.issuers[].url` | string | yes |  |  | format uri | Exact iss claim; discovery is &lt;url>/.well-known/openid-configuration. https (http only for loopback). |
| `workloads.rules` | array of object | yes |  |  |  | Tried in order; the first rule of the token's issuer whose every match entry holds mints the credential. |
| `workloads.rules[]` | object |  |  |  |  |  |
| `workloads.rules[].groups` | array of string |  |  |  |  | Groups the workload gets (ring membership, budgets) like a human's IdP groups. |
| `workloads.rules[].groups[]` | string |  |  |  | minLength 1 |  |
| `workloads.rules[].issuer` | string | yes |  |  | minLength 1 | An issuers[].name. |
| `workloads.rules[].match` | object | yes |  |  |  | Claim name -> exact value or glob (* never crosses /). At least one pattern must not start with a wildcard. |
| `workloads.rules[].match.*` | string |  |  |  | minLength 1 |  |
| `workloads.rules[].maxTTLSeconds` | integer |  |  |  | minimum 1; maximum 3600 | Credential lifetime (default 900). |
| `workloads.rules[].name` | string | yes |  |  | minLength 1 |  |
| `workloads.rules[].subject` | string | yes |  |  | pattern ^workload:.+ | Workload subject id; &#123;claim} expands to that claim's value, e.g. workload:gh:&#123;repository}. |

## Constraints

- `provider`: exactly one of `name`
- `tools.*`: exactly one of `version`
