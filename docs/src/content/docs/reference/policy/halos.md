---
title: "Halos root"
description: "The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`."
---

The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`.

Generated from `schemas/halos.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string |  |  | const halos.dev/v1alpha1 |  | Document version. |
| `gateway` | string |  |  |  | format uri | Simple mode: the gateway base URL clients are pointed at. |
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

## Constraints

- `provider`: exactly one of `name`
- `tools.*`: exactly one of `version`
