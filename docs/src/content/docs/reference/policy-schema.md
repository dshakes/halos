---
title: Policy schema
description: Every field of Gateway, Profile, Ring and Experiment, derived from internal/policy/types.go.
---

Source of truth: `internal/policy/types.go` (the `yaml` tags). JSON Schemas are published under `schemas/` (`halos`, `gateway`, `profile`, `ring`, `experiment`) for editor autocomplete. All documents use `apiVersion: halos.dev/v1alpha1`. Decoding is strict: unknown fields are errors. Identifiers (names, aliases, upstreams, variants, MCP servers) match `^[a-z0-9][a-z0-9._-]{0,62}$`.

## Root (`halos.yaml`)

| Field | Type | Notes |
|---|---|---|
| `org` | string | Required. Must equal the org in signed pointers and releases |
| `identity.issuer` | string | OIDC issuer; used by the portal, `halo-proxy`, `halo-kong` |
| `identity.clientID` | string | Portal OIDC client |
| `identity.audience` | string | Expected in gateway bearer tokens; defaults to `clientID` |
| `identity.userClaim` / `groupsClaim` | string | JWT claims for user id (default `email`) and groups (default `groups`). With the `email` claim the token must carry `email_verified=true`, otherwise it is rejected unless unverified email is explicitly trusted; prefer a stable IdP subject |
| `identity.adminGroups` | list | May approve requests and manage experiments in the portal |
| `selfService.enabled` | bool | Turns on the portal kiosk |
| `selfService.launchers` | list | `devcontainer`, `codespaces`, `coder`, `laptop` |
| `selfService.requestable` | list | `mcp-server`, `model`, `ring-opt-in`, `harness` |
| `selfService.catalog[]` | `{name, url, command[], headers}` | MCP servers developers may request |
| `selfService.enrollmentTTLSeconds` | int | One-time laptop token lifetime, default 900 |

## Common (`Meta`)

| Field | Type | Notes |
|---|---|---|
| `apiVersion` | string | Must be `halos.dev/v1alpha1` |
| `kind` | string | `Profile`, `Ring`, `Experiment`, `Gateway` |
| `name` | string | |
| `labels` | map | optional |

## Gateway

| Field | Type | Notes |
|---|---|---|
| `baseURL` | string | What clients are pointed at (the gateway's public listener) |
| `protocols` | map harness to string | `anthropic-messages`, `bedrock-invoke`, `openai-responses`, `gemini` |
| `auth.helperCommand` | string | Prints a short-lived token (Claude `apiKeyHelper`, Codex `env_key` source) |
| `auth.ttlSeconds` | int | |
| `auth.identityHeader` | string | Header the auth gateway sets with the verified user id. Used only by `trusted_header` mode and never an `x-halo-*` name |
| `models` | map alias to route | `{upstream, model}`; model is provider id or Bedrock inference profile ARN |
| `upstreams` | map name to `{url, kind}` | kind: `orchestrator`, `anthropic`, `bedrock`, `openai`, `gemini` |

## Profile

| Field | Type | Notes |
|---|---|---|
| `extends` | string | Parent profile |
| `harnesses.<name>.version` | string | Exact CLI pin; required for rings |
| `harnesses.<name>.overrides` | map | Raw harness-native keys merged last. Only allowlisted keys are accepted (per-harness list in [policy model](/halos/concepts/policy-model/#guardrails)); any other key is an error, and a harness with no allowlist accepts none |
| `models.default` / `allowed` / `enforce` | string / list / bool | `enforce` rejects rather than hides |
| `permissions.mode` | string | `default`, `acceptEdits`, `plan`, `auto` |
| `permissions.allow` / `deny` / `ask` | list | Rules |
| `permissions.disableBypass` | bool | Must be `true` on every ring's profile |
| `permissions.sandbox` | string | `off`, `workspace-write`, `read-only` |
| `mcp.managedOnly` | bool | Block servers not listed |
| `mcp.servers[]` | `{name, url, command[], headers}` | Exactly one of `url` (https) or `command`. Header values that look like credentials are rejected; use `${VAR}` references |
| `mcp.denied` | list | |
| `hooks.managedOnly` | bool | |
| `hooks.items[]` | `{event, matcher, command}` | event: `PreToolUse`, `PostToolUse`, `SessionStart`, `Stop`, `UserPromptSubmit` |
| `telemetry.enabled` / `otlpEndpoint` / `protocol` / `logPrompts` / `attributes` | | protocol: `grpc` or `http/protobuf`. Must be enabled on every ring's profile |
| `egress.allowedDomains` | list | Only egress permitted from managed environments |
| `instructions` | string | Managed `CLAUDE.md` / `AGENTS.md` / `GEMINI.md` |
| `env` | map | Extra environment for every harness. Prefixes `OTEL_`, `ANTHROPIC_`, `CLAUDE_CODE_`, `DISABLE_`, `CODEX_`, `GEMINI_`, `GOOGLE_GEMINI_` are reserved; literal secrets are rejected |

## Ring

| Field | Type | Notes |
|---|---|---|
| `order` | int | Earliest first |
| `profile` | string | |
| `release` | string | Immutable release digest; empty means build from profile |
| `membership.users` | list | User ids always in the ring (checked before groups) |
| `membership.groups` | list | IdP groups always in the ring |
| `membership.percent` | float | 0-100, basis-point precision, of remaining users |
| `membership.default` | bool | Catch-all (GA) |
| `membership.optIn` | bool | Developers may request to join from the portal |

## Experiment

| Field | Type | Notes |
|---|---|---|
| `type` | string | `ab`, `canary`, `shadow` |
| `axis` | string | `client`, `traffic` |
| `status` | string | `draft`, `running`, `paused`, `concluded` |
| `rings` | list | Rings users are drawn from |
| `variants[]` | | `name`, `weight` (normalized), `control`, `profile` (client axis), `routes` (traffic axis: alias to `{upstream, model}`) |
| `sampleRate` | float | Shadow only, 0-1 |
| `metrics.primary` | `{metric, direction}` | metric must be a known [`halo.*` metric](/halos/reference/metrics/) |
| `metrics.guardrails[]` | `{metric, direction, maxRegression}` | `maxRegression` is relative (0.05 = 5%) |
| `stopping.method` | string | `msprt`, `fixed` |
| `stopping.alpha` / `minSamples` / `maxDays` / `maxSpendUSD` | | |
| `salt` | string | Defaults to `name` |

`axis` has exactly two values, `client` and `traffic`; there is no `both`.
