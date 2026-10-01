---
title: Policy model
description: Gateway, Profile, Ring and Experiment documents, and how they compose.
---

Most repos start in [simple mode](/halos/concepts/simple-mode/): `halo init` writes one `halos.yaml` (tools, provider, models, gateway, a safety preset and a rollout preset), and Halos generates the documents on this page from it. `halo explain` prints them; `halo eject` writes them out. This page describes those documents, which you can also write yourself, alongside simple mode or instead of it.

A policy repo is a directory of YAML documents plus one root file, `halos.yaml`. Every other document has the common header:

```yaml
apiVersion: halos.dev/v1alpha1
kind: Profile          # Profile | Ring | Experiment | Gateway
name: baseline
labels: {team: platform}
```

The Go types in `internal/policy/types.go` are the source of truth. Full field list: [policy schema reference](/halos/reference/policy-schema/).

## Root: `halos.yaml`

The root file names the org and configures identity and the developer portal. It is required; `halo validate` fails without `org`. It may also carry the simple-mode keys (`tools`, `provider`, `models`, `gateway`, `telemetry`, `team`, `safety`, `rollout`); see [simple mode](/halos/concepts/simple-mode/). The example below is a full-mode root without them.

```yaml
apiVersion: halos.dev/v1alpha1
kind: Halos
org: acme-corp
identity:
  issuer: https://acme.okta.com/oauth2/default
  clientID: halos-portal
  audience: halos-gateway   # expected in gateway bearer tokens; defaults to clientID
  userClaim: email               # default
  groupsClaim: groups            # default
  adminGroups: [ai-platform]     # may approve requests and manage experiments in the portal
selfService:
  enabled: true
  launchers: [devcontainer, codespaces, laptop]   # devcontainer | codespaces | coder | laptop
  requestable: [mcp-server, ring-opt-in]          # mcp-server | model | ring-opt-in | harness
  catalog:
    - name: linear
      url: https://mcp.linear.app/sse
  enrollmentTTLSeconds: 900      # default 900
```

`org` must equal the org in every signed ring pointer and release; `halod` refuses a mismatch. Any OIDC-compliant IdP works. See the [self-service portal](/halos/concepts/self-service-portal/).

Decoding is strict: an unknown field is an error reported with file and line.

## Documents

<img class="diagram dark:sl-hidden" src="/halos/diagrams/policy-model-light.svg" alt="Rings point at a profile. Experiments target rings and vary either a profile (client axis) or gateway routes (traffic axis). Profiles extend other profiles." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/policy-model-dark.svg" alt="Rings point at a profile. Experiments target rings and vary either a profile (client axis) or gateway routes (traffic axis). Profiles extend other profiles." width="760" />

## Gateway

```yaml
apiVersion: halos.dev/v1alpha1
kind: Gateway
name: acme
baseURL: https://ai.acme.example
protocols:
  claude-code: anthropic-messages
  codex: openai-responses
auth:
  helperCommand: acme-sso-token --audience ai-gateway
  ttlSeconds: 900
  identityHeader: x-acme-user   # only for trusted_header mode; JWT mode does not read it
models:
  sonnet:
    upstream: orchestrator
    model: us.anthropic.claude-sonnet-4-5-v1:0
  opus:
    upstream: orchestrator
    model: us.anthropic.claude-opus-4-v1:0
upstreams:
  orchestrator: {url: https://orchestrator.internal.acme.example, kind: orchestrator}
  anthropic:    {url: https://api.anthropic.com, kind: anthropic}
```

Clients request stable **aliases** (`sonnet`); the gateway maps them to upstream model ids, which is what lets a model upgrade be a route change. Model ids above are examples; use your own inference profile ARNs. An alias that is not in `models` is rejected with 403 (the allowlist fails closed). Alias, upstream, profile, ring, experiment, variant and MCP server names must match `^[a-z0-9][a-z0-9._-]{0,62}$` because they flow into scripts, paths and headers.

## Profile

```yaml
apiVersion: halos.dev/v1alpha1
kind: Profile
name: baseline
harnesses:
  claude-code: {version: "2.1.280"}
  codex:       {version: "0.60.0"}
models:
  default: sonnet
  allowed: [sonnet, opus]
  enforce: true
permissions:
  mode: default
  deny: ["Read(./.env)", "Bash(curl:*)"]
  disableBypass: true
  sandbox: workspace-write
mcp:
  managedOnly: true
  servers:
    - name: github
      url: https://mcp.acme.example/github
hooks:
  managedOnly: true
  items:
    - {event: PreToolUse, matcher: Bash, command: /opt/acme/hooks/audit.sh}
telemetry:
  enabled: true
  otlpEndpoint: https://otel.acme.example:4318
  protocol: http/protobuf
  logPrompts: false
egress:
  allowedDomains: [ai.acme.example, github.com, registry.npmjs.org]
instructions: |
  Follow the Acme engineering handbook. Never commit secrets.
```

Notes:

- `hooks.items` is the YAML key for the hook list (Go field `Hooks.Hooks`).
- `harnesses.<name>.version` is an exact pin and is required for rings. Harness names: `claude-code`, `codex`, `gemini-cli`, `copilot-cli`.
- `overrides` merges raw harness-native keys last, but only an allowlist of cosmetic/behavioural keys is accepted; everything else is rejected (see [guardrails](#guardrails)).
- `extends` inherits from another profile; scalars: child wins.
- Credentials are never literals: use `${VAR}` references resolved on the client.

## Ring

```yaml
apiVersion: halos.dev/v1alpha1
kind: Ring
name: ring1-canary
order: 1
profile: baseline
release: sha256:9f2c...    # empty = build from profile (dev only)
membership:
  percent: 5
  optIn: true       # developers may ask to join from the portal
```

`membership.users` and `groups` are always in the ring (users are checked first); `percent` is the share of *remaining* users hashed in; `default: true` marks the GA catch-all; `optIn` lets developers request the ring in the portal. See [rings and releases](/halos/concepts/rings-and-releases/).

## Experiment

```yaml
apiVersion: halos.dev/v1alpha1
kind: Experiment
name: opus-5-5-canary
type: canary
axis: traffic
status: draft
rings: [ring1-canary]
variants:
  - {name: control, weight: 90, control: true}
  - name: candidate
    weight: 10
    routes:
      opus: {upstream: orchestrator, model: us.anthropic.claude-opus-5-5-v1:0}
metrics:
  primary: {metric: halo.task.success, direction: increase}
  guardrails:
    - {metric: halo.cost.usd_per_session, direction: decrease, maxRegression: 0.10}
    - {metric: halo.api.error_rate, direction: decrease, maxRegression: 0.02}
stopping: {method: msprt, alpha: 0.05, minSamples: 300, maxDays: 14, maxSpendUSD: 500}
```

See [experiments](/halos/concepts/experiments/).

## Guardrails

`halo validate` runs these org guardrails after schema and reference checks; `halo release build/publish` runs them again, then re-checks the *rendered* files. They are plain Go ([ADR-0007](/halos/adr/0007-guardrails-in-go-not-opa/)).

| Guardrail | Severity | Rule |
|---|---|---|
| No bypass | error | No profile may set `permissions.mode: bypassPermissions`. `auto` on the default (GA) ring warns |
| Ring profiles | error / warning | Every ring's profile must set `permissions.disableBypass: true`. `telemetry.logPrompts` on the GA ring warns |
| Telemetry on | error | Every ring's profile must enable telemetry |
| MCP servers | error | Exactly one of `url` (https only) or `command` |
| Egress has gateway | error | A non-empty `egress.allowedDomains` must include the gateway host |
| Override allowlist | error | `harnesses.<h>.overrides` may set only the allowlisted keys for that harness (list below); any other key is an error, and a harness with no allowlist accepts no overrides |
| Names | error | Identifiers must match `^[a-z0-9][a-z0-9._-]{0,62}$` |
| Widening | warning | A child profile that adds `permissions.allow`, `permissions.ask` or `egress.allowedDomains` entries beyond its parent |
| Secrets | error | Literal-looking credentials in MCP headers or `env` (prefixes such as `sk-`, `ghp_`, AWS key ids, `Bearer ...`, high-entropy tokens). `${VAR}` references pass |
| Reserved env | error | `env` keys with prefixes `OTEL_`, `ANTHROPIC_`, `CLAUDE_CODE_`, `DISABLE_`, `CODEX_`, `GEMINI_`, `GOOGLE_GEMINI_` |

Overrides are an **allowlist**, not a denylist: only these harness-native keys (dotted paths; a trailing `.*` allows anything below) may be set, and every other key is an error. Commands (Claude `statusLine`/`fileSuggestion`, Codex `notify`) are never allowed.

| Harness | Allowed override keys |
|---|---|
| `claude-code` | `cleanupPeriodDays`, `companyAnnouncements`, `outputStyle`, `language`, `theme`, `spinnerTipsEnabled`, `spinnerTipsOverride`, `spinnerVerbs`, `showTurnDuration`, `includeCoAuthoredBy`, `attribution`, `prefersReducedMotion`, `respectGitignore` |
| `codex` | `model_reasoning_effort`, `model_reasoning_summary`, `model_verbosity`, `hide_agent_reasoning`, `show_raw_agent_reasoning`, `file_opener`, `tui.*` |
| `gemini-cli` | `ui.*`, `general.preferredEditor`, `general.openEditorInNewWindow`, `general.vimMode`, `general.enableNotifications`, `general.notificationMethod`, `general.checkpointing.enabled`, `general.sessionRetention.*`, `context.fileName`, `context.importFormat` |

A harness not in this table accepts no overrides. Source: `allowedOverrides` in `internal/policy/guardrails.go`.

The release build then parses each rendered JSON/TOML file and fails if `bypassPermissions` or `danger-full-access` appears as any value, or if a profile's `disableBypass` is not reflected in the output. That backstop covers adapter regressions and anything an override could merge in after rendering.

## Validation order

<img class="diagram dark:sl-hidden" src="/halos/diagrams/validation-pipeline-light.svg" alt="YAML is strictly decoded, loaded (references, extends, ring order), schema-validated, checked by Go guardrails, rendered by adapters that warn on unsupported fields, and finally re-checked by the release backstop on the rendered files." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/validation-pipeline-dark.svg" alt="YAML is strictly decoded, loaded (references, extends, ring order), schema-validated, checked by Go guardrails, rendered by adapters that warn on unsupported fields, and finally re-checked by the release backstop on the rendered files." width="760" />

Adapters *warn* rather than drop silently: `halo render` prints warnings such as `codex: profile field "hooks.items" is not supported and was not rendered`, and `halo release build` records them in the release manifest.
