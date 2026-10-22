---
title: "Halos root"
description: "The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`."
---

The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`.

Generated from `schemas/halos.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `agents` | object |  |  |  |  | Agent identity and delegation (ADR-0024): which agents may act for a principal (RFC 8693 act chain), how deep and for how long, what delegated agents may not do, and the allowlist of remote A2A agents. |
| `agents.actors` | array of object |  |  |  |  | Agents that may act. Any other actor_id is refused. |
| `agents.actors[]` | object |  |  |  |  |  |
| `agents.actors[].groups` | array of string |  |  |  |  | The root must hold one of these groups; empty = any root. |
| `agents.actors[].groups[]` | string |  |  |  | minLength 1 |  |
| `agents.actors[].harnesses` | array of string |  |  |  |  | Harnesses it may run in (claude-code, codex, gemini-cli, copilot-cli, cursor-agent, opencode); empty = any. |
| `agents.actors[].harnesses[]` | string |  |  |  | minLength 1 |  |
| `agents.actors[].models` | array of string |  |  |  |  | Narrows agents.allowedModels for this agent. |
| `agents.actors[].models[]` | string |  |  |  | minLength 1 |  |
| `agents.actors[].name` | string | yes |  |  | pattern ^[a-z0-9][a-z0-9._-]&#123;0,62}$ | The actor_id an exchange names. |
| `agents.allowedModels` | array of string |  |  |  |  | Gateway model aliases any delegated agent may call; empty = every alias the root may. |
| `agents.allowedModels[]` | string |  |  |  | minLength 1 |  |
| `agents.deniedTools` | array of string |  |  |  |  | Tool names a delegated agent's model call may not declare (tools[].name; Gemini functionDeclarations[].name). Case-insensitive. |
| `agents.deniedTools[]` | string |  |  |  | minLength 1 |  |
| `agents.experiments` | boolean |  |  |  |  | Enroll delegated callers in experiments with their root (default false: control routing, no shadow). |
| `agents.maxDepth` | integer |  |  |  | minimum 1; maximum 5 | Longest delegation chain (default 2). |
| `agents.maxTTLSeconds` | integer |  |  |  | minimum 1; maximum 3600 | Delegated credential lifetime cap (default 900). Never longer than the parent's remaining lifetime. |
| `agents.remote` | array of object |  |  |  |  | Allowlisted remote A2A agents. Answered by POST /api/v1/agents/egress and pinned into ring releases. |
| `agents.remote[]` | object |  |  |  |  |  |
| `agents.remote[].cardURL` | string | yes |  |  | format uri; pattern ^https:// | The AgentCard, usually https://host/.well-known/agent-card.json. |
| `agents.remote[].digest` | string | yes |  |  | pattern ^sha256:[0-9a-f]&#123;64}$ | sha256 of the card's RFC 8785 canonical JSON, as `halo agents verify` prints it. |
| `agents.remote[].jwksURL` | string |  |  |  | format uri; pattern ^https:// | https JWKS holding the card signing key. A jku in the card is never followed. |
| `agents.remote[].name` | string | yes |  |  | pattern ^[a-z0-9][a-z0-9._-]&#123;0,62}$ |  |
| `agents.remote[].publicKey` | string |  |  |  | minLength 1 | PEM public key (Ed25519, ECDSA P-256/P-384, RSA >= 2048) the card's JWS signature must verify with. |
| `agents.remote[].rings` | array of string |  |  |  |  | Rings whose members may call it. |
| `agents.remote[].rings[]` | string |  |  |  | minLength 1 |  |
| `agents.remote[].skills` | array of string |  |  |  |  | Skill ids that may be invoked; empty = any. |
| `agents.remote[].skills[]` | string |  |  |  | minLength 1 |  |
| `agents.remote[].units` | array of string |  |  |  |  | Units (and units below them) whose members may call it. |
| `agents.remote[].units[]` | string |  |  |  | minLength 1 |  |
| `apiVersion` | string |  |  | const halos.dev/v1 |  | Document version. |
| `delegation` | object |  |  |  |  | What units (ADR-0018) may add on top of the baseline; anything else a unit adds is a loosening that validate rejects. MCP servers a unit adds must be exact selfService.catalog entries. |
| `delegation.allowHooks` | boolean |  |  |  |  | Let units add hooks.items (shell commands every member's harness runs). Default false. |
| `delegation.envKeys` | array of string |  |  |  |  | Env names units may add. Provider, cloud, base-URL, proxy, telemetry, CA-trust and runtime-injection names (*_BASE_URL, *_API_KEY, ANTHROPIC_*, OPENAI_*, GEMINI_*, CLAUDE_CODE_*, AWS_*, GOOGLE_*, CLOUD_ML_REGION, HTTP(S)_PROXY, ALL_PROXY, NO_PROXY, OTEL_EXPORTER_OTLP_*, SSL_CERT_FILE, SSL_CERT_DIR, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, NODE_EXTRA_CA_CERTS, PATH, BASH_ENV, ENV, GIT_SSH_COMMAND, GIT_CONFIG_*, GIT_EXEC_PATH, npm_config_*, JAVA_TOOL_OPTIONS, _JAVA_OPTIONS, PERL5OPT, RUBYOPT, NODE_*, LD_*, DYLD_*, PYTHON*; any case) are refused even here. |
| `delegation.envKeys[]` | string |  |  |  | minLength 1 |  |
| `gateway` | string |  |  |  | format uri | Simple mode: the gateway base URL clients are pointed at. |
| `gatewayEngine` | string |  |  | halo-proxy, kong, external |  | Simple mode: what serves gateway: halo-proxy (default), kong, or external (your own API gateway; clients are sent provider model ids). |
| `identity` | object |  |  |  |  | The org's OIDC provider (any compliant IdP: Okta, Entra ID, Google, Keycloak, Ping, Auth0...). Used by the portal, halo-proxy / halo-kong and enrollment. |
| `identity.adminGroups` | array of string |  |  |  |  | Groups holding halo-server's admin role. Same as roles.admin; kept for existing policy repos. |
| `identity.adminGroups[]` | string |  |  |  |  |  |
| `identity.audience` | string |  |  |  |  | Audience expected in gateway bearer tokens; defaults to clientID. |
| `identity.clientID` | string |  |  |  |  | OAuth client id used by the portal. |
| `identity.groupsClaim` | string |  |  |  |  | JWT claim holding the user's groups (default "groups"). |
| `identity.issuer` | string |  |  |  | format uri | OIDC issuer URL; discovery is fetched from &lt;issuer>/.well-known/openid-configuration. |
| `identity.roles` | object |  |  |  |  | halo-server roles (ADR-0015): IdP groups per role. A user holds every role any of their groups maps to. |
| `identity.roles.admin` | array of string |  |  |  |  | Everything, including devices, sessions and toggle proposals. Same as adminGroups. |
| `identity.roles.admin[]` | string |  |  |  | minLength 1 |  |
| `identity.roles.approver` | array of string |  |  |  |  | Viewer plus approving and denying access requests. |
| `identity.roles.approver[]` | string |  |  |  | minLength 1 |  |
| `identity.roles.auditor` | array of string |  |  |  |  | Read and export the audit log; nothing else. |
| `identity.roles.auditor[]` | string |  |  |  | minLength 1 |  |
| `identity.roles.operator` | array of string |  |  |  |  | Viewer plus kill switch and experiment status (pause, resume, conclude). |
| `identity.roles.operator[]` | string |  |  |  | minLength 1 |  |
| `identity.roles.viewer` | array of string |  |  |  |  | Read fleet, releases, rollouts, experiments, toggles and policy. |
| `identity.roles.viewer[]` | string |  |  |  | minLength 1 |  |
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
| `vendorAdmin` | object |  |  |  |  | Vendor admin sync (ADR-0025): drive the vendors' cloud admin consoles from one ring's profile with `halo admin plan\|apply\|export`. A vendor is managed when its key is present. Credentials never live here. |
| `vendorAdmin.claude` | object |  |  |  |  |  |
| `vendorAdmin.claude.location` | string |  |  |  |  | Location of the Gemini settings resources (gemini only; default global). |
| `vendorAdmin.claude.org` | string |  |  |  | pattern ^[^/?#% ]*$ | Tenant: the GitHub organization login (copilot, required), or the Claude organization / ChatGPT workspace / Cursor team id recorded in exports. |
| `vendorAdmin.claude.project` | string |  |  |  | pattern ^[^/?#% ]*$ | Google Cloud project holding the Gemini Code Assist settings (gemini only, required). |
| `vendorAdmin.claude.releaseChannel` |  |  |  | stable, experimental |  | Gemini Code Assist release channel (gemini only); unset leaves it unmanaged. |
| `vendorAdmin.codex` | object |  |  |  |  |  |
| `vendorAdmin.codex.location` | string |  |  |  |  | Location of the Gemini settings resources (gemini only; default global). |
| `vendorAdmin.codex.org` | string |  |  |  | pattern ^[^/?#% ]*$ | Tenant: the GitHub organization login (copilot, required), or the Claude organization / ChatGPT workspace / Cursor team id recorded in exports. |
| `vendorAdmin.codex.project` | string |  |  |  | pattern ^[^/?#% ]*$ | Google Cloud project holding the Gemini Code Assist settings (gemini only, required). |
| `vendorAdmin.codex.releaseChannel` |  |  |  | stable, experimental |  | Gemini Code Assist release channel (gemini only); unset leaves it unmanaged. |
| `vendorAdmin.copilot` | object |  |  |  |  |  |
| `vendorAdmin.copilot.location` | string |  |  |  |  | Location of the Gemini settings resources (gemini only; default global). |
| `vendorAdmin.copilot.org` | string |  |  |  | pattern ^[^/?#% ]*$ | Tenant: the GitHub organization login (copilot, required), or the Claude organization / ChatGPT workspace / Cursor team id recorded in exports. |
| `vendorAdmin.copilot.project` | string |  |  |  | pattern ^[^/?#% ]*$ | Google Cloud project holding the Gemini Code Assist settings (gemini only, required). |
| `vendorAdmin.copilot.releaseChannel` |  |  |  | stable, experimental |  | Gemini Code Assist release channel (gemini only); unset leaves it unmanaged. |
| `vendorAdmin.cursor` | object |  |  |  |  |  |
| `vendorAdmin.cursor.location` | string |  |  |  |  | Location of the Gemini settings resources (gemini only; default global). |
| `vendorAdmin.cursor.org` | string |  |  |  | pattern ^[^/?#% ]*$ | Tenant: the GitHub organization login (copilot, required), or the Claude organization / ChatGPT workspace / Cursor team id recorded in exports. |
| `vendorAdmin.cursor.project` | string |  |  |  | pattern ^[^/?#% ]*$ | Google Cloud project holding the Gemini Code Assist settings (gemini only, required). |
| `vendorAdmin.cursor.releaseChannel` |  |  |  | stable, experimental |  | Gemini Code Assist release channel (gemini only); unset leaves it unmanaged. |
| `vendorAdmin.gemini` | object |  |  |  |  |  |
| `vendorAdmin.gemini.location` | string |  |  |  |  | Location of the Gemini settings resources (gemini only; default global). |
| `vendorAdmin.gemini.org` | string |  |  |  | pattern ^[^/?#% ]*$ | Tenant: the GitHub organization login (copilot, required), or the Claude organization / ChatGPT workspace / Cursor team id recorded in exports. |
| `vendorAdmin.gemini.project` | string |  |  |  | pattern ^[^/?#% ]*$ | Google Cloud project holding the Gemini Code Assist settings (gemini only, required). |
| `vendorAdmin.gemini.releaseChannel` |  |  |  | stable, experimental |  | Gemini Code Assist release channel (gemini only); unset leaves it unmanaged. |
| `vendorAdmin.ring` | string |  |  |  |  | Ring whose profile the consoles get; console settings are org-wide (default: the last ring, GA). |
| `workloads` | object |  |  |  |  | Workload identity federation for headless CI / cloud agents (ADR-0023): halo-server exchanges a token from a trusted OIDC issuer for a short-lived gateway credential when a rule matches its claims. |
| `workloads.audience` | string | yes |  |  | minLength 1 | aud the CI token must carry (e.g. halos); an issuer may override it. |
| `workloads.experiments` | boolean |  |  |  |  | Enroll workloads in experiments and shadows like humans (default false: control routing). |
| `workloads.issuers` | array of object | yes |  |  | minItems 1 | Trusted OIDC issuers, e.g. GitHub Actions https://token.actions.githubusercontent.com, GitLab https://gitlab.com, Buildkite https://agent.buildkite.com, CircleCI https://oidc.circleci.com/org/&lt;org-id>, Google https://accounts.google.com. |
| `workloads.issuers[]` | object |  |  |  |  |  |
| `workloads.issuers[].audience` | string |  |  |  | minLength 1 | Overrides workloads.audience for this issuer (CircleCI's default aud is the organization id). |
| `workloads.issuers[].name` | string | yes |  |  | minLength 1 | Name rules refer to. |
| `workloads.issuers[].tenantClaim` | string |  |  |  | minLength 1 | The claim naming the tenant (org, group, account) a token was minted for; every rule of this issuer must match it exactly. Required for issuers Halos does not know; for GitHub, GitLab.com, Buildkite, CircleCI, Google and Entra ID it may only pick one of their tenant claims. |
| `workloads.issuers[].url` | string | yes |  |  | format uri | Exact iss claim; discovery is &lt;url>/.well-known/openid-configuration. https (http only for loopback). |
| `workloads.rules` | array of object | yes |  |  |  | Tried in order; the first rule of the token's issuer whose every match entry holds mints the credential. |
| `workloads.rules[]` | object |  |  |  |  |  |
| `workloads.rules[].groups` | array of string |  |  |  |  | Groups the workload gets (ring membership, budgets) like a human's IdP groups. |
| `workloads.rules[].groups[]` | string |  |  |  | minLength 1 |  |
| `workloads.rules[].issuer` | string | yes |  |  | minLength 1 | An issuers[].name. |
| `workloads.rules[].match` | object | yes |  |  |  | Claim name -> exact value or glob (* never crosses /). One of the issuer's tenant claims must be matched exactly, or as literal/* (GitHub: repository_owner_id, repository_owner, repository or repository_id; GitLab.com: namespace_id, namespace_path, project_id or project_path; Buildkite: organization_id or organization_slug; CircleCI: oidc.circleci.com/org-id; Google: email or sub; Entra ID: tid; other issuers: their tenantClaim). |
| `workloads.rules[].match.*` | string |  |  |  | minLength 1 |  |
| `workloads.rules[].maxTTLSeconds` | integer |  |  |  | minimum 1; maximum 3600 | Credential lifetime (default 900). |
| `workloads.rules[].name` | string | yes |  |  | minLength 1 |  |
| `workloads.rules[].subject` | string | yes |  |  | pattern ^workload:.+ | Workload subject id; &#123;claim} expands to that claim's value, e.g. workload:gh:&#123;repository}. |

## Constraints

- `provider`: exactly one of `name`
- `tools.*`: exactly one of `version`
