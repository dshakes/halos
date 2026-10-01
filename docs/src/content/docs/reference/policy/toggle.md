---
title: "Toggle"
description: "A feature toggle: one capability turned on for a targeted cohort and killable instantly without a new release."
---

A feature toggle: one capability turned on for a targeted cohort and killable instantly without a new release.

Generated from `schemas/toggle.schema.json`; do not edit. Nested fields use dotted paths, `[]` marks array items and `.*` map values.

| Field | Type | Required | Default | Allowed values | Constraints | Description |
|---|---|---|---|---|---|---|
| `apiVersion` | string | yes |  | const halos.dev/v1alpha1 |  | Document version. |
| `axis` | string | yes |  | client, traffic |  | client: a settings fragment in the signed release. traffic: a model route switch at the gateway. |
| `client` | object |  |  |  |  | Payload of a client-axis toggle. |
| `client.harnesses` | object | yes |  |  |  | Fragment per harness name. |
| `client.harnesses.*` | object |  |  |  |  | What the toggle adds to this harness's resolved profile when on. Goes through the profile guardrails (override allowlist, secrets, reserved env, no bypassPermissions). |
| `client.harnesses.*.env` | object |  |  |  |  | Environment variables to add (no reserved renderer prefixes, no literal secrets). |
| `client.harnesses.*.env.*` | string |  |  |  |  |  |
| `client.harnesses.*.hooks` | array of object |  |  |  |  | Hooks to add. Give them a matcher of their own. |
| `client.harnesses.*.hooks[]` | object |  |  |  |  |  |
| `client.harnesses.*.hooks[].command` | string | yes |  |  |  |  |
| `client.harnesses.*.hooks[].event` | string | yes |  | PreToolUse, PostToolUse, SessionStart, Stop, UserPromptSubmit |  |  |
| `client.harnesses.*.hooks[].matcher` | string |  |  |  |  |  |
| `client.harnesses.*.mcpServers` | array of object |  |  |  |  | MCP servers to add: exactly one of url (https) or command. |
| `client.harnesses.*.mcpServers[]` | object |  |  |  |  |  |
| `client.harnesses.*.mcpServers[].command` | array of string |  |  |  |  |  |
| `client.harnesses.*.mcpServers[].command[]` | string |  |  |  |  |  |
| `client.harnesses.*.mcpServers[].headers` | object |  |  |  |  | Use $&#123;VAR} references, never literal credentials. |
| `client.harnesses.*.mcpServers[].headers.*` | string |  |  |  |  |  |
| `client.harnesses.*.mcpServers[].name` | string | yes |  |  |  |  |
| `client.harnesses.*.mcpServers[].url` | string |  |  |  | pattern ^https:// |  |
| `client.harnesses.*.overrides` | object |  |  |  |  | Harness-native keys, restricted to the same allowlist as profile overrides. |
| `default` | boolean |  |  |  |  | State when no rule matches. |
| `description` | string |  |  |  |  | What the toggle does. |
| `expires` | string |  |  |  | pattern ^\d&#123;4}-\d&#123;2}-\d&#123;2}$ | Removal date (YYYY-MM-DD); past it, validate warns that the toggle is stale. |
| `kind` | string | yes |  | const Toggle |  | Document kind. |
| `labels` | object |  |  |  |  | Free-form labels. |
| `labels.*` | string |  |  |  |  |  |
| `name` | string | yes |  |  | pattern ^[a-z0-9][a-zA-Z0-9._-]*$ | Unique name within its kind. |
| `owner` | string | yes |  |  |  | Team or person who answers for the toggle. |
| `rules` | array of object |  |  |  |  | Evaluated in order; the first match decides. |
| `rules[]` | object |  |  |  |  | Matches when every condition it sets holds; the first matching rule decides. |
| `rules[].effect` | string |  |  | on, off |  | State when the rule matches (default on). |
| `rules[].groups` | array of string |  |  |  |  | Match subjects in any of these IdP groups. |
| `rules[].groups[]` | string |  |  |  |  |  |
| `rules[].name` | string |  |  |  |  |  |
| `rules[].percent` | number |  |  |  | minimum 0; maximum 100 | Percent (0-100) of matching subjects, hashed under the salt halos/toggles/&lt;name>. Omitted = no percent condition; an explicit 0 matches nobody. |
| `rules[].rings` | array of string |  |  |  |  | Match subjects in any of these rings. |
| `rules[].rings[]` | string |  |  |  |  |  |
| `rules[].users` | array of string |  |  |  |  | Match these user ids. |
| `rules[].users[]` | string |  |  |  |  |  |
| `traffic` | object |  |  |  |  | Payload of a traffic-axis toggle. |
| `traffic.routes` | object | yes |  |  |  | Gateway model alias -> route used while the toggle is on. |
| `traffic.routes.*` | object |  |  |  |  | A single upstream+model. |
| `traffic.routes.*.model` | string |  |  |  |  |  |
| `traffic.routes.*.targets` | array of object |  |  |  |  | Ordered/weighted targets (mutually exclusive with upstream+model). |
| `traffic.routes.*.targets[]` | object |  |  |  |  |  |
| `traffic.routes.*.targets[].model` | string | yes |  |  |  |  |
| `traffic.routes.*.targets[].priority` | integer |  |  |  |  |  |
| `traffic.routes.*.targets[].timeoutSeconds` | integer |  |  |  |  |  |
| `traffic.routes.*.targets[].upstream` | string | yes |  |  |  |  |
| `traffic.routes.*.targets[].weight` | number |  |  |  |  |  |
| `traffic.routes.*.upstream` | string |  |  |  |  |  |
