---
title: Org hierarchy
description: Business units and teams with delegated owners, an org security baseline they can only tighten, and per-unit overlays.
---

A **Unit** is a business unit or team. It has owners, a member selector and an overlay of profile settings. Units nest through `parent`. The central platform team keeps the baseline (rings and their profiles); each unit's owners change their own overlay, in their own directory of the policy repo, and `halo validate` rejects any overlay that weakens an enforced field. The decision record is [ADR-0018](/halos/adr/0018-org-hierarchy-and-delegated-policy/).

## How a user's config resolves

1. **Ring.** `internal/assign` puts the user in a ring, exactly as without units. If a running client-axis experiment enrolls the ring and assigns the user a variant, the variant's profile replaces the ring's.
2. **Unit.** The user belongs to the deepest unit whose `members` selector matches, and so does every ancestor's selector: a team can only narrow its parent's members. Two matching units at the same depth resolve to the lexically smaller name. No hashing is involved.
3. **Merge**, in a fixed order: the profile (its `extends` chain, root first), then each ancestor unit's overlay (root first), then the unit's own.

| Overlay field | Merge |
|---|---|
| scalars (`permissions.mode`, `permissions.sandbox`, `models.default`, ...) | the overlay wins when set |
| `permissions.deny`, `mcp.denied`, `hooks.items` | union |
| `mcp.servers` | added; reusing a name provided above is an error |
| `models.allowed`, `permissions.allow`, `permissions.ask`, `egress.allowedDomains` | replace |
| `env`, `telemetry.attributes` | merged per key |
| `instructions` | appended |

Harness pins and `overrides` are not part of an overlay. They ship per ring.

## Enforced fields

These fields make up the org security baseline. An overlay may tighten them but never loosen them. The check runs for every unit against its parent's effective config, on every profile that ships: each ring's profile and each running client-axis variant.

| Field | Tighter means |
|---|---|
| `permissions.mode` | `plan` < `default` < `acceptEdits` < `auto` |
| `permissions.sandbox` | `read-only` < `workspace-write` < `off` |
| `permissions.disableBypass`, `sandboxRequired`, `mcp.managedOnly`, `hooks.managedOnly`, `telemetry.enabled` | never turned off |
| `permissions.deny`, `permissions.ask`, `mcp.denied` | never drop an entry |
| `permissions.allow`, `egress.allowedDomains` | never add an entry |
| `telemetry.otlpEndpoint`, `telemetry.protocol`, `telemetry.logPrompts` | unchanged |
| `telemetry.attributes` | add keys; never change an inherited one |
| `env` | never change an inherited key; add only keys `delegation.envKeys` lists, and never a provider, proxy, telemetry (`OTEL_*`), shell-hook, pager or editor, git-wrapper, compiler or runtime-injection, or harness config-dir key ([full list](/halos/concepts/security-model/#delegated-units)) |
| `hooks.items` | add none, unless `delegation.allowHooks` |
| `mcp.servers` | add only exact `selfService.catalog` entries |
| `models.allowed` while `models.enforce` is set | a subset |

Additions are loosenings because a unit's own owners approve its file: a hook is a shell command every member's harness runs, an env key such as `NODE_OPTIONS` or `ANTHROPIC_BASE_URL` injects code or reroutes model traffic, and an MCP server is code or a network endpoint the harness trusts. The org opts in to what units may add in `halos.yaml`:

```yaml
delegation:
  allowHooks: false        # default; true lets units add hooks.items
  envKeys: [TEAM, JIRA_PROJECT]
selfService:
  catalog:                 # the MCP servers units may add, matched exactly
    - {name: linear, url: https://mcp.linear.app/sse}
```

`*_BASE_URL`, `*_API_KEY`, `ANTHROPIC_*`, `OPENAI_*`, `GEMINI_*`, `CLAUDE_CODE_*`, `AWS_*`, `GOOGLE_*`, `CLOUD_ML_REGION`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `OTEL_EXPORTER_OTLP_*`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `PATH`, `BASH_ENV`, `ENV`, `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `GIT_EXEC_PATH`, `npm_config_*`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `NODE_*`, `LD_*`, `DYLD_*` and `PYTHON*` (any case) are refused even when listed. halo-server and the gateways refuse to activate a policy with a unit loosening (they keep the last good policy), so the check does not rest on `halo validate` alone. Overlays have no `extensions` field: plugins and marketplaces stay central.

A loosening is a validation error with the exact field path and the layer it loosens:

```
error   units[checkout].overlay.permissions.sandbox  "off" is looser than "workspace-write" (vs parent unit payments on profile engineering): units may only tighten the enforced baseline
```

Each effective config must also pass the same profile checks and built-in guardrails as the profile it starts from. Examples: no `bypassPermissions`, https MCP servers, no literal secrets.

## Example

```yaml
# examples/acme-corp/units/payments/unit.yaml
apiVersion: halos.dev/v1
kind: Unit
name: payments
owners: ["@acme/payments-platform"]
members:
  groups: [payments-eng]
overlay:
  models:
    allowed: [sonnet, haiku, codex-default, gemini-default] # narrows: no opus
  permissions:
    deny: [Read(./pci-vault/**), Bash(psql:*)]
  telemetry:
    attributes: {business_unit: payments}
```

```yaml
# examples/acme-corp/units/payments/checkout/unit.yaml
apiVersion: halos.dev/v1
kind: Unit
name: checkout
parent: payments
owners: ["@acme/checkout-team"]
members:
  groups: [checkout-eng]
overlay:
  permissions:
    mode: plan
    ask: [Bash(git push:*)]
```

## Delegated ownership

Each unit lives in a directory of its own (for example `units/payments/unit.yaml`). Validate keeps the delegation honest:

- A unit directory may hold only Unit documents, so a unit's owners cannot add a Ring, Profile or Toggle there.
- A unit nested in another unit's directory must be its descendant, so it cannot capture users outside its parent.
- A unit may not live in the policy root, and only one unit may live in each directory.
- A top-level unit (no `parent`) selects from the whole org, so it may use `members.groups` only; `members.users` is for units inside it.

`halo units codeowners` prints a CODEOWNERS file. The catch-all line goes to the central team, and each unit's directory goes to its owners and its ancestors' owners. A top-level unit's own file goes to the central team alone, because its `members` decide who in the whole org gets the overlay and CODEOWNERS lets any one listed owner approve; its owners still own the rest of their directory, including every nested unit. `--owner` is therefore required when there is a top-level unit:

```sh
halo units codeowners --policy-dir . --owner @acme/ai-platform > .github/CODEOWNERS
```

```
* @acme/ai-platform
/units/payments/ @acme/payments-platform
/units/payments/checkout/ @acme/checkout-team @acme/payments-platform
/units/payments/unit.yaml @acme/ai-platform
```

Require code-owner review and the `halo validate` check on the policy repo's main branch. Unit owners then merge their own overlays, and nothing they merge can loosen the baseline.

## Explaining one user

`halo explain --user` shows where a user lands and every field of their effective config, with the layer that set it:

```sh
halo explain --policy-dir . --user carol --groups payments-eng,checkout-eng
```

```
user     carol
ring     ring3-ga
profile  engineering
unit     payments > checkout

FIELD                          VALUE                      SET BY
permissions.mode               plan                       unit checkout
permissions.deny[]             Read(./.env)               profile base
permissions.deny[]             Bash(psql:*)               unit payments
harnesses.claude-code.version  2.1.280                    profile engineering
instructions                   # Acme engineering ...     profile base + unit payments
...
```

## Delivery

A release carries every unit in its signed manifest: the member selector, plus the files the unit's effective config renders differently, as whole files. `halod` picks the device's unit with the subject and IdP groups that halo-server's ring endpoint returns, writes the unit's files in place of the release's own, and then merges client toggle fragments on top. A device with no unit, or one pinned to a ring in `halod.yaml` (so it has no groups), gets the release's own files. The unit applied is reported as `unit` in the device status.
