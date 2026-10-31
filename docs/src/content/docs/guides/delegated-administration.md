---
title: Delegated administration
description: Give business units and ring owners halo-server roles over their own rings and units with identity.roleBindings, scoped service tokens and scoped approvers, and check what each person holds.
---

Units ([org hierarchy](/halos/concepts/org-hierarchy/)) delegate who owns a part of the policy. Scoped role bindings delegate who operates that part in the console: a business unit's on-call sees and revokes their own members' devices, a canary owner kills canary experiments and approves canary rollout steps, without either becoming a global admin. Decision record: [ADR-0037](/halos/adr/0037-scoped-role-bindings/).

## Bind roles to a scope

In `halos.yaml`, next to the global roles:

```yaml
identity:
  adminGroups: [platform-admins]       # global, unchanged
  roles:
    viewer: [engineering]              # global, unchanged
  roleBindings:
    - role: admin                      # payments' own devices and tokens
      groups: [payments-platform]
      scope: { units: [payments] }
    - role: viewer                     # read payments' fleet and requests
      groups: [payments-sre]
      scope: { units: [payments] }
    - role: approver                   # payments members' access requests
      groups: [payments-leads]
      scope: { units: [payments] }
    - role: operator                   # kill switch and status PRs in canary
      groups: [canary-oncall]
      users: [lead@acme.example]
      scope: { rings: [ring1-canary] }
    - role: approver                   # canary rollout steps
      groups: [canary-oncall]
      scope: { rings: [ring1-canary] }
```

- `role` is one of `viewer`, `operator`, `approver`, `auditor`, `admin` ([console roles](/halos/concepts/security-model/#console-roles)).
- `groups` (IdP or SCIM groups) and `users` (user ids, case-insensitive) hold the binding; at least one is required.
- `scope.rings` and `scope.units` name rings and units in policy; a unit includes its descendants. Both lists together intersect: `{rings: [ring1-canary], units: [payments]}` is payments' members in canary. No scope is global.
- Run `halo validate`. An unknown ring, unit or role, or a binding with nobody in it, is an error, and halo-server keeps serving the last good policy until it is fixed. Keep `halos.yaml` with the root owners: a unit's own owners must not be the ones granting authority over it.

Changes apply on the next request; a newly referenced group applies at the user's next login (the session keeps only groups policy refers to).

## What a scope covers

A grant covers a resource only when the resource lies wholly inside the scope.

| You hold | You can act on |
|---|---|
| `units: [payments]` | Devices whose owner is in payments or a unit below it; their access requests (opt-in to a ring) |
| `rings: [ring1-canary]` | Experiments, toggles and rollouts that run only in ring1-canary; devices whose owner is in ring1-canary; that ring's freeze windows and release |
| `rings: [ring1-canary], units: [payments]` | Payments members' devices in ring1-canary. Not experiments: they run for every unit's members |
| No scope | Everything the role allows, as `identity.roles` |

Some routes are global only: the policy snapshot, budgets, cloud agents, the audit log and session ledger, credential and per-user session revocation, toggle proposals, the incident freeze and break-glass unlock. Scoped callers get a 403 there. An `mcp-server` access request edits the requester's ring's profile, which also reaches every ring on a profile that extends it and every ring of an experiment with a variant on one, so only an approver covering all of those rings, or a global one, can decide it. Requests of kinds with no automatic change are global only.

Lists (fleet, devices, releases, experiments, rollouts, toggles, kill list, freeze, requests, service tokens) show only what you cover, with counts computed from that. A resource you do not cover and one that does not exist answer the same 403.

## Check what someone holds

```bash
halo whoami --user sam@acme.example --groups payments-sre,engineering
# ...
# console  viewer over global (identity.roles.viewer)
# console  viewer over units=payments (identity.roleBindings[1])
```

Signed in, `GET /api/v1/me` returns the same as `bindings`. A scoped refusal is audited as `authz.deny` with `scope` (`global`, `unknown` or `out of scope`), the resource and the caller's bindings; an action a scoped grant allowed carries `authzRole`, `authzScope` and `authzBinding`:

```bash
curl -s -H "Authorization: Bearer $HALO_TOKEN" "$HALO_SERVER/api/v1/audit?action=authz.deny&limit=20"   # an auditor token
```

## Scoped automation

A unit admin mints tokens within their own scope ([Admin access](/halos/guides/admin-access/)):

```bash
export HALO_SERVER=https://halo.acme.example HALO_SESSION=...   # an interactive session
halo service-token create --name payments-lost-laptops --role admin --scope-unit payments --ttl 720h
halo service-token create --name checkout-fleet --role viewer --scope-unit checkout
```

The scope must be within one of your admin grants, and each permission of the role must be yours over it: a payments admin cannot mint a global token or a canary-ring token. A misspelt scope key, ring or unit is refused. A scoped admin lists and revokes only tokens within their scope.

## Approvals and quorums

Approving needs an approve grant covering what the decision changes: a rollout step's rings, or the requester's rings and unit. With an approval rule ([change governance](/halos/guides/change-governance/)), a scoped approval counts toward the quorum only while its scope covers the change; if the step is later edited to enter a ring outside it, the approval stops counting. Approvers must still hold one of the rule's groups.

A toggle's "who gets it?" preview is limited the same way: without a global read grant you can preview yourself, or a user in a ring you read (`ring` given).

A scoped token keeps the scope of the admin grant that allowed it. If a later policy puts the token's scope outside it (a unit moved to another parent), the token is refused until you mint a new one.

## Upgrading

Before adding the first `roleBindings` entry, upgrade to the first release with ADR-0037: every halo-server replica, the `halo` CLI, `halo mcp serve` and any standalone `halo controller run`. An older halo-server refuses such a policy (and keeps its last good one), refuses scoped tokens and counts scoped approvals for no approval rule; an older halo-server, CLI or MCP server would still count a scoped approval toward a step's plain approval gate. An older halo-server also ignores a token's `scope` and mints a global token: `halo service-token create --scope-*` notices, revokes it and fails.

Rollout-step approvals are keyed by the rings they approve (the next step's and the experiment's) from this release on. The key changed shape, so every rollout-step approval recorded before the upgrade stops counting, for every rollout: give pending ones again after upgrading.

Scopes name rings and units. A ring or unit deleted and later recreated under the same name is the same scope to bindings and tokens: retire names rather than reuse them, or revoke the tokens that name them.
