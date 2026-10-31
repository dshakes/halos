---
title: "ADR-0037: Scoped role bindings for org units and rings"
description: identity.roleBindings grant a halo-server role over a scope of rings and units. Every route declares how its resource is scoped; a grant authorizes only resources wholly inside its scope, lists are filtered, unknown resources deny, and existing global roles behave exactly as before.
status: accepted
date: 2026-10-31
---

# ADR-0037: Scoped role bindings for org units and rings

- Status: accepted
- Date: 2026-10-31

## Context and problem statement

halo-server's roles ([ADR-0015](/halos/adr/0015-rbac-roles-for-halo-server/)) are global: an operator can kill any experiment, a viewer reads every device, an admin revokes any device. ADR-0015 says so: "Per-experiment or per-ring scoping is not modelled." Units ([ADR-0018](/halos/adr/0018-org-hierarchy-and-delegated-policy/)) delegate ownership of policy to business units and teams, but the console has no unit-scoped roles, so a business unit's on-call engineer who must see their own fleet and revoke their own lost laptop has to be a global viewer and a global admin. Delegated administration and multi-tenancy stop at the policy repo.

How does halo-server grant a role over part of the org without making the authorization surface harder to review, and without changing anything for the policies that exist today?

## Decision drivers

- Existing policy and existing tests mean exactly what they meant: `identity.roles` and `adminGroups` stay global, and a policy with no scoped binding authorizes every request as before.
- Deny by default: a resource whose scope cannot be determined (unknown name, unprovisioned owner, policy not loaded) is out of every scope.
- One reviewable table: every route says how its resource is scoped, next to the permission it needs, and a test fails when a route has no entry.
- Scope comes from the server, never the client: rings and units are derived from policy and the server's own records, never from a request body, a query parameter or a device's report.
- Lists must not leak: out-of-scope items, and counts or aggregates computed from them, are not returned.
- The ADR-0036 and ADR-0030 guarantees extend to scopes: no token stronger than its creator, no approval counting for what its approver could not approve.
- No new dependency, no new storage, no new trust boundary.

## Considered options

1. **Scoped bindings in `identity.roleBindings` (halos.yaml), a route-to-resource table, conjunctive ring and unit scopes.** Chosen.
2. **Unit files declare their own console roles** (`Unit.admins`). Each unit's owners approve their own unit file (ADR-0018 CODEOWNERS), so a unit owner could grant anyone authority over the unit without central review, and nested units could each re-delegate. The grant of authority is a security decision for the root owners; it stays in `halos.yaml`.
3. **Per-route group lists in policy.** Rejected by ADR-0015 for the same reasons; scoping each one multiplies the problem.
4. **An external policy engine (OPA, Cedar).** A new dependency and trust boundary; ADR-0007 already chose Go over Rego.
5. **Disjunctive scopes (a resource in any listed ring OR any listed unit).** Matches `ChangeScope` in ADR-0030, but a binding `{rings: [canary], units: [payments]}` would then cover all of canary and all of payments. Authority should narrow as a scope grows more specific, so dimensions intersect; two bindings express a union.
6. **Scope at the route only (a binding names routes).** Cannot express "this unit's devices", which is the case that motivated the change.

## Decision outcome

### Configuration

```yaml
identity:
  adminGroups: [platform-admins]          # global, as before
  roles: { viewer: [eng] }                # global, as before
  roleBindings:
    - role: operator
      groups: [canary-oncall]
      scope: { rings: [ring1-canary] }
    - role: admin
      groups: [payments-platform]
      users: [lead@acme.example]
      scope: { units: [payments] }
    - role: viewer
      groups: [payments-sre]
      scope: { rings: [ring1-canary], units: [payments] }
```

- A binding grants `role` to every listed group and user (user ids compared canonicalized, as everywhere else). An empty `scope` is global and means exactly what the same group under `identity.roles` means.
- `scope.rings` and `scope.units` name rings and units in policy. A unit covers its descendants. Within a list any value matches; across the two lists both must.
- Validation (`internal/policy/rolebinding.go`, `roleBindings`): a known role, at least one group or user, no blank or space-padded names, every ring and unit defined, no duplicates. Errors sit under `identity`, a security path: halo-server refuses such a policy and keeps the last good one. A scoped `auditor` binding is a warning (audit routes are global only, so it grants nothing). The JSON schema matches.
- Role bindings' groups are kept in the session like role groups (`roleGroups`). Grants are recomputed from current policy and the directory on every request, as roles are.

### Grants and resources

- `policy.Identity.Grants(subject)` returns every grant: the global ones from `adminGroups`/`roles`, then each matching binding in file order, with its source (`identity.roles.viewer`, `identity.roleBindings[3]`). `Principal.Bindings` holds them; `Principal.Roles` is their distinct role names, so `/me`, `/capabilities`, login audit entries and the console's page hiding read as before. `Principal.Admin` (kept for pre-ADR-0015 clients) is true only for a **global** admin grant; a scoped admin shows in `bindings` only.
- A **resource** (`policy.Resource`) is the rings and units whose members something affects. `RoleScope.Covers` holds when the resource lies **wholly** inside the scope: every ring of the resource is a scope ring, and the resource's unit chain contains a scope unit. A bounded dimension never covers a resource that is unbounded or unknown in it.

| Resource | Rings | Units |
|---|---|---|
| Experiment | its `rings` | every unit (ring members come from any unit, ADR-0018) |
| Toggle | the rings its rules select; every ring if `default: true` or any rule has no ring condition | every unit |
| Rollout (read, and its approvals) | every ring any step exposes | every unit |
| Rollout step approval (deciding) | the rings the next step enters (`rollout.TargetResource`, the target ADR-0030 already uses) | every unit |
| Device | the owner's ring, resolved now from policy and the groups the server holds (SCIM authoritative wins), never the ring the device reports | the owner's unit chain |
| Access request, `ring-opt-in` | the requester's ring when filed and the requested ring | the requester's unit chain when filed |
| Access request, `mcp-server` | `Org.ProfileReach` of the requester's ring's profile, which the approval edits: every ring whose profile is it or `extends` it at any depth, and every ring of each experiment with a variant on such a profile; an unresolvable chain counts as reached | every unit |
| Access request, other kinds | every ring (no automatic change; reach unknown) | every unit |
| Service token | its scope, compared with `ScopeWithin` | |

Consequence: a unit-only scope covers people-shaped resources (devices, their requests); rings, experiments, rollouts and toggles are org-wide and need a ring scope without units, or a global grant. This is deliberate: a unit admin cannot kill an experiment that also runs for other units' members.

### Enforcement

- `routePerms` is unchanged (one permission per route). `routeScopes` (`internal/server/scope.go`) gives every route one of: `self` (the caller's own data), `byPath` (a resource function), `filtered` (a list the handler narrows), `inHandler` (body-derived or a handler lookup, with the reason), or `global` (with the reason it cannot be scoped). `TestRouteScopesCoverPerms` requires an entry for every routed permission and a reason for every global or in-handler one.
- `s.route` first checks `p.can(need)` (some grant holds the permission: ADR-0015's gate, its denial unchanged), then `authorizeScope`. A global grant for the permission passes **without resolving the resource**: byte-for-byte the old behaviour, including 404 for unknown names. Otherwise: `byPath` resolves the resource from current policy and server records and passes when a grant covers it; an error (unknown name, unprovisioned owner, policy not loaded) is a 403, the same 403 as out of scope, so a scoped caller cannot probe names outside their scope. `global` refuses every scoped caller. A route missing from `routeScopes` refuses every scoped caller.
- Global-only routes: policy snapshot, budgets, cloud agents and their kill, audit log and session ledger (one hash chain; separation of duties keeps its review whole), session ingest, credential revocations, per-user session revocation (a user id has no server-side ring or unit), toggle proposals (the proposed rules may target anything), the incident freeze, break-glass unlock, and `whoami` for another user (the subject's groups come from the query, so they cannot bound a scope).
- **One policy snapshot per request.** `authorizeScope` takes the policy once and pins it on the request (`withPolicy`); the scope check and the handler read it (`reqPolicy`), so a reload between them cannot let a handler act on a resource the check never saw. Done for kill and unkill (experiments and toggles), rollout and access-request approvals and decisions (including the PR the decision opens), experiment status, the toggle view and the list filters. Handlers that read the policy *view* (the experiment list's display data, releases, rollouts, freeze) still read it separately for display; a reload there can only show a newer view, filtered by the pinned policy, never authorize an action.
- **Toggle preview.** `GET /api/v1/toggles/{name}?user=` evaluates the toggle for a subject. A reader without a global read grant may preview only themselves (with their own groups, not the query's) or a subject in a ring they read (`ring` given). An unknown ring answers with the same 403 as an out-of-scope one, and a ring the reader does not cover is not named in the subject or the rule trace.
- Lists: fleet (device reports placed by the server; fleet-token reports have no owner and are global-only), devices, releases (in-scope rings; convergence counted from visible hosts), experiments, rollouts, toggles, kill list (a kill of a name no longer in policy has no scope), freeze windows per ring (the incident freeze is shown to every reader: it holds every ring), access requests, service tokens. Totals and per-ring stats are computed from what is returned.

### Interactions

- **Service tokens (ADR-0036).** `POST /api/v1/service-tokens` takes `scope`. The whole body is decoded strictly: exact keys (a case variant such as `Scope` is refused, though `encoding/json` would accept it), each key once (`encoding/json` keeps the last), no unknown keys, and a `scope` that is present must name a ring or a unit (`{}`, `null` and empty lists are refused, never global). Rings and units are checked against policy. The creator must hold an admin grant whose scope holds the token's (`ScopeWithin`: rings a subset, each unit equal to or below a creator unit), and each permission of the token's role over a scope that holds it (`grantWithin`, which `roleWithin` now calls with the global scope). A scoped admin lists and revokes only tokens within their admin grants; an unknown id answers as out of scope. The principal holds exactly one grant `{role, scope, "service-token"}`. The record also keeps `creatorScope`, the scope of the creator's admin grant that allowed it; on every use the token's scope must still be within it under current policy (`ScopeWithin`), so a later policy that moves a unit out from under the creator's unit refuses the token (403, audited as `authz.deny` with both scopes). `halo service-token create --scope-*` compares the scope the server returns with the one requested; a server that ignored it (one from before this ADR mints a global token) gets the token revoked at once and an error, in every output mode.
- **Mixed versions.** A binary from before this ADR ignores unknown JSON fields. A scoped token's record therefore stores its role in `scopedRole` and leaves `role` empty, so an older replica finds no role and refuses the token rather than treating it as global; a record with both, or a scope without `scopedRole`, grants nothing. Likewise a scoped approval stores the approver's groups in `scopedGroups`, so an older replica counts it for no rule. An older binary also refuses a policy with `roleBindings` (strict decoding) and keeps its last good policy. `rollout.ApprovalKey` now includes the next step's rings and the backing experiment's rings, so an approval stops counting when either is retargeted, on every binary and client that reads approvals by key (older replicas, `halo rollout` and `halo mcp serve`, which fetch them from halo-server). Pending rollout-step approvals recorded before the upgrade are under the old key and must be given again.
- **Minimum versions.** Before adding the first `roleBindings` entry, run the first release with this ADR for every halo-server replica (scoped tokens, approvals and the policy itself), the `halo` CLI and `halo mcp serve` (they evaluate rollout gates locally from approvals: an older one counts a scoped approval toward a plain approval gate) and any standalone `halo controller run`.
- **Approvals and quorums (ADR-0030).** Approving needs an approve grant covering what the decision changes (route check). Each approval records the scopes of the approver's scoped approve grants (`Approval.Scopes`, nil for a global approver, which every approval before this ADR was). `Org.QuorumFor(res, ...)` counts a scoped approval only when one of its scopes covers `res`; `Quorum` (no resource) counts none. The rollout controller (`rollout.Governance.Apply`), the approvals view and access-request decisions all pass the resource, so an approval recorded for a step whose rings are later edited stops counting; a scoped approval that does not cover the step satisfies no plain approval gate either, nor does the requester's own approval. Approval rules (ADR-0030) select an access request by the same reach: an opt-in adds the requested ring, an MCP server request every ring of `ProfileReach` and every unit.
- **Audit.** Every 403 from a scope check is `authz.deny` with `scope` (`global`, `unknown`, `out of scope`), `resource` when known, and the caller's `bindings`. Every entry a handler writes for an action a **scoped** grant authorized carries `authzRole`, `authzScope` and `authzBinding`. An action authorized by a global grant adds nothing, so its entry reads exactly as before this ADR and as every older entry: absent means global.
- **Break-glass** stays one global admin grant: it exists for when policy or the IdP is broken, and scoping it to policy would defeat that.
- **Dev mode.** `--dev-insecure-roles` grants global roles, as before.

### Clients

- `GET /api/v1/me` and `GET /api/v1/capabilities` return `bindings` (`[{role, scope, source}]`).
- `halo whoami --user U --groups G` prints the console roles and scopes the user holds under the policy (`consoleRoles` in JSON). `halo service-token create --scope-ring R --scope-unit U` mints a scoped token; `list` shows each token's scope.
- The console (`web/`) still hides pages by permission and shows nothing about scope; the server filters and refuses regardless. Showing scopes in the console is a follow-up.

## Threat model

| Threat | Mitigation | Residual |
|---|---|---|
| Scope confusion through a body or query field (a ring in the body that differs from the resource's) | Resources are derived from the path's server-side record and current policy only; decision bodies carry no scope; `halo whoami` for another user, whose groups come from the query, is global only | |
| A device reports a ring it is not in to become visible to, or hidden from, a ring-scoped reader | Devices are placed by the server from the owner's identity (`deviceResource`); the reported ring is display data | |
| Probing for names outside one's scope | Unknown and out-of-scope resources answer the same 403 body; lists never include them; counts are recomputed | A scoped caller learns that a name is "not theirs", not whether it exists |
| Unit admin acts on an org-wide object (kills an experiment running for other units) | Experiments, toggles, rings and rollouts are every-unit resources: a unit scope never covers them | Units cannot own experiments; that needs a policy model change |
| Approving a change wider than the approver's scope (an opt-in from another ring, an MCP server added to a profile other profiles extend or experiment variants use) | Request resources model what approving changes, from the server's record: both rings for opt-in, `ProfileReach` (the profile's rings, the rings of every profile extending it, the rings of experiments with a variant on any of them; unresolvable chains count) for MCP, every ring for kinds with no automatic change. Approval rules use the same reach | Reach is computed from the policy at decision time: a profile that starts extending the edited one later is not re-judged |
| Toggle preview used to evaluate subjects outside one's scope, or as a ring-name oracle | Scoped readers preview themselves or a subject in a ring they read; unknown rings answer as out of scope; uncovered rings are redacted from the subject and the trace | |
| Policy reload between the scope check and the action | One snapshot per request for kill, unkill, approvals, decisions, status PRs, toggle view and filters | Display-only views read the newest policy separately |
| A scoped approval counted after the step it approved is retargeted | Approvals record scopes; quorums and the plain gate count them only while they cover the step; `ApprovalKey` includes the step's and the experiment's rings, so any retargeting starts a new key, for older binaries and local CLI/MCP evaluation too | Pending approvals are lost once at upgrade (new key) |
| Token minted wider than its creator | `adminGrantOver` and `grantWithin` at creation; strict body decoding (exact keys, once, no empty scope); unknown rings and units refused; `creatorScope` re-checked against current policy on every use | A creator who later loses their binding leaves their tokens in force until expiry or revocation (the token is checked against the grant's recorded scope, not the creator's current bindings, which a token cannot see) |
| A server that predates scopes mints a global token for a scoped request | `halo service-token create` compares the returned scope, revokes on mismatch and fails | A client other than `halo` must check `serviceToken.scope` itself |
| An older replica reads a scoped token or approval as global | `scopedRole` / `scopedGroups` fields older binaries do not read (tested against the old record shape) | An older replica counts a scoped approval toward a step's plain approval gate (no rule); upgrade every replica before adding the first binding |
| Policy typo grants too much (misspelt unit) or too little silently | Unknown rings and units, unknown roles and empty bindings are validation errors on a security path: the server keeps the last good policy | |
| A route added later without thinking about scope | `TestRouteScopesCoverPerms` fails; at runtime a route with no `routeScopes` entry refuses every scoped caller | |
| Audit cannot tell what authorized an action | `authzRole`/`authzScope`/`authzBinding` on every entry a scoped grant authorized; `authz.deny` names why | Entries from global grants carry nothing new (absent = global) |

## Consequences

- **Good.** Delegated administration reaches the console: a unit admin sees and revokes their members' devices, a ring operator kills that ring's experiments and toggles, a ring approver approves that ring's rollout steps and counts toward its quorum, with tokens to automate exactly that.
- **Good.** Additive: no existing route, role, policy, token, approval or audit entry changes meaning. `TestRolePermissionMatrix` and every other existing test pass unchanged; `TestUnscopedBindingMatchesRoles` checks an unscoped binding against the same role in `identity.roles` on every route.
- **Bad.** Scoped callers resolve resources per request (a policy lookup, a device and directory lookup for device routes); list filtering is O(items). Human-scale data; global callers skip it.
- **Bad.** Unit scopes do not reach org-wide objects, and the audit log, budgets and policy are global only. A unit that needs those needs a global grant.
- **Neutral.** The console shows no scope yet; a scoped user sees pages whose lists are filtered and whose buttons may 403.

## Implementation status (2026-10-31)

| Commitment | Code | Test | Status |
|---|---|---|---|
| `identity.roleBindings`, validation, schema, grants | `internal/policy/rolebinding.go`, `types.go`, `identity.go`, `schemas/halos.schema.json` | `internal/policy/rolebinding_test.go` (`TestGrants`, `TestRoleBindingValidation`) | Done |
| Covers, ScopeWithin | `internal/policy/rolebinding.go` | `TestRoleScopeCovers`, `TestScopeWithin` | Done |
| Route scope table, enforcement, list filters, deny audit | `internal/server/scope.go`, `rbac.go`, handlers | `internal/server/scope_test.go` (`TestRouteScopesCoverPerms`, `TestScopedAuthorizationMatrix`, `TestScopedListFiltering`, `TestUnscopedBindingMatchesRoles`) | Done |
| Request resources, scoped approvals, QuorumFor | `internal/server/scope.go`, `governance.go`, `internal/policy/governance.go`, `internal/rollout/governance.go` | `TestScopedRequests`, `TestScopedQuorum`, `TestQuorumScoped`, `TestGovernanceApply` | Done |
| Token scope, ceiling, management, skew-safe record | `internal/server/servicetokens.go` | `TestScopedServiceTokens`, `TestScopedRoleCeiling`, `TestScopedTokenRecordSkew` | Done |
| Security review (2026-10-31): profile reach for MCP requests and approval rules; strict token body; CLI revokes an unscoped token; toggle preview; creator scope re-checked on use; ApprovalKey rings; approvals read as the rollout; global-only `admin`; requester excluded from the plain gate; one policy snapshot per request | `internal/policy/rolebinding.go` (`ProfileReach`), `internal/server/scope.go`, `governance.go`, `servicetokens.go`, `toggles.go`, `auth.go`, `internal/rollout/governance.go`, `cmd/halo/cmd_servicetoken.go` | `internal/server/scope_review_test.go`, `TestProfileReach`, `TestApprovalKeyChangesWithStepAndChange`, `TestGovernanceApply`, `TestScopedServiceTokens`, `TestServiceTokenCLIScopeIgnored`, `TestOpenAPILiveConformance` (scoped pass) | Done |
| Audit fields | `internal/server/scope.go` (`withAuthz`, `authzDetails`), `audit.go` | `TestScopedAuditFields` | Done |
| CLI | `cmd/halo/cmd_policy.go`, `cmd_servicetoken.go` | `TestWhoamiConsoleRoles`, `TestServiceTokenCLIScope` | Done |
| Console shows scopes | `web/` | | Follow-up |

Mutation check: each of 15 single-line mutations (scope ignored by Covers, the path check, list filters, the token ceiling, quorum counting, audit fields, global-only routes, request resources, the token record, token management, strict decoding, binding scopes, unit chains, approval scopes, device placement) makes at least one of these tests fail. The security review's fixes were checked the same way: 18 mutations (profile reach without extends or variants, the approval-rule target, repeated, case-variant and unknown keys, empty scopes, the CLI scope check, the toggle preview's self, groups and redaction rules, the creator-scope check and record, ApprovalKey rings, approvals scoping, `admin`, the requester's own approval, and both halves of the policy snapshot) each fail a test.

## More information

- [Delegated administration](/halos/guides/delegated-administration/), [Security model](/halos/concepts/security-model/#console-roles), [API reference](/halos/reference/api/#scoped-grants).
- ADR-0015 (roles), ADR-0018 (units), ADR-0030 (approval quorums), ADR-0036 (service tokens, break-glass).
