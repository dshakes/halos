---
title: "ADR-0015: RBAC roles for halo-server"
description: Five roles (viewer, operator, approver, auditor, admin) mapped from IdP groups in policy, enforced by one route-to-permission table that denies unmapped routes, with every denial audited.
status: accepted
date: 2026-10-21
---

# ADR-0015: RBAC roles for halo-server

> **Amended 2026-10-31.** A role may now be held over a scope of rings and units: `identity.roleBindings` and a per-route resource table ([ADR-0037](/halos/adr/0037-scoped-role-bindings/)). `identity.roles` and `adminGroups` stay global and mean exactly what this record says.

## Context and problem statement

`halo-server` had two kinds of user: a developer (self-service) and an admin (`identity.adminGroups`), and every privileged route checked the same `admin` flag. Regulated organisations need segregation of duties: the people who can kill an experiment should not automatically approve access requests, and the people who review the audit log should not be able to change what it records. The single flag forces them to make everyone who needs any of that an admin. How does `halo-server` grant narrower authority without making the authorization surface harder to review?

## Decision drivers

- Separation of duties a compliance review can check: who can operate, approve, audit and administer are separate grants.
- One place to review: an auditor reading the code should see every route and what it needs in one table.
- Deny by default: a privileged route added later without a decision must not be reachable.
- Every refusal is evidence: an authenticated user probing for authority leaves an audit trail.
- Existing policy repos keep working: `adminGroups` keeps meaning admin.
- The group-to-role mapping is reviewed like any other policy change (PR in the policy repo), not set by a flag on one server.

## Considered options

1. **Fixed roles mapped from IdP groups in policy (`identity.roles`), permissions per route in one table.**
2. **Per-route group lists in policy.** Maximum flexibility, but every new route needs a policy change in every org, and nobody can say what "an operator" is.
3. **External policy engine (OPA/Cedar).** Expressive, but a new dependency and trust boundary for five roles, and ADR-0007 already chose Go over Rego for guardrails.

## Decision outcome

Chosen: **option 1**.

Roles and the permissions they grant (`internal/server/rbac.go`, `rolePerms`):

| Role | Permissions | Can |
|---|---|---|
| `viewer` | read | Fleet, devices, releases, rollouts, experiments, toggles, kill list, policy, other users' assignments, everyone's view in the console |
| `operator` | read, operate | Viewer plus kill and unkill (experiments and toggles), experiment status PRs (pause, resume, conclude) |
| `approver` | read, approve | Viewer plus approve and deny access requests; sees every request |
| `auditor` | audit | Read and page through (export) the audit log. Nothing else: map the group to `viewer` too if auditors should see the fleet |
| `admin` | all of the above, admin | Device and session revocation, toggle change proposals, launcher setup details |

Every logged-in user keeps self-service (`/me`, own devices, catalog, launch, own requests, own assignments) without a role.

- **Mapping.** `identity.roles.{viewer,operator,approver,auditor,admin}` lists IdP groups. A user holds every role any of their groups maps to. `identity.adminGroups` grants `admin` exactly as before; it is not deprecated, and `roles.admin` is equivalent. Strict YAML decoding rejects an unknown role name, so a typo is a load error rather than a silent empty grant. Roles are recomputed from current policy on every request, so removing a group from a role takes effect on the next request. Adding one applies at the user's next login, because the session keeps only the groups policy referred to when it was issued.
- **Enforcement.** `routePerms` maps every cookie-authenticated route pattern to one permission. Routes register through `s.route`, which looks the pattern up; a pattern with no entry is refused to everyone, admins included. Bearer-token and public routes (fleet reports, gateway, enrollment, OIDC) are outside the table and listed in the test. `TestRoutePermsCoverMux` walks every registered pattern and fails if one is neither public nor mapped, if a mapped route bypasses `s.route`, or if the table names a route that no longer exists. `TestRolePermissionMatrix` requests every mapped route as every role.
- **Two in-handler checks stay** because they depend on the request, not the route: `whoami` for another user needs `read`, and listing everyone's requests needs `approve`. Both call the same `deny`.
- **Audit.** Every 403 for lack of permission appends `authz.deny` with the actor, path, route pattern, method, needed permission and the caller's roles. It is best effort: the request is refused whether or not the append succeeds.
- **Console.** `GET /api/v1/me` and `GET /api/v1/capabilities` return the caller's `roles` and `permissions`; the console shows only the pages and buttons those allow. The server enforces regardless. `admin` stays in `/me` for older clients.
- **Demo mode.** `--dev-insecure-roles` sets the roles of `--dev-insecure-user`; `--dev-insecure-admin` still adds `admin`.

## Consequences

- Good: segregation of duties is a policy-repo diff; a reviewer sees the group-to-role mapping and the route table without reading handlers.
- Good: a new privileged route cannot ship reachable by accident: the test fails, and at runtime it is denied.
- Good: denied attempts are in the hash-chained audit log alongside the actions themselves.
- Bad: roles are fixed in code. An org that needs, say, "operator without unkill" cannot express it; that needs a new permission and a code change.
- Bad: an authenticated user can grow the audit log by repeating denied requests. Each entry names them; rate limiting is left to the reverse proxy.
- Neutral: permissions are coarse (one per route). Per-experiment or per-ring scoping is not modelled.

## More information

- `internal/server/rbac.go` (`rolePerms`, `routePerms`, `route`, `deny`), `internal/policy/types.go` (`RoleGroups`), `schemas/halos.schema.json` (`identity.roles`).
- Tests: `internal/server/rbac_test.go`, `internal/policy/roles_test.go`.
- [Security model](/halos/concepts/security-model/#console-roles), [production deployment](/halos/guides/production-deployment/).
