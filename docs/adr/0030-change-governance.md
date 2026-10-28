---
title: "ADR-0030: Change governance"
description: Freeze windows and an incident freeze hold forward changes (never rollbacks or the kill switch), approver quorums with separation of duties gate access requests and rollout steps, and `halo plan --diff` previews who a change reaches before anyone approves it.
status: accepted
date: 2026-10-27
---

# ADR-0030: Change governance

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Halos moves configuration through rings with eval gates and a human merge (invariant 5). Enterprises also run a change process around that: change freezes (weekends, year-end, an incident in progress), a named number of approvers who are not the person asking, a change ticket, and an answer to "who does this reach" before anyone signs off. Today all of that lives outside Halos, so the rollout controller can advance a ring during a declared freeze and an approval is whoever merges the PR.

How does Halos enforce a change calendar and an approver quorum without ever blocking the way back, and show the blast radius of a policy change before it is approved?

## Decision drivers

- Rollbacks, pauses and the kill switch are never held. A freeze that blocks the way back makes an incident worse.
- Invariant 3: impact previews resolve rings and variants through `internal/assign` (via `policy.ResolveRing` and `Experiment.ResolveVariant`), so the preview and the fleet agree.
- Invariant 5: governance only adds gates. Nothing here merges, promotes or advances on its own.
- Wall-clock windows in a named zone must stay correct across DST on every binary, including distroless images and Windows.
- Every freeze toggle and every approval is audit-strict: no record, no change.
- Fail closed: an unreadable window or unreadable governance state holds forward changes.

## Considered options

1. **Policy windows and rules, plus one incident freeze on halo-server.** Chosen. Planned freezes and approval rules are reviewed like any policy; the one thing that must change in seconds (the incident freeze) is an audited server toggle.
2. **Everything on halo-server.** Rejected: planned freezes and quorum rules are policy, and should be reviewed, diffed and versioned like policy.
3. **Leave it to GitHub branch protection and CODEOWNERS.** Rejected as the only control: it covers the merge but not the rollout controller, the MCP write tools, access requests, or a ticket pattern, and it cannot see IdP groups.

## Decision outcome

### Policy

`halos.yaml` gains an additive `governance` section (omitted when unset, so existing snapshot digests do not change):

```yaml
governance:
  freezes:
    - name: ga-weekend
      reason: No GA changes over the weekend
      timezone: America/New_York      # IANA; default UTC
      scope: {rings: [ring3-ga]}      # rings and/or units; empty = org-wide
      weekly: {from: "Fri 18:00", to: "Mon 06:00"}
    - name: year-end
      reason: Year-end change freeze
      timezone: America/New_York
      start: "2026-12-18T18:00"       # wall clock in timezone, a date, or RFC 3339
      end: "2027-01-04T06:00"
  approvals:
    - name: ga-two-person
      scope: {rings: [ring3-ga]}
      quorum: 2
      groups: [ai-platform, sre-leads]  # IdP or SCIM groups
      distinctGroups: true
      ticket: 'CHG[0-9]{7}'             # matched whole
```

Validation errors (missing reason, unknown zone, bad weekday or time, end not after start, a window named `incident`, quorum below 1 or above the group count with `distinctGroups`, no approver groups, a ticket pattern that does not compile, unknown rings or units in a scope) are security issues: halo-server keeps the last good policy.

### Freeze windows

- A one-off window is `[start, end)`. A weekly window repeats from `from` to `to`; a `to` at or before `from` in the week ends the following week.
- Times are wall-clock in the window's zone, so DST moves the instant, not the time: `Fri 18:00` is 18:00 local before and after the change. A time a spring-forward gap skips maps to the same reading after the jump (02:30 becomes 03:30), as `java.time` and Python's `zoneinfo` do. A repeated fall-back time maps to its first instant. Binaries embed `time/tzdata`, so every host agrees.
- A ring change touches every unit (a ring's members come from any unit), so unit-scoped windows also cover ring changes.
- The refusal names every active window with its reason and end, and the next open time. Overlapping and abutting windows are walked until none covers the change.
- A window that does not parse is active forever (fail closed); `validate` reports it.

### Incident freeze

`POST /api/v1/freeze {"frozen": true|false, "reason": "..."}` (admin role, reason required) sets or lifts one org-wide incident freeze. `halo freeze on|off --reason` calls it. It is stored beside the kill list (`killswitch.jsonl`, shared with the controller) but never in it, so it cannot disable an experiment. Audit-strict: a freeze whose record fails stays set; a lift whose record fails is reverted. `GET /api/v1/freeze` (read) returns the incident freeze and every ring's status.

### What a freeze holds

| Action | During a freeze |
|---|---|
| Rollout controller advance | held; the decision says why, once per step |
| `halo rollout advance`, MCP `propose_rollout_advance` | refused with the windows and next open time (`--force` does not override) |
| `halo exp promote`, MCP `propose_promotion` | refused (dry runs show the patch and the refusal) |
| Rollout rollback and pause, `propose_rollback`, the kill switch | always allowed |
| Policy-repo PRs | `halo freeze check --event "$GITHUB_EVENT_PATH"` (pull_request and merge_group) is a required status check that fails while frozen. Windows are read from the base branch, never the PR. A rollback, classified from the diff (rollout status paused or aborted, experiment status paused, ring release moved to one it pointed at before on the base branch, nothing else), always passes; branch names are not trusted |

`halo freeze status [--ring] [--at]` lists each ring, whether it is frozen, why, and when it opens. The controller treats unreadable governance state as an incident freeze.

### Approver quorums and separation of duties

Every rule whose scope covers a change must be met. An approval counts when the approver holds one of the rule's groups at approval time (IdP claims or the SCIM directory), is not the requester, has not already approved, and, with `distinctGroups`, adds a group no counted approval used. Ignored approvals are listed with the reason. When a rule has a `ticket` pattern, the change needs a ticket reference matching it whole.

- **Access requests.** A covered request needs its ticket when filed. Each approval is audit-strict; the request answers 202 until the quorum is met, then is granted.
- **Rollout steps.** `POST /api/v1/rollouts/{name}/approve` (approver role; `halo rollout approve <name> --ticket`) records an approval for advancing from the live step. Approvals are keyed by rollout, step and a hash of the change (release digest, alias, backing experiment and the treatment's route for the alias), so they never carry over to another step or to an edited change. `change.release` must be a `sha256:<64 hex>` digest. The controller, `halo rollout advance` and `propose_rollout_advance` count them; the CLI and MCP pass the caller as requester so they cannot approve their own advance. Advance PR bodies record the ticket and the approvers.

### Impact preview

`halo plan --diff <git ref>` (and the MCP `plan` tool's `diff_base`) loads the policy at that ref from `git archive` into a temporary directory, and for every member of a population resolves ring, experiment variants and an effective-settings fingerprint (effective profile with unit overlays, pinned release, gateway models, variant routes) under both policies. It reports counts per kind (users, devices, agents) and per org unit, and examples of affected members.

- With `--server` and `HALO_SESSION`, the population is halo-server's enrolled fleet: each reporting host as a device (revoked devices skipped), each user once, and the policy's workload subjects as agents.
- Otherwise it is a policy-only estimate: every user the policies name, one member of each named group, each workload subject, and a hashed sample of 1000 anonymous users, shown as a percentage.
- Workloads are enrolled in experiments only when policy enrols them, as in the gateway.

## Consequences

- Good: planned freezes are reviewed policy; the incident freeze takes one audited command; the way back is never held.
- Good: quorum, separation of duties and ticket checks happen where the change happens (server, controller, CLI, MCP), not only at merge.
- Good: the impact preview uses the fleet's own assignment, so "how many move" matches what moves.
- Bad: rollouts record no author, so the controller's own advances have no requester to exclude; separation of duties there rests on the quorum of distinct approvers and the human merge.
- Bad: `halo freeze check` only blocks merges if the repo makes it a required check (ideally in the merge queue, so it is evaluated at merge time).
- Neutral: the policy-only estimate cannot see group sizes; it reports one member per group and a sample, and says so.
- Neutral: embedding `time/tzdata` adds about 450 KB per binary.

## More information

`internal/policy/governance.go`, `internal/rollout/governance.go`, `internal/server/governance.go`, `internal/controller/rollouts.go`, `internal/impact`, `cmd/halo/cmd_freeze.go`, `cmd/halo/cmd_release.go` (`plan --diff`), `internal/mcpserver/tools_rollout.go`, `internal/mcpserver/tools_write.go`; [Change governance guide](/halos/guides/change-governance/).
