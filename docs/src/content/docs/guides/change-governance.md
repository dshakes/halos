---
title: Change governance
description: Freeze windows and an incident freeze that never hold a rollback, approver quorums with separation of duties and change tickets, and a preview of who a policy change reaches before it is approved.
---

Change governance ([ADR-0030](/halos/adr/0030-change-governance/)) adds three controls to the rollout path:

- **Freezes.** Policy freeze windows (weekly or one-off, in a named time zone) and one incident freeze on halo-server hold forward changes: rollout advances and promotions. Rollbacks, pauses and the kill switch are never held.
- **Approver quorums.** N approvals from IdP or SCIM groups, never counting the requester, optionally from distinct groups and with a change ticket. Enforced on access requests and rollout steps.
- **Impact preview.** `halo plan --diff main` counts the users, devices and agents whose ring, variant or effective settings change, by org unit, with examples.

## Declare freezes and approval rules

In `halos.yaml` ([example](https://github.com/dshakes/halos/blob/main/examples/acme-corp/halos.yaml)):

```yaml
governance:
  freezes:
    - name: ga-weekend
      reason: No GA changes over the weekend
      timezone: America/New_York
      scope: {rings: [ring3-ga]}
      weekly: {from: "Fri 18:00", to: "Mon 06:00"}
    - name: year-end
      reason: Year-end change freeze
      timezone: America/New_York
      scope: {rings: [ring3-ga]}
      start: "2026-12-18T18:00"
      end: "2027-01-04T06:00"
  approvals:
    - name: ga-two-person
      scope: {rings: [ring3-ga]}
      quorum: 2
      groups: [ai-platform, sre-leads]
      distinctGroups: true
      ticket: 'CHG[0-9]{7}'
```

- `scope` takes `rings` and `units`; empty means org-wide. A ring change touches every unit, so a unit-scoped window or rule also covers ring changes.
- Times are wall-clock in `timezone` (IANA, default UTC). `Fri 18:00` stays 18:00 local across DST. A time skipped by a spring-forward gap moves to the same reading after the jump.
- One-off bounds accept `2026-12-18T18:00`, `2026-12-18` (midnight) or RFC 3339 with an offset. The window is `[start, end)`.
- `ticket` is a regular expression the whole ticket reference must match.

`halo validate` rejects bad zones, times, scopes and patterns. halo-server keeps the last good policy when a change fails validation.

## Check what is frozen

```sh
halo freeze status                        # every ring, now
halo freeze status --at 2026-12-24T12:00:00Z --ring ring3-ga
```

With `--server` (or `HALO_SERVER`) and `HALO_SESSION`, the incident freeze is included. Without them, only policy windows are shown, and the output says so.

## Declare an incident freeze

```sh
export HALO_SERVER=https://halo.acme.internal HALO_SESSION=...   # an admin session
halo freeze on  --reason "INC0042: gateway latency"
halo freeze off --reason "INC0042 resolved"
```

Both are admin-only and audit-strict, and need a reason. The incident freeze covers every ring until it is lifted. It never disables an experiment: that is the kill switch, which stays available.

## What a freeze holds

| Action | During a freeze |
|---|---|
| Rollout controller advance | held, with the reason in the rollout status |
| `halo rollout advance`, MCP `propose_rollout_advance` | refused with the windows and the next open time; `--force` does not override |
| `halo exp promote`, MCP `propose_promotion` | refused; `--dry-run` shows the patch and the refusal |
| `halo rollout rollback`/`pause`, MCP `propose_rollback`, the kill switch | always allowed |

## Block merges during a freeze

A PR opened before a freeze can still be merged during one. Add `halo freeze check` as a required status check on the policy repo, ideally in the merge queue so it runs at merge time:

```yaml
on: [pull_request, merge_group]
jobs:
  change-freeze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # the base branch and its history
      - run: halo freeze check --event "$GITHUB_EVENT_PATH"
```

It exits non-zero while any ring (or `--ring`) is frozen. With `--event` (a `pull_request` or `merge_group` payload), the freeze windows come from the base branch (`origin/<base>`), never from the PR: a PR that deletes a window is still held by it. A rollback always passes, recognised from the diff, not the branch name. A change is a rollback only when every changed file is an existing policy YAML file, no document is added or removed, and each changed document differs only in:

- a Rollout `status` set to `paused` or `aborted`;
- an Experiment `status` set to `paused`;
- a Ring `release` set to a release that ring pointed at before on the base branch.

Anything else, comments aside, is a forward change. Locally, `--base origin/main` does the same against a ref. Without either flag, the check reads the local policy and exempts nothing. `--branch` is no longer accepted.

## Approve a rollout step

When an approval rule covers the rings a rollout's next step enters, the step needs its quorum before the controller (or `halo rollout advance`) moves it:

```sh
halo rollout approve claude-upgrade --ticket CHG0012345
```

- The approver must hold one of the rule's groups (IdP claims or the SCIM directory). Approvals are audit-strict and keyed by rollout, step and change: they never carry over.
- The person proposing an advance never counts toward its quorum, and nobody counts twice. With `distinctGroups`, each counted approval adds a group no other counted approval used.
- `halo rollout status` and MCP `rollout_status` show approvals, what is missing and any freeze. The advance PR body records the ticket and approvers.

Access requests covered by a rule need the ticket when filed. They stay pending (202) until the quorum is met, and the requester's own approval never counts.

## Preview the impact of a change

```sh
halo plan --diff main
halo plan --diff main --server "$HALO_SERVER"   # over the enrolled fleet
```

`--diff` loads the policy at that git ref, diffs the releases it builds, and resolves every member's ring, variants and effective settings under both policies, using the same hashing as the gateway and `halod`. The output counts users, devices and agents that change ring, variant or settings, then breaks them down by org unit, with examples.

Without `--server`, the population is an estimate: every user the policies name, one member of each named group, each workload subject, and a hashed sample of 1000 other users (shown as a percentage). Agents get the MCP `plan` tool with `diff_base`, which returns the same report.
