---
title: "Policy reference"
description: "Every policy file kind and field, generated from the JSON Schemas."
---

Generated from `schemas/*.schema.json`; do not edit. Regenerate with `make docs-gen`.

| Kind | Description |
|---|---|
| [`experiment`](/halos/reference/policy/experiment/) | An A/B, canary or shadow experiment with sticky per-user assignment. |
| [`gateway`](/halos/reference/policy/gateway/) | How harness traffic reaches models: public URL, auth, model aliases and upstreams. |
| [`halos`](/halos/reference/policy/halos/) | The policy repo root document (halos.yaml). The simple-mode keys (tools, provider, models, gateway, telemetry, team, safety, rollout) expand into the Gateway, the default Profile and the Rings; see `halo explain`. |
| [`policytest`](/halos/reference/policy/policytest/) | A suite of policy test cases for `halo test`: given an identity, the ring, experiment variants and rendered setting values the policy must produce. Lives under tests/ in the policy repo; the loader does not read it as policy. |
| [`profile`](/halos/reference/policy/profile/) | Desired harness behaviour, independent of any one CLI. Supports inheritance via extends. |
| [`ring`](/halos/reference/policy/ring/) | An ordered rollout cohort pointing at a profile. |
| [`rollout`](/halos/reference/policy/rollout/) | A phased rollout of one change: ordered steps with a ring, percent, bake, gates and a failure action. Advancing only opens a PR; rollback and pause are automatic. |
| [`toggle`](/halos/reference/policy/toggle/) | A feature toggle: one capability turned on for a targeted cohort and killable fleet-wide at the next kill-list poll, without a new release. |
| [`unit`](/halos/reference/policy/unit/) | A business unit or team in the org hierarchy (ADR-0018): delegated owners, a member selector and an overlay applied on top of the ring profile. Enforced security fields may only be tightened. |
