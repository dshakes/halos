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
| [`profile`](/halos/reference/policy/profile/) | Desired harness behaviour, independent of any one CLI. Supports inheritance via extends. |
| [`ring`](/halos/reference/policy/ring/) | An ordered rollout cohort pointing at a profile. |
| [`rollout`](/halos/reference/policy/rollout/) | A phased rollout of one change: ordered steps with a ring, percent, bake, gates and a failure action. Advancing only opens a PR; rollback and pause are automatic. |
| [`toggle`](/halos/reference/policy/toggle/) | A feature toggle: one capability turned on for a targeted cohort and killable instantly without a new release. |
