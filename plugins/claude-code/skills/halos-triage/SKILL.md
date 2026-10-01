---
name: halos-triage
description: Diagnose an experiment whose guardrail is failing or whose canary looks unhealthy, and propose a rollback. Use when asked why an experiment is red, or to roll one back.
---

# Triage a failing experiment

1. `show_experiment` for the definition (variants, guardrails, rings, stopping rule).
2. `analyze_experiment` for the verdict, per-arm sample sizes, effect and guardrail results. Identify exactly which metric regressed, in which variant, by how much, and whether n is large enough to trust it. If ClickHouse is not configured, say so and ask the human for the data instead of guessing.
3. Use `whoami` with a few known users to confirm who is enrolled, and `render_preview` on the ring to see the config the treatment actually receives. Look for the setting that plausibly explains the regression.
4. Write a diagnosis: symptom, evidence, likely cause, confidence.
5. If rollback is warranted, call `propose_rollback` with `dry_run: true`, pass the last known-good release digest if the ring was already re-pointed, and show the diff with a one-paragraph `reason`.
6. **STOP: wait for human confirmation** before `dry_run: false`. The commit lands on a local branch. Retagging the registry ring back (`halo rollback`) and merging are human actions; give the human the exact command but do not run it.
