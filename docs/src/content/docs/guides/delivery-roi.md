---
title: Delivery ROI
description: Measure what a model, CLI or policy change did to delivery (PR cycle time, throughput, review rounds, change failures, cost per merged PR), causally, from the experiment's own random assignment.
---

Halos assigns each developer to an experiment variant at random (`internal/assign`). `halo roi` joins pull-request outcomes to those arms, so the difference between arms is the effect of the change itself, not of who chose to use it. Dashboards that compare users with non-users cannot make that claim. The design is in [ADR-0027](/halos/adr/0027-randomized-roi/).

ROI is informational. A promotion verdict never reads it. It appears in the promotion PR for the human who merges.

## 1. A roster

The roster maps SCM logins to Halos subjects, with the IdP groups that ring membership uses:

```csv
login,subject,groups,kind
alice-gh,alice@acme.com,eng;ai-platform,
bob,bob@acme.com,eng,
release-bot,ci@acme.com,,workload
```

Halos recomputes each developer's ring and variant from this file and the policy, exactly as the gateway and `halod` served them. Wrong groups give wrong arms. `kind: workload` excludes CI and bot identities. Authors missing from the roster are listed in every report and left out.

## 2. Ingest outcomes

GitHub, read-only (one fixed GraphQL query; the token needs read access to pull requests):

```sh
export HALO_GITHUB_TOKEN=...   # never a flag
halo roi ingest github --repo acme/api --repo acme/web --since 2026-09-01 \
  --clickhouse http://clickhouse:8123 --database halo
```

Any other SCM or tracker, from a CSV or JSONL export with these columns: `repo,number,author|subject,opened_at,merged_at,review_rounds,additions,deletions,change_failure[,bot,source]`.

```sh
halo roi ingest file gitlab-mrs.csv --clickhouse http://clickhouse:8123 --database halo
```

Without ClickHouse, use `--store prs.jsonl` in place of `--clickhouse`. Re-run the ingest over the window before reporting: later reverts and merges update the earlier rows.

What is stored: author login, open and merge times, review rounds (change requests plus one once reviewed), lines changed, and the change-failure proxy (the PR was reverted, or referenced by a merged `hotfix`-labelled PR). Titles, bodies and diffs are not stored.

## 3. Report

```sh
halo roi report --experiment claude-cli-2.1.3xx-ab --identities roster.csv \
  --clickhouse http://clickhouse:8123 --database halo
```

```text
claude-cli-2.1.3xx-ab: randomized, status ok
  Randomized: internal/assign hashed each developer in rings ring1-canary, ring2-early into a variant ...
  SRM: chi2 0.31 p 0.578 mismatch false

ARM       DEVELOPERS  ACTIVE  PRS   MERGED  COST/MERGED PR
control   212         198     1630  1544    $3.12 (gateway)
cli-next  207         195     1702  1611    $3.40 (gateway)

METRIC                   ARM       control  ARM VALUE  DIFF [95% CI]          REL     STATE
pr_cycle_time_hours      cli-next  21.4     18.9       -2.5 [-4.1, -0.9]      -11.7%  significant, improved
merged_prs_per_dev_week  cli-next  1.21     1.30       +0.09 [-0.04, +0.22]   +7.4%   insufficient_power
...
```

- **States.** `significant` means the 95% CI excludes zero. `no_detectable_effect` means the CI includes zero and the study could have detected a change of `--mde` (default 10%). `insufficient_power` means it could not, so say "we don't know yet", not "no effect". `insufficient_data` means fewer than `--min-developers` per arm.
- **SRM.** If active developers per arm don't match the variant weights (p < 0.001), the status is `srm`. Find the cause (roster groups, ingest gaps, the treatment driving people away) before using any number.
- **Novelty.** Each metric is re-estimated in `--slices` time slices. `novelty` means the first and last slices disagree, and the last one is the better long-run estimate.
- **Cost per merged PR** needs ClickHouse with `halo.cost.usd` rows. It is a per-arm ratio with no CI.

`--since` defaults to the experiment's first telemetry. Give it explicitly with `--store`.

### Rings are observational

```sh
halo roi report --rings ring3-ga,ring1-canary --identities roster.csv --store prs.jsonl --since 2026-09-01
```

Ring membership is chosen (explicit users, groups, opt-in, rollout order), so a ring comparison reports `kind: association` and a "Difference", never an effect. For a causal answer, run an experiment over the rings.

## 4. In the promotion PR

```sh
halo exp promote claude-cli-2.1.3xx-ab --ring ring2-early --release sha256:... \
  --clickhouse http://clickhouse:8123 --roi-identities roster.csv
```

This adds a `Delivery ROI (randomized, informational)` section above the patch. If ROI cannot be computed, `halo` prints a warning and opens the PR without the section.

## Agents

`halo mcp serve --roi-identities roster.csv [--roi-store prs.jsonl] [--clickhouse URL]` enables the read-only `roi_report` tool and adds the section to `propose_promotion` PRs. The roster and store are server flags, never tool arguments. `next_steps` tells the agent when it must say "association" or "insufficient power" instead of quoting an effect.

## Limits

- The estimate is intent-to-treat: it measures being assigned the variant, not using it.
- Arms are recomputed from the current policy. Keep ring membership and weights unchanged during the window.
- The change-failure proxy misses incidents fixed without a revert or a labelled hotfix.
- Live GitHub and ClickHouse were not exercised in CI (httptest fakes only).
