---
title: "ADR-0027: Randomized delivery ROI"
description: Halos already randomizes who gets a policy change. Joining pull-request outcomes to those arms gives causal delivery effects (cycle time, throughput, review rounds, change failures, cost per merged PR) with developer-clustered CIs, an SRM check and novelty slices. Ring comparisons are labelled observational. It is informational and never promotes.
status: accepted
date: 2026-10-27
---

# ADR-0027: Randomized delivery ROI

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

Every AI coding tool sells a productivity number. DORA dashboards and vendor ROI tabs (for example Copilot's) compare developers who use the tool with developers who do not, or this quarter with last quarter. Both comparisons are observational: heavy users differ from light users, and quarters differ in everything. They cannot separate the tool from who chose it.

Halos is the one place in the stack that assigns the change at random. `internal/assign` hashes each developer into an experiment variant (ADR-0003), so the arms differ only by chance and by the variant. Joining delivery outcomes to those arms answers the question the dashboards cannot: what did this policy change do to delivery?

What should Halos ingest, how should it estimate, and what may it claim?

## Decision drivers

- Claim causality only where assignment was random. Say so in the output, not only in the docs.
- Invariant 3: arms come from `internal/assign`, never a second hash.
- Invariant 5: ROI informs a human. It never promotes, and a promotion verdict never reads it.
- Read-only on the SCM: one fixed query, a token from the environment, no titles or bodies stored.
- Honest nulls: "no effect" only when the study could have seen one. Otherwise say "insufficient power".
- Stdlib statistics, reusing `internal/stats`.

## Considered options

1. **Join outcomes to experiment arms recovered from assignment; label ring comparisons observational.** Chosen.
2. **Take each developer's arm from telemetry (`halo_metrics.variant` per `unit_id`).** Rejected: gateway units are an HMAC of the subject under a secret salt (`halo.unit`), and CLI `user.id` values are vendor-specific. Neither maps to an SCM login without new secrets or guesswork. The served arm is a pure function of policy and subject, so recomputing it is exact.
3. **Treat hash-placed ring members as randomized.** Rejected for now. Percent rings are hash slices, but ring sizes change during a rollout, explicit users, groups and opt-in mix in, and exposure time differs by ring. That breaks the comparison more often than it helps. Ring comparisons stay observational.
4. **Regression with covariates (CUPED on a pre-period).** Deferred. It adds a pre-period ingest and a model for a variance gain. Developer-clustered bootstrap first.

## Decision outcome

### Ingest (`halo roi ingest`)

One record per pull/merge request: `source, repo, number, author (login), subject (optional), bot, opened_at, merged_at, review_rounds, additions, deletions, change_failure`.

- **GitHub** (`halo roi ingest github --repo o/r --since D`): one GraphQL query, newest first, paging until `createdAt < since` (500-page bound). The token comes only from the variable named by `--token-env` (default `HALO_GITHUB_TOKEN`) and goes only into `Authorization`. It is scrubbed from every error. Only https is allowed, or http to a loopback host (`vendoradmin.CheckBaseURL`). Redirects are never followed. Review rounds are change requests plus one once a PR is reviewed. The change-failure proxy is set when a merged PR is reverted (GitHub's revert body `Reverts o/r#N`) or referenced (`#N`) by a merged PR with the `--hotfix-label` label (default `hotfix`). Titles and bodies are read for those references and then dropped. Bot authors (`__typename = Bot`) and deleted accounts are kept but flagged, and never counted.
- **Generic** (`halo roi ingest file x.csv|x.jsonl`): the same fields, for GitLab, Bitbucket, Gerrit or a Jira export. Unknown columns or keys are errors, so a `title` column cannot slip in.
- **Storage.** ClickHouse table `halo_delivery_prs` (`deploy/observability/clickhouse/schema.sql`) is a `ReplacingMergeTree(ingested_at)` keyed by `(source, repo, number)` and read with `FINAL`. Re-ingesting a window refreshes late merges and reverts. `--store FILE.jsonl` is the same with a local file, for tests and teams without ClickHouse.

### Identity

A roster CSV `login,subject[,groups][,kind]` maps SCM logins to Halos subjects (`policy.Subject`): subjects are canonicalised with `policy.CanonicalUser`, logins compare case-insensitively, one login cannot map to two subjects, and `kind: workload` excludes CI and bot identities. Groups must be the IdP groups ring membership uses, because the arm is recomputed from them. Authors missing from the roster are counted, listed (the first 20) and left out. They are never guessed. The roster is also the denominator for throughput, so a developer who merged nothing counts as zero.

### Arms

- **Experiment (randomized).** `policy.ResolveRing(subject)`, then `Experiment.AssignVariant(subject, ring)`, which is `ResolveVariant` without the status check. It recovers the arm of a paused or concluded experiment exactly as it was served (`TestArmMatchesServedVariant`). Developers outside the enrolled rings are excluded. The estimate is intent-to-treat: assignment, not usage. The claim reads: causal effect of being assigned the variant for developers in the experiment's rings, and nowhere else.
- **Rings (observational).** `--rings a,b` compares ring members, with the first ring as the baseline. Every effect is `kind: association`, the table says "Difference", and the claim says these are not effects of the ring's release.

The arm is computed from the policy at analysis time. If ring membership or experiment weights changed during the window, the recovered arms differ from those served. Keep policy changes out of an experiment's window, as stopping rules already require.

### Estimation

The window is `[since, until)`. `since` defaults to the experiment's first telemetry in ClickHouse. Only PRs opened in the window count, so pre-period work never enters, and a PR is merged when it merged before `until`.

| Metric | Per developer (numerator / denominator) | Better |
|---|---|---|
| `pr_cycle_time_hours` | sum of merge minus open hours / merged PRs | decrease |
| `merged_prs_per_dev_week` | merged PRs / window weeks (every rostered developer) | increase |
| `review_rounds_per_pr` | review rounds / merged PRs | decrease |
| `change_failure_rate` | change failures / merged PRs | decrease |
| `lines_changed_per_pr` | additions + deletions / merged PRs | descriptive |

The arm value is the ratio of sums. The difference uses `stats.ClusterBootstrapDiff`, a new two-arm percentile bootstrap that resamples whole developers within each arm. A developer's PRs are correlated, so PR-level resampling would understate the variance. It reports the absolute and relative difference with 95% CIs (2000 resamples, fixed seed).

States per metric:

- `significant`: the CI excludes 0 beyond float tolerance. `improved` or `worsened` comes from the metric's direction.
- `no_detectable_effect`: the CI includes 0 and the relative minimum detectable effect, `(z(1-alpha/2) + z(0.8)) * SE / |control|`, is at most `--mde` (default 10%).
- `insufficient_power`: the CI includes 0 and the study could not have detected `--mde`.
- `insufficient_data`: fewer than `--min-developers` (default 10) per arm.

**SRM.** `stats.SRM` is a chi-square goodness-of-fit test of active developers (at least one PR) per variant against the configured weights, at alpha 0.001. A mismatch means developers were gained or lost unevenly: roster groups, ingest gaps, or attrition caused by the treatment. The report status is then `srm` and the warning says not to trust the effects.

**Novelty.** The window is split into `--slices` (default 3) and every metric is re-estimated per slice. If the first and last slices' relative CIs do not overlap, the metric is flagged `novelty`, with a warning that the last slice is the better long-run estimate. The test is relative because the last slice is right-censored (recent PRs have not merged) in both arms alike. Non-overlap is conservative: on synthetic data with a constant effect, about 1 false flag in 80.

**Cost per merged PR.** When ClickHouse is configured, AI spend is `sum(halo.cost.usd)` per variant (or per ring) over the window. Rows from the gateway receiver win. Otherwise CLI rows are used and labelled `cli` (client-reported). Cost per merged PR is arm spend divided by arm merged PRs. Spend units are hashed or vendor ids that do not join to SCM logins, so this ratio is per arm and has no CI. The report says so.

### Surfaces

- `halo roi report --experiment X | --rings a,b --identities roster.csv` prints a text table, or the full report with `--output json`.
- MCP `roi_report` is read-only. The roster and store are server flags (`halo mcp serve --roi-identities F [--roi-store F]`), never tool arguments. Without them the tool answers `configured: false` with the human's command. `next_steps` covers SRM, missing roster entries and the observational label.
- Promotion PRs: `halo exp promote --roi-identities F` and MCP `propose_promotion` (when configured) add a `### Delivery ROI (<design>, informational)` section above the patch. It is computed after the verdict and never read by it. A failure to compute it is a warning, and the PR goes out without the section.

## Consequences

- Good: Halos can report the causal delivery effect of a model, CLI or policy change on the developers who got it, with CIs and an honest null. Observational tools cannot.
- Good: no new hashing, no new secret and no write scope on the SCM. The experiment's own assignment is the identification strategy.
- Bad: the roster is a second identity source to maintain. Unmapped authors are visible in every report, but they still have to be fixed by hand.
- Bad: delivery metrics are slow and noisy. Most two-week canaries will report `insufficient_power` for throughput. That is the honest answer. Use longer windows or larger rings when delivery is the question.
- Bad: the change-failure proxy (reverts and hotfix references) misses incidents fixed without a revert or a labelled hotfix. It is a proxy and is named one.
- Neutral: no live GitHub or ClickHouse was called in building this. The GraphQL fields (`changesRequested: reviews(states: [CHANGES_REQUESTED])`, `author { __typename login }`) follow the public schema, and the httptest fakes encode those shapes. The table DDL and the `FINAL` reads were not run against a live server: UNVERIFIED until `make obs-e2e` covers them.

## More information

`internal/roi`, `internal/stats/srm.go`, `internal/stats/bootstrap.go` (`ClusterBootstrapDiff`), `cmd/halo/cmd_roi.go`, `internal/mcpserver/tools_roi.go`; [Delivery ROI guide](/halos/guides/delivery-roi/).
