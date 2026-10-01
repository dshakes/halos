---
title: Roll out a Claude Code upgrade safely
description: Pin a new Claude Code version on a -next profile, diff it against what is published, simulate the rollout, and promote by PR.
---

This is the **client axis**: the upgrade changes what runs on developers' machines, so it goes through a signed release, an experiment and rings. You will bump a pin, plan the change against the published release, simulate the rollout under healthy and failing evidence, and see the promote patch. Commands were run against `examples/acme-corp` and a local registry.

**Prerequisites:** [Your first 10 minutes](/halos/tutorials/first-10-minutes/) (a built `halo`, `keys/dev.key`, a registry on `localhost:5055`).

## 1. Work in a copy and publish the baseline

```console
$ cp -r examples/acme-corp policy && cd policy && cp -r /tmp/acme-policy/keys keys
$ halo release publish --ring ring1-canary --release-version 2.1.300 \
    --registry localhost:5055/acme/halos --key keys/dev.key --plain-http --no-artifacts
…
Signing ring ring1-canary → version 2.1.300 (digest sha256:af9c3526…, seq …)
published localhost:5055/acme/halos tags v2.1.300, ring-ring1-canary (sha256:af9c3526…)
  channel experiment claude-cli-2.1.3xx-ab variant control: …
  channel experiment claude-cli-2.1.3xx-ab variant cli-next: …
```

`ring1-canary` runs the `engineering` profile (Claude Code 2.1.280). The running experiment `claude-cli-2.1.3xx-ab` adds two signed channels, one per variant.

## 2. Pin the new version on the -next profile

Edit `profiles/engineering-next.yaml` and change the Claude Code pin from `2.1.312` to `2.1.313`:

```console
$ grep -n version profiles/engineering-next.yaml
8:    version: 2.1.313
10:    version: 0.60.0
12:    version: 0.13.0
$ halo validate
OK: policy valid (0 warnings)
```

A client-axis variant is held to its ring profile: exact pins, nothing widened ([variant guardrails](/halos/concepts/experiments/#variant-guardrails)).

## 3. Plan against the published release

```console
$ halo plan --ring ring1-canary --against localhost:5055/acme/halos:v2.1.300 \
    --plain-http --pubkey keys/dev.pub --release-version 2.1.301
release version: 2.1.300 -> 2.1.301
…
version changes:
  claude-code: 2.1.280 (unchanged)
  codex: 0.58.0 (unchanged)
  gemini-cli: 0.12.0 (unchanged)
```

Control is untouched: only the release label changes. The new pin lives in the `cli-next` channel. To preview **promoting**, set `profile: engineering-next` in `rings/ring1-canary.yaml` and plan again:

```console
$ halo plan --ring ring1-canary --against localhost:5055/acme/halos:v2.1.300 \
    --plain-http --pubkey keys/dev.pub --release-version 2.1.301 --output json
{
  "changed": true,
  "versions": [
    "claude-code: 2.1.280 -> 2.1.313",
    "codex: 0.58.0 -> 0.60.0",
    "gemini-cli: 0.12.0 -> 0.13.0"
  ],
  …
```

The diff also moves `requiredMinimumVersion` and `requiredMaximumVersion` to `2.1.313`. Revert the ring edit; promotion is a PR.

## 4. Look at the rollout and simulate it

```console
$ halo rollout plan claude-code-2.1.300
Rollout claude-code-2.1.300  (client axis, draft)
…
  1  T+0      canary-1   canary       [#.........]   1%  1% of ring1-canary,ring2-early on treatment   2h    100    tool.error_rate<=10%, …
  2  T+2h     canary-5   canary       [#.........]   5%  …
…
Earliest completion: T+7d14h (sum of bakes; samples and approvals add time). Every step is a PR a human merges.
```

Simulate runs the real gate logic on synthetic evidence and writes nothing:

```console
$ halo rollout simulate claude-code-2.1.300 --scenario healthy
…
T+22h    canary-5   advance   all gates passed: propose step canary-25
…
Outcome: complete after 8d11h
$ halo rollout simulate claude-code-2.1.300 --scenario regression
…
T+16h  canary-5  rollback  guardrail:halo.tool.error_rate failed: +21.2% [+15.9%, +26.5%] (threshold regression <= 10.0%)

Outcome: rollback after 16h
```

Output is reproducible (`--seed`). The ring steps wait for a simulated human approval, so a healthy run takes 8 days.

## 5. Gate on evals

Run the eval suite with the candidate against the current pin before the first step ([Gate upgrades on evals](/halos/tutorials/gate-upgrades-on-evals/)). The rollout also has a scorecard gate at `canary-25`.

## 6. Start and promote by PR

`halo rollout advance` opens the PR for the next step; it never merges. A dry run prints the patch:

```console
$ halo rollout advance claude-code-2.1.300 --dry-run --reason "canary-1 healthy"
--- a/experiments/claude-cli-2.1.3xx-ab.yaml
…
-type: ab
+type: canary
…
-    weight: 50
+    weight: 99
…
-    weight: 50
+    weight: 1
…
+step: canary-1
-status: draft
+status: active
```

The 1% canary reshapes the experiment weights, and a human merges that change, then runs `halo release publish`. At the end, `halo exp promote` opens the PR that points the ring at the winning release. It needs ClickHouse evidence, so it is not run here.

## What just happened

- `halo plan` compared the release a ring would get against the signed one already published, per harness and OS, without publishing.
- The bumped pin only affects the `cli-next` channel; the ring release (control) is unchanged until a promote PR points the ring at `engineering-next`.
- `rollout simulate` ran the real controller state machine on synthetic evidence: healthy ends in completion, a regression ends in automatic rollback.
- Nothing merged or promoted by itself: every step is a PR, and rollback is the only automatic direction.

## Next

- [A/B a CLI upgrade](/halos/guides/cli-upgrade-ab/): the full device-side run with `halod`
- [Rollouts](/halos/concepts/rollouts/) and [rings and releases](/halos/concepts/rings-and-releases/)
- [Kill a bad change in 10 seconds](/halos/tutorials/kill-a-bad-change/)
