---
title: Reliable upgrades
description: Watch upstream CLIs and models, verify their artifacts, run the eval gate, and open a PR only for candidates that are not worse.
---

Coding CLIs ship weekly and providers add models monthly. `halo upgrade` turns each new release into an **eval-gated pull request**. It never merges, never publishes a release and never retags a ring: a human merges every PR, and the normal [ring rollout](/halos/concepts/rings-and-releases/) takes it from there.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/upgrade-watch-light.svg" alt="halo upgrade watch finds a new CLI version on npm or a new model in a provider list, verifies the install artifacts, pins the candidate on a branch and runs the eval gate. Ship or hold opens a PR a human merges; block opens nothing." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/upgrade-watch-dark.svg" alt="halo upgrade watch finds a new CLI version on npm or a new model in a provider list, verifies the install artifacts, pins the candidate on a branch and runs the eval gate. Ship or hold opens a PR a human merges; block opens nothing." width="760" />

## What it does, per candidate

1. **Discover.** For CLIs, the npm `latest` dist-tag of each harness pinned in the watched profile (for example `@anthropic-ai/claude-code`). For models, each configured provider's model list, read through your gateway and filtered by `match` and `known`.
2. **Verify.** A CLI version must resolve to hash-pinned install artifacts (sha256 or npm integrity) through the same resolver `halo release build` uses. A version with no verified artifacts is reported but never pinned, because `halod` would refuse those bytes. It is retried on the next check.
3. **Pin on a branch.** One scalar edit: `harnesses.<h>.version` in the profile, or `models.<alias>.model` in the Gateway.
4. **Gate.** Run the [eval suite](/halos/concepts/evals/) with the candidate against the current pin as control.
5. **Decide.** On **ship** or **hold**, open a PR whose title and body carry the verdict, the diff, the artifact count and the full scorecard. On **block**, no PR is opened. Either way the outcome is recorded in the state file, so a candidate is handled once.

## Configure

The config lives in a dot-dir the policy loader skips. Paths are relative to the policy dir.

```yaml
# examples/acme-corp/.halos/upgrade.yaml
profile: engineering-next          # its harnesses.<name>.version pins are the candidates
suite: ../../evals/suites/upgrade-gate.yaml
harnesses: [claude-code, codex, gemini-cli]
models:
  - provider: orchestrator-openai
    url: https://ai.acme.example/v1/models
    api_key_env: HALO_EVAL_GATEWAY_TOKEN
    match: "^gpt-[0-9.]+-codex$"   # RE2; only these ids are worth evaluating
    known: [gpt-5-codex]           # already evaluated or deliberately skipped
    alias: codex-default           # the candidate edits models.codex-default.model
# base: main                       # PR base branch (default: repo default)
# state: .halos/upgrade-state.json # default
```

Point `profile` at the **-next** profile your canary ring uses. An upgrade then lands in ring1 first and reaches GA only through the normal promotion PR.

## Check once

```console
$ halo upgrade check --dry-run --policy-dir examples/acme-corp \
    --config stub-upgrade.yaml --npm-registry http://127.0.0.1:8765
KIND   TARGET                  FROM            TO              ARTIFACTS   GATE   PR / NOTE
cli    claude-code             2.1.312         2.1.330         UNVERIFIED  -      artifacts not verified: release: resolve claude-code@2.1.330 artifacts: GET https://downloads.claude.ai/claude-code-releases/2.1.330/manifest.json: status 404
cli    codex                   0.100.0         0.101.0         UNVERIFIED  -      artifacts not verified: release: resolve codex@0.101.0 artifacts: npm returned @openai/codex/0.101.0@0.101.0, want @openai/codex@0.101.0
cli    gemini-cli              0.35.0          0.36.0          UNVERIFIED  -      artifacts not verified: release: resolve gemini-cli@0.36.0 artifacts: npm returned @google/gemini-cli/0.36.0@0.36.0, want @google/gemini-cli@0.36.0
model  orchestrator-openai/codex-default  gpt-5-codex     gpt-5.5-codex   -           -      dry run
```

This output came from the example repo run against a local stub npm registry and model list (`stub-upgrade.yaml` is the example config with the model URL pointed at the stub). The stub npm registry answers `2.1.330` for claude-code, `0.101.0` for codex and `0.36.0` for gemini-cli, and the stub model list returns `gpt-5-codex`, `gpt-5.5-codex` and `gpt-4o`, so only `gpt-5.5-codex` passes `match`. The output is pasted unedited. The artifacts are unverified because the stub serves no tarballs. In a real run, a CLI row shows its verified artifact count, and without `--dry-run` the GATE column fills in with the PR URL or `blocked by the eval gate; no PR`.

## Run it continuously

```console
$ halo upgrade watch --every 6h --policy-dir .
```

Run it in CI on a schedule, or as a long-running job with `gh` authenticated: PRs are opened through the GitHub CLI. Flags: `--config` (default `<policy-dir>/.halos/upgrade.yaml`), `--npm-registry` (a mirror), `--parallel` (eval trials), `--local` (evals on the host, testing only).

## Why this is safe to automate

- **Bytes before verdicts.** Nothing is evaluated or pinned unless its install artifacts verify against a hash.
- **Statistically honest gate.** Paired per-task comparison with CIs, flaky tasks excluded, and grader errors force **hold**: see [evals](/halos/concepts/evals/).
- **Humans own the irreversible steps.** The watcher writes a branch and a PR. Merging changes policy only; releases, ring pointers and promotion stay with the release flow.

Related: [CLI upgrade A/B](/halos/guides/cli-upgrade-ab/), [model upgrade canary](/halos/guides/model-upgrade-canary/).
