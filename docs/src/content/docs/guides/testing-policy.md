---
title: Testing a policy change
description: halo test, the offline tier — validate, render, release, invariants, impact, policy test cases and rollout simulation in seconds, with no credentials.
---

A policy change has four confidence tiers. Run them cheapest first:

| Tier | Command | Needs | Time |
|---|---|---|---|
| Offline | `halo test` | nothing | seconds |
| Replay evals | `halo eval run` | Docker, provider keys | minutes, costs money |
| Shadow | gateway shadow mirror | a gateway | hours |
| Experiment | ring1 experiment | a fleet | days |

`halo test` never touches the network or a credential, so it belongs in the editor loop and in every pull request.

```sh
halo test --policy-dir examples/acme-corp
halo test --policy-dir . --against main          # also: who does this change reach?
halo test --strict -o junit > halo-test.xml      # CI: fail on warnings, JUnit report
```

## What it checks

| Check | What it asserts |
|---|---|
| `validate` | The policy loads and validates, as `halo validate`. |
| `render` | Every ring renders for every enabled harness on darwin, linux and windows through the adapters. Adapter warnings are listed; `--strict` fails on them. |
| `release` | Each ring's release builds into a temp dir, its manifest matches the ring, profile and blobs, and a second build gives the same digest. |
| `invariants` | No `bypassPermissions`, `danger-full-access` or other permission-bypass token in any rendered file, toggle fragment, cloud agent file or manifest (invariant 1). |
| `impact` | With `--against REF`: who changes ring, variant or settings versus the policy at `REF`. Fails when more than `--max-impact` percent (default 25) of the sampled users of all users, or of any ring, change. It is the policy-only estimate of `halo plan --diff`. |
| `cases` | The `PolicyTest` documents under `tests/` (below). |
| `rollout` | Every rollout is simulated on healthy synthetic evidence and must complete. For a failing run use `halo rollout simulate <name> --scenario regression`; the acme-corp example has three runnable rollouts, e.g. `halo rollout simulate claude-code-2.1.300 --policy-dir examples/acme-corp`. |

Rings whose profiles use remote (git or oci) supply-chain artifacts are skipped, not failed: fetching them needs the network and is covered by `halo release build`.

## Policy test cases

Put `PolicyTest` documents (schema: `schemas/policytest.schema.json`) in `tests/`. The loader ignores that directory as policy. Each case gives an identity and what it must get:

```yaml
apiVersion: halos.dev/v1
kind: PolicyTest
name: ring-placement
cases:
  - name: ai-platform group is ring0
    identity: {user: pat@acme.example, groups: [ai-platform]}
    expect:
      ring: ring0-harness-team
      variants: {opus-5-5-canary: ""}     # "" = not enrolled
      settings:
        claude-code:
          permissions.disableBypassPermissionsMode: disable
          sandbox.enabled: true
          somekey: null                     # null = must be absent
```

`settings` are dotted key paths into the JSON or TOML a device in that cohort receives (`os:` picks darwin, linux or windows; default linux). A user in a client-axis experiment variant is checked against the variant's release. Unit overlays and toggles are not applied. Ring and variant assignment use the same functions as `halo whoami`.

## Output and exit codes

`-o text` (default) prints PASS, FAIL or SKIP per check with the reasons and `next steps`; `-o json` is for agents and carries `next_steps`; `-o junit` is for CI test reports. Exit `0`: every check passed (skips do not fail). Exit `2`: a check failed. Exit `1`: the run could not happen (no policy repo, unknown ring, unreadable `--against` ref, bad flag).

Agents call the read-only MCP tool `policy_test` with the same options.

## In CI

```yaml
- run: halo test --policy-dir . --against origin/main --strict -o junit > halo-test.xml
```

`halo test` does not replace the human gates: it cannot approve, publish or promote.
