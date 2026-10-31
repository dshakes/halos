---
title: "halo test"
description: "Test a policy change offline in seconds: validate, render, release, invariants, impact, policy tests, rollouts"
---

Test a policy change offline in seconds: validate, render, release, invariants, impact, policy tests, rollouts

The fast, credential-free confidence signal before `halo eval run` (Docker, provider keys, minutes) and
experiments (hours). Nothing here touches the network or a credential. It runs:

  validate    the policy loads and validates (as `halo validate`)
  render      every ring x harness x OS renders through the adapters; adapter warnings are surfaced
  release     each ring's release builds into a temp dir, its manifest is consistent and a rebuild
              reproduces the digest
  invariants  no bypassPermissions, danger-full-access or other permission-bypass token in any
              rendered file or manifest (AGENTS.md invariant 1)
  impact      with --against REF: who changes ring, variant or settings against the policy at REF,
              failing when more than --max-impact percent of the sampled users of all users or of any
              ring change (a policy-only estimate, as `halo plan --diff` without a server)
  cases       the PolicyTest documents under tests/ (schemas/policytest.schema.json): given an identity,
              expect its ring, experiment variants and rendered setting values per harness
  rollout     every rollout is simulated on healthy evidence and must complete

Remote (git, oci) supply-chain artifacts need the network: rings that use them are skipped here and
covered by `halo release build`.

Exit codes: 0 every check passed (skips do not fail), 1 the run could not happen (no policy repo,
unknown ring, unreadable --against ref, bad flag), 2 one or more checks failed.
-o json is for agents (it carries next_steps), -o junit for CI test reports.

## Usage

```console
halo test [flags]
```

## Flags

| Flag | Shorthand | Type | Default | Description |
|---|---|---|---|---|
| `--against` |  | string |  | git ref of the policy to compare with (e.g. main): adds the impact check |
| `--max-impact` |  | float64 | 25 | impact check: fail when more than this percent (0-100) of the sampled users of all users or of any ring change |
| `--output` | `-o` | string | text | output format: text\|json\|junit |
| `--policy-dir` |  | string |  | policy repo directory (default ".") |
| `--release-version` |  | string | 0.0.0-dev | release version label the test builds use |
| `--ring` |  | string |  | limit the render, release and invariant checks to this ring (default: every ring) |
| `--strict` |  | bool | false | fail on warnings too: policy validation warnings and adapter warnings in the release manifest |

## Examples

```console
halo test --policy-dir examples/acme-corp
  halo test --policy-dir examples/acme-corp --against main --max-impact 10
  halo test --strict -o junit > halo-test.xml
```

## Parent

[`halo`](/halos/reference/cli/)
