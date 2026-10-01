---
title: Rings and releases
description: Immutable releases, signed ring pointers with sequence and expiry, membership, the promotion lifecycle and rollback.
---

## Release

A **release** is an immutable, content-addressed OCI artifact containing:

- pinned CLI versions per harness, each with verified install artifacts (URL, size, sha256 or npm sha512 integrity) resolved at build time,
- rendered per-harness files for each target OS (managed settings, requirements, system settings, managed MCP config, managed instructions), each with its sha256 and mode,
- warnings for anything an adapter could not enforce,
- the org name.

It is identified by digest and signed with ed25519 ([ADR-0005](/halos/adr/0005-signed-oci-bundles/)); cosign can be added as a co-signature. `halo release publish` tags it `v<version>` and `ring-<ring>` for humans, but consumers never trust tags.

## Ring pointer

A ring is served by a **signed pointer**, stored as its own OCI artifact under the tag `ring-<name>.pointer`:

```json
{"org":"acme-corp","ring":"ring1-canary","digest":"sha256:...","manifest":"sha256:...","manifestSize":1234,
 "seq":1790784827,"issuedAt":"2026-09-30T16:13:47Z","expiresAt":"2026-10-07T16:13:47Z"}
```

`halod` trusts the pointer, never the ring tag. Before it fetches anything it verifies the signature (domain-separated from release signatures) and then checks:

| Check | Refuses |
|---|---|
| `org` equals the org in `halod.yaml` | a release built for another org |
| `ring` equals the ring `halod` follows | a pointer copied from another ring |
| `seq` is not lower than the last applied `seq` for that ring | replay of an older pointer (freshness) |
| `expiresAt` is in the future | a frozen or stale registry |
| the release signature over the digest it names | a tampered release |

`seq` is `max(served + 1, recorded + 1, unix time)`: `served` is the pointer the registry currently serves and `recorded` the last one this signer wrote (see [signer continuity](#signer-continuity)), so a replayed old pointer cannot make the signer reuse a number. `halod` stores the last applied `{seq, digest}` per ring in its state file.

### Pointers expire after 7 days

If nobody re-signs a pointer, `halod` refuses the ring after seven days and keeps the last good release. Run `halo release refresh` on a schedule well inside that window, for example daily. `halod` logs a warning when a pointer has less than 24 hours left.

```bash
halo release refresh --ring ring1-canary --registry ghcr.io/acme/halos --key halo.key
```

`.github/workflows/refresh-pointers.yml.example` is a ready-to-copy scheduled workflow. See [production deployment](/halos/guides/production-deployment/#pointer-refresh).

`refresh` refuses an **expired** pointer: it cannot tell a lapsed schedule from a replayed pointer, and re-signing it would launder a replay into a fresh one. To recover a ring whose pointer expired, point it at a release you choose: `halo rollback --ring <R> --to <version>`.

### Signer continuity

`halod` validates what it reads; the signing commands validate what they write. `publish`, `promote`, `refresh` and `rollback` keep a **signer state file** (`$XDG_STATE_HOME/halos/pointers.json`, else `~/.local/state/halos/pointers.json`; `--state-file` overrides) with the last pointer written per registry repo and ring. They refuse a registry that serves a lower `seq`, the same `seq` with a different digest, or no pointer where this signer wrote one. In CI, cache the file between runs or pass `--expect-digest sha256:<release digest>` to `refresh`/`promote`; a fresh runner without either has no replay protection.

Every signature is announced on stderr first, which is the line to read in a CI log:

```text
Signing ring ring1-canary → version 1.4.2 (digest sha256:..., seq 1790784827)
```

Design: [ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/#addendum-2026-09-30-signer-side-continuity).

## Ring

A **ring** is an ordered cohort that points at a profile (`Ring.profile`) and, once published, at a release.

<img class="diagram dark:sl-hidden" src="/halos/diagrams/rings-light.svg" alt="ring0 is the harness team by IdP group, ring1 a 5 percent hash, ring2 25 percent, ring3 the GA default; the bar under each ring shows its share of the fleet." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/rings-dark.svg" alt="ring0 is the harness team by IdP group, ring1 a 5 percent hash, ring2 25 percent, ring3 the GA default; the bar under each ring shows its share of the fleet." width="760" />

### Membership

1. `users` and IdP `groups` are always in the ring (users checked first).
2. Remaining users are hashed: `hash(user, salt) % 10000` falls into a ring by cumulative `percent`. Basis-point precision, deterministic, and computed by one Go package shared by `halod`, `halo-proxy`, `halo-kong` and `halo-shadow`.
3. The ring with `default: true` catches everyone else.
4. `optIn: true` lets a developer request the ring from the [portal](/halos/concepts/self-service-portal/); approval opens a PR.

## Experiment channels

When a running [client-axis experiment](/halos/concepts/experiments/#client-axis-delivery) enrolls a ring, `halo release publish --ring <R> --release-version <V>` writes more than the ring release:

| Written | Tags |
|---|---|
| Ring release | `v<V>`, `ring-<R>`, pointer `ring-<R>.pointer` |
| One variant release per variant | `v<V>-x-<exp>.<variant>`, `ring-<R>.x-<exp>.<variant>`, pointer `ring-<R>.x-<exp>.<variant>.pointer` |

Variants are pushed first and the ring last, so no device sees a ring manifest that names an unpublished channel. A channel name longer than 100 characters uses a sha256 fallback (`<R>.x-<hash20>`); see [experiments](/halos/concepts/experiments/#client-axis-delivery).

- **A channel pointer is a ring pointer** whose `ring` field is the channel name: same signature, org binding, `seq` and 7-day expiry. `halod` keeps a separate `{seq, digest}` mark per channel, so anti-rollback applies to each.
- **A variant release is only served on its own channel.** Pointing any other ring or channel at it is refused.
- **`refresh` and `rollback` include channels automatically.** `refresh` re-signs the ring pointer and the pointer of every channel the ring's current release names. `rollback --to <version>` moves the ring and each channel to the variant releases published with that version (each with a higher `seq`). Nothing extra to run.
- **Cross-ring `promote` moves only the ring pointer.** `halo release promote --from-ring A --to-ring B` points B at the release A's **signed pointer** names (not the `ring-A` tag, which is unauthenticated). That release was built for A, so B's devices ignore its `experiments` section and get control; B's channels are not created. To run the experiment in B, enroll B in the experiment and publish B.

## Lifecycle

<img class="diagram dark:sl-hidden" src="/halos/diagrams/release-lifecycle-light.svg" alt="A release moves from draft to eval-gated on publish, to ring0 when evals pass, ring1 when guardrails hold, ring2 when the canary passes and GA when the PR is merged. From any stage it can be rolled back, which re-points the ring at the last good release." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/release-lifecycle-dark.svg" alt="A release moves from draft to eval-gated on publish, to ring0 when evals pass, ring1 when guardrails hold, ring2 when the canary passes and GA when the PR is merged. From any stage it can be rolled back, which re-points the ring at the last good release." width="760" />

| Transition | Who decides |
|---|---|
| draft to eval-gated | `halo release publish` (guardrails, render, sign, push) |
| eval-gated to ring0 | Eval scorecard passes the gate you set in CI |
| ring N to ring N+1 | `halo exp analyze` gives a `promote` verdict; `halo exp promote` opens a PR; **a human merges**; a human or CI then runs `halo release promote` |
| any to rolled-back | Human, or automatic on guardrail breach |

Automatic promotion is never allowed. Automatic rollback is.

## Rollback

Rollback signs a **new** pointer with a higher `seq` that names an older release, so clients that refuse to go backwards still follow it.

```bash
halo rollback --ring ring1-canary --to 1.0.0                 # release version
halo rollback --ring ring1-canary --to sha256:...            # or OCI manifest digest
```

`--to <version>` resolves tag `v<version>` and is refused unless the release's **signed manifest** carries that version, so a retagged `v` tag cannot redirect a rollback. `--to sha256:...` is the OCI **manifest** digest (the `manifest` field of `halo release publish --output json`), content-addressed; it is not the release digest that `publish` prints and `--expect-digest` takes. Rollback also works on a ring whose pointer has expired.

`--registry`, `--key` and (for a local registry) `--plain-http` are required as for `publish`. If the ring runs a client-axis experiment, its [channels](#experiment-channels) roll back with it. Dev containers pick it up on rebuild; `halod` on its next pull (default every 15 minutes). Traffic-axis changes roll back at the gateway immediately: pause or conclude the experiment (`halo exp pause`, `halo exp conclude`) and let the policy reload.

## Sample timeline

<img class="diagram dark:sl-hidden" src="/halos/diagrams/cli-rollout-timeline-light.svg" alt="Example CLI upgrade: eval scorecard for 2 days, ring0 harness team for 3 days, ring1 canary 5 percent for 5 days, ring2 25 percent for 5 days, then the GA PR is merged." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/cli-rollout-timeline-dark.svg" alt="Example CLI upgrade: eval scorecard for 2 days, ring0 harness team for 3 days, ring1 canary 5 percent for 5 days, ring2 25 percent for 5 days, then the GA PR is merged." width="760" />
