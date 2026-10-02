---
title: "ADR-0010: Release channels for client-axis experiments"
description: A client-axis variant is a signed release on its own channel; halod picks the variant with the gateway's hash and never falls back to control silently.
status: accepted
date: 2026-09-30
---

# ADR-0010: Release channels for client-axis experiments

- Status: accepted (extends ADR-0008)
- Date: 2026-09-30

## Context and problem statement

ADR-0003 put experiments on the traffic plane first. Client-axis experiments (for example a CLI upgrade A/B) were declared in policy but could not be delivered: a ring had one signed pointer to one release, so every device in the ring got the same profile.

A client-axis variant changes what runs on the machine, so it must travel through the path ADR-0008 built (signed pointer, signed release, anti-rollback, expiry) and not through a new, weaker one. It also has to agree with the gateway: a request from a treatment device must be attributed to the same variant `halod` applied.

## Decision drivers

- Every byte a device applies stays under the existing signature checks; no unsigned side channel.
- Device and gateway compute the same variant without talking to each other.
- A verification failure must never silently move a treatment device to control (that would corrupt the experiment and hide an attack).
- An older `halod` and the ring's own release keep working unchanged.
- The variant must not be able to grant more than the ring's profile.

## Considered options

1. **One pointer per device.** Publish a release per user. Does not scale and leaks cohort structure into the registry.
2. **Server-side assignment.** `halo-server` tells `halod` which release to pull. The decision is then not covered by the release signature and needs the server in the trust path.
3. **Channels.** Publish one signed release per variant, each behind its own signed pointer, and list them in the signed ring manifest; `halod` assigns itself.

## Decision outcome

Option 3.

- **Channel.** Variant `V` of client-axis experiment `E` on ring `R` is served on channel `R.x-E.V`, published as tags `v<ver>-x-E.V`, `ring-R.x-E.V` and `ring-R.x-E.V.pointer`. A channel pointer is an ordinary ring pointer whose `ring` field is the channel name, so it is bound to org and channel, carries `seq` and a 7-day expiry, and has its own anti-rollback mark in `halod` state. Names longer than 100 characters use `R.x-<first 20 hex of sha256(E NUL V)>`; OCI tags are limited to 128 characters.
- **Manifest.** The ring release manifest gains an `experiments` section (name, salt, per-variant weight and channel), covered by the release signature. `halod` recomputes each channel name and refuses a mismatch.
- **Assignment.** `halod` evaluates `policy.Experiment.ResolveVariant`, the gateway's function, over the signed salt and weights. Subject sources, in order: the ring endpoint's `subject` (halo-server returns the bound user id), `subject:` in `halod.yaml` (MDM-templated), the last saved subject. No subject means the ring release and `no_subject_for_experiment`; `halod` never guesses.
- **Failure.** A channel that fails verification fails the cycle and keeps last-good. There is no fallback to the ring release.
- **Publish order and scope.** `halo release publish` pushes variants first, then the ring. `refresh` and `rollback` move the ring and its channels together. Cross-ring `promote` moves only the ring pointer. A variant release is refused on any channel but its own.
- **Guardrails.** Variant profiles are checked against the ring profile as **errors**: exact version pins, telemetry on, `disableBypass`, no widening, no MCP changes, no weaker sandbox, `managedOnly` or `enforce`, no more permissive `permissions.mode`, hooks a subset of the ring's, `telemetry.otlpEndpoint` and `logPrompts` equal, `models.allowed` a subset, `instructions` and `env` equal. At most one running client-axis experiment per ring, since a device applies one release. Channel names must be unique.
- **Attribution.** The variant release sets `halo.experiment` and `halo.variant` in Claude Code's `OTEL_RESOURCE_ATTRIBUTES`; other harnesses warn. The gateway attributes a request to a client-axis experiment only when no traffic-axis experiment applies.

## Consequences

- Good: no new trust root; the registry and signing keys are the same as for rings.
- Good: device and gateway agree on the variant by construction, and an older `halod` ignores the `experiments` section and stays on control.
- Good: `refresh` and `rollback` need no new steps.
- Bad: each variant is a full release, so publishing costs one build per variant and registry storage grows with variants.
- Bad: channel pointers expire like ring pointers; a missed `refresh` stops treatment devices (they keep last-good), not just control.
- Bad: a halod that cannot verify a channel stays on its previous release, so a broken publish strands treatment devices until fixed. That is the intended trade against silent contamination.
- Limit: the signed kill list reaches client-axis devices only where `halod` has `killSwitch` configured (portal enrollment sets it when `halo-server` has a kill key; see ADR-0009); otherwise a device reverts on pause and republish.
- Limit: only Claude Code carries experiment attribution in CLI metrics.

## More information

- Concepts: [client-axis delivery](/halos/concepts/experiments/#client-axis-delivery), [experiment channels](/halos/concepts/rings-and-releases/#experiment-channels)
- Walkthrough: [A/B a CLI upgrade](/halos/guides/cli-upgrade-ab/)
- Code: `internal/policy/channel.go`, `internal/policy/guardrails.go` (`guardClientVariants`), `internal/release/channels.go`, `internal/bundle/channels.go`, `cmd/halod/agent.go` (`selectVariant`), `internal/gateway/decision.go`
- Test: `test/e2e/experiment_test.go`

## Addendum 2026-10-02: every harness carries attribution

"Other harnesses warn" and the limit "only Claude Code carries experiment attribution in CLI metrics" are superseded. Codex, Gemini CLI and Copilot CLI have no resource-attribute config key, so the variant release ships a `/etc/profile.d` shell function (`hutil.OTELShellWrapper`) that runs the CLI with the release's `OTEL_RESOURCE_ATTRIBUTES`, including `halo.experiment` and `halo.variant`. It covers login shells and their bash children; an exec that bypasses the shell (`timeout`, `env`, `xargs`) runs unlabeled, which the gateway-side attribution still covers for traffic.

## Implementation status (2026-10-02)

| Commitment | Code | Test | Status |
|---|---|---|---|
| Channel `R.x-E.V`; tags `v<ver>-x-E.V`, `ring-R.x-E.V`, `ring-R.x-E.V.pointer`; long names hashed to fit 128-char tags | `internal/policy/channel.go` (`ChannelName`); `internal/bundle/channels.go` | `policy` `TestChannelName` (length, collision); `bundle` `TestChannelBindingRefusals` | Done |
| Channel pointer is an ordinary ring pointer bound to org and channel, with `seq`, 7-day expiry and its own anti-rollback mark in `halod` | `internal/bundle/pointer.go`; `cmd/halod/agent.go` state `Pointers[channel]` | `cmd/halod` `TestExperimentApplyLifecycle` ("replayed channel pointer refused", "signed by another key refused") | Done |
| Signed `experiments` section in the ring manifest; `halod` recomputes channel names and refuses a mismatch | `internal/release/channels.go` (`BuildRing`); `cmd/halod/agent.go` (`selectVariant`) | `release` `TestBuildRingClientExperiment`; `cmd/halod` `TestVariantSelectionMatchesGateway` | Done |
| Assignment via `policy.Experiment.ResolveVariant` (the gateway's function); subject from ring endpoint, then `halod.yaml`, then last saved; no subject means ring release and `no_subject_for_experiment` | `cmd/halod/agent.go` (`selectVariant`, `subject`); `internal/policy/resolve.go` | `TestVariantSelectionMatchesGateway`; `TestExperimentApplyLifecycle` ("unknown subject stays on the ring release"); `TestRingEndpoint` | Done |
| A channel that fails verification fails the cycle and keeps last-good; no fallback to the ring release | `cmd/halod/agent.go` (`cycle`) | `TestExperimentApplyLifecycle` (refusals keep the previous release) | Done |
| Publish variants first, then the ring; `refresh` and `rollback` move ring and channels together; cross-ring `promote` moves only the ring; a variant is refused on any channel but its own | `internal/bundle/channels.go` (`PublishRing`, `RefreshRing`, `PromoteRing`; rollback is `PromoteRing` with a `Source` version or digest) | `bundle` `TestPublishPromoteRefreshRing`, `TestChannelBindingRefusals` | Done |
| Variant guardrails as errors (pins, telemetry, `disableBypass`, no widening, no MCP changes, no weaker sandbox, managed/enforce kept, mode, hooks subset, OTLP and `logPrompts` equal, models subset, instructions and env equal); one running client-axis experiment per ring; unique channel names | `internal/policy/guardrails.go` (`guardClientVariants`, `variantProfileIssues`) | `policy` `TestClientVariantGuardrails`, `TestClientExperimentsAndBaseline` | Done |
| Attribution: `halo.experiment` / `halo.variant` in `OTEL_RESOURCE_ATTRIBUTES`; gateway attributes to a client-axis experiment only when no traffic-axis experiment applies | `internal/harness/hutil/hutil.go` (`OTELResourceAttributes`, `OTELShellWrapper`); every adapter; `internal/gateway/decision.go` | `claudecode` `TestGolden`; `gateway` `TestDecideClientAxisAttribution`; `test/uat` `TestCLIs` | Done (all harnesses, see addendum) |
| Older `halod` ignores `experiments` and stays on control | the section is additive in the manifest | `release` `TestBuildRingClientExperiment` | Done |
| Kill list reaches client-axis devices where `halod` has `killSwitch` | `cmd/halod/agent.go`, `config.go` | `cmd/halod` `TestKillSwitchRevertsClientExperiment` | Done (opt-in, see ADR-0009 addendum) |
| End-to-end | `test/e2e/experiment_test.go` `TestClientAxisExperiment` | `make e2e` | Done |
