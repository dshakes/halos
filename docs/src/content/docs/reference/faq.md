---
title: FAQ
description: Common questions and honest answers.
---

## What is a policy repo?

A git repo of YAML documents (`Gateway`, `Profile`, `Ring`, plus optional `Experiment`, `Toggle`, `Rollout`) and a root `halos.yaml`. It is the single source of truth: Halos validates it, renders each harness's native config from it, signs the result as an immutable release, and points rings at releases. Start from an [example](/halos/examples/) or `halo init`, and read the [policy model](/halos/concepts/policy-model/).

## Do developers need to install anything?

Not by hand, in the usual setups. They keep using the vendor CLI. Config reaches the machine through a dev container Feature, a Coder or Codespaces prebuild, an MDM profile, or the `halod` agent that the [portal](/halos/concepts/self-service-portal/) enrolls. Developers do need a way to get a token for the gateway (an `apiKeyHelper` or equivalent that your IdP backs). See [delivery](/halos/concepts/delivery/).

## Which CLIs are supported?

Claude Code, Codex and Gemini CLI have adapters and are applied by `halod`. Copilot CLI is rendered by its adapter, but `halod` does not yet write its files, so use dev containers or MDM for it. `halo harnesses` prints the capability matrix, and an unsupported setting becomes a warning in the release manifest rather than being silently dropped. See the [harness matrix](/halos/reference/harness-matrix/).

## Does it proxy my code?

Only if you put a traffic plane in the path. `halo-proxy` (or the `halo-kong` plugin) is a gateway you run: model requests pass through it so it can verify identity, route, fail over and record metrics. It runs in your infrastructure; there is no Halos-hosted service that sees your prompts or code. Prompt logging is off unless a profile sets `telemetry.logPrompts`, and validation warns if you enable it on the default ring. `halo-shadow` mirrors single turns only when you configure a shadow experiment.

## What does it cost?

Halos is Apache-2.0 and free. You pay for what you already pay for (model usage) and for the small services you run: `halo-proxy` or `halo-kong`, optionally `halo-server`, a registry for releases, and a telemetry store such as ClickHouse if you want experiment analysis.

## Can I use it without the gateway?

Yes, for the config half. `halo render`, signed releases, rings, `halod` and MDM deliver pinned versions, permissions, MCP allowlists, hooks and telemetry settings with no traffic plane. What you lose is everything that needs one: traffic-axis experiments, weighted routes and failover, cohort derived from a verified token at request time, and shadowing. A direct-to-provider setup with client-side delivery is a legitimate starting point.

## Is it self-hosted only?

Yes. Everything runs where you run it, and the policy repo is yours. There is no hosted offering or vendor account to sign up for.

## How does rollback work?

Releases are immutable and content-addressed; a ring is a signed pointer to one. Rolling back means pointing the ring at an earlier release: `halo rollback --ring <R> --to <version>`. For traffic-axis changes the gateway reverts a cohort to control immediately, and a signed kill switch turns off experiments and [toggles](/halos/concepts/toggles/) without a release. Rollback is the only direction that can be automatic; promotion is always a PR a human merges.

## How is this different from managed settings?

Managed settings are a vendor's way to enforce configuration for that vendor's CLI. Halos writes them (for Claude Code it renders `managed-settings.json`) and adds what they do not: one policy across several CLIs, signed rings and rollback, pinned versions with drift reporting, experiments and eval-gated promotion. If one vendor's console covers your needs, use it. See the [comparison](/halos/reference/comparison/).

## What license is it under?

Apache-2.0, see `LICENSE` in the repo.

## Does this replace my LLM gateway?

No. `halo-proxy` runs in front of, behind or instead of Kong, LiteLLM, Envoy, nginx or AWS API Gateway (or as a Kong plugin, `halo-kong`). Gateways route and meter traffic; Halos adds cross-harness config releases, rings, sticky experiments, shadowing and eval-gated promotion. See [stack-agnostic](/halos/concepts/stack-agnostic/).

## Why not just use Claude Code server-managed settings?

They are not fetched with Bedrock or a custom `ANTHROPIC_BASE_URL`. If you use either, you need file, MDM or environment delivery. Halos also spans Codex and Gemini CLI.

## Do I need Kong Enterprise?

No. Kong OSS has no request-mirroring plugin and `ai-proxy-advanced` is Enterprise-only; `halo-shadow` and `halo-kong` cover that. Kong Enterprise and Konnect have not been tested (**UNVERIFIED**).

## Can I shadow a whole agent session?

No, by design. See [ADR-0004](/halos/adr/0004-shadow-single-turn-only/). Use replay evals for whole tasks.

## Can Halos auto-promote?

No. The controller may trip the kill switch on a rollback verdict (an instant return to control), but only when the evidence came through the authenticated gateway receiver and `halo-server` serves a kill list. It opens PRs, but promotion is a PR a human merges. It never merges anything.

## Does Codex support version pinning?

Not in the CLI. `halod` and the dev container Feature install the exact version (from a hash-verified artifact) and report drift; enforcement is Halos's. Claude Code enforces it itself via `requiredMinimumVersion` / `requiredMaximumVersion`.

## Will Halos ever set `bypassPermissions`?

Never. It is rejected by guardrails, the overrides allowlist, and a check on the rendered output.

## Can a user opt out of a ring?

A user can change local files but not their traffic cohort: the gateway derives it from the verified token. Rings marked `optIn` can be joined from the [portal](/halos/concepts/self-service-portal/) via an approved PR. Client policy on a laptop is best-effort; dev containers are stronger.

## What about OPA?

Default guardrails are Go ([ADR-0007](/halos/adr/0007-guardrails-in-go-not-opa/)); Rego can be added later for org-specific rules.

## What happens if the signing key or the registry is compromised?

A compromised registry cannot roll a ring back to an older signed release or serve a release for another ring: ring pointers are signed with a sequence number and expiry, and the signing commands refuse to re-sign a pointer older than the last one they wrote (the signer state file, plus `--expect-digest` in stateless CI). A compromised **key** is fleet-wide; rotate it ([production deployment](/halos/guides/production-deployment/)). See the [threat model](/halos/reference/threat-model/).

## What if nobody refreshes the pointers?

After 7 days `halod` refuses the ring and keeps the last good release. Run `halo release refresh` daily.

## `halo release refresh` says the pointer expired. How do I recover?

`refresh` will not re-sign an expired pointer, because it cannot tell a lapsed schedule from a replayed one. Pick the release you want the ring to serve and roll back to it: `halo rollback --ring <R> --to <version> --registry <repo> --key <key>`. `--to <version>` is checked against the version in the release's signed manifest. Then restore the daily refresh. See [pointer refresh](/halos/guides/production-deployment/#expired-pointers).

## The signer refuses with "replayed/rolled-back pointer refused" or "registry reset or tag deleted?"

The signer state file (`$XDG_STATE_HOME/halos/pointers.json`, or `--state-file`) says this signer already wrote a newer pointer than the registry now serves, or one the registry no longer has. That is the replay check working. If you did not reset the registry on purpose, treat it as a possible attack and investigate registry history first. If you did (for example a demo registry), restore or delete that ring's entry in the state file, or use a fresh `--state-file`, after confirming what the ring should serve. In CI, cache the state file between runs; a missing file is silently empty state, so an evicted cache means no replay check unless you pass `--expect-digest`.

## Why did a rollback fail with "registry retag refused"?

`halo rollback --to <version>` resolves tag `v<version>` and requires the release's signed manifest to carry that version. A mismatch means the tag points at a different release than the one published under that version. Use `--to sha256:<OCI manifest digest>` (the `manifest` field of `halo release publish --output json`) if you know exactly which release you want.

## Why did the controller not trip the kill switch on a rollback verdict?

Two common reasons, both visible in the notification and the webhook event's `killOutcome`: the deciding evidence was CLI-sourced (`not_gateway_evidence`; send `halo-proxy` telemetry to the gateway receiver), or `halo-server` has no `--killswitch-key-file` (`not_configured`: merge the pause PR urgently). An experiment that is already killed is not evaluated at all until someone unkills it. See [experiments](/halos/concepts/experiments/#the-controller-loop).

## Is it production ready?

It is `v1alpha1`: the components are built and unit-tested, but several integrations have never run against the real system (Kong Enterprise, Bedrock, MDM on real devices, PowerShell, Terraform, `halod` on Windows). Pages label those **UNVERIFIED**; believe those labels.
