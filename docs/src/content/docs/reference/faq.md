---
title: FAQ
description: Common questions and honest answers.
---

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
