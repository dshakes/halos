---
title: "ADR-0011: Gateway-enforced device posture and CLI version"
description: The gateway refuses model calls from devices whose halod posture is stale, drifted or off-release, and from CLIs off the ring's pinned version, so stopping halod costs gateway access.
status: accepted
date: 2026-10-02
---

# ADR-0011: Gateway-enforced device posture and CLI version

- Status: accepted (extends ADR-0001 and ADR-0009)
- Date: 2026-10-02

## Context and problem statement

`halod` runs as root on laptops: it installs the pinned CLI, writes managed config, restores drift and reports to `halo-server`. Two limits were documented as "a local admin can defeat it":

1. A developer with root can stop `halod`, edit managed config, and keep using the models.
2. Codex, Gemini CLI and Copilot CLI have no self-enforced version pin. Only `halod` installs the pinned version, so a developer who installs another version keeps working.

Developers control their laptops but not the traffic path: every model call goes through `halo-proxy` or `halo-kong`. Moving these checks there makes the cost of defeating `halod` explicit.

## Decision drivers

- Enforce in the traffic path, which developers do not control.
- No new crypto and no new client credential: reuse the device token `halod` already holds and the gateway token gateways already use.
- Fail closed only on a verdict `halo-server` actually returned; an unreachable control plane must not take the fleet offline.
- Roll out safely: off, warn (log and count) and enforce per ring, default warn.
- Never guess a User-Agent format.

## Considered options

1. **Per-request device credential.** Each CLI sends a device header; the gateway verifies it. Needs a per-CLI custom-header mechanism (Gemini CLI has none), and the credential would sit in a file the developer can read, so it adds secret sprawl without stopping root.
2. **Device attestation (TPM / Secure Enclave).** Strong, but new crypto and per-OS work. Out of scope.
3. **Per-subject posture from halod reports (chosen).** `halo-server` already stores each enrolled device's latest report (authenticated with the device token). The gateway asks it whether the verified caller's devices are compliant.

## Decision outcome

Chosen: **option 3**, plus a User-Agent version gate.

**Posture.**

- `halo-server` serves `GET /api/v1/gateway/posture?subject=<id>` behind the gateway token (`--gateway-token-file`; rate-limited like the kill switch). The verdict is compliant when the subject has at least one enrolled device (not revoked, not expired) and **every** such device reported within `--posture-max-age` (default 45m, three `halod` intervals), with no drift, on its ring's current verified release or one of that release's experiment channels. Every device counts, so a healthy second machine cannot cover for one where `halod` was stopped. The release check is skipped when no registry is configured.
- `halo-proxy` (`posture.url`, `posture.tokenFile`) and `halo-kong` (`posture_url`, `posture_token`) ask for the verified subject on model calls of rings whose `posture` is warn or enforce. Verdicts are cached per subject (`cacheTTL`, default 1m).
- **Fail closed only on a server verdict.** If `halo-server` cannot be reached, the last verdict serves for `grace` (default 15m); after that the posture is *unknown* and the request passes, counted as `outcome="unknown"`. An anonymous caller (identity mode none or `allowAnonymous`) is also unknown.
- Enforce answers 403 in the caller's wire format with the reason and the fix: "Run `halod status` on this machine, make sure halod is running and has applied your ring's release, then retry."

**Version gate.**

- The gateway parses the CLI version from the User-Agent and compares it with the ring's pins: the ring profile's harness version plus the variant profiles of its running client-axis experiment (the gateway cannot tell which variant a device applied).
- A ring that pins no version for the detected harness passes. An unknown or missing User-Agent fails the gate under the ring's mode.

User-Agent formats, each from a recording or the CLI's source:

| CLI | Format | Source |
|---|---|---|
| Claude Code | `claude-cli/2.1.287 (external, sdk-cli)` (`cli` in interactive mode) | Recorded from Claude Code 2.1.287 against a capturing listener; [anthropics/claude-code#72879](https://github.com/anthropics/claude-code/issues/72879) |
| Codex | `codex_cli_rs/<version> (<os> <os version>; <arch>) <terminal>` | [`codex-rs/login/src/auth/default_client.rs`](https://github.com/openai/codex/blob/d04b0561d35487c84817491060d10f294c2c60a4/codex-rs/login/src/auth/default_client.rs) (`get_codex_user_agent`, originator `codex_cli_rs`) |
| Gemini CLI | `GeminiCLI/0.26.0/gemini-2.5-pro (darwin; x64)`; `GeminiCLI[-<client>]/<version>/<model> (<platform>; <arch>; <surface>)` | Recorded from Gemini CLI 0.26.0; [`packages/core/src/core/contentGenerator.ts`](https://github.com/google-gemini/gemini-cli/blob/62364cb2000795537a6895261b37ec668e4cf527/packages/core/src/core/contentGenerator.ts) |
| Copilot CLI | Not documented and not recorded | Copilot BYOK traffic does not reach `halo-proxy` today (no chat-completions route); its UA is treated as unknown |

The version is the token after the first `/`, up to a space, `/`, `(` or `;`, and must be semver.

**Policy.** `Ring.posture` and `Ring.versionGate`, each `off | warn | enforce`, default warn. Both apply only to model calls. Warn logs on the request line (`gates=`) and counts `halo_proxy_gate_total{gate,ring,outcome}`; `halo-kong` logs at NOTICE and sets `x-halo-gate` upstream (client copies are stripped with every other `x-halo-*`).

**Immutable flag.** Optional `immutable: true` in `halod.yaml` sets `chflags schg` (macOS) or `chattr +i` (Linux) on each managed file after the atomic write and clears it before a rewrite or removal. A missing tool or permission is logged once and ignored.

### Consequences

- Good: stopping `halod`, editing managed config, or running an unpinned CLI now costs gateway access in enforce mode. The limits in the security model change from "a local admin can defeat it" to "root can still stop halod, but then loses gateway access".
- Good: no new secrets on the device; the gateway token and device token already exist.
- Bad: posture is `halod`'s self-report, not hardware attestation. Root can read the device token and post forged reports with the right digest and no drift. Detecting that needs attestation (option 2).
- Bad: posture is per user, not per request: a user with a compliant laptop can use their identity from an unmanaged machine. Per-request device binding (option 1) would close it where the CLI can send a header.
- Bad: a User-Agent is client-controlled. The version gate catches stale or unmanaged installs, not a developer who forges the header.
- Neutral: enforcement lags. A stopped `halod` is noticed after `--posture-max-age` plus the cache TTL; a server outage is tolerated for `grace`, after which requests pass as unknown.
- Neutral: a retired laptop that was never revoked keeps its user non-compliant once its reports go stale. Revoke devices you retire.
