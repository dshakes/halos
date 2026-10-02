---
title: Security model
description: Trust boundaries, signed releases and ring pointers, signer continuity, evidence trust, the signed kill switch, audit chain, verified installs, root-side hardening, identity, guardrails, and honest limits.
---

The full asset list, attacker models and per-control mapping are in the [threat model](/halos/reference/threat-model/). This page is the design.

## Trust boundaries

<img class="diagram dark:sl-hidden" src="/halos/diagrams/security-boundaries-light.svg" alt="Untrusted clients and networks; the gateway boundary that verifies OIDC JWTs, strips x-halo headers and fails closed on the model allowlist; a supply chain where a CI or HSM key signs releases into an OCI registry; halod as root verifying pointer and release before writing managed config; and halo-server issuing device tokens and a kill list signed with a separate key." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/security-boundaries-dark.svg" alt="Untrusted clients and networks; the gateway boundary that verifies OIDC JWTs, strips x-halo headers and fails closed on the model allowlist; a supply chain where a CI or HSM key signs releases into an OCI registry; halod as root verifying pointer and release before writing managed config; and halo-server issuing device tokens and a kill list signed with a separate key." width="760" />

| Boundary | Threat | Control |
|---|---|---|
| Registry to `halod` | Tampered release; replay of an older signed release; frozen registry; release built for another org or ring | Signed ring pointer `{org, ring, digest, seq, expiry}`; release signature; ([ADR-0005](/halos/adr/0005-signed-oci-bundles/), [ADR-0008](/halos/adr/0008-signed-ring-pointers-and-verified-artifacts/)) |
| Vendor download to `halod` | Compromised or swapped CLI binary; install script run as root | Hash-pinned artifacts from the signed manifest; no `curl \| bash`; npm `--ignore-scripts` |
| Manifest to root filesystem | Signing key alone writing arbitrary files as root | Per-harness path allowlist, 0644 mode ceiling, root-ownership and symlink checks |
| Client to gateway | Client claims a ring, variant or identity; unknown or batch model endpoints; other models | OIDC JWT verified at the gateway; every inbound `x-halo-*` stripped; fail-closed model allowlist |
| Policy to harness | Dangerous permission modes, non-allowlisted overrides, secrets in bundles | Go guardrails at validate and again at release, plus a rendered-output backstop |
| Workspace to internet | Exfiltration by agent | Egress firewall to `egress.allowedDomains` plus the harness sandbox |
| Laptop enrollment | Stolen or replayed enrollment token | Single-use, short TTL, stored only as SHA-256; device token stored only as SHA-256 and revocable |
| Shadow store | Prompt leakage; shadow token aiming replays at arbitrary URLs | Upstreams resolved from policy; AES-256-GCM at rest; retention; budget |
| Signer to registry | A registry serving an old signed pointer that `refresh` or `promote` would re-sign into a fresh one | Signer state file, promote from the source ring's signed pointer, expired pointers refused ([below](#signer-continuity)) |
| Developer machines to the collector | Forged metrics that trip, promote or hide an experiment | Up to three receivers (CLI, gateway, optional eval); only the authenticated gateway receiver may drive a kill ([below](#evidence-trust)) |
| `halo-server` to gateway | Forged, stale or replayed kill list; a stolen release key forging kills; an attacker on the path un-killing an experiment | Kill list signed with a dedicated ed25519 key; gateway token; freshness and strictly-newer checks ([below](#kill-switch)) |
| Console and API to privileged actions | Silent or rewritten history of who killed, revoked or changed what | Hash-chained audit log ([below](#audit-log)) |
| `halo-proxy` to Bedrock | Client credentials reaching AWS; unsigned requests | Client auth stripped, request SigV4-signed with the gateway's own AWS identity; no credentials means 502, never unsigned ([below](#bedrock-credentials)) |

## Signing

Releases are OCI artifacts signed with ed25519. The primary signer must be ed25519 because `halod` verifies only ed25519 and never shells out to cosign as root. cosign (key, KMS URI or keyless) can be added as a co-signature (`--cosign-key`, `--cosign-keyless`); keyless uploads the release digest to the public Rekor transparency log.

Protect the signing key: anyone who can sign can ship hooks to every developer. Use a CI-only or KMS-backed key, and require PR review on ring changes. See [production deployment](/halos/guides/production-deployment/) for rotation.

### Signed ring pointers (TUF-lite)

A ring tag alone is unauthenticated: whoever controls the registry could retag it to an older signed release or one built for another ring. So each ring has a separately signed pointer with `org`, `ring`, `digest`, `seq`, `issuedAt` and `expiresAt`. `halod` trusts the pointer, checks the fields against its config, refuses a lower `seq` than it last applied, refuses an expired pointer (7-day TTL), and only then fetches the release the pointer names by content digest, never by a mutable tag.

Consequences: a compromised registry cannot roll a ring back to an older signed release, cannot serve a release for another org or ring, and cannot freeze clients indefinitely without them noticing (they stop updating and warn after 7 days). Rollback is a new pointer with a higher `seq`. **Pointers must be refreshed on a schedule** (`halo release refresh`, daily) or every client stops updating after seven days; `halod` warns when fewer than 24 hours remain.

This is not full TUF: there is no root key rotation protocol, threshold signing or delegated roles. A key compromise is handled by rotating the key in every `halod` config (see [production deployment](/halos/guides/production-deployment/)).

### Signer continuity

`halod` checks pointers it reads. The signer needs the same discipline, because a registry can serve an old but validly signed pointer, and a signer that refreshes "what the registry serves" would re-issue it with a higher `seq` and a fresh expiry. The release commands close that:

- **Promote follows the source ring's signed pointer.** `halo release promote --from-ring A --to-ring B` reads A's signed pointer (signature, ring, org, expiry, continuity), fetches the release it names and checks its digest against the pointer. The `ring-A` tag, which is unauthenticated, is never used as the source.
- **Rollback needs a matching version.** `halo rollback --to <version>` resolves tag `v<version>` and refuses the release unless its **signed manifest** carries that version, so a retagged `v` tag cannot redirect it. `--to sha256:<manifest digest>` is the OCI manifest digest and is content-addressed.
- **Refresh refuses expired pointers.** An expired pointer cannot be told apart from a replayed one. Recover explicitly with `halo rollback --to <version>`.
- **Signer state file.** The last pointer written per registry repo and ring (`seq`, `digest`, `issuedAt`) is kept in `$XDG_STATE_HOME/halos/pointers.json` (`--state-file`). A served pointer with a lower `seq`, the same `seq` and another digest, or no pointer where one was written is refused. New `seq = max(served + 1, recorded + 1, unix now)`.
- **`--expect-digest sha256:<release digest>`** on `refresh`, `promote` and `rollback` refuses unless the release involved is exactly that one: the check that works without state.
- **Every signature is announced.** Before signing, the CLI prints `Signing ring X → version V (digest D, seq S)` to stderr.

Limit: **stateless CI has no state file**, and a signer with no record for a ring refuses to re-sign a pointer the registry already serves unless you confirm it with `--expect-digest` (the served release digest) or `--adopt-existing` (use it only on a first run or after a cache eviction: it trusts what the registry serves, so that run has no replay protection). Cache `pointers.json` between runs ([production deployment](/halos/guides/production-deployment/#replay-protection-the-signer-state-file)). The file has one writer; an unparseable file blocks signing rather than disabling the check.

## Evidence trust

Experiments decide rollouts, so telemetry is an attack surface. Developer machines must reach the collector, so the CLI receiver is client-controlled. The collector (`halo telemetry collector-config`) therefore has two receivers by default, plus an optional third: the CLI receiver (4317/4318) drops every `halo.gateway.*` metric, stamps `halo.source=cli`, caps requests at 4 MiB and can require per-device bearer tokens (`--cli-token-file`); the gateway receiver (4319) requires `HALO_OTLP_GATEWAY_TOKEN`, which `halo-proxy` presents (`--telemetry-token-file`), and stamps `halo.source=gateway`. The optional eval receiver (`--eval-receiver`, 4320) accepts only `halo.eval.*` metrics, stamps `halo.source=eval` and requires its own token, `HALO_OTLP_EVAL_TOKEN` (never the gateway token), so `halo eval online` can publish without gateway credentials; nothing auto-kills on eval-sourced rows. Analysis trusts gateway rows only with that stamp, and the controller **auto-kills only on gateway-sourced evidence**; a CLI-sourced rollback still opens the pause PR and notifies. Units are `HMAC(salt, verified subject)`, so a client cannot choose or inflate its own unit. Details: [evidence plane](/halos/concepts/evidence-plane/#evidence-trust).

## Kill switch

The kill switch lets `halo-server` (the controller on a rollback verdict, or an admin) switch an experiment off at the gateways in seconds. Because it can change live routing without a merge, it has its own trust chain:

- **Separate key.** The kill list is signed with its own ed25519 key (`halo keys generate --name killswitch`, private half in `halo-server --killswitch-key-file`). It is **not** the release key. A stolen kill key can kill experiments (routing everyone to control) but cannot sign a release or a ring pointer; a stolen release key cannot forge a kill list. The signature covers a domain prefix (`halo-killswitch-v1\n`) plus the payload, so it cannot be confused with any other signature.
- **Gateway token.** Gateways fetch the list with a bearer token (`--gateway-token-file`, at least 16 characters), compared in constant time, with failed attempts rate-limited per client IP. The endpoint returns 404 unless both the key and the token are configured. The token gates who can read the list, the signature gates what a gateway believes.
- **Freshness.** A list is rejected if its `issuedAt` is more than 10 minutes old or more than 1 minute in the future.
- **Replay.** A list is accepted only if its `issuedAt` is strictly newer than the list the gateway already holds, so replaying an older envelope cannot undo a kill.
- **Fail toward keeping kills.** If the fetch or verification fails, the gateway keeps the last accepted list. If it never accepted one, it kills nothing and the policy snapshot decides. Kills do not expire.
- **Admin actions are audited, fail-closed.** Kill and unkill (by an admin, or by the controller as `halo-controller`) write `experiment.kill` and `experiment.unkill` (`toggle.kill` and `toggle.unkill` for feature toggles) audit entries with the reason ([audit log](#audit-log)). A kill needs a reason (HTTP 422 without one).
- **No key, no kill.** Without `--killswitch-key-file` (which requires `--data-dir` and `--gateway-token-file`) the server serves no list, answers 501 to kill and unkill, and `GET /api/v1/capabilities` reports `killSwitch: false`. The in-process controller then does not pretend: it reports the rollback as not enforced and asks humans to merge the pause PR urgently.
- **The controller holds killed experiments.** A running experiment that is already killed is not evaluated (its evidence is all control); humans are told once to unkill before resuming.
- **TLS for the token.** Gateways refuse plain `http://` to a non-loopback kill URL, since the bearer token would travel in the clear, unless `killSwitch.allowInsecureInCluster` (`halo-kong`: `killswitch_allow_insecure_in_cluster`) is set for a trusted in-cluster URL. A misconfigured `halo-kong` still serves traffic but logs at ERROR and adds `x-halo-killswitch: misconfigured` to the upstream request.
- **Notification webhooks are signed and timestamped.** The controller's generic webhook carries `X-Halo-Timestamp` and `X-Halo-Signature: sha256=<hex>`, an HMAC-SHA256 over `timestamp + "." + body` under a shared secret. Receivers must verify it and reject timestamps more than 5 minutes off, which stops replay of a captured request ([snippets](/halos/reference/binaries/#verifying-the-webhook-signature)). Delivery is retried per channel on later ticks. Slack uses its own incoming-webhook URL, which is itself a secret.

Limits: a kill affects gateways (routing and mirroring). It reaches client-axis variants on machines only where `halod` has `killSwitch` configured (portal enrollment sets it when `halo-server` has a kill key); otherwise those revert on pause and republish ([details](/halos/concepts/experiments/#limits-the-client-axis)). If `halo-server` is down when a kill is issued, nothing is killed until it is back. Decision record: [ADR-0009](/halos/adr/0009-signed-kill-switch/).

## Audit log

Privileged actions (login, logout, device enroll and revoke, session revoke, access-request decisions, experiment status PRs, kill and unkill) append to `audit.jsonl` in `--data-dir`. Each entry carries `seq`, `prev` (the previous entry's hash) and its own `hash` over every other field. `GET /api/v1/audit` re-reads the file, verifies the whole chain and returns `verified` plus a `head` hash. Editing, reordering or removing any entry except the newest breaks the chain from that point on, and the console shows it.

Appends are fsynced before the action is acknowledged, and **privileged actions fail closed**: kill and unkill, device enrollment, session and device revocation and experiment-status PRs return HTTP 500 if the append fails. A kill whose audit append fails stays applied (fail safe), a failed unkill is reverted, and a revocation stays in force; the audit gap is what the error reports. `halo controller run` appends through the same chain, so it is a **single writer**: never run it against a data dir a live `halo-server` is writing.

**Limit: tail truncation is undetectable.** Dropping the newest entries leaves a chain that still verifies. To detect it, record `head` (and `total`) somewhere the server's writer cannot rewrite, for example a periodic copy into your SIEM, and compare later. The log is also only as trustworthy as the host's file permissions: someone who can rewrite the file can recompute every hash. Without `--data-dir` the log lives in memory and is lost on restart.

## Bedrock credentials

For `kind: bedrock` upstreams `halo-proxy` signs with SigV4 using **its own** AWS identity (the AWS SDK default chain: env, SSO profile, EKS IRSA or Pod Identity, ECS task role, EC2 instance profile). The caller's `Authorization`, `x-api-key` and **every** client `x-amz*` / `x-amzn*` header are always dropped, even with `forwardAuth: true`, so only gateway-set headers enter the signature. Signing happens only for AWS endpoint hosts (suffix `.amazonaws.com`, `.amazonaws.com.cn` or `.api.aws`) or hosts listed in `signHosts`; a `kind: bedrock` upstream with a region on any other host gets a 502 `bad_upstream` rather than the gateway's signature. No credentials means a 502 `upstream_auth_error`; nothing is forwarded unsigned. The role should grant only `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` on the models in policy. Setup: [stack-agnostic](/halos/concepts/stack-agnostic/#direct-bedrock-sigv4-in-halo-proxy).

## Verified installs

The release manifest carries, per harness, OS and architecture, an https URL with an exact size and a sha256 (binary) or sha512 integrity (npm tarball). `halod` refuses artifacts that do not match. The old install path (`installCommand`: `curl | bash`, `npm install -g` running lifecycle scripts as root) is disabled unless `allowShellInstall: true`, which logs a warning on every use. An artifact cannot replace `halod` itself.

## Gateway gates

Two per-ring policies enforce in the traffic path, which developers do not control ([ADR-0011](/halos/adr/0011-gateway-enforced-posture-and-version/); details in [delivery](/halos/concepts/delivery/#gateway-gates)):

- **`posture`.** The gateway asks `halo-server` (`GET /api/v1/gateway/posture`, gateway token, rate-limited) whether every enrolled device of the verified caller reported recently, without drift, on its ring's release. Reports are authenticated with the device token `halod` already holds; no new credential or crypto. It fails closed only on a verdict the server returned: an unreachable server leaves the last verdict in force for a grace window, then the request passes and is counted as unknown. An anonymous caller is unknown too.
- **`versionGate`.** The gateway parses the CLI version from the User-Agent and refuses one the ring does not pin. An unknown or missing User-Agent follows the same mode.

Both default to `warn` (log and count). In `enforce` they answer 403 with the reason and the fix (`halod status`). Neither reads a client `x-halo-*` header; `halo-kong`'s `x-halo-gate` upstream tag is stripped from the client first like every other `x-halo-*`.

## Root-side hardening in `halod`

`halod` runs as root and applies configuration delivered over the network, so it treats the signing key as *necessary but not sufficient*:

- **Path allowlist.** Files may be written only under each harness's admin config directories (see [delivery](/halos/concepts/delivery/)). `..`, relative paths, backslashes on unix and alternate-stream characters on Windows are refused. Stale-file removal uses the same allowlist.
- **Mode ceiling.** A manifest entry with a mode above 0644 is refused.
- **Ownership preflight.** Before it starts, `halod` verifies the config, public key, device-token file and state file, and every ancestor directory, are owned by root (or SYSTEM/Administrators on Windows), not writable by group or other, and contain no symlink planted by a non-root user. The device-token file must be mode 0600. On Windows only the owner SID is checked, not the DACL, so harden the directory.
- **Atomic apply.** Temp file, fsync, rename. On any failure before verification nothing on disk changes, and the last good release stays.
- **Bounds.** Release size (default 256 MiB), artifact size and https-only redirects are capped. A failed ring lookup falls back to the last known ring, never to "no ring".

## Identity at the gateway

The gateway verifies the caller's OIDC JWT against the IdP's discovery document and JWKS (cached, refetched on an unknown `kid`): `iss`, `aud`, `exp`, `nbf`, and an algorithm limited to RS256, ES256 or EdDSA (`none` and `HS*` are rejected). The ring, experiment and variant are derived from the verified user and groups. Failed verification returns 401 unless `allowAnonymous` is set, in which case the caller gets default routing and ring `unknown`, never an experiment.

`trusted_header` mode exists for gateways that authenticate for you. It honors the identity headers only when the TCP peer is inside `trustedProxyCIDRs`; with no CIDRs it fails closed with 503. Never use it without the CIDR pin, and only if the gateway overwrites the header and clients cannot reach `halo-proxy` directly.

## Header spoofing

Clients can send any header. The gateway deletes every inbound `x-halo-*` (and the configured identity and groups headers once the subject is derived), then computes and sets the stamps. See [gateway headers](/halos/reference/gateway-headers/). This is exercised in the compose demo: a request claiming `x-halo-ring: ring3-ga` reaches the upstream with the ring derived from the token.

## Model allowlist fails closed

Only exact model-call paths are accepted (`/v1/messages`, `/v1/messages/count_tokens`, `/v1/responses`, Bedrock `/model/{id}/invoke*` and `converse*`). Any other path under those prefixes is 404, `/v1/messages/batches*` is 400, oversize or unreadable bodies are 413, and a model that is not a policy alias is 400 (`invalid_request_error`) with an error body in the caller's wire format. Nothing rejected is forwarded, and a rewrite failure is never forwarded un-rewritten.

## Guardrails

Default guardrails are Go code ([ADR-0007](/halos/adr/0007-guardrails-in-go-not-opa/)) run by `halo validate` and again at release build: no `bypassPermissions`, `disableBypass` required on every ring, reserved non-allowlisted override keys, reserved env prefixes, literal-secret detection, strict names. The release build then parses the rendered files and rejects `bypassPermissions` or `danger-full-access` in any value, as a backstop for adapter bugs and for `overrides`, which are merged after rendering. See [policy model](/halos/concepts/policy-model/#guardrails).

## What Halos will not do

- Emit `bypassPermissions` or `danger-full-access`, including via `overrides` (overrides are an allowlist).
- Auto-promote a release, auto-merge a PR, or push to your main branch. The MCP server has no publish, retag, merge or push tool.
- Execute a shadow candidate's tool calls.
- Merge or auto-promote from the controller: it only opens PRs. Its one automatic action that changes live traffic is the kill switch, which only ever reverts to control.

## Limits

- Harness enforcement is only as strong as the harness. Where the [matrix](/halos/reference/harness-matrix/) says `halod` enforces, root can still stop `halod` or edit its files; on rings with `posture: enforce` that device then loses gateway access, and `versionGate: enforce` refuses CLIs off the pin ([gateway gates](#gateway-gates)).
- Posture is `halod`'s own report, not hardware attestation: root can read the device token and post a forged clean report. Posture is checked per user, not per request, so a user with a compliant laptop can use their credential from an unmanaged machine. The User-Agent is client-controlled: the version gate catches stale and unmanaged installs, not a forged header.
- The signing key is a single point of trust. There is no threshold signing. The kill-switch key is a second, narrower one.
- The audit log is tamper-evident, not tamper-proof, and tail truncation is undetectable on its own (see [Audit log](#audit-log)).
- The enrollment bootstrap (`curl -fsSL <server>/enroll.sh | sh -s -- <token>`) is itself a piped script whose integrity rests on TLS to your server. It pins the `halod` binary by sha256 and refuses to install without a pinned checksum.
- Shadow is single-turn only ([ADR-0004](/halos/adr/0004-shadow-single-turn-only/)).
- The `halo-kong` Go plugin runs as a separate process; treat its socket as part of the trust boundary.
- **UNVERIFIED:** the above was tested with unit tests and the compose demo, not against a real fleet, a real Kong Enterprise, real AWS Bedrock, or a third-party penetration test.

Report vulnerabilities via the repository's `SECURITY.md`.
