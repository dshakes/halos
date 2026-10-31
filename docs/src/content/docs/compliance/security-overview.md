---
title: Security overview for buyers
description: "Answers a security team can lift into a SIG or CAIQ response: architecture and trust boundaries, cryptography, authentication, logging, vulnerability management, SDLC, disclosure, and the known gaps, each backed by code, an ADR or a CI job."
---

This page answers the questions a vendor security review asks, in the order those questionnaires ask them. Every answer links to code, an ADR, a test or a CI job. Where the honest answer is "no", it says no.

Halos is Apache-2.0 open-source software that you run. There is no Halos-operated service and no vendor hosting your data: your security posture is the posture of your deployment. The deeper documents are the [security model](/halos/concepts/security-model/) (the design) and the [threat model](/halos/reference/threat-model/) (assets, attackers, controls). Companion pages: [control mapping](/halos/compliance/control-mapping/) and [data flow and PII inventory](/halos/compliance/data-flow-and-pii/).

## At a glance

| Question | Answer |
|---|---|
| Hosted by the vendor? | No. Self-hosted: you run `halo-server`, the gateway, the collector and the registry |
| Independent assurance? | **None.** No third-party penetration test, code audit, SOC 2 report or ISO certificate. [SECURITY.md](https://github.com/dshakes/halos/blob/main/SECURITY.md) states it |
| Release integrity | ed25519- or ECDSA P-256-signed releases and ring pointers (key in a file, AWS KMS or an HSM via an external signer); cosign-signed checksums and images; build-provenance attestations; SBOMs |
| Authentication | OIDC (console and gateway), SCIM 2.0, short-lived workload and agent credentials. **No SAML** |
| Encryption in transit | Not terminated by Halos services. Put TLS in front of them. Outbound calls use Go's TLS defaults |
| FIPS 140-3 cryptography | **FIPS builds, no Halos certificate.** `_fips` archives and `-fips` images are built against the Go Cryptographic Module v1.0.0; every algorithm on the signing path is inside it. See [FIPS 140-3 builds](/halos/guides/fips/) |
| Audit | Hash-chained, tamper-evident audit log with SIEM export |
| Customer data in prompts | Passes through the gateway to the model provider you chose; not stored by Halos unless you enable shadow or prompt telemetry |
| Vulnerability reporting | GitHub private vulnerability reporting; 3-business-day acknowledgment |

## Architecture and trust boundaries

<img class="diagram dark:sl-hidden" src="/halos/diagrams/security-boundaries-light.svg" alt="Untrusted clients and networks; the gateway boundary that verifies OIDC JWTs, strips x-halo headers and fails closed on the model allowlist; a supply chain where a CI or HSM key signs releases into an OCI registry; halod as root verifying pointer and release before writing managed config; and halo-server issuing device tokens and a kill list signed with a separate key." width="760" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/security-boundaries-dark.svg" alt="Untrusted clients and networks; the gateway boundary that verifies OIDC JWTs, strips x-halo headers and fails closed on the model allowlist; a supply chain where a CI or HSM key signs releases into an OCI registry; halod as root verifying pointer and release before writing managed config; and halo-server issuing device tokens and a kill list signed with a separate key." width="760" />

Components ([package map](https://github.com/dshakes/halos/blob/main/AGENTS.md), [architecture](/halos/concepts/architecture/)):

| Plane | Components | Trust note |
|---|---|---|
| Control | `halo` CLI, policy repo (git), OCI registry, `halo-server` | The policy repo's merge gate and the release signing key are the root of trust. Halos does not prevent a malicious merge |
| Client | `halod` (root, on laptops and workspaces), the coding CLIs | `halod` applies only releases that verify against its pinned key, writes only to an allowlist of paths and runs no shell installers by default |
| Traffic | `halo-proxy` or `halo-kong`, `halo-shadow` | Cohort comes from the verified identity only; client `x-halo-*` headers are stripped; unknown models fail closed |
| Evidence | OTel collector, ClickHouse | The client-reachable receiver is untrusted; only the authenticated gateway receiver can drive an automatic kill |

Boundaries and the control at each are tabulated in the [security model](/halos/concepts/security-model/#trust-boundaries). Four design invariants hold across the codebase ([AGENTS.md](https://github.com/dshakes/halos/blob/main/AGENTS.md)): no permission-bypass modes are ever rendered; adapters warn rather than silently drop a setting; client-supplied identity headers never choose a cohort; and no auto-merge or auto-promote exists, so a human owns every irreversible step. The MCP server has no tool that publishes, retags, merges or pushes to main (`internal/mcpserver/write_safety_test.go`).

Multi-tenancy: Halos is an organization-scoped tool, not a multi-tenant SaaS. One deployment serves one org; org units scope policy and ownership inside it ([ADR-0018](/halos/adr/0018-org-hierarchy-and-delegated-policy/)).

## Authentication and authorization

| Subject | Mechanism | Detail |
|---|---|---|
| Developer, console | OIDC authorization-code login against your IdP | 12-hour session in an `HttpOnly`, `SameSite=Lax` cookie, `Secure` over https; state-changing requests refused when `Origin` or `Sec-Fetch-Site` says cross-site; failed logins rate-limited per client IP (`internal/server/auth.go`) |
| Developer, gateway | OIDC JWT verified at every request | `iss`, `aud`, `exp`, `nbf`; RS256, ES256 or EdDSA only; `none` and `HS*` rejected; JWKS refetch throttled to once per 30 seconds per issuer (`internal/identity/oidc.go`) |
| Gateway behind your own gateway | `trusted_header` | Honored only from `trustedProxyCIDRs`; fails closed without a pin |
| Laptop | Single-use enrollment token (15 minutes), then a device token, stored as SHA-256, revocable, expiring after 90 days | `internal/server/portal.go`, `devices.go` |
| CI job or cloud workload | RFC 8693 exchange of the job's OIDC token for a credential of 15 minutes by default, 1 hour at most; per-issuer claim rules that must pin the tenant | [ADR-0023](/halos/adr/0023-workload-identity-federation/) |
| Subagent or A2A caller | Delegated credential with an `act` chain, scope that only narrows | [ADR-0024](/halos/adr/0024-agent-identity-and-delegation/) |
| IdP provisioning | SCIM 2.0 with a dedicated bearer token held as SHA-256 | [ADR-0022](/halos/adr/0022-scim-provisioning/) |
| Gateway to `halo-server` | Per-capability bearer tokens (kill list, posture, budget, directory, DLP); 32+ characters and 128+ bits of estimated entropy, enforced at startup | `cmd/halo-server/main.go` |

Authorization is one table: five roles (`viewer`, `operator`, `approver`, `auditor`, `admin`) mapped from IdP groups, recomputed on every request, deny by default, with every denial audited. A test fails when a route is added without an entry (`TestRoutePermsCoverMux` in `internal/server/rbac_test.go`; [ADR-0015](/halos/adr/0015-rbac-roles-for-halo-server/)).

MFA, password policy and conditional access are the IdP's. Halos adds nothing to them.

## Cryptography

Every algorithm Halos uses, from the source:

| Purpose | Algorithm | Where |
|---|---|---|
| Release and ring-pointer signatures | ed25519 over the digest, or ECDSA P-256 over its SHA-256 (ADR-0038); the manifest records the algorithm and key id; `halod` verifies either against its configured keys, each under its own algorithm only, and never shells out to cosign | `internal/bundle/sign.go`, `keys.go`, `pointer.go` |
| Signing key custody | `file://` PEM (default), `awskms://` (AWS KMS asymmetric key, private half never leaves KMS) or `exec://` (external signer: PKCS#11 HSM, GCP/Azure KMS, Vault). Every remote signature is verified against the key before use | `internal/signer/`, [key management](/halos/guides/key-management/) |
| Optional co-signature on releases and pointers | cosign: key file, KMS URI or keyless (Fulcio and Rekor) | `cmd/halo/cmd_release.go` (`--cosign-key`, `--cosign-keyless`) |
| Artifact (skill, hook, plugin) signatures | ed25519 (`halo artifact sign`) or a cosign key | [agent supply chain](/halos/guides/agent-supply-chain/) |
| Kill list | ed25519 or ECDSA P-256 over `halo-killswitch-v1\n` plus the payload, with a key separate from the release key (file or key URI) | `internal/gateway/killswitch.go` |
| Workload and delegated-agent credentials | EdDSA JWTs (`halo-workload+jwt`, `halo-agent+jwt`) signed with a third, dedicated key | `internal/identity/workload.go`, `delegation.go` |
| Inbound IdP and CI token verification | RS256, ES256, EdDSA | `internal/identity/oidc.go` (`AllowedAlgs`) |
| Remote AgentCard signature verification | ed25519, ECDSA, RSA (PKCS#1 v1.5 and PSS, SHA-256) | `internal/a2a/card.go` |
| Console session cookie | HMAC-SHA256 over base64 JSON. **Integrity only: the cookie is not encrypted** and carries the subject and groups | `internal/server/auth.go` (`seal`) |
| Webhooks (controller notifications, SIEM `webhook` sink) | HMAC-SHA256 over `timestamp + "." + body`; 5-minute replay window for receivers | `internal/controller/notify.go`, `internal/server/audit_export.go` |
| Inbound GitHub cloud-agent webhooks | HMAC-SHA256 verification | `internal/cloudagents/task.go` |
| Audit chain | SHA-256 over every other field of each entry | `internal/server/audit.go` (`sum`) |
| Token storage | SHA-256 (device, enrollment, SCIM) | `internal/server/devices.go`, `portal.go` |
| Pseudonyms | HMAC-SHA256 under a salt: `halo.unit`, ledger path and repository hashes | `internal/telemetry/gwmetrics/gwmetrics.go`, `internal/ledger/ledger.go` |
| Shadow pairs at rest (optional) | AES-256-GCM with a module-generated random 96-bit nonce, 32-byte key from a file | `internal/shadow/shadow.go` |
| Binary integrity | sha256 or sha512 pinned in the signed manifest | `cmd/halod/install.go` |
| Upstream auth | AWS SigV4 for Bedrock (gateway's own identity); service-account JWT signed RSA-SHA256 for Vertex | `internal/gateway/upstreamauth/` |

TLS:

- **`halo-server`, `halo-proxy` and `halo-shadow` have no TLS listener.** Terminate TLS at your ingress or load balancer; the Helm chart's own comments say so (`deploy/helm/halos/values.yaml`). Only the standard library's `crypto/tls` is used, in two places, both setting a TLS 1.2 minimum: the SIEM syslog sink (`internal/server/audit_export.go`) and AgentCard fetches (`internal/a2a/card.go`).
- Other outbound HTTPS (providers, GitHub, vendor consoles, the registry) uses Go's default client configuration for the Go version in `go.mod` (1.25). Halos sets no cipher suites.
- Credentials and tokens go only over https; http is accepted only to loopback for the vendor admin, ROI and copilot clients. The kill-list URL must be https unless explicitly marked in-cluster.
- Postgres to a non-loopback host requires `sslmode=verify-full` (`internal/pgstore/pgstore.go`).

Key management:

- **The release signing key is the root of trust.** Keep it in AWS KMS (`--key-uri awskms://...`), in an HSM behind an external signer (`--key-uri exec://...`), or as a file in CI secrets ([key management](/halos/guides/key-management/), ADR-0038). Rotation, revocation (`revokedKeys`) and compromise handling are in [key management](/halos/guides/key-management/#rotation) and [production deployment](/halos/guides/production-deployment/#signing-key-management). There is no threshold signing and no key revocation list in the protocol beyond `revokedKeys` in each `halod` config.
- Three keys are kept apart on purpose: release, kill switch, workload credential. A stolen kill key cannot sign a release. The release and kill-switch keys can live in a KMS or HSM; the workload-credential key is still a file.
- **FIPS 140-3: builds, not a certificate.** The `_fips` archives and `-fips` images are built with `GOFIPS140=v1.0.0`, Go's frozen FIPS 140-3 module (the version the Go team submitted for CMVP validation; check the CMVP listing for its current status), so the module runs its self-tests and `fips140=on` is the default. Every algorithm on the signing, verification, TLS, session and encryption paths (ed25519, ECDSA P-256, SHA-256, HMAC-SHA256, AES-256-GCM) is inside the module, and those packages pass their tests under `GODEBUG=fips140=only` in CI. Halos itself holds no FIPS certificate, and the standard (non-`_fips`) artifacts make no FIPS claim. Details and the operator requirements (HMAC secrets of at least 112 bits) are in [FIPS 140-3 builds](/halos/guides/fips/).

## Logging and monitoring

- **Audit log.** Privileged actions append to a hash chain (`seq`, `prev`, `hash`), fsynced before the response, and fail closed with HTTP 500 if the append fails. Verify with `halo audit verify` or `GET /api/v1/audit`. Tail truncation is undetectable from the log alone: the SIEM copy closes that gap ([audit log](/halos/concepts/security-model/#audit-log)).
- **SIEM export.** Every entry, at least once and in order, to Splunk HEC, a signed webhook (Datadog and others) or syslog over TLS, native or OCSF ([SIEM export](/halos/guides/siem-export/)).
- **Session ledger.** One redacted record per agent session, who and what and on whose evidence ([session ledger](/halos/guides/session-ledger/)).
- **Gateway request log.** Method, path, status, bytes, duration, ring, remote address, experiment, variant, upstream, model. Never bodies, headers or query strings (`cmd/halo-proxy/proxy.go`).
- **Metrics.** Prometheus on `halo-server`, `halo-proxy`, `halo-shadow` and `halo-kong` ([reference](/halos/reference/metrics/)); example alert rules in the [operations guide](/halos/guides/operations/).
- **Not provided:** log retention policy enforcement, time synchronization, log review. Retention defaults are in the [inventory](/halos/compliance/data-flow-and-pii/#retention-defaults).

## Vulnerability management

Of Halos itself:

| Control | Where |
|---|---|
| `govulncheck` on every PR and push to `main` | `vuln` job in [`ci.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml); `make vuln` locally |
| `golangci-lint`, `go vet`, `go test -race`, `go mod tidy` drift check | `lint`, `test`, `tidy` jobs |
| Native Go fuzz targets over parsers of untrusted input: 10 seconds per PR, 10 minutes per target nightly | `fuzz` job; [`fuzz-nightly.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/fuzz-nightly.yml); `scripts/fuzz.sh` |
| OpenSSF Scorecard, weekly and on `main`; results kept as a workflow artifact for 5 days, not published | [`scorecard.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/scorecard.yml) |
| GitHub Actions pinned to full commit SHAs in every workflow; workflows default to `contents: read` | `.github/workflows/*.yml` |
| Web and docs builds with `npm ci --ignore-scripts` in the release path; the npm build runs in an unprivileged job with no signing credentials | `web` job; `release.yml` |
| Private vulnerability reporting, severity by CVSS v3.1, fix targets | [SECURITY.md](https://github.com/dshakes/halos/blob/main/SECURITY.md) |

Gaps: there is **no Dependabot or Renovate configuration** in the repository, so dependency updates are manual and `govulncheck` is the detective control. Scorecard results are not published or tracked. There is no third-party penetration test.

For your estate: `versionGate` and rollouts get a patched coding CLI to the fleet in stages and refuse unpinned versions ([reliable upgrades](/halos/guides/reliable-upgrades/)). Halos does not scan your hosts.

## SDLC

How the code gets written and merged, stated plainly.

- **Agents write and review code.** The project is developed with AI coding agents in the loop. [AGENTS.md](https://github.com/dshakes/halos/blob/main/AGENTS.md) is the instruction file for contributors' agents, and the `sdlc-*` workflows run Claude as a builder (on an `@claude` comment), a reviewer on every PR, a QA pass and a security pass. The repository holds no measure of what share of the code agents wrote.
- **Agents do not merge.** The workflows can push only to a `claude/`-prefixed branch and open a PR. An optional policy-gated auto-approve step (`sdlc-autoapprove.yml`) is off unless the repository variable `SDLC_AUTOAPPROVE=on`, only labels a PR, never authors an approval and never merges. The `/approve` command queues auto-merge only when `SDLC_AUTO_MERGE=true` and after branch protection is satisfied. The same rule is a product invariant: Halos itself has no auto-merge or auto-promote.
- **Agent review is a check, not a reviewer of record.** The review and QA jobs are LLM-driven. [CONTRIBUTING.md](https://github.com/dshakes/halos/blob/main/CONTRIBUTING.md) lists `review` and `qa` as required to merge and `security` as advisory, and says a maintainer merges. That a status check is *required* is a GitHub branch-protection setting, which is not in the repository: **UNVERIFIED** here. Verify it in the repository settings before relying on it.
- **One maintainer today.** [CODEOWNERS](https://github.com/dshakes/halos/blob/main/.github/CODEOWNERS) lists a single owner for every path, and [GOVERNANCE.md](https://github.com/dshakes/halos/blob/main/GOVERNANCE.md) says the `MAINTAINERS` file will be added with the first external maintainer. Load-bearing changes need an ADR and, with one maintainer, a 5-business-day comment window. There is no independent second approver for the maintainer's own changes.
- **Gates every change passes (CI).** Build and vet, `go test -race` across the module, lint, `govulncheck`, cross-OS builds (Linux, macOS, Windows), end-to-end tests on real binaries, a kind (Helm) UAT suite, real-CLI and Kong OSS UAT suites, fuzzing, docs and console builds, and a generated-docs drift check ([`ci.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml), [`docs-gen.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/docs-gen.yml)).
- **Releases.** A tag on `main` runs `gate` (strict SemVer, tag on `main`, CHANGELOG section, `go vet`, `go test -race`), an unprivileged web build, GoReleaser with SBOMs, cosign keyless signatures and image signing, a build-provenance attestation, then `verify`, which downloads what was published and checks the signature, checksums, attestation, image signatures and `install.sh` the way a user gets them ([`release.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/release.yml), [RELEASING.md](https://github.com/dshakes/halos/blob/main/RELEASING.md)). Halos' own artifacts are signed keyless with the workflow identity, so no long-lived signing key for them exists to steal.
- **Design records.** Load-bearing changes get an ADR first ([`docs/adr/`](/halos/adr/0001-environment-as-policy/)); every claim in the security model is bound to a named test that CI fails on if it is renamed or removed (`internal/docgen/security_model_test.go`).
- **Developer Certificate of Origin.** Contributors sign off commits (`git commit -s`); nothing in CI was found that enforces it.

## Incident response and disclosure

- Report through GitHub private vulnerability reporting. Acknowledgment within 3 business days, triage within 10, a fix or mitigation plan within 30 days (critical and high: target 7 days), then a patched release, a published advisory and a CVE request. Coordinated disclosure up to 90 days. No bug bounty ([SECURITY.md](https://github.com/dshakes/halos/blob/main/SECURITY.md)).
- Supported versions: the latest `0.x` release and `main`; older releases are not patched ([support policy](/halos/reference/support-policy/)).
- There is no Halos-operated service, so there is no vendor-side breach of your data to notify you about. A flaw in the software is announced through the advisory channel.
- Your incident levers in the product: kill switch, incident freeze, session, device and credential revocation, each requiring a reason and written to the audit log ([security model](/halos/concepts/security-model/#kill-switch)). The incident plan around them is yours.

## Availability and recovery

`halo-server` runs as several replicas on Postgres with a fenced controller lease ([ADR-0021](/halos/adr/0021-ha-control-plane-on-postgres/)). Clients keep the last good release. Gateways keep the last accepted kill list and policy snapshot; their directory and posture lookups follow the configured fail mode and grace window ([SCIM provisioning](/halos/concepts/security-model/#scim-provisioning), [gateway gates](/halos/concepts/security-model/#gateway-gates)). Backup, restore and the files you cannot lose are in [operations](/halos/guides/operations/#backup-and-restore). No recovery time or availability figure is promised; the example SLOs there are targets for you to set.

## Known gaps

Stated so you do not have to find them.

| Gap | Detail |
|---|---|
| No third-party assurance | No penetration test, code audit, SOC 2 or ISO certification. The [threat model](/halos/reference/threat-model/) is the maintainers' own |
| No Halos FIPS certificate | `_fips` builds use the Go Cryptographic Module v1.0.0, but Halos is not itself validated; `fips140=only` is tested on the crypto packages, not the whole tree (gateway telemetry salts and webhook secrets must be at least 14 bytes). The workload-credential key has no KMS backend ([FIPS 140-3 builds](/halos/guides/fips/)) |
| One built-in KMS | `awskms://` is built in; GCP, Azure, Vault and PKCS#11 need an `exec://` adapter you supply ([key management](/halos/guides/key-management/#external-signers)) |
| No SAML | OIDC and SCIM only |
| No TLS in the services | Terminate TLS in front of `halo-server`, `halo-proxy` and `halo-shadow`. No mTLS, no per-user rate limiting |
| Single signing key | No threshold signing; compromise is fleet-wide ([residual risk](/halos/reference/threat-model/#residual-risk-and-non-goals)) |
| Cookie not encrypted | The console session cookie is signed, not encrypted, and carries the subject and groups |
| Audit retention unbounded, tail truncation undetectable alone | Pin the chain head or use the SIEM copy |
| Root can defeat client enforcement | Gateway gates (`posture`, `versionGate`) are the backstop; posture is `halod`'s self-report |
| DLP is pattern-based | Misses secrets with no recognizable format; injection scoring is a tripwire, not a guarantee |
| Single maintainer; branch protection unverified here | See [SDLC](#sdlc) |
| No dependency-update bot | Dependencies move by hand |
| Not validated at scale | Tested with unit tests, the compose demo, and kind, real-CLI and Kong OSS UAT suites in CI. Not validated on a real fleet, Kong Enterprise, real AWS Bedrock, or Windows fleets; release binaries are not Authenticode-signed |

## Questionnaire answers

Short answers for a SIG or CAIQ response, by domain. "N/A" means Halos is not the system of record for it.

| Domain | Question (paraphrased) | Answer |
|---|---|---|
| Governance, risk and compliance | Independent attestation? | No. See [known gaps](#known-gaps) |
| Application and interface security | Secure SDLC, code review, SAST, dependency scanning? | Yes, with the caveats in [SDLC](#sdlc): CI lint, race tests, fuzzing, `govulncheck`; agent plus human review; no automated dependency updates |
| Application and interface security | Input validation on untrusted data? | Yes. Parsers of untrusted input have fuzz targets; request bodies are size-limited; gateway fails closed. [Tests](/halos/concepts/security-model/#tests-binding-each-claim) |
| Change control | Formal change management, approvals, rollback? | Yes for the managed fleet: PR, plan, eval, rings, human merge, quorums, freezes, rollback by re-pointing ([change governance](/halos/guides/change-governance/)). For the Halos project: PR and release gates above |
| Cryptography, encryption and key management | Algorithms, key custody, rotation? | [Cryptography](#cryptography). Customer holds the keys (file, AWS KMS or HSM via an external signer). Rotation procedure documented. FIPS 140-3 builds on the Go Cryptographic Module; no Halos certificate |
| Identity and access management | SSO, MFA, RBAC, least privilege, deprovisioning? | OIDC SSO; MFA at the IdP; five-role RBAC, deny by default; SCIM deprovisioning revokes immediately. [Authentication](#authentication-and-authorization) |
| Logging and monitoring | Tamper-evident logs, SIEM integration, retention? | Hash-chained, SIEM export native or OCSF; retention is yours ([inventory](/halos/compliance/data-flow-and-pii/#retention-defaults)) |
| Threat and vulnerability management | Scanning, patch SLAs, pen test? | `govulncheck` per PR, weekly Scorecard, fuzzing; disclosure SLAs in SECURITY.md; no pen test |
| Supply chain management | SBOM, signed artifacts, provenance, third-party risk? | SBOMs, cosign signatures, build-provenance attestations, SHA-pinned Actions. For your fleet: AI-BOM and SLSA-format provenance per release ([control mapping](/halos/compliance/control-mapping/#nist-ssdf-and-slsa)) |
| Security incident management | Incident process, breach notification, disclosure? | Disclosure per SECURITY.md. No hosted service, so no vendor-side data breach path. Your IR plan uses the product levers above |
| Data security and privacy | Data inventory, classification, retention, residency, deletion? | [Data flow and PII inventory](/halos/compliance/data-flow-and-pii/). Residency is where you deploy. Some stores are unbounded by default and have no erasure API |
| Data security and privacy | Is customer content used to train models? | Halos does not train models and sends nothing to its maintainers. The model provider's terms govern what the provider does with prompts |
| Business continuity and resilience | HA, backup, DR? | HA on Postgres; documented backup and restore; gateways and clients degrade to last good state. No tested DR figures |
| Datacenter and physical security | Physical controls? | N/A, self-hosted |
| Human resources | Background checks, training? | N/A for the software; see the project's [Code of Conduct](https://github.com/dshakes/halos/blob/main/CODE_OF_CONDUCT.md) only |
| Interoperability and portability | Open formats, exit? | Apache-2.0; policy is YAML in your git; releases are OCI artifacts; audit is JSONL or OCSF; AI-BOM is CycloneDX 1.6 |
| Infrastructure and virtualization security | Network segmentation, hardening? | Helm `NetworkPolicy` is provided; non-root, read-only filesystem and the like are in the chart values; segmentation is yours |
