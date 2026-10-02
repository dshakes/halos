# Security policy

Halos sits on trust boundaries: it signs and applies configuration as root on developer machines, and it assigns cohorts on the request path. We take reports seriously.

## Reporting a vulnerability

**Do not open a public issue, PR or discussion.** Use GitHub private vulnerability reporting: <https://github.com/dshakes/halos/security/advisories/new>. Fallback: security@halos.dev (placeholder: replace before the first public release).

Include the affected component and version (`halo version`), reproduction steps or a proof of concept, and the impact you see.

## Disclosure process

1. **Acknowledge** within 3 business days, with a tracking advisory (GHSA) opened privately.
2. **Triage** within 10 business days: we confirm or reject the report, assign a severity (CVSS v3.1) and tell you which versions are affected.
3. **Fix** in a private fork of the advisory: a patch with a regression test, a fix or mitigation plan within 30 days (critical and high: as fast as practical, target 7 days).
4. **Release** a patched version, then publish the advisory and request a CVE through GitHub. Coordinated disclosure: we ask you to keep the issue private until the advisory is published, at most 90 days from your report unless we agree otherwise.
5. **Credit** the reporter in the advisory and the CHANGELOG unless asked not to.

There is no bug bounty.

## Supported versions

Pre-1.0 (`v1alpha1` policy API): security fixes go to `main` and ship in the next release of the latest minor line only.

| Version | Supported |
|---|---|
| latest `0.x` release (including its release candidates until the final is out) | yes |
| `main` | yes (fixes land here first) |
| older `0.x` releases | no: upgrade |

From 1.0, the latest two minor lines will receive security fixes.

## In scope

- Signature or ring-pointer verification bypass in `halod`, the Dev Container Feature or `internal/bundle`: accepting unsigned or tampered releases, an expired pointer, a lower `seq`, or a pointer for another org or ring.
- Header spoofing or cohort manipulation past `halo-proxy` or `halo-kong`: client-supplied `x-halo-*` surviving, JWT verification bypass (issuer, audience, algorithm, expiry), `trusted_header` accepted from an unpinned peer, or cohort not derived from verified identity.
- Model allowlist bypass: reaching an unlisted model, the batches API or a non-model endpoint through the gateway.
- Privilege escalation via `halod`: path allowlist or mode-ceiling bypass, symlink or ownership-check bypass, artifact verification bypass, or execution of an install command without `allowShellInstall`.
- Portal and enrollment flaws in `halo-server`: enrollment-token reuse or guessing, device-token disclosure or bypass of revocation, injection through generated enrollment scripts, access requests that merge or bypass review.
- MCP server (`halo mcp serve`) doing anything beyond its documented write model (publishing, retagging, merging or pushing).
- Emission of `bypassPermissions` or `danger-full-access` by any adapter, or bypass of the guardrails, reserved-override list or release backstop.
- Leakage of prompts or credentials through `halo-shadow`, telemetry or the console.

## Out of scope

- Vulnerabilities in Claude Code, Codex, Gemini CLI, Kong or other upstream projects: report those upstream.
- Attacks requiring an already-compromised release signing key or a malicious merge to the policy repo. Protect that key and your merge gate; see the [security model](https://dshakes.github.io/halos/concepts/security-model/) and the [threat model](https://dshakes.github.io/halos/reference/threat-model/), which lists these as residual risk.
- Local administrators defeating client-side enforcement that the harness matrix marks as enforced by `halod`.
- Denial of service from the developer's own machine against their own workspace.

## Design references

Trust boundaries and mitigations are documented in the [security model](https://dshakes.github.io/halos/concepts/security-model/), the [threat model](https://dshakes.github.io/halos/reference/threat-model/), [ADR-0005](docs/adr/0005-signed-oci-bundles.md) and [ADR-0008](docs/adr/0008-signed-ring-pointers-and-verified-artifacts.md).

No external security review or penetration test has been performed on this pre-release code.
