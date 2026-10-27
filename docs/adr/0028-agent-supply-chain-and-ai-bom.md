---
title: "ADR-0028: Agent supply chain and AI-BOM"
description: Skills, plugins, hooks, slash commands and agent definitions become content-addressed artifacts pinned by sha256 in the signed release manifest, statically scanned at validate and build, optionally signature-checked, verified by halod before it writes them, and listed with models, MCP servers and harnesses in a signed CycloneDX 1.6 AI-BOM with SLSA provenance.
status: accepted
date: 2026-10-27
---

# ADR-0028: Agent supply chain and AI-BOM

- Status: accepted
- Date: 2026-10-27

## Context and problem statement

A coding agent's behaviour is shaped as much by the text it loads as by its settings: skills, plugins, hook scripts, slash commands and subagent definitions. Today Halos pins and signs the settings (ADR-0005, ADR-0008) but an extension is whatever happens to be in a marketplace or a checkout when a developer installs it. That is an unreviewed, unpinned dependency that runs with the developer's credentials, and it is the easiest place to hide a prompt injection: a zero-width character, a bidi override or an HTML comment is invisible to a reviewer reading rendered Markdown and fully visible to a model.

Security teams also ask, per release, "which models, MCP servers, CLIs and extensions can this agent use, and where did each one come from?" Nothing answers that in a machine-readable, signed form.

How should Halos deliver extensions so that what reaches a machine is exactly what a human reviewed, and how does it describe a release's AI components?

## Decision drivers

- Invariant 6: releases are immutable and content-addressed. An artifact is pinned inside the release, so changing it is a new release.
- Invariant 1: no extension may smuggle `bypassPermissions` or `danger-full-access` past the guardrails.
- Invariant 2: an adapter that cannot place an artifact warns; it never drops it silently.
- Reproducible without Halos: an auditor must be able to recompute a pin with stock tools.
- No new trust root and no new dependency: reuse the release signers and verifiers in `internal/bundle`.
- Scanning must be conservative. A noisy scanner gets turned off.

## Considered options

1. **Pin extensions by content digest in the release manifest, scan them, verify them in halod, and describe the release in a signed AI-BOM.** Chosen.
2. **Trust the vendors' marketplaces and pin plugin versions only** (`extensions.plugins.enabled` already does this for Claude Code). Rejected as the only mechanism: a version is not content, marketplaces differ per CLI, and skills, hooks and agents have no marketplace at all. It stays available for plugins.
3. **Run an LLM-based or heuristic-heavy scanner.** Rejected: non-deterministic, slow, and a finding nobody can reproduce is not reviewable. A small deterministic ruleset with digest-keyed suppressions is.

## Decision outcome

### Artifacts and digests

`halos.yaml` gains `supplyChain.artifacts`: each has a `name`, a `kind` (`skill`, `plugin`, `hook`, `command`, `agent`) and exactly one source:

- `path`: a file or directory in the policy repo;
- `git`: `url` (https, ssh or file) and a full `commit` id, plus an optional `path`. Branches and tags are refused;
- `oci`: `host/repo@sha256:<hex>`. Tags are refused. Each layer is one file named by its `org.opencontainers.image.title` annotation, which is what `oras push <ref> <file>...` writes. Packed directory layers are refused.

The artifact digest is `sha256` of the sorted `sha256sum` listing of its files: one `<hex>  <path>\n` line per file, sorted by path in byte order. It is reproducible with:

```sh
cd artifacts/skills/pr-review && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum
```

`halo artifact digest <path>` prints the same value. A `git` or `oci` artifact must carry `digest`; a `path` artifact may (and is then checked by `halo validate`). Paths inside an artifact are portable (`[A-Za-z0-9._@+-]`, no `.`/`..`), symlinks are refused, and an artifact is capped at 512 files and 8 MiB.

A profile delivers artifacts by name with `extensions.artifacts`. `halo release build` fetches every remote artifact, fails on a digest mismatch, and pins each delivered artifact in the release manifest's `supplyChain` with its digest, source, signer and full file listing. Every rendered file that belongs to an artifact carries `artifact` and `artifactPath`. Build refuses a manifest whose listing does not hash to the pin or whose file is not in the listing.

### Placement

Claude Code places skills in `<managed dir>/.claude/skills/<name>/`, agents in `<managed dir>/.claude/agents/<name>.md`, commands in `<managed dir>/.claude/commands/<name>.md`, and hook scripts in `<managed dir>/hooks/<name>/` for a `hooks.items` command to run through an interpreter (halod writes 0644). Plugins warn: Claude Code installs plugins from marketplaces, which `extensions.marketplaces` and `extensions.plugins.enabled` already govern. Every other adapter warns per artifact; the artifact is still pinned, scanned and listed in the AI-BOM.

### halod

Before writing an artifact file, halod checks that the artifact's listing in the signed manifest hashes to its pinned digest, that the listing names the file with the file's hash, and that the bytes hash to it. A failure refuses that file, keeps the previous content, and reports the path as drift with the reason in `lastError`. The release signature already covers the manifest; this check makes the pin self-consistent so a builder bug or a hand-crafted manifest cannot deliver content other than what the pin names.

### Static scan

`halo validate` (path artifacts, offline) and `halo release build` (all artifacts, after fetching) scan every artifact with eight deterministic rules:

| Rule | Matches |
|---|---|
| `hidden-unicode` | zero-width, bidi-control, Unicode tag and variation-selector characters (a leading BOM is allowed) |
| `html-comment-instruction` | an HTML comment carrying an instruction cue: ignore previous instructions, do not tell the user, run curl/bash, ... |
| `permission-bypass` | `bypassPermissions`, `danger-full-access`, `--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--yolo` |
| `remote-exec` | curl/wget piped to a shell or interpreter, `sh -c "$(curl ...)"`, `bash <(curl ...)`, `iex (irm ...)` |
| `credential-path` | `~/.ssh`, `~/.aws`, gcloud credentials, `.netrc`, `.git-credentials`, docker and kube config, reading a `.env` file |
| `exfil-url` | request-capture, tunnel and paste services (webhook.site, ngrok, interact.sh, pastebin, Discord webhooks, ...) and raw public-IP URLs |
| `base64-blob` | a base64 run of 1024 characters or more (inline `data:image/` payloads excepted) |
| `executable-binary` | ELF, Mach-O, PE or Java class files |

Findings are warnings by default. `supplyChain.scan: enforce`, or `--strict` on `validate` and `release build`, makes them errors; `scan: off` skips the scan. `supplyChain.allowFindings` suppresses a finding by the artifact digest or one file's sha256, a rule, an optional path and a mandatory `reason`. Because it is keyed by content, a changed file is scanned afresh, and an entry that suppresses nothing warns. `halo artifact scan <path>` runs the same scan on any directory.

The extensions Halos ships, `plugins/claude-code` and `examples/acme-corp/artifacts`, are scanned in CI (`TestShippedExtensionsScan`). The four plugin skills that state invariant 1 ("never emit `bypassPermissions`") carry suppressions keyed by file sha256 with that reason.

### Signatures

`supplyChain.trustedIdentities` lists signing keys: an ed25519 `publicKey` PEM in the policy repo or a `cosignKey` (file or KMS URI). An artifact's `signature` names an identity and a signature file over its digest: base64 ed25519 (`halo artifact sign --key`) or cosign `sign-blob` output. `halo release build` verifies it through `internal/bundle`'s verifiers and records the signer in the manifest and BOM. `requireSignatures: true` refuses any `git` or `oci` artifact without one.

### AI-BOM and provenance

Every `halo release build` and `halo release publish` produces:

- a CycloneDX 1.6 BOM: the release as the metadata component (by digest), each harness with its pinned version, npm purl and install artifacts and its rendered files, each supply-chain artifact with its files, each model alias the profile can call as a `machine-learning-model` component with its gateway route targets, each MCP server (URL servers as services; command servers as components with a purl when the package is pinned exactly), remote A2A agents with their card digests, and the policy commit and repo;
- an in-toto Statement v1 whose subject is the release digest, with a SLSA provenance v1 predicate: build type `https://github.com/dshakes/halos/release-build/v1`, the org, ring, profile and version as external parameters, the policy commit, every artifact and every install artifact as resolved dependencies, and the BOM's digest as a byproduct.

Both are deterministic for the same inputs. They describe the release by digest, so they travel beside the content-addressed tar rather than inside it: a policy commit or a Halos upgrade must not change a release's digest (invariant 6). `release build -o x.tar` writes `x.tar.bom.cdx.json` and `x.tar.intoto.json`. `release publish` pushes them as one OCI referrer of the release manifest (artifact type `application/vnd.halos.attestations.v1+json`), signed by the release signer, and co-signers, over a domain-separated statement naming the release digest and both layer digests. Older halods ignore the referrer.

`halo release bom <tar | registry ref>` prints the BOM (or `--provenance`) after checking it: both documents must name the release digest, the BOM must list every rendered file and artifact with the manifest's hash and nothing else, the provenance must pin every artifact and install artifact as the manifest does, and its byproduct must be this BOM. From a registry, the release and attestation signatures must verify with `--pubkey` or `--cosign-key`.

## Consequences

- Good: what reaches a machine is byte-for-byte what was pinned, reviewed and signed, and a moved branch, retagged image or edited file fails the build instead of shipping.
- Good: the cheap, common injection tricks are caught deterministically before a release exists, and every suppression is reviewable and expires with the content.
- Good: one signed document answers "what AI components does this release use and where did they come from".
- Bad: an extension update is a policy change (new digest, new release). That is the intent, but it is slower than a marketplace auto-update.
- Bad: the scan is pattern-based. It raises the cost of an attack; it does not prove an extension safe. A human still reviews the PR that changes a digest.
- Neutral: Claude Code's managed-directory placement for skills, agents and commands follows its documented managed scope and is covered by unit tests, not yet by a UAT run against a live CLI.

## More information

`internal/supplychain` (digests, fetch, scan), `internal/policy/supplychain.go`, `internal/release/supplychain.go` and `attest.go`, `internal/bundle/attest.go`, `internal/harness/hutil` (`RenderArtifacts`), `cmd/halo/cmd_supplychain.go`, `cmd/halod/agent.go`; [Agent supply chain guide](/halos/guides/agent-supply-chain/).

- CycloneDX 1.6: https://cyclonedx.org/docs/1.6/json/ (checked 2026-10-27)
- in-toto Statement v1: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md (checked 2026-10-27)
- SLSA provenance v1: https://slsa.dev/spec/v1.0/provenance (checked 2026-10-27)
- OCI referrers: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers (checked 2026-10-27)
