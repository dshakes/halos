---
title: Agent supply chain
description: Pin skills, plugins, hooks, slash commands and agent definitions by content digest, scan them for hidden instructions, optionally require signatures, and publish a signed CycloneDX AI-BOM with SLSA provenance for every release.
---

Skills, hooks, slash commands and subagent definitions change what a coding agent does as much as its settings. Halos delivers them the way it delivers settings: pinned by content, reviewed in a PR, signed with the release, and checked by `halod` before it writes them ([ADR-0028](/halos/adr/0028-agent-supply-chain-and-ai-bom/)).

## Declare and pin artifacts

Put the artifact in the policy repo, or point at a git commit or an OCI digest, and pin its digest in `halos.yaml`:

```yaml
supplyChain:
  scan: enforce          # off | warn (default) | enforce
  artifacts:
    - name: pr-review
      kind: skill          # skill | plugin | hook | command | agent
      path: artifacts/skills/pr-review
      digest: sha256:39a6210a056f9c0c889b5c13ef9a18f9b0584e7a7558fdb115b4812f24ab5186
    - name: vendor-review
      kind: skill
      git: {url: https://github.com/acme/agent-skills, commit: 4f1c0d9e2b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d, path: skills/review}
      digest: sha256:...
    - name: release-notes
      kind: command
      oci: ghcr.io/acme/commands/release-notes@sha256:...
      digest: sha256:...
```

Then deliver them from a profile:

```yaml
extensions:
  artifacts: [pr-review, vendor-review]
```

Compute a digest with `halo artifact digest <path>`, or without Halos:

```sh
cd artifacts/skills/pr-review
find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum
```

Rules:

- `git` needs a full commit id and `oci` a `@sha256:` reference. Branches and tags are refused, and both need `digest`.
- For an `oci` artifact, push each file as its own layer (`oras push ref SKILL.md notes.md`); packed directories are refused.
- Symlinks, paths with `..`, more than 512 files or more than 8 MiB are refused.

`halo validate` reads `path` artifacts, checks their pins and scans them, offline. `halo release build` also fetches `git` and `oci` artifacts and fails if any content does not match its pin.

## Where they land

| Kind | Claude Code (managed directory) | Other CLIs |
|---|---|---|
| `skill` | `.claude/skills/<name>/` | warning |
| `agent` | `.claude/agents/<name>.md` | warning |
| `command` | `.claude/commands/<name>.md` | warning |
| `hook` | `hooks/<name>/` (run it from `hooks.items` as `sh <managed dir>/hooks/<name>/<script>`) | warning |
| `plugin` | warning: use `extensions.marketplaces` and `extensions.plugins.enabled` | warning |

A warning goes in the release manifest. The artifact is still pinned, scanned and listed in the AI-BOM.

`halod` checks every artifact file before writing it: the artifact's listing in the signed manifest must hash to its pin and name the file with the file's hash. A mismatch keeps the old file, reports the path as drift, and puts the reason in `lastError`.

## Scan

| Rule | Catches |
|---|---|
| `hidden-unicode` | zero-width, bidi-control, tag and variation-selector characters |
| `html-comment-instruction` | an HTML comment that tells the model to ignore instructions, hide something from the user, or run curl/bash |
| `permission-bypass` | `bypassPermissions`, `danger-full-access`, `--dangerously-skip-permissions`, `--yolo`, ... |
| `remote-exec` | `curl ... \| sh`, `sh -c "$(curl ...)"`, `bash <(curl ...)`, `iex (irm ...)` |
| `credential-path` | `~/.ssh`, `~/.aws`, gcloud credentials, `.netrc`, `.git-credentials`, docker or kube config, `cat .env` |
| `exfil-url` | webhook.site, ngrok, interact.sh, pastebin, Discord webhooks, raw public IPs, ... |
| `base64-blob` | 1024+ characters of base64 (inline images excepted) |
| `executable-binary` | ELF, Mach-O, PE, Java class |

Findings warn by default. `scan: enforce` or `--strict` (`halo validate --strict`, `halo release build --strict`) makes them errors. Scan any directory with `halo artifact scan <path>` (exit 2 on findings).

To accept a finding, suppress it by content with a reason. Every finding message prints the entry to add:

```yaml
supplyChain:
  allowFindings:
    - digest: sha256:<file sha256 or artifact digest>
      rule: remote-exec
      path: install.md
      reason: documents the vendor's installer; the hook never runs it
```

When the file changes, the suppression stops matching, the finding returns and the stale entry warns.

## Require signatures

```yaml
supplyChain:
  requireSignatures: true          # git and oci artifacts must be signed
  trustedIdentities:
    - {name: platform, publicKey: keys/platform.pub}   # ed25519 PEM (halo keys generate)
    - {name: vendor, cosignKey: keys/vendor-cosign.pub}
  artifacts:
    - name: vendor-review
      ...
      signature: {identity: platform, file: sigs/vendor-review.sig}
```

Sign the artifact's digest with `halo artifact sign <path> --key halo.key -o sigs/vendor-review.sig`, or `cosign sign-blob` over the digest string for a cosign identity. `halo release build` verifies each signature and records the signer in the manifest and AI-BOM.

## AI-BOM and provenance

`halo release build -o release.tar` also writes:

- `release.tar.bom.cdx.json`: a CycloneDX 1.6 BOM listing the harnesses with their versions and install artifacts, every rendered file, every artifact with its files, each model alias as a `machine-learning-model` component with its gateway route targets, MCP servers (and whether command servers are pinned), remote A2A agents, and the policy commit;
- `release.tar.intoto.json`: an in-toto Statement v1 for the release digest with a SLSA provenance v1 predicate (policy commit, artifacts and install artifacts as resolved dependencies, the BOM as a byproduct).

`halo release publish` attaches both to the release in the registry as one OCI referrer signed with the release key. They sit beside the release, not inside it, so the release digest depends on content only.

Print and verify:

```sh
halo release bom release.tar                              # checks the files beside the tar
halo release bom ghcr.io/acme/halos:v1.4.0 --pubkey halo.pub
halo release bom ghcr.io/acme/halos:v1.4.0 --pubkey halo.pub --provenance
```

Verification fails unless both documents name the release digest, the BOM lists exactly the manifest's files and artifacts with the same hashes, the provenance pins the same artifacts, and, from a registry, both signatures verify.
