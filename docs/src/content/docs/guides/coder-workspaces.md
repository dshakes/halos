---
title: Coder workspaces
description: Use the Halos Coder module in templates, including Coder Tasks.
---

:::note[Verified scope]
`make uat-coder` (CI job `uat-coder`) runs this module on a real Coder v2.38.6 server (Docker, docker template) with a local TLS registry and a signed release of `examples/acme-corp`. It asserts: the `coder_script` succeeds and the agent reaches `ready`; `halod status` reports the published release digest; the workspace owner's email lands as `subject` in `halod.yaml`; `halod` is installed root-owned from the release-style `.tar.gz` (and, in a second workspace, from a raw binary); `managed-settings.json` has `disableBypassPermissionsMode: disable`; Claude Code is installed; `requirements.toml` exists; neither managed file contains `bypassPermissions` or `danger-full-access`; the managed files are root-owned and mode 0644 or tighter. Three refusals leave the workspace with a failed start script, no `halod` binary and no managed settings: a wrong `halod` sha256, a release signed by a different key, and a pinned archive whose `halod` member is a symlink.

**UNVERIFIED:** Kubernetes-template Coder, Coder Tasks, and a real Coder deployment at scale.
:::

Workspace images must ship a root-owned `nodejs` and `npm` for npm-delivered CLIs (Codex, Gemini CLI); `halod` rejects user-owned (for example nvm) installs.

Coder templates define the workspace, so applying policy there gives environment-as-policy for cloud workspaces and unattended Coder Tasks.

```hcl
module "halos" {
  source           = "github.com/dshakes/halos//features/coder"
  agent_id         = coder_agent.main.id
  registry         = "ghcr.io/acme/halos-releases"
  org              = "acme"
  ring             = "ring1-canary"
  pubkey_pem       = file("release.pub")
  halod_url          = "https://github.com/dshakes/halos/releases/download/v0.6.1/halod_0.6.1_linux_{arch}.tar.gz"
  halod_sha256_amd64 = "bca5dc2f37e181e5b83b5e50d58bc07238d3dacf840825d56da4d9274a3c6003"
  halod_sha256_arm64 = "bf30cb22c5f43fb955dd56ba6366a2289f31ecfc722ef0090fd7d4804c14beed"
  # subject = "ada@acme.example"  # default: the workspace owner's email
}
```

`halod_url` is either a raw binary or, when the path ends in `.tar.gz`, a release archive. For an archive the sha256 pins the archive itself (the values above are from the v0.6.1 `checksums.txt`) and only a top-level regular file `halod` is extracted and installed; an archive where `halod` is a symlink or sits under a directory is refused. The same applies to the Dev Container Feature's `halodUrl` and `halodSha256` options.

All variables are regex-validated (no quotes, `$`, backticks or newlines except the PEM body). The module adds a `coder_script` that runs at workspace start and blocks login until done: it downloads `halod`, **verifies its sha256**, installs it root-owned, writes `/etc/halos/halod.yaml` (including `subject`, used by client-axis experiments, when non-empty) and the key, then runs `halod once --install` (verify pointer and release, apply, install verified CLI artifacts).

## Rollout

1. Point the template's `ring` at the desired ring.
2. Push the template version; existing workspaces adopt it on restart or update.
3. **Check:** `halod status` inside a workspace prints the release digest; it should equal the digest of the ring's current pointer.

## Tasks

Coder Tasks run agents unattended. Pair them with the profile's `permissions.sandbox`, `egress.allowedDomains` and a budget on headless runs. Never rely on `bypassPermissions`: Halos does not emit it.
