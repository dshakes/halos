---
title: Coder workspaces
description: Use the Halos Coder module in templates, including Coder Tasks.
---

:::caution[UNVERIFIED]
The Terraform module in `features/coder/` passes `tofu init && tofu validate` (OpenTofu 1.12.0, run by hand on 2026-10-04; not part of CI) but has never been applied, and no Coder deployment was used. Variable names below are read from `main.tf`.
:::

Coder templates define the workspace, so applying policy there gives environment-as-policy for cloud workspaces and unattended Coder Tasks.

```hcl
module "halos" {
  source           = "github.com/dshakes/halos//features/coder"
  agent_id         = coder_agent.main.id
  registry         = "ghcr.io/acme/halos-releases"
  org              = "acme"
  ring             = "ring1-canary"
  pubkey_pem       = file("release.pub")
  halod_url          = "https://releases.acme.example/halod/{os}-{arch}/halod"
  halod_sha256_amd64 = "<sha256>"
  halod_sha256_arm64 = "<sha256>"
}
```

All variables are regex-validated (no quotes, `$`, backticks or newlines except the PEM body). The module adds a `coder_script` that runs at workspace start and blocks login until done: it downloads `halod`, **verifies its sha256**, installs it root-owned, writes `/etc/halos/halod.yaml` and the key, then runs `halod once --install` (verify pointer and release, apply, install verified CLI artifacts).

## Rollout

1. Point the template's `ring` at the desired ring.
2. Push the template version; existing workspaces adopt it on restart or update.
3. **Check:** `halod status` inside a workspace prints the release digest; it should equal the digest of the ring's current pointer.

## Tasks

Coder Tasks run agents unattended. Pair them with the profile's `permissions.sandbox`, `egress.allowedDomains` and a budget on headless runs. Never rely on `bypassPermissions`: Halos does not emit it.
