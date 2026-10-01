---
title: Laptops and MDM
description: Deliver releases to laptops with the halod agent, portal enrollment, or Jamf, Kandji and Intune exports.
---

:::caution[UNVERIFIED on real devices]
`halod` runs as root inside Linux containers in `make uat-clis`; it has not run on real macOS or Windows hosts or as a long-running service. MDM exports (Jamf, Kandji, Intune) are generated and unit-tested but were **not pushed to any real tenant or device**. The PowerShell they emit (and `enroll.ps1`) has not been executed.
:::

Laptops are the weakest delivery path: a local admin can stop an agent or edit files. Use them as the last ring, and rely on the gateway for authoritative cohort and model enforcement.

## Option A: `halod` agent

`halod` runs as root under launchd (macOS) or systemd (Linux). On Windows, `halod service install` registers a SYSTEM scheduled task at startup (there is no native Windows service; see `cmd/halod/packaging/WINDOWS.md`). Each cycle it resolves the ring, verifies the signed ring pointer and release, applies files atomically, installs pinned CLIs from verified artifacts, and reports status.

Files (root-owned; `halod` refuses to start otherwise):

| | macOS | Linux |
|---|---|---|
| Binary | `/Library/Halos/bin/halod` | `/usr/local/lib/halos/halod` |
| Config | `/Library/Halos/etc/halod.yaml` | `/etc/halos/halod.yaml` |
| Public key | `/Library/Halos/etc/release.pub` | `/etc/halos/release.pub` |
| State | `/Library/Halos/var/state.json` | `/var/lib/halos/state.json` |
| Service | `cmd/halod/packaging/dev.halos.halod.plist` | `cmd/halod/packaging/halod.service` |

```yaml
# halod.yaml
registry: ghcr.io/acme/halos
org: acme-corp
ring: ring3-ga             # or ringEndpoint: https://halo.acme.example/api/v1/fleet/ring
pubkey: /etc/halos/release.pub
interval: 15m
reportURL: https://halo.acme.example/api/v1/fleet/report
deviceTokenFile: /etc/halos/device.token    # mode 0600
```

```bash
sudo halod once --config /etc/halos/halod.yaml     # one verified cycle
halod status --state /var/lib/halos/state.json   # last status as JSON
```

**Check:** `halod status` prints the ring, the release `digest`, per-harness `want` and `installed` versions, and an empty `drift` list. Full field list: [CLI reference](/halos/reference/binaries/#halod).

Claude Code paths are OS-protected, so a non-admin user cannot edit them. See [delivery](/halos/concepts/delivery/#where-the-files-land) for every harness and OS. Windows: config, key, token and state live under `C:\Program Files\Halos\`, never `C:\ProgramData` (whose default ACL lets any user pre-seed a config); verified binaries go to `C:\Program Files\Halos\bin`, which you add to the machine PATH via MDM.

### Enrolling with the portal

The [self-service portal](/halos/concepts/self-service-portal/) issues a single-use token that the developer passes to the `enroll.sh` script it serves (the exact command is shown in the portal). The script installs a sha256-pinned `halod`, fetches the release key, exchanges the token for a per-device credential and writes `halod.yaml` with `ringEndpoint`, so the server decides the ring from the developer's identity.

## Option B: MDM exports

```bash
halo export jamf --registry ghcr.io/acme/halos --pubkey release.pub --ring ring3-ga --org acme \
  --download-url 'https://dl.acme.example/halod-{os}-{arch}' \
  --halod-sha256 darwin/amd64=<hex> --halod-sha256 darwin/arm64=<hex> --out dist/jamf

halo export intune --registry ghcr.io/acme/halos --pubkey release.pub --ring ring3-ga --org acme \
  --download-url 'https://dl.acme.example/halod-{os}-{arch}.exe' \
  --halod-sha256 windows/amd64=<hex> --halod-sha256 windows/arm64=<hex> --out dist/intune
```

The export pulls the ring's signed pointer and release and **verifies both with `--pubkey` before writing anything**; `--org` is required with `--ring` and must match the org in the signed pointer.

| MDM | Output | Mechanism |
|---|---|---|
| Jamf, Kandji | `.mobileconfig` plus a `halod` postinstall | Claude Code reads the `com.anthropic.claudecode` managed preferences domain; the postinstall installs a sha256-pinned `halod` under `/Library/Halos` and a launchd daemon |
| Intune | PowerShell script | Writes `HKLM\SOFTWARE\Policies\ClaudeCode` and registers a SYSTEM startup task for `halod` |

Only Claude Code has an MDM channel; other harnesses are delivered through `halod`. MDM pushes a snapshot: it does not verify signatures at the endpoint by itself and cannot pin a CLI version. That is why the postinstall installs `halod`, and why `requiredMinimumVersion`/`requiredMaximumVersion` in the rendered settings make Claude Code refuse to run out of range.

## Choosing

| Need | Use |
|---|---|
| Drift detection, signature verification, CLI install | `halod` |
| Fleet already MDM-controlled | MDM export that installs `halod` (the exports do) |
| BYO laptops, no MDM | Portal enrollment |
| Managed, disposable environments | [Dev containers](/halos/guides/dev-containers/) or [Coder](/halos/guides/coder-workspaces/) |
