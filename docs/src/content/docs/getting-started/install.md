---
title: Install
description: Install halo and halod on macOS, Linux and Windows, in CI, in dev containers and workspaces, and the control plane on Kubernetes.
---

<img class="diagram dark:sl-hidden" src="/halos/diagrams/everywhere-light.svg" alt="macOS, Linux, Windows, Dev Containers, Codespaces and Coder workspaces, CI runners and Kubernetes." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/everywhere-dark.svg" alt="macOS, Linux, Windows, Dev Containers, Codespaces and Coder workspaces, CI runners and Kubernetes." width="880" />

**`halo`** is the CLI you run in CI and on your workstation. **`halod`** is the fleet agent; it runs as root on each machine and applies the ring's signed release. Every channel below installs the same checksummed archives from a GitHub release. Always pin a version in automation; `v0.1.0` below is the current release.

:::note[Release status]
[`v0.1.0`](https://github.com/dshakes/halos/releases/tag/v0.1.1) is the first general-availability release. Every channel below installs from it: binaries, deb/rpm/apk packages, `install.sh`/`install.ps1`, Homebrew (`dshakes/homebrew-tap`), Scoop (`dshakes/scoop-bucket`), signed checksums and signed ghcr.io images, all verified by the release workflow after publishing; winget is submitted by hand. The [changelog](https://github.com/dshakes/halos/blob/main/CHANGELOG.md#011---2026-10-03) states what is GA and what is supported but not yet field-verified. Or [build from source](/halos/getting-started/installation/#from-source).
:::

## macOS

Homebrew (`brew install dshakes/tap/halo`) is not available until the tap is published. Use the script, which works on macOS and Linux and needs no sudo:

```sh
curl -fsSLO https://raw.githubusercontent.com/dshakes/halos/v0.1.0/install/install.sh
sh install.sh --version v0.1.0                # halo into ~/.local/bin
```

`install.sh` verifies `checksums.txt` against its cosign signature when `cosign` is on `PATH`. Without cosign it warns loudly and trusts only the sha256 checksums. It then verifies each archive. `--prefix DIR` changes the install location; `--with-agent` adds `halod`.

## Linux

```sh
sudo apt install ./halo_*.deb      # from the release assets; also .rpm / .apk, and the halod package
```

The `halo` and `halod` packages (deb, rpm, apk) install to `/usr/bin`. `halod` ships a systemd unit and `/etc/halos/`, but is **never enabled or enrolled** by the package. You write `/etc/halos/halod.yaml`, then run `systemctl enable --now halod`. `install.sh` works on Linux too.

## Windows

Scoop is not available until the bucket repo exists. Use `install.ps1` from the release, from an **elevated** PowerShell:

```powershell
.\install.ps1 -Version v0.1.0 -WithAgent         # to $env:ProgramFiles\Halos
```

`install.ps1` restricts the directory to SYSTEM and Administrators (write) and Users (read/execute), matching `halod`'s owner check. The binaries are not Authenticode-signed. A winget manifest (`Halos.Halo`) is built with each release but is not yet submitted to `winget-pkgs`.

## Run halod as a service

```sh
sudo halod service install --start        # print the unit first: halod service print
```

| OS | Registers | halod binary (default `--exe`) |
|---|---|---|
| macOS | launchd daemon `/Library/LaunchDaemons/dev.halos.halod.plist` | `/Library/Halos/bin/halod` |
| Linux | systemd unit `/etc/systemd/system/halod.service` | `/usr/bin/halod` |
| Windows | SYSTEM scheduled task `Halos`, at startup | `C:\Program Files\Halos\halod.exe` |

`halod` refuses to start unless its binary directory, config and state are root-owned and not writable by group or others. Install it into a root-owned path; `~/.local` is fine for `halo` but not for `halod`. Enroll a machine through the [self-service portal](/halos/concepts/self-service-portal/), or push the config with your MDM: see [laptops and MDM](/halos/guides/laptops-mdm/).

## Dev containers and cloud workspaces

- **Dev containers and Codespaces:** the Dev Container Feature. See [dev containers](/halos/guides/dev-containers/).
- **Coder:** the Coder module. See [Coder workspaces](/halos/guides/coder-workspaces/).

## CI runners

GitHub Actions:

```yaml
- uses: dshakes/halos@v0.1.0
  with:
    version: v0.1.0          # required; there is no "latest"
    # apply: "true"          # run `halod once` for a fixed ring (Linux/macOS, uses sudo)
    # registry: ghcr.io/acme/halos-releases
    # org: acme
    # ring: ci
    # pubkey: ${{ secrets.HALOS_RELEASE_PUBKEY }}
- run: halo validate
```

GitLab CI:

```yaml
include:
  - remote: https://raw.githubusercontent.com/dshakes/halos/v0.1.0/deploy/ci/gitlab/halos.gitlab-ci.yml
variables: {HALOS_VERSION: v0.1.0}
policy-check:
  extends: .halos
  script: [halo validate]
```

## Kubernetes: the control plane

```sh
helm install halos deploy/helm/halos --namespace halos --create-namespace
```

The chart runs `halo-server`, `halo-proxy` and `halo-shadow`, with an optional OTel collector and a Kong plugin resource. Images default to `ghcr.io/dshakes/halo-*:<chart appVersion>` (currently 0.1.0), which will not match a later release; set each component's `image.tag` to the version you install (for example `--set server.image.tag=0.4.0`). See [production deployment](/halos/guides/production-deployment/).

## Check

```console
$ halo version
$ halo --help        # lists validate, release, rollout, toggle, eval, upgrade, gateway, mcp ...
```

Then continue with the [quickstart](/halos/getting-started/quickstart/).
