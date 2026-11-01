---
title: Install
description: Install halo and halod on macOS, Linux and Windows, in CI, in dev containers and workspaces, and the control plane on Kubernetes.
---

<img class="diagram dark:sl-hidden" src="/halos/diagrams/everywhere-light.svg" alt="macOS, Linux, Windows, Dev Containers, Codespaces and Coder workspaces, CI runners and Kubernetes." width="880" />
<img class="diagram light:sl-hidden" src="/halos/diagrams/everywhere-dark.svg" alt="macOS, Linux, Windows, Dev Containers, Codespaces and Coder workspaces, CI runners and Kubernetes." width="880" />

**`halo`** is the CLI you run in CI and on your workstation. **`halod`** is the fleet agent; it runs as root on each machine and applies the ring's signed release. Every channel below installs the same checksummed archives from a GitHub release. Always pin a version in automation; `v0.5.0` below is the current release.

:::note[Release status]
[`v0.5.0`](https://github.com/dshakes/halos/releases/tag/v0.5.0) is the current release (`v0.1.0` was published without its Homebrew formula, Scoop manifest and provenance attestation; see the changelog; `v0.1.1` superseded it). Every channel below installs from it: binaries, deb/rpm/apk packages, `install.sh`/`install.ps1`, Homebrew (`dshakes/homebrew-tap`), Scoop (`dshakes/scoop-bucket`), signed checksums and signed ghcr.io images, all verified by the release workflow after publishing; winget is built but not submitted. The [changelog](https://github.com/dshakes/halos/blob/main/CHANGELOG.md#030---2026-10-23) states what is GA and what is supported but not yet field-verified. Or [build from source](#from-source).
:::

## macOS

```sh
brew install dshakes/tap/halo                 # formula in github.com/dshakes/homebrew-tap
```

Or the script, which works on macOS and Linux and needs no sudo:

```sh
curl -fsSLO https://raw.githubusercontent.com/dshakes/halos/v0.5.0/install/install.sh
sh install.sh --version v0.5.0                # halo into ~/.local/bin; tells you if that is not on PATH
```

`install.sh` verifies `checksums.txt` against its cosign signature when `cosign` is on `PATH`. Without cosign it warns loudly and trusts only the sha256 checksums. It then verifies each archive. `--prefix DIR` changes the install location; `--with-agent` adds `halod`.

## Linux

```sh
curl -fsSLO https://github.com/dshakes/halos/releases/download/v0.5.0/halo_0.5.0_linux_amd64.deb
sudo apt install ./halo_0.5.0_linux_amd64.deb      # also .rpm / .apk, arm64, and the halod_* packages
```

The `halo` and `halod` packages (deb, rpm, apk) install to `/usr/bin`. `halod` ships a systemd unit and `/etc/halos/`, but is **never enabled or enrolled** by the package. You write `/etc/halos/halod.yaml`, then run `systemctl enable --now halod`. `install.sh` works on Linux too.

## Windows

```powershell
scoop bucket add dshakes https://github.com/dshakes/scoop-bucket
scoop install halo
```

Or [`install.ps1`](https://raw.githubusercontent.com/dshakes/halos/v0.5.0/install/install.ps1) from the release tag, from an **elevated** PowerShell:

```powershell
.\install.ps1 -Version v0.5.0 -WithAgent         # to $env:ProgramFiles\Halos
```

## npm (any OS)

With Node 18 or later, run `halo` without installing it, or install it globally:

```sh
npx @dshakesnotbot/halo quickstart
npm install -g @dshakesnotbot/halo
```

npm downloads only the binary for your OS and CPU (macOS, Linux and Windows, on x64 or arm64). The release workflow builds these packages from the signed release archives after checking each one against the Sigstore-verified `checksums.txt`, and publishes them with npm provenance. `npm audit signatures` confirms the provenance. The npm packages contain `halo` only; use another method for `halod`.

`install.ps1` restricts the directory to SYSTEM and Administrators (write) and Users (read/execute), matching `halod`'s owner check. The binaries are not Authenticode-signed. A winget manifest (`Halos.Halo`) is built with each release but is not submitted to `winget-pkgs`.

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
- uses: dshakes/halos@v0.5.0
  with:
    version: v0.5.0          # required; there is no "latest"
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
  - remote: https://raw.githubusercontent.com/dshakes/halos/v0.5.0/deploy/ci/gitlab/halos.gitlab-ci.yml
variables: {HALOS_VERSION: v0.5.0}
policy-check:
  extends: .halos
  script: [halo validate]
```

## Kubernetes: the control plane

```sh
helm install halos deploy/helm/halos --namespace halos --create-namespace
```

The chart runs `halo-server`, `halo-proxy` and `halo-shadow`, with an optional OTel collector and a Kong plugin resource. Images default to `ghcr.io/dshakes/halo-*:<chart appVersion>` (currently 0.5.0); to run a different release, set each component's `image.tag` (for example `--set server.image.tag=0.1.1`). See [production deployment](/halos/guides/production-deployment/).

## Components

| Binary | Where it runs | Purpose |
|---|---|---|
| `halo` | CI, your workstation | Validate, plan, render, release (publish, promote, refresh), rollback, experiments, evals, exports, gateway artifacts, MCP server |
| `halod` | Developer machine or dev container (as root) | `run`, `once`, `status`: pull the ring's signed pointer, verify, apply, install pinned CLIs, report drift |
| `halo-proxy` | Anywhere on the request path | Stack-agnostic traffic plane: verify OIDC JWT, assign cohort, rewrite model, mirror, stamp headers |
| `halo-kong` | Kong (Go PDK plugin server) | The same behavior as an in-process Kong plugin |
| `halo-shadow` | Next to the gateway | Async mirror (first turn or every step) and pair store |
| `halo-server` | Your cluster | Fleet inventory, experiments API, self-service portal, enrollment, device tokens |

## From source

Requires Go 1.25+.

```bash
git clone https://github.com/dshakes/halos && cd halos
make build                     # halo halod halo-shadow halo-server halo-proxy halo-kong into bin/
export PATH="$PWD/bin:$PATH"
halo --help
```

`halo version` prints `halo <version> (commit ..., built ...)` and `halo --help` lists `validate`, `release`, `exp`, `eval`, `export`, `gateway`, `mcp` and more. Other checks the repo runs: `make test` (`go test -race ./...`), `make lint`, `make vuln`.

For FIPS 140-3 deployments, `make build-fips` builds the same binaries against Go's FIPS module into `bin/fips/`; releases ship them as `*_fips_*` archives and `:<version>-fips` images ([FIPS 140-3 builds](/halos/guides/fips/)).

## What you need around them

| Need | Used for | Notes |
|---|---|---|
| An OCI registry | Releases and signed ring pointers | Any registry ORAS can push to. A local `registry:2` works with `--plain-http` |
| A signing key (ed25519 or ECDSA P-256) | `halo release publish/promote/refresh`, `halo rollback` | `halo keys generate` (written to your per-user config directory; never into a git work tree without `--force`), or a KMS or HSM key with `--key-uri` ([key management](/halos/guides/key-management/)). The primary signer must be ed25519 or ECDSA P-256 because `halod` verifies only those. cosign (key, KMS or keyless) can be added as a co-signature with `--cosign-key` / `--cosign-keyless` |
| An OIDC provider | Portal login, gateway JWT verification, enrollment | Any compliant IdP (Okta, Entra ID, Google, Keycloak, Ping, Auth0). Set in `halos.yaml` under `identity` |
| A gateway (optional) | Traffic plane | `halo-proxy` runs with or without Kong, LiteLLM, Envoy, nginx or AWS API Gateway. See [stack-agnostic](/halos/concepts/stack-agnostic/) |
| ClickHouse + OTEL collector (optional) | Experiment analysis | `halo telemetry collector-config` generates the collector config; schema in `deploy/observability/clickhouse/schema.sql` |
| Docker (optional) | `halo eval run` trials, compose demo | Trials run with no network egress by default |

## Kong requirements

- You do **not** need Kong Enterprise. `halo-kong` runs as an external Go plugin server in Kong OSS; `halo-shadow` supplies the mirroring OSS lacks.
- Kong must be run with `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m`, or larger Claude Code first turns are spooled to disk and answered with 413 (never forwarded un-inspected). Details in [stack-agnostic](/halos/concepts/stack-agnostic/).
- Kong Enterprise and Konnect are **UNVERIFIED**.

## Signing

See [security model](/halos/concepts/security-model/) and [production deployment](/halos/guides/production-deployment/) for key handling and pointer refresh, and [signing keys in a KMS or HSM](/halos/guides/key-management/) to keep the key in AWS KMS or an HSM.

## Check

```console
$ halo version
halo 0.5.0 (commit <sha>, built <date>)
$ halo --help        # lists validate, release, rollout, toggle, eval, upgrade, gateway, mcp ...
```

Then go back to [Start here](/halos/getting-started/start-here/) and pick a path: `halo quickstart` to see the whole thing on Docker, or `halo doctor` to put your own machine under policy.
