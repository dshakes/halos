---
title: Dev containers
description: Apply a Halos release inside a Dev Container with the Halos Feature.
---

:::caution[UNVERIFIED end to end]
The Feature lives in `features/halos/` and its options below are read from `devcontainer-feature.json`. It has not been built into a real dev container image and started against a live registry in this repository's checks.
:::

## What the Feature does

1. Installs `halod` from `halodUrl`, **refusing to proceed unless its sha256 matches** `halodSha256`.
2. Embeds the release public key inline (`pubkeyPem`), or downloads it from `pubkey` only together with a verified `pubkeySha256`. Files are root-owned and non-writable by others, as `halod` requires.
3. Writes `/etc/halos/halod.yaml` and runs `halod once --install`: verify the ring's signed pointer and release, apply the managed settings, install the pinned CLIs from hash-verified artifacts.
4. Optionally starts an egress firewall at container start (default DROP for IPv4 and IPv6; allows the gateway and the registry only).

## Options

| Option | Default | Purpose |
|---|---|---|
| `registry` | | OCI repository holding releases, for example `ghcr.io/acme/halos-releases` |
| `org` | | Must equal the org in the signed release |
| `ring` | `ga` | Ring to follow |
| `pubkeyPem` | | ed25519 release public key, PKIX PEM contents (`\n`-escaped). Preferred |
| `pubkey`, `pubkeySha256` | | https URL of the key and its sha256 (both or neither) |
| `halodUrl` | | `halod` download URL; `{os}` and `{arch}` substituted |
| `halodSha256` | | **Required.** sha256, or `amd64=<hex>,arm64=<hex>` |
| `gatewayHost` | | Gateway hostname allowed through the firewall |
| `firewall` | `false` | Egress allowlist; needs `NET_ADMIN` and `NET_RAW` |

## Usage

`features/halos/example/.devcontainer/devcontainer.json`:

```json
{
  "name": "acme-dev",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  "features": {
    "ghcr.io/acme/halos-features/halos:0": {
      "registry": "ghcr.io/acme/halos-releases",
      "org": "acme",
      "ring": "canary",
      "pubkeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
      "halodUrl": "https://releases.acme.example/halod/{os}-{arch}/halod",
      "halodSha256": "amd64=<sha256>,arm64=<sha256>",
      "gatewayHost": "llm-gateway.acme.example",
      "firewall": true
    }
  },
  "runArgs": ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"]
}
```

Publish the Feature to your own registry (the `ghcr.io/acme/...` reference above is yours to define). The [portal](/halos/concepts/self-service-portal/) can hand developers a filled-in snippet with their ring, and `halo export devcontainer` bakes org defaults into a Feature source tree.

The ring name in this file is a request for *client* policy. The cohort for *traffic* is derived at the gateway from the verified token, so editing this file does not change a user's experiments. Treat the container as best-effort for client policy and the gateway as authoritative for cohorts.

**Check:** in the container, `claude --version` matches the release pin, the managed settings exist under `/etc/claude-code/`, `halod status` prints the release digest, and (with `firewall: true`) `curl https://example.com` is blocked.

## Rolling a ring change

A ring change is a new signed pointer (see [rings and releases](/halos/concepts/rings-and-releases/)). New containers and rebuilds pick it up at Feature install time. For running containers, add `"postStartCommand": "sudo /usr/local/lib/halos/halod once --install"`. Codespaces prebuilds must be re-triggered.
