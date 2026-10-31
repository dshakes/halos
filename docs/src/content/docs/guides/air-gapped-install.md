---
title: Air-gapped install
description: Install Halos with no internet access, from an internal registry. Mirror images and the chart, point the chart at the mirror, verify signatures offline, and point halod at an internal OCI registry.
---

Halos needs the internet only to fetch its own artifacts. Mirror them once, on a connected machine, into a registry you control, and everything after that is internal. The commands below are for a human to run; none of them is run by the chart.

Status: the chart's `global.imageRegistry` and `global.imagePullSecrets` are rendered and tested (`go test ./internal/obsassets`). The mirroring and offline-verification commands below were **not exercised against a disconnected cluster** (UNVERIFIED); check them in your environment, in particular the cosign flags for your cosign version.

## 1. What to mirror

| Artifact | Source | Notes |
|---|---|---|
| `halo-server`, `halo-proxy`, `halo-shadow` (and `kong-halo` for Kong mode) | `ghcr.io/dshakes/<name>:<version>` | Only the ones you enable |
| git-sync | `registry.k8s.io/git-sync/git-sync:v4.4.0` | Policy sync sidecar and init container (`policy.gitSync.image`) |
| OTel collector | `docker.io/otel/opentelemetry-collector-contrib:0.161.0` | Only with `otel.enabled` |
| Helm chart | `oci://ghcr.io/dshakes/charts/halos` (v0.5.0 and later) | Older versions: the source checkout of the tag |
| Signatures | `.sig` and attestation tags next to each image and the chart | Copied with the artifact (below) |
| `halo`, `halod` binaries | Release archives + `checksums.txt` + `checksums.txt.sigstore.json` | For the portal's `halodURL` and your signer |
| Policy repo | Your Git host | Internal already |
| Releases (rings) | Your internal OCI registry | `halo release publish` pushes there |

The exact image list for your values is what `helm template` renders:

```bash
helm template halos oci://ghcr.io/dshakes/charts/halos --version 0.5.0 -f my-values.yaml | grep -E '^\s+image:' | sed 's/.*image: //' | sort -u
```

## 2. Mirror (connected machine)

With `crane` (preserves digests and multi-arch manifests):

```bash
MIRROR=registry.corp.example
V=0.5.0
for img in halo-server halo-proxy halo-shadow; do
  crane copy ghcr.io/dshakes/$img:$V $MIRROR/dshakes/$img:$V
  # cosign signature and attestation tags live beside the image; copy them too
  cosign copy ghcr.io/dshakes/$img:$V $MIRROR/dshakes/$img:$V
done
crane copy registry.k8s.io/git-sync/git-sync:v4.4.0 $MIRROR/git-sync/git-sync:v4.4.0
crane copy docker.io/otel/opentelemetry-collector-contrib:0.161.0 $MIRROR/otel/opentelemetry-collector-contrib:0.161.0
```

`skopeo copy --all docker://SRC docker://DST` does the same. With no direct path between the networks, write to a directory (`crane pull --format oci SRC dir/`, or `skopeo copy ... oci:dir`), carry the directories across, and `crane push dir DST` inside.

The chart, with Helm and `oras`:

```bash
helm pull oci://ghcr.io/dshakes/charts/halos --version $V            # halos-$V.tgz
oras copy -r ghcr.io/dshakes/charts/halos:$V $MIRROR/charts/halos:$V   # -r also copies the signature referrers
# or inside the network: helm push halos-$V.tgz oci://$MIRROR/charts   (Helm push does not carry the signature; cosign copy it)
```

The mirror must hold each image under the **same repository path** as upstream (`dshakes/halo-server`, `git-sync/git-sync`, `otel/opentelemetry-collector-contrib`), because `global.imageRegistry` replaces only the registry host.

## 3. Verify signatures offline

Images and the chart are signed **keyless** (Sigstore, the release workflow's identity); there is no long-lived image-signing public key to bundle. Offline you verify against a trusted root instead of calling Fulcio and Rekor:

```bash
# connected machine: fetch the Sigstore trusted root once and carry it in
cosign trusted-root create > trusted_root.json                  # or copy it from a TUF mirror you operate

# offline machine (confirm the flags with `cosign verify --help` for your cosign version)
cosign verify --offline --trusted-root trusted_root.json \
  --certificate-identity https://github.com/dshakes/halos/.github/workflows/release.yml@refs/tags/v$V \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  $MIRROR/dshakes/halo-server:$V
```

Archives are verified the same way with `checksums.txt.sigstore.json`: `cosign verify-blob --offline --trusted-root trusted_root.json --bundle checksums.txt.sigstore.json --certificate-identity ... --certificate-oidc-issuer ... checksums.txt`, then `sha256sum -c`.

The **ring signing key** is different and fully offline: releases and ring pointers are signed with your own `halo keys generate` key pair, and `halod` verifies them against the bundled public key (`pubkey: /etc/halos/release.pub`, also served by `halo-server` at `/enroll/release.pub`). Nothing about ring verification touches the internet.

Pin the mirrored images by digest (`server.image.digest`, `proxy.image.digest`, ...) so a mutated mirror tag cannot change what runs; an admission policy that checks the signature on admit is the strongest gate.

## 4. Install from the mirror

```yaml
# my-values.yaml
global:
  imageRegistry: registry.corp.example          # replaces the registry of every image, including git-sync and the collector
  imagePullSecrets: [{name: corp-registry}]     # on every pod, the migrate Job included
policy:
  gitSync:
    repo: https://git.corp.example/platform/halos-policy.git
```

```bash
helm install halos oci://registry.corp.example/charts/halos --version 0.5.0 -n halos -f my-values.yaml   # a human runs this
helm template halos oci://registry.corp.example/charts/halos --version 0.5.0 -f my-values.yaml | grep 'image:' | grep -v registry.corp.example   # must print nothing
```

The network policy has no FQDN matching: grant the internal registry, Git host and IdP by CIDR or peer through `networkPolicy.egress.*` ([production deployment](/halos/guides/production-deployment/)).

## 5. Point halod at the internal registry

`halod` pulls ring pointers and releases from an OCI registry. Run it against yours, with the public key you generated and, if the registry is plain HTTP inside the network, `plainHTTP`:

```yaml
# /etc/halos/halod.yaml
registry: registry.corp.example/halos       # where `halo release publish` pushed
ring: ring3-ga
pubkey: /etc/halos/release.pub
# plainHTTP: true                           # only for an HTTP registry on a trusted network
```

For the self-service portal, set `server.portal.registry` to the same registry and `server.portal.halodURL` to an internal URL that serves the `halod` binary for each OS and architecture (with `server.portal.halodSHA256` matching), so `enroll.sh` downloads nothing from the internet. Publish releases with `halo release publish --registry registry.corp.example/halos --key ...` from a signer that can reach it. Upstream CLI version watching (`halo upgrade`) and provider calls need their own internal routes (a model gateway, an npm mirror); Halos does not mirror those.

## What still needs outside access

Model providers (unless you route to an internal gateway or a cloud endpoint reachable from the cluster), the OIDC issuer if it is external, ClickHouse and the SIEM if hosted. Those are your egress rules, not Halos downloads.
