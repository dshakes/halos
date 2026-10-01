---
title: Installation
description: Build the Halos binaries, what each one does, and what you need around them.
sidebar:
  label: Components and source
---

:::note[No tagged release yet]
Build from source. `.goreleaser.yaml` is configured for checksummed, SBOM-carrying, cosign-signed archives, but it has not been run for a tag, so treat that pipeline as **UNVERIFIED**. Container images referenced by the Helm chart are placeholders until images are published.
:::

## Components

| Binary | Where it runs | Purpose |
|---|---|---|
| `halo` | CI, your workstation | Validate, plan, render, release (publish, promote, refresh), rollback, experiments, evals, exports, gateway artifacts, MCP server |
| `halod` | Developer machine or dev container (as root) | `run`, `once`, `status`: pull the ring's signed pointer, verify, apply, install pinned CLIs, report drift |
| `halo-proxy` | Anywhere on the request path | Stack-agnostic traffic plane: verify OIDC JWT, assign cohort, rewrite model, mirror, stamp headers |
| `halo-kong` | Kong (Go PDK plugin server) | The same behavior as an in-process Kong plugin |
| `halo-shadow` | Next to the gateway | Async single-turn mirror and pair store |
| `halo-server` | Your cluster | Fleet inventory, experiments API, self-service portal, enrollment, device tokens |

## From source

Requires Go 1.25+.

```bash
git clone https://github.com/dshakes/halos && cd halos
make build                     # halo halod halo-shadow halo-server halo-proxy halo-kong into bin/
export PATH="$PWD/bin:$PATH"
halo --help
```

**Check:** `halo version` prints `halo dev (commit ..., built ...)` and `halo --help` lists `validate`, `release`, `exp`, `eval`, `export`, `gateway`, `mcp` and more. Other checks the repo runs: `make test` (`go test -race ./...`), `make lint`, `make vuln`.

## What you need around them

| Need | Used for | Notes |
|---|---|---|
| An OCI registry | Releases and signed ring pointers | Any registry ORAS can push to. A local `registry:2` works with `--plain-http` |
| An ed25519 signing key | `halo release publish/promote/refresh`, `halo rollback` | `halo keys generate`. The primary signer must be ed25519 because `halod` verifies only ed25519. cosign (key, KMS or keyless) can be added as a co-signature with `--cosign-key` / `--cosign-keyless` |
| An OIDC provider | Portal login, gateway JWT verification, enrollment | Any compliant IdP (Okta, Entra ID, Google, Keycloak, Ping, Auth0). Set in `halos.yaml` under `identity` |
| A gateway (optional) | Traffic plane | `halo-proxy` runs with or without Kong, LiteLLM, Envoy, nginx or AWS API Gateway. See [stack-agnostic](/halos/concepts/stack-agnostic/) |
| ClickHouse + OTEL collector (optional) | Experiment analysis | `halo telemetry collector-config` generates the collector config; schema in `deploy/observability/clickhouse/schema.sql` |
| Docker (optional) | `halo eval run` trials, compose demo | Trials run with no network egress by default |

## Kong requirements

- You do **not** need Kong Enterprise. `halo-kong` runs as an external Go plugin server in Kong OSS; `halo-shadow` supplies the mirroring OSS lacks.
- Kong must be run with `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m`, or larger Claude Code first turns are spooled to disk and answered with 413 (never forwarded un-inspected). Details in [stack-agnostic](/halos/concepts/stack-agnostic/).
- Kong Enterprise and Konnect are **UNVERIFIED**.

## Signing

See [security model](/halos/concepts/security-model/) and [production deployment](/halos/guides/production-deployment/) for key handling and pointer refresh.
