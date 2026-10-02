---
title: Tech stack
description: Every language, library, image and tool Halos is built, shipped and tested with, read from go.mod, the package.json files, deploy/ and the CI workflows.
---

This page lists everything Halos depends on, grouped by what it is for. Each entry comes from a source file in the repo, not from memory:

- **Go modules** come from [`go.mod`](https://github.com/dshakes/halos/blob/main/go.mod).
- **npm packages** come from [`web/package.json`](https://github.com/dshakes/halos/blob/main/web/package.json) and [`docs/package.json`](https://github.com/dshakes/halos/blob/main/docs/package.json).
- **Container images** come from `deploy/` and `test/uat/`.
- **CI tooling** comes from `.github/workflows/` and [`.goreleaser.yaml`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml).

:::note[Drift check]
A test in [`internal/docgen/architecture_test.go`](https://github.com/dshakes/halos/blob/main/internal/docgen/architecture_test.go) checks this page against the source files:

- **Go module tables:** they must list exactly the direct requirements in `go.mod`, with the same versions. For each module, the "Used by" column must match what `go list` reports across `GOOS=linux`, `darwin` and `windows`. Packages that import a module only from tests are listed after `tests:`.
- **npm tables:** they must match both `package.json` files.

Edit a dependency and forget this page, and `go test ./internal/docgen` fails.
:::

## Language and runtime

| Piece | Version | Where it is pinned | Notes |
| --- | --- | --- | --- |
| Go language | `go 1.25.0` | [`go.mod:3`](https://github.com/dshakes/halos/blob/main/go.mod#L3) | Minimum language version. |
| Go toolchain | `go1.26.6` | [`go.mod:5`](https://github.com/dshakes/halos/blob/main/go.mod#L5) | CI uses `go-version-file: go.mod` ([`ci.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml)). |
| Go build images | `golang:1.25` | [`deploy/compose/Dockerfile.svc:2`](https://github.com/dshakes/halos/blob/main/deploy/compose/Dockerfile.svc#L2) | Demo and compose builds. The eval images pin `golang:1.25-bookworm` by digest ([`evals/images/claude/Dockerfile:4`](https://github.com/dshakes/halos/blob/main/evals/images/claude/Dockerfile#L4)). |
| Node.js | `22` | [`ci.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) (`setup-node` with `node-version: 22`), [`docs.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/docs.yml) | Builds the web console and the docs only. No Node runs in a Halos binary at run time. |
| Binaries | `CGO_ENABLED=0`, `-trimpath` | [`.goreleaser.yaml:16-20`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L16-L20) | Static binaries for darwin, linux and windows, amd64 and arm64. `halo-kong` is linux only. |

Most of the core is the Go standard library:

- **Reverse proxy:** `net/http` and `net/http/httputil.ReverseProxy` ([`cmd/halo-proxy/proxy.go:95-107`](https://github.com/dshakes/halos/blob/main/cmd/halo-proxy/proxy.go#L95-L107)).
- **Signatures:** `crypto/ed25519` for release, pointer and kill-list signatures ([`internal/bundle/sign.go`](https://github.com/dshakes/halos/blob/main/internal/bundle/sign.go), [`internal/gateway/killswitch.go:44-75`](https://github.com/dshakes/halos/blob/main/internal/gateway/killswitch.go#L44-L75)).
- **Hashing:** `crypto/sha256` for content addressing and assignment hashing ([`internal/assign/assign.go:16-19`](https://github.com/dshakes/halos/blob/main/internal/assign/assign.go#L16-L19)).
- **Bundles:** `archive/tar` for the release bundle ([`internal/release/release.go:191-223`](https://github.com/dshakes/halos/blob/main/internal/release/release.go#L191-L223)).
- **Logs:** `log/slog` for structured logs.

## Go modules

### CLI

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `github.com/spf13/cobra` | `v1.10.2` | The `halo` command tree; the CLI reference pages are generated from it. | `cmd/halo`, `internal/docgen` |
| `github.com/spf13/pflag` | `v1.0.9` | Reading flag definitions when generating the CLI reference. | `internal/docgen` |
<!-- /check -->

### Policy and configuration

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `gopkg.in/yaml.v3` | `v3.0.1` | Policy YAML with strict decoding and line-numbered errors ([`internal/policy/load.go:110-117`](https://github.com/dshakes/halos/blob/main/internal/policy/load.go#L110-L117)), binary configs, and comment-preserving YAML edits for PRs. | `cmd/halo`, `cmd/halo-proxy`, `cmd/halo-shadow`, `cmd/halod`, `internal/eval`, `internal/gateway/kong`, `internal/intent`, `internal/mcpserver`, `internal/policy`, `internal/promote`, `internal/rollout`, `internal/server`, `internal/telemetry`, `internal/upgrade`, `internal/yamledit`; tests: `internal/gateway/adapters` |
| `github.com/pelletier/go-toml/v2` | `v2.4.3` | Codex `config.toml` rendering, the rendered-config backstop, and toggle fragment merges. | `internal/harness/codex`, `internal/release`, `internal/toggle` |
| `github.com/santhosh-tekuri/jsonschema/v6` | `v6.0.3` | Tests that validate policy documents against `schemas/*.schema.json`. | tests: `internal/policy` |
| `howett.net/plist` | `v1.0.1` | macOS MDM configuration profile export. | `internal/delivery/mdm` |
<!-- /check -->

### Crypto and supply chain

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `oras.land/oras-go/v2` | `v2.6.2` | Pushing and pulling release bundles and signed ring pointers as OCI artifacts ([`internal/bundle/bundle.go:50-125`](https://github.com/dshakes/halos/blob/main/internal/bundle/bundle.go#L50-L125)). | `cmd/halo`, `cmd/halod`, `internal/bundle`, `internal/server` |
| `github.com/opencontainers/image-spec` | `v1.1.1` | OCI manifest and descriptor types. | `internal/bundle`; tests: `cmd/halo` |
| `github.com/opencontainers/go-digest` | `v1.0.0` | Content digests for blobs and pointer statements. | `internal/bundle` |
<!-- /check -->

Signing itself uses the standard library: ed25519 primary signatures in [`internal/bundle/sign.go`](https://github.com/dshakes/halos/blob/main/internal/bundle/sign.go). cosign is an optional co-signer, called as an external `cosign sign-blob` process ([`internal/bundle/sign.go:103-190`](https://github.com/dshakes/halos/blob/main/internal/bundle/sign.go#L103-L190)); it is not a Go dependency.

### Identity

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `github.com/coreos/go-oidc/v3` | `v3.21.0` | OIDC discovery and JWT / ID-token verification against the issuer's JWKS: gateway callers ([`internal/identity/oidc.go:71-91`](https://github.com/dshakes/halos/blob/main/internal/identity/oidc.go#L71-L91)) and console login. | `internal/identity`, `internal/server` |
| `golang.org/x/oauth2` | `v0.36.0` | The console's OIDC authorization-code flow. | `internal/server` |
| `golang.org/x/time` | `v0.15.0` | Per-IP rate limiting of failed token attempts. | `internal/server` |
<!-- /check -->

### Gateway

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `github.com/Kong/go-pdk` | `v0.11.2` | The Kong Go plugin server and PDK that `halo-kong` runs on ([`cmd/halo-kong/main.go:316-320`](https://github.com/dshakes/halos/blob/main/cmd/halo-kong/main.go#L316-L320)). | `cmd/halo-kong` |
| `github.com/aws/aws-sdk-go-v2` | `v1.47.0` | SigV4 signing of direct Bedrock requests (`aws/signer/v4`) ([`internal/gateway/upstreamauth/bedrock.go:139-194`](https://github.com/dshakes/halos/blob/main/internal/gateway/upstreamauth/bedrock.go#L139-L194)). | `internal/gateway/upstreamauth`; tests: `cmd/halo-proxy` |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.33.4` | The default AWS credential chain for that signer. | `internal/gateway/upstreamauth` |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.20.4` | Static credentials in the SigV4 tests. | tests: `cmd/halo-proxy`, `internal/gateway/upstreamauth` |
| `github.com/aws/smithy-go` | `v1.28.1` | Used by the SigV4 tests. | tests: `internal/gateway/upstreamauth` |
<!-- /check -->

The gateway's data path is `net/http` and `httputil.ReverseProxy`. Vertex tokens come from the metadata server, or from a service-account JWT signed with the standard library ([`internal/gateway/upstreamauth/vertex.go:205-214`](https://github.com/dshakes/halos/blob/main/internal/gateway/upstreamauth/vertex.go#L205-L214)); no Google SDK is used.

### Telemetry

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `google.golang.org/protobuf` | `v1.36.11` | Hand-encodes OTLP/HTTP protobuf with `protowire` for `halo.gateway.*` metrics ([`internal/telemetry/gwmetrics/gwmetrics.go`](https://github.com/dshakes/halos/blob/main/internal/telemetry/gwmetrics/gwmetrics.go)). | `internal/telemetry/gwmetrics` |
| `go.opentelemetry.io/proto/otlp` | `v1.10.0` | Decodes that output in tests. | tests: `internal/telemetry/gwmetrics` |
<!-- /check -->

No OpenTelemetry SDK runs in a Halos binary. The collector, ClickHouse and Grafana run as containers (see [Images](#container-images)).

### Agents (MCP)

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | The MCP server behind `halo mcp serve` ([`internal/mcpserver/server.go:48-71`](https://github.com/dshakes/halos/blob/main/internal/mcpserver/server.go#L48-L71)). | `cmd/halo`, `internal/mcpserver` |
<!-- /check -->

### Platform

<!-- check: go.mod -->
| Module | Version | Used for | Used by |
| --- | --- | --- | --- |
| `golang.org/x/sys` | `v0.41.0` | Windows ACL and ownership checks on halod's trusted files and private files (`windows` build tag only). | `cmd/halod`, `internal/fsutil` |
<!-- /check -->

## Web console

[`web/package.json`](https://github.com/dshakes/halos/blob/main/web/package.json) is a React single-page app built with Vite. With the `webdist` build tag it is embedded in `halo-server` ([`.goreleaser.yaml:29-33`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L29-L33)).

<!-- check: web/package.json -->
| Package | Range | Role |
| --- | --- | --- |
| `react` | `^19.3.0` | UI |
| `react-dom` | `^19.3.0` | DOM renderer |
| `@tanstack/react-query` | `^5.104.0` | Server state and caching for the `/api/v1` calls |
| `zod` | `^4.6.5` | Runtime validation of API responses |
| `vite` | `^8.3.1` | Dev server and bundler |
| `@vitejs/plugin-react` | `^6.1.1` | React support for Vite |
| `tailwindcss` | `^4.3.3` | Styling |
| `@tailwindcss/vite` | `^4.3.3` | Tailwind Vite plugin |
| `typescript` | `^7.0.2` | Type checking (`tsc --noEmit` in `npm run build`) |
| `@types/react` | `^19.3.0` | React types |
| `@types/react-dom` | `^19.3.0` | React DOM types |
| `@types/node` | `^22.20.5` | Node types for the Playwright config |
| `@playwright/test` | `^1.63.0` | Headless Chromium click-through of the console (`make demo-e2e`) |
<!-- /check -->

## Docs site

[`docs/package.json`](https://github.com/dshakes/halos/blob/main/docs/package.json) is Astro with Starlight, deployed to GitHub Pages by [`docs.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/docs.yml) (`withastro/action`).

<!-- check: docs/package.json -->
| Package | Range | Role |
| --- | --- | --- |
| `astro` | `^7.3.5` | Static site generator |
| `@astrojs/starlight` | `^0.42.4` | Docs theme, search, sidebar |
| `@fontsource-variable/inter` | `^5.3.0` | Body font |
| `@fontsource-variable/jetbrains-mono` | `^5.3.0` | Code font |
| `@fontsource-variable/sora` | `^5.3.0` | Display font |
<!-- /check -->

The diagrams on these pages are SVGs generated by [`assets/src/build.py`](https://github.com/dshakes/halos/blob/main/assets/src/build.py), with light and dark versions. They are not Mermaid.

## Container images

| Image | Tag / digest | Where | Role |
| --- | --- | --- | --- |
| `gcr.io/distroless/static-debian12:nonroot` | `sha256:afa5c872…` | [`deploy/docker/Dockerfile.service:4`](https://github.com/dshakes/halos/blob/main/deploy/docker/Dockerfile.service#L4) | Base image of the released `halo-server`, `halo-proxy` and `halo-shadow` images ([`.goreleaser.yaml:43-67`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L43-L67)). |
| `kong` | `3.9`, `sha256:12972ce1…` | [`deploy/docker/Dockerfile.kong:6`](https://github.com/dshakes/halos/blob/main/deploy/docker/Dockerfile.kong#L6), [`scripts/uat-kong.sh:15-16`](https://github.com/dshakes/halos/blob/main/scripts/uat-kong.sh#L15-L16) | Kong OSS that `halo-kong` runs inside (`ghcr.io/dshakes/kong-halo`). The compose stack uses the unpinned `kong:3.9` ([`deploy/compose/Dockerfile.kong:9`](https://github.com/dshakes/halos/blob/main/deploy/compose/Dockerfile.kong#L9)). |
| `otel/opentelemetry-collector-contrib` | `0.161.0`, `sha256:fd328de2…` | [`deploy/observability/docker-compose.yml:28`](https://github.com/dshakes/halos/blob/main/deploy/observability/docker-compose.yml#L28), [`deploy/helm/halos/values.yaml:274`](https://github.com/dshakes/halos/blob/main/deploy/helm/halos/values.yaml#L274) | OTLP receivers to ClickHouse. Its config is generated by `internal/telemetry` ([`collector.go:157-282`](https://github.com/dshakes/halos/blob/main/internal/telemetry/collector.go#L157-L282)). |
| `clickhouse/clickhouse-server` | `26.9.7.9`, `sha256:1f9c29a7…` | [`deploy/observability/docker-compose.yml:16`](https://github.com/dshakes/halos/blob/main/deploy/observability/docker-compose.yml#L16) | Evidence store; schema in [`deploy/observability/clickhouse/schema.sql`](https://github.com/dshakes/halos/blob/main/deploy/observability/clickhouse/schema.sql). |
| `grafana/grafana` | `13.2.3`, `sha256:b28bae15…` | [`deploy/observability/docker-compose.yml:73`](https://github.com/dshakes/halos/blob/main/deploy/observability/docker-compose.yml#L73) | Dashboards ([`deploy/observability/grafana/dashboard.json`](https://github.com/dshakes/halos/blob/main/deploy/observability/grafana/dashboard.json)). |
| `registry.k8s.io/git-sync/git-sync` | `v4.4.0` | [`deploy/helm/halos/values.yaml:37`](https://github.com/dshakes/halos/blob/main/deploy/helm/halos/values.yaml#L37) | Keeps the served policy directory in sync in the Helm chart. |
| `registry:2` | `2` | [`deploy/compose/docker-compose.demo.yml:23`](https://github.com/dshakes/halos/blob/main/deploy/compose/docker-compose.demo.yml#L23), [`ci.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) (`e2e` service) | OCI registry for the demo and the e2e tests. |
| `alpine` | `3.20` / `3.22` | [`deploy/compose/Dockerfile.svc:10`](https://github.com/dshakes/halos/blob/main/deploy/compose/Dockerfile.svc#L10), [`test/uat/k8s/Dockerfile:4`](https://github.com/dshakes/halos/blob/main/test/uat/k8s/Dockerfile#L4) | Runtime images for the demo and UAT. |
| `node` | `22-alpine`, `22-bookworm-slim` (digest) | [`deploy/compose/demo/Dockerfile.console:4`](https://github.com/dshakes/halos/blob/main/deploy/compose/demo/Dockerfile.console#L4), [`evals/images/claude/Dockerfile:6`](https://github.com/dshakes/halos/blob/main/evals/images/claude/Dockerfile#L6) | Builds the console in the demo; base image of the eval images that run the real CLIs. |

## Packaging and deploy

| Tool | Version | Where | What it does |
| --- | --- | --- | --- |
| GoReleaser | `~> v2` (config `version: 2`) | [`.goreleaser.yaml`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml), [`ci.yml` `packaging` job](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) | Archives, checksums, multi-arch images (`dockers_v2`), Homebrew, Scoop and a winget manifest. |
| nfpm (via GoReleaser) | n/a | [`.goreleaser.yaml:97-122`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L97-L122) | `deb`, `rpm` and `apk` packages for `halo` and `halod`, plus the `halod` systemd unit ([`deploy/packaging/halod.service`](https://github.com/dshakes/halos/blob/main/deploy/packaging/halod.service)). |
| cosign (via GoReleaser) | n/a | [`.goreleaser.yaml:157-169`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L157-L169) | Keyless `sign-blob` of `checksums.txt` and keyless `sign` of images. |
| syft (via GoReleaser) | n/a | [`.goreleaser.yaml:155-156`](https://github.com/dshakes/halos/blob/main/.goreleaser.yaml#L155-L156) | SBOMs for archives (needs `syft` on `PATH`). |
| Helm chart `halos` | chart `0.1.0`, `kubeVersion >=1.27.0-0` | [`deploy/helm/halos/Chart.yaml`](https://github.com/dshakes/halos/blob/main/deploy/helm/halos/Chart.yaml) | `halo-server`, `halo-proxy`, `halo-shadow`, an optional OTel collector and the Kong plugin CR. |
| Docker Compose | v2 | [`deploy/compose/`](https://github.com/dshakes/halos/tree/main/deploy/compose), [`deploy/observability/`](https://github.com/dshakes/halos/tree/main/deploy/observability) | `make demo` (the whole stack, seeded from `examples/acme-corp`) and the observability stack. |

:::caution[UNVERIFIED: real release signing]
CI runs GoReleaser only as a snapshot, with `--skip=publish,sign,sbom,docker` ([`ci.yml` `packaging` job](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml)). [`release.yml`](https://github.com/dshakes/halos/blob/main/.github/workflows/release.yml) tags the release and publishes GitHub release notes, but does not run GoReleaser. So no workflow in this repo exercises the keyless cosign signing, the SBOMs or the image pushes configured in `.goreleaser.yaml`.
:::

## CI and quality tooling

| Tool | Version | Where |
| --- | --- | --- |
| golangci-lint | `v2.14.0` (golangci-lint-action `v8.0.0`) | [`ci.yml` `lint`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) |
| govulncheck | govulncheck-action `v1.1.0` | [`ci.yml` `vuln`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml); `make vuln` runs `govulncheck@latest` ([`Makefile:15-16`](https://github.com/dshakes/halos/blob/main/Makefile#L15-L16)) |
| `go test -race` | toolchain from `go.mod` | [`ci.yml` `test`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml), plus macOS and Windows in the `cross` job |
| `go mod tidy` drift check | n/a | [`ci.yml` `tidy`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) |
| shellcheck | runner default | [`ci.yml` `packaging`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml) (`install/install.sh`, `deploy/packaging/*.sh`) |
| GitHub Actions | pinned by commit SHA | every `uses:` in [`.github/workflows/`](https://github.com/dshakes/halos/tree/main/.github/workflows) |

## Test tooling

| Tool | Version | Where | What it tests |
| --- | --- | --- | --- |
| kind | `v0.27.0` (`go install sigs.k8s.io/kind@v0.27.0`) | [`ci.yml` `uat-k8s`](https://github.com/dshakes/halos/blob/main/.github/workflows/ci.yml), [`scripts/uat-k8s.sh`](https://github.com/dshakes/halos/blob/main/scripts/uat-k8s.sh) | The Helm chart on a throwaway cluster, with user stories in `test/uat/k8s`. |
| Kong OSS | `3.9.x` by digest | [`scripts/uat-kong.sh:15-16`](https://github.com/dshakes/halos/blob/main/scripts/uat-kong.sh#L15-L16), [`test/uat/kong`](https://github.com/dshakes/halos/tree/main/test/uat/kong) | `halo-kong` inside a real DB-less Kong. |
| Real CLIs | acme pins | [`scripts/uat-clis.sh`](https://github.com/dshakes/halos/blob/main/scripts/uat-clis.sh), [`test/uat/clis_test.go`](https://github.com/dshakes/halos/blob/main/test/uat/clis_test.go) | Claude Code, Codex, Gemini CLI and Copilot CLI behind `halo-proxy`. |
| Mock OIDC IdP | in repo | [`deploy/compose/mockidp`](https://github.com/dshakes/halos/tree/main/deploy/compose/mockidp), [`internal/identity/identitytest`](https://github.com/dshakes/halos/tree/main/internal/identity/identitytest) | JWT issuance and JWKS for the demo, e2e and unit tests. |
| Mock model APIs | in repo | [`deploy/compose/mockllm`](https://github.com/dshakes/halos/tree/main/deploy/compose/mockllm), [`test/uat/mock`](https://github.com/dshakes/halos/tree/main/test/uat/mock) | Provider wire formats without API keys. |
| vhs | not pinned | [`assets/tapes/`](https://github.com/dshakes/halos/tree/main/assets/tapes), [`docs/scripts/record-media.sh`](https://github.com/dshakes/halos/blob/main/docs/scripts/record-media.sh) | Records the README GIFs and the site's terminal clips from the real binaries. |
| Headless Chrome over CDP | not pinned | [`docs/scripts/record-console.mjs`](https://github.com/dshakes/halos/blob/main/docs/scripts/record-console.mjs) | Records the console walkthrough on `make demo`. |
