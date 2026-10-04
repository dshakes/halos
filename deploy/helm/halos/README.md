# halos Helm chart

Deploys halo-server (console/API), halo-proxy (policy gateway), halo-shadow (shadow mirror), and optionally an
OpenTelemetry collector and a `KongPlugin` CR for halo-kong. Each component is toggled with `<component>.enabled`.

```
helm lint deploy/helm/halos -f deploy/helm/halos/ci/all-values.yaml
helm template halo deploy/helm/halos -f my-values.yaml | kubectl diff -f -   # review, then a human runs helm upgrade --install
```

## Prerequisites (Secrets you create; the chart never holds secret values)

| Secret (default name) | Key | Used by |
|---|---|---|
| `halos-fleet-token` | `token` | halo-server `--token-file` (halod report auth) |
| `halos-session` | `session-key` | halo-server session signing (`server.sessionKey`, empty name disables) |
| `server.oidcClientSecret.existingSecret` | `client-secret` | halo-server OIDC client secret |
| `halos-halo-shadow` | `token` | halo-shadow `HALO_SHADOW_TOKEN`; also injected into halo-proxy as `HALO_PROXY_HALO_SHADOW_TOKEN`, and into Kong as `HALO_SHADOW_TOKEN` (you configure Kong) |
| `halo-shadow.upstreamHeaders.existingSecret` | `upstream-headers.yaml` | halo-shadow `--upstream-headers`: YAML `{upstream: {Header: value}}`, `${ENV}` expanded (`halo-shadow.extraEnv`). `HALO_SHADOW_AUTH_HEADER` is refused by halo-shadow |
| `halo-shadow.pairKey.existingSecret` | `pair-key` | optional `--pair-key-file` (base64 32-byte AES-256-GCM key) |
| `server.killSwitch.existingSecret` | `signing-key`, `gateway-token` | halo-server `--killswitch-key-file` (Ed25519 PKCS#8 PEM, `halo keys generate --name killswitch`) and `--gateway-token-file` (>= 16 chars); set together |
| `proxy.killSwitch.pubkey.existingSecret` | `killswitch.pub` | PUBLIC half of the signing key -> halo-proxy `killSwitch.pubkeyFile`; token defaults to `server.killSwitch.existingSecret`/`gateway-token` |
| `server.controller.clickhouse.existingSecret` | `username`, `password` | `--clickhouse-user` (via env) / `--clickhouse-password-file` |
| `server.controller.notify.slack.existingSecret` | `url` | `--notify-slack-url-file` |
| `server.controller.notify.webhook.existingSecret` | `url`, `secret` | `--notify-webhook-url-file` / `--notify-webhook-secret-file` |
| `server.controller.policyRepo.ghToken.existingSecret` | `token` | `GH_TOKEN` for `gh` (PR opening) |
| `policy.gitSync.auth.existingSecret` | `ssh`+`known_hosts` (ssh) or `password` (token) | git-sync |
| `proxy.telemetry.tokenSecret.existingSecret` (defaults to `otel.gatewayToken.existingSecret`) | `token` | otel gateway-receiver bearer token -> halo-proxy `telemetry.tokenFile` (mounted at `/etc/halo-telemetry/token`); `proxy.telemetry.enabled=true` also sets `telemetry.otlpEndpoint` (default `http://<release>-otel:4319`) and opens proxy->otel:4319 in NetworkPolicy |
| `proxy.telemetry.unitSaltSecret.existingSecret` | `unit-salt` | optional `--telemetry-unit-salt-file`: one shared `halo.unit` salt across proxy replicas |
| `otel.clickhouse.existingSecret` | `username`, `password` | `${env:CLICKHOUSE_USER}` / `${env:CLICKHOUSE_PASSWORD}` in the generated collector config |

OIDC issuer/audience live in the policy repo (halo-server) and `proxy.config.identity` (halo-proxy).

## Design notes

- Policy: git-sync (`registry.k8s.io/git-sync/git-sync:v4.x`) runs as a one-time init container plus a sidecar into an
  `emptyDir`; the link is `/policy/current`. halo-server reloads by mtime, no SIGHUP. `server.proposals.enabled` (and/or
  `server.controller.policyRepo.enabled`) adds ONE writable clone at `/policy-writer/repo` (`portal.policyRepoDir`, separate from
  `--policy-dir`), made by an init container running a real `git clone` (git-sync worktrees are detached and cannot push);
  `make uat-k8s` pushes controller PR branches from it to an in-cluster remote on every PR (`test/uat/REPORT.md`, scenario e).
- halo-proxy policy snapshot: `proxy.policy.source=configMap` (inline `snapshot` or `existingConfigMap`) or `gitSync`
  (`gitSyncPath` inside the repo). ConfigMap volumes update via symlink swap; verify halo-proxy's reload picks that up (UNVERIFIED).
- halo-proxy timeouts default to long-stream values (`upstreamHeaderTimeout` 10m, responses never time-limited);
  `terminationGracePeriodSeconds` (150) must exceed `shutdownTimeout` (2m). HPA scale-down is slow (600s window, 1 pod / 2 min).
  Ingress defaults carry nginx 3600s timeouts and buffering off.
- halo-server and halo-shadow are single-replica with RWO PVCs (Recreate strategy; PVCs carry `helm.sh/resource-policy: keep`).
  Their PDBs are off by default because a PDB on one replica blocks node drains.
- NetworkPolicy: default deny for all chart pods + DNS + proxy->halo-shadow. Everything else (IdP, model upstreams, git host,
  registry, ClickHouse, ingress controller, Prometheus) must be granted through `networkPolicy.ingressFrom.*`,
  `networkPolicy.egress.*`, `networkPolicy.metricsFrom` (raw peers/rules; default allows the `monitoring` namespace to scrape 9090/9091/otel only). Other empty defaults mean pods cannot reach them.
- Security: non-root (65532), read-only rootfs, drop ALL, RuntimeDefault seccomp, no SA token. The otel-collector image
  must tolerate uid 65532 (override `podSecurityContext` if not).
- Images: `image.registry` + `<component>.image.repository`; `tag` defaults to appVersion; `digest` (sha256) overrides tag.
  The default repositories (`ghcr.io/dshakes/{halo-server,halo-proxy,halo-shadow}`) are published and cosign-signed by the release
  workflow; set `tag` to the release you install (appVersion lags a patch release).
- halo-shadow: requires `--policy` = the same compiled snapshot as halo-proxy, produced by `halo gateway compile` in CI (inherits
  `proxy.policy.*`: the proxy ConfigMap or git-sync; override with `halo-shadow.policy.*`). Upstreams are resolved from it.
  Listens on `0.0.0.0:8090` (binary default is loopback; NetworkPolicy limits ingress to halo-proxy and
  `networkPolicy.ingressFrom.halo-shadow`). `budgetUSD` must be > 0 (default 50). Upstream credentials go in
  `--upstream-headers` (Secret file), never `HALO_SHADOW_AUTH_HEADER`. `--retention` = `halo-shadow.retention` (720h).
  `/metrics` on the main listener requires header `X-Halo-Shadow-Token`, so the chart sets `halo-shadow.metricsListen` (default
  `:9091`, `--metrics-listen`): unauthenticated `GET /metrics` only (counters), scraped by `serviceMonitor` and reachable only
  from `networkPolicy.metricsFrom` (default: namespace `monitoring`). Set it to `""` to disable.
- halo-proxy serves `/healthz` and `/metrics` only on its admin listener (`proxy.adminPort`, default 9090 -> `adminListen`);
  probes, the `admin` Service port and the ServiceMonitor use it; the public port serves only proxied model paths.
- Kong (`kong.enabled`, UNVERIFIED): renders `KongPlugin` `halo-kong` with `shadow_url` and
  `shadow_token: "{vault://env/halo-shadow-token}"` (no token in the CR; it would leak via the Admin API). The chart does not
  deploy Kong; REQUIRED values on the Kong release (kong/kong or kong/ingress `env:`): `HALO_SHADOW_TOKEN` (from the halo-shadow
  Secret), `KONG_NGINX_MAIN_ENV=HALO_SHADOW_TOKEN`, `KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=32m`. The halo-kong plugin and the
  compiled policy at `kong.config.policy_path` must exist in the Kong pods. Annotate the Ingress/Service `konghq.com/plugins: halo-kong`.
- halo-server `server.trustedProxyCIDRs` -> `--trusted-proxy-cidrs` (empty = XFF never trusted; set the ingress controller pod CIDR).
- OTel: default config is `files/otel-collector.yaml`, generated with
  `go run ./cmd/halo telemetry collector-config --clickhouse tcp://clickhouse:9000 -o deploy/helm/halos/files/otel-collector.yaml`
  (halo.* normalisation, needs `otel.clickhouse.existingSecret`). Preferred: generate for your ClickHouse in CI and set
  `otel.existingConfigMap` (key `config.yaml`); `otel.config` is an inline override.
- Controller (`server.controller.enabled` -> `--controller`): needs `clickhouse.url` and `server.persistence` (chart fails otherwise;
  the action log in `--data-dir` prevents duplicate PRs). `policyRepo.enabled` shares the `/policy-writer/repo` clone above
  (`--policy-repo-dir`, separate from the served policy). The controller shells out to `git` and `gh`, so the halo-server image must
  contain both: set `server.controller.policyRepo.image` to an image that does. `gh pr create` against real GitHub is UNVERIFIED
  (the UAT uses a recording `gh` stub).
  Without `policyRepo`, the controller only evaluates, kills and notifies (no PRs).
- Kill switch: `server.killSwitch.existingSecret` passes `--killswitch-key-file`/`--gateway-token-file`. `proxy.killSwitch.enabled` writes
  `killSwitch{url,tokenFile,pubkeyFile,interval}` into the proxy config; `url` defaults to the in-cluster halo-server Service (plain HTTP,
  bearer token + signed list; front it with TLS if it leaves the cluster). `kong.killSwitch.enabled` sets `killswitch_*` with vault refs
  (`HALO_KILLSWITCH_TOKEN`, `HALO_KILLSWITCH_PUBKEY` on the Kong release).
- Metrics: `server.metrics.enabled` adds `--metrics-listen=:<port>` (9092, unauthenticated), a `metrics` Service port, a ServiceMonitor
  (with `serviceMonitor.enabled`) and a NetworkPolicy ingress from `networkPolicy.metricsFrom` only.
- AWS Bedrock (halo-proxy): upstreams are SigV4-signed via the AWS default credential chain; `region` is per upstream in the policy snapshot.
  Use `proxy.serviceAccount.create=true` with `annotations: {eks.amazonaws.com/role-arn: ...}` (IRSA), or create an EKS Pod Identity association
  for the proxy ServiceAccount (no annotation; human runs `aws eks create-pod-identity-association`). `automountServiceAccountToken` stays false;
  the EKS webhook injects its own token volume. Role needs `bedrock:InvokeModel` and `InvokeModelWithResponseStream`.
- NetworkPolicy additions (all values-driven, raw peers, empty = not rendered): proxy->server kill switch is automatic;
  `networkPolicy.controllerEgress.{clickhouse,git,webhook}` for the server controller; `networkPolicy.aws` for proxy->AWS (Bedrock
  `bedrock-runtime.<region>.amazonaws.com:443`; IRSA also needs STS; `podIdentityAgent: true` allows 169.254.170.23:80). Plain NetworkPolicy
  cannot match FQDNs: use a bedrock-runtime VPC endpoint CIDR, or a CNI FQDN policy through `networkPolicy.egress.proxy`.
- Not exposed: halo-server `--dev-insecure-*` flags (use `server.args` deliberately if ever needed).

## Values

| Key | Default | Description |
|---|---|---|
| `image.registry` / `image.pullPolicy` | `ghcr.io` / `IfNotPresent` | global registry and pull policy |
| `imagePullSecrets` | `[]` | |
| `serviceAccount.*` | create, no token automount | |
| `podSecurityContext` / `securityContext` | hardened (see above) | applied to every container |
| `topologySpread.*` | zone+hostname, `ScheduleAnyway` | per-component selector added automatically |
| `policy.gitSync.{repo,ref,depth,period,auth,image,resources}` | placeholder repo, `main`, `30s`, `none` | shared git-sync config |
| `server.enabled` | `true` | |
| `server.{image,replicas,port,args,extraEnv,extraVolumes,extraVolumeMounts}` | 1 replica, 8080 | |
| `server.policySubdir` / `server.verdictsPath` | `""` | `--policy-dir` subpath / `--verdicts` |
| `server.{fleetToken,sessionKey,oidcClientSecret}` | existing Secret refs | see prerequisites |
| `server.portal` | `{baseURL: ...}` | rendered to `--portal-config` JSON (strict fields) |
| `server.killSwitch.{existingSecret,signingKey,gatewayToken}` | off | see prerequisites |
| `server.metrics.{enabled,port}` | off, 9092 | `--metrics-listen` |
| `server.controller.{enabled,interval,clickhouse,notify,policyRepo}` | off, `5m` | automated experiment loop (see design notes) |
| `server.proposals.enabled` | `false` | writable clone for self-service proposals |
| `server.persistence.*` | 5Gi RWO | `--data-dir`; `existingClaim` supported; disabled = in-memory store |
| `server.{service,resources,pdb,ingress,nodeSelector,tolerations,affinity,podAnnotations}` | | |
| `proxy.enabled` | `true` | |
| `proxy.{image,replicas,port,adminPort,args,extraEnv,extraVolumes,extraVolumeMounts}` | 2 replicas, 8088, admin 9090 | |
| `proxy.config` | long-stream timeouts | halo-proxy YAML (strict keys); `listen`,`adminListen`,`policy`,`shadow.url` set by chart |
| `proxy.policy.{source,existingConfigMap,key,snapshot,gitSyncPath}` | `configMap`, `{}` | policy snapshot source |
| `proxy.shadow.enabled` | `true` | mirror to in-chart halo-shadow when `halo-shadow.enabled` |
| `proxy.serviceAccount.{create,name,annotations}` | shared SA | dedicated SA for IRSA (annotations need `create: true`) |
| `proxy.killSwitch.{enabled,url,interval,token,pubkey}` | off, `10s` | gateway kill switch client |
| `proxy.{terminationGracePeriodSeconds,preStopSleepSeconds}` | `150`, `5` | preStop sleep needs k8s >= 1.30 |
| `proxy.autoscaling.*` | 2-10, CPU 70% | HPA v2 |
| `proxy.{pdb,service,resources,ingress}` | PDB on, nginx stream annotations | |
| `halo-shadow.enabled` | `false` | |
| `halo-shadow.{image,port,listen,metricsListen,queue,workers,budgetUSD,priceIn,priceOut,retention,args,extraEnv}` | 8090, `0.0.0.0`, `:9091`, 64, 4, 50, 3, 15, 720h | halo-shadow flags |
| `halo-shadow.{token,upstreamHeaders,pairKey}` | Secret refs | see prerequisites |
| `halo-shadow.policy.*` | inherit `proxy.policy` | compiled snapshot source |
| `server.trustedProxyCIDRs` | `""` | `--trusted-proxy-cidrs` |
| `halo-shadow.persistence.*` | 10Gi RWO | pairs JSONL; disabled = emptyDir |
| `otel.enabled` | `false` | |
| `otel.{image,replicas,existingConfigMap,config,clickhouse,service,resources,pdb}` | | see design notes |
| `networkPolicy.{enabled,dnsNamespaceSelector,ingressFrom,egress,metricsFrom}` | on, deny by default | |
| `networkPolicy.{controllerEgress,aws}` | empty | server controller and proxy->AWS egress |
| `serviceMonitor.{enabled,interval,labels}` | off | proxy (admin port), halo-shadow (metrics port), otel `/metrics`, halo-server (`server.metrics.enabled`) |
| `kong.{enabled,pluginName,config,mirrorToShadow,killSwitch}` | off | UNVERIFIED |

`values.schema.json` validates types, enums (`policy.gitSync.auth.type`, `proxy.policy.source`), ports, digests, and pins
`server.replicas`/`halo-shadow.replicas` to 1.
