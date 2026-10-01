---
title: Production deployment
description: Helm chart, secrets, the pointer refresh schedule, signing key management and rotation, and what to back up.
---

:::caution[Not yet run in a cluster]
The Helm chart passes `helm lint` and `helm template` in CI values, but has **not** been installed in a real cluster, and container images are not published (`image.registry` and the default repositories are placeholders). Kong integration in the chart is **UNVERIFIED**. Build and push your own images until releases exist.
:::

## What runs where

| Component | Where | State |
|---|---|---|
| `halo` (publish, promote, refresh, rollback) | CI runners and operator workstations | The signing key (CI secret or KMS) |
| OCI registry | Managed registry (GHCR, ECR, Artifactory) | Releases and signed pointers |
| `halo-server` | Cluster, single replica | `--data-dir`: device store, request log, fleet reports |
| `halo-proxy` | Cluster, 2+ replicas behind your ingress, or beside your gateway | Stateless; policy snapshot |
| `halo-shadow` | Cluster, single replica | Pair file (contains prompts) |
| OTEL collector, ClickHouse | Cluster | Telemetry |
| `halod` | Every managed machine (or dev container) | `state.json` |

## Helm

```bash
helm lint deploy/helm/halos -f deploy/helm/halos/ci/all-values.yaml
helm template halo deploy/helm/halos -f my-values.yaml | kubectl diff -f -    # review
helm upgrade --install halo deploy/helm/halos -n halos -f my-values.yaml  # a human runs this
```

The chart deploys `halo-server`, `halo-proxy`, `halo-shadow`, optionally an OTEL collector and a `KongPlugin` custom resource, each toggled by `<component>.enabled`. Policy reaches the pods through git-sync (init container plus sidecar into an `emptyDir`; `halo-server` reloads by mtime). `halo-proxy` reads its compiled snapshot from a ConfigMap (`proxy.policy.source: configMap`) or from the git-sync clone (`gitSync`, using `gitSyncPath`).

Things the chart does for you: non-root (65532), read-only root filesystem, drop ALL capabilities, RuntimeDefault seccomp, no service-account token, default-deny NetworkPolicy, HPA and PDB for the proxy, long-stream timeouts and `terminationGracePeriodSeconds: 150` (must exceed the proxy's 2m `shutdownTimeout`).

Things you must do:

- **Grant network access.** The default-deny policy allows only DNS and proxy to halo-shadow. Grant the IdP, model upstreams, git host, registry, ClickHouse, ingress controller and Prometheus through `networkPolicy.ingressFrom.*`, `networkPolicy.egress.*` and `networkPolicy.metricsFrom`, or the pods cannot reach them.
- **Terminate TLS** in front of `halo-proxy` (it serves plain HTTP). The default ingress annotations assume nginx with 3600s timeouts and buffering off.
- **Keep single-replica components single.** `halo-server` and `halo-shadow` use RWO volumes with a Recreate strategy; `values.schema.json` pins their replicas to 1.
- **Set the policy repo.** `policy.gitSync.repo` ships as a placeholder and `NOTES.txt` warns until you change it.

### Secrets

The chart never holds secret values; it references Secrets you create.

| Secret (default name) | Key | Used by |
|---|---|---|
| `halos-fleet-token` | `token` | `halo-server --token-file`, shared fleet report token |
| `halos-session` | `session-key` | Portal session signing; at least 32 bytes |
| `server.oidcClientSecret.existingSecret` | `client-secret` | Portal OIDC client secret |
| `halos-halo-shadow` | `token` | `halo-shadow` `HALO_SHADOW_TOKEN`; also injected into `halo-proxy` as `HALO_PROXY_HALO_SHADOW_TOKEN` |
| `halo-shadow.authHeader.existingSecret` | `auth-header` | Upstream credential header for halo-shadow (`Name: value`) |
| `server.killSwitch.existingSecret` | `signing-key`, `gateway-token` | Kill-switch signing key (Ed25519 PKCS#8 PEM) and gateway bearer token (16+ chars); set together |
| `proxy.killSwitch.pubkey.existingSecret` | `killswitch.pub` | Public half of the signing key, for `halo-proxy` |
| `server.controller.clickhouse.existingSecret` | `username`, `password` | Controller evidence store |
| `server.controller.policyRepo.ghToken.existingSecret` | `token` | `GH_TOKEN` for `gh` (controller PRs) |
| `policy.gitSync.auth.existingSecret` | `ssh` and `known_hosts`, or `password` | git-sync |
| `otel.clickhouse.existingSecret` | `username`, `password` | Collector ClickHouse exporter |
| `otel.gatewayToken.existingSecret` | `token` | Collector gateway receiver (`HALO_OTLP_GATEWAY_TOKEN`, required by the generated config). Without it the collector does not start |
| `proxy.telemetry.tokenSecret.existingSecret` | `token` | Bearer token `halo-proxy` presents to that receiver, mounted as a file (`--telemetry-token-file`). Defaults to `otel.gatewayToken.existingSecret`: same value |
| `proxy.telemetry.unitSaltSecret.existingSecret` | `unit-salt` | Optional `halo.unit` hash salt (`--telemetry-unit-salt-file`), identical on every proxy replica |

```bash
kubectl -n halos create secret generic halos-fleet-token --from-literal=token="$(openssl rand -base64 32)"
kubectl -n halos create secret generic halos-session --from-literal=session-key="$(openssl rand -base64 48)"
```

Prefer External Secrets or your secret manager over shell history for real values. The `--dev-insecure-*` flags of `halo-server` are deliberately not exposed by the chart.

## Controller

`server.controller.enabled` runs the automated experiment loop inside `halo-server` (`--controller`): every `server.controller.interval` (default 5m, minimum 1m) it evaluates experiments from ClickHouse, trips the kill switch on a rollback verdict, opens policy-repo PRs and sends notifications. It never merges.

- **Evidence must be gateway-sourced.** The controller auto-kills only on evidence that arrived through the collector's authenticated gateway receiver (`:4319`). Set `proxy.telemetry.enabled: true` (and `otel.enabled` with `otel.gatewayToken`), or a rollback verdict opens the pause PR and notifies but never trips the kill switch; `NOTES.txt` warns when telemetry is off. See [evidence plane](/halos/concepts/evidence-plane/#evidence-trust).
- **Kill only with a kill key.** The in-process controller trips the kill switch only when `server.killSwitch.existingSecret` is set (`--killswitch-key-file`). Without it, rollback notifications say the kill was not enforced and tell humans to **merge the pause PR urgently**. A running experiment that is already killed is held, not evaluated, until someone unkills it.
- **Required:** `server.controller.clickhouse.url` (HTTP interface, e.g. `http://clickhouse.data.svc:8123`) and `server.persistence.enabled`. The chart fails to render without them; the action log in `--data-dir` is what prevents duplicate PRs across restarts. Credentials come from `server.controller.clickhouse.existingSecret` (`username`, `password`).
- **PRs (optional):** `server.controller.policyRepo.enabled` (and/or `server.proposals.enabled`) adds ONE writable clone at `/policy-writer/repo`, shared by console proposals and controller PRs (never the served policy directory). An init container runs a real `git clone` of `policy.gitSync.repo` (origin remote, base branch checked out; git-sync worktrees are detached with no origin and cannot be used); halo-server then fetches and hard-resets it before each PR. Credentials come from `policy.gitSync.auth.existingSecret`, never the URL: `token` via a `GIT_ASKPASS` helper reading the mounted `password`, `ssh` via `GIT_SSH_COMMAND` with the mounted `ssh`/`known_hosts`. The clone and PRs shell out to `git`, `sh` and `gh` (and `ssh` for ssh auth), so the image must contain them: point `server.controller.policyRepo.image` at one that does, and supply `server.controller.policyRepo.ghToken.existingSecret`. Without `policyRepo` the controller evaluates, kills and notifies only. **UNVERIFIED** against a real cluster and GitHub.
- **Notifications (optional):** `server.controller.notify.slack.existingSecret` (`url`) and `server.controller.notify.webhook.existingSecret` (`url`, `secret`). The webhook carries `X-Halo-Timestamp` and a timestamped `X-Halo-Signature`; receivers must verify both ([snippets](/halos/reference/cli/#verifying-the-webhook-signature)). Each channel retries on later ticks until it succeeds, without re-posting to channels that already did.
- **Network:** grant egress with `networkPolicy.controllerEgress.clickhouse` (8123), `.git` (443, 22; the git host and `api.github.com` for `gh`) and `.webhook` (443). Each takes a raw NetworkPolicy peer list in `to`; an empty `to` renders no rule, so the controller cannot reach that destination.
- `server.metrics.enabled` exposes controller metrics on an unauthenticated port (9092 by default); keep it internal and scrape it from `networkPolicy.metricsFrom` only.

## Kill switch

The kill switch drops a misbehaving experiment back to control within one gateway poll, with no PR and no merge. `halo-server` signs a kill list; gateways poll it and verify the signature with the public key.

1. Generate the signing key pair: `halo keys generate --name killswitch` (private PKCS#8 PEM and public key).
2. Create the server Secret (`server.killSwitch.existingSecret`) with `signing-key` (the private key) and `gateway-token` (for example `openssl rand -hex 32`). `halo-server` needs both, so set them together.
3. Create the proxy Secret (`proxy.killSwitch.pubkey.existingSecret`, key `killswitch.pub`) holding only the public half. The proxy token defaults to the server Secret's `gateway-token`; override it with `proxy.killSwitch.token.existingSecret`.
4. Set `proxy.killSwitch.enabled: true`. `url` defaults to the in-cluster `halo-server` Service at `/api/v1/gateway/killswitch` and `interval` to 10s. `halo-proxy` refuses plain `http://` to a non-loopback host unless `proxy.killSwitch.allowInsecureInCluster` is true (chart default `true`, because the in-cluster `halo-server` Service has no TLS listener; the list is signed but the bearer token travels in the clear). To enforce TLS, set an `https://` `proxy.killSwitch.url` (TLS terminated in front of `halo-server`) and `allowInsecureInCluster: false`.
5. The proxy-to-server NetworkPolicy rule is added automatically when `proxy.killSwitch.enabled` is set.

Admins can kill and unkill from the console's Experiments page or via `POST /api/v1/experiments/{name}/kill|unkill`; both are audit-logged. For Kong, `kong.killSwitch.enabled` (or `halo gateway deck --killswitch-url ...`) sets `killswitch_*` with vault references, so `HALO_KILLSWITCH_TOKEN` and `HALO_KILLSWITCH_PUBKEY` must be in Kong's environment and listed in `KONG_NGINX_MAIN_ENV`. `halo-kong` enforces the same URL rule through `killswitch_allow_insecure_in_cluster` (`kong.killSwitch.allowInsecureInCluster`). An invalid kill-switch config does not block traffic: it is logged at ERROR once a minute and the plugin adds `x-halo-killswitch: misconfigured` to the upstream request, so alert on that header.

**Check:** `GET /api/v1/killswitch` (admin) lists active kills, and a gateway that cannot verify or fetch the list keeps serving (nothing is killed until its first successful poll).

## Direct AWS Bedrock

`halo-proxy` can call Bedrock directly: upstreams are signed with SigV4 using the AWS default credential chain, and each upstream's `region` lives in the policy snapshot. Give the proxy its own ServiceAccount so the role is scoped to it.

```yaml
proxy:
  serviceAccount:
    create: true
    annotations:
      eks.amazonaws.com/role-arn: arn:aws:iam::<account>:role/halos-proxy-bedrock   # IRSA
```

- **IRSA** uses the annotation above. **EKS Pod Identity** uses no annotation: a human creates the association with `aws eks create-pod-identity-association --cluster-name <c> --namespace <ns> --service-account <name> --role-arn <arn>` (the name is `<fullname>-proxy` unless `proxy.serviceAccount.name` is set).
- **Signing is host-gated.** `halo-proxy` SigV4-signs only for hosts ending in `.amazonaws.com`, `.amazonaws.com.cn` or `.api.aws`, or listed in `signHosts` (exact hostnames, for example a private VPC endpoint DNS name). A `kind: bedrock` upstream with a region on any other host gets a 502 instead of credentials. With the chart: `proxy.config.signHosts: [bedrock.corp.example]`. Every client `x-amz*` / `x-amzn*` header is stripped before signing.
- The role needs `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`. `automountServiceAccountToken` stays false; the EKS webhook injects its own projected token.
- **Network:** plain NetworkPolicy cannot match FQDNs. Set `networkPolicy.aws.to` to the CIDR of a `bedrock-runtime` VPC interface endpoint (ports default to 443), or use a CNI FQDN policy through `networkPolicy.egress.proxy`. IRSA also calls `sts.<region>.amazonaws.com:443`, so include the STS endpoint. For Pod Identity set `networkPolicy.aws.podIdentityAgent: true` to allow the node-local agent at `169.254.170.23:80`.

Direct Bedrock has not been exercised against a real AWS account (**UNVERIFIED**).

## Pointer refresh

Signed ring pointers expire after **7 days**. If nothing re-signs them, every `halod` stops updating (keeping its last good release) and warns from 24 hours out. Run `halo release refresh` for **every ring** on a schedule, at least daily:

```bash
halo release refresh --ring ring3-ga --registry ghcr.io/acme/halos --key "$RUNNER_TEMP/halo.key"
```

`.github/workflows/refresh-pointers.yml.example` is a ready-to-copy daily GitHub Actions workflow (ring matrix, key from a secret written with `umask 077`, signer state cached between runs). Alert on the job failing; two failed days is the point to page someone. Refresh keeps the same release and produces a new `seq` and expiry.

Before every signature the command prints to stderr (so `--output json` stays parseable):

```text
Signing ring ring3-ga → version 1.4.2 (digest sha256:..., seq 1767225600)
```

Read it: it is the release and `seq` you are about to put your key behind.

### Replay protection: the signer state file

A registry can serve an old but validly signed pointer. If the signer re-signed from it, the replay would come back with a fresh `seq` and expiry. So `refresh`, `promote`, `publish` and `rollback` all consult a **signer state file** recording the last pointer this signer wrote per registry repo and ring (`seq`, `digest`, issue time). A registry serving an older `seq`, the same `seq` with another digest, or no pointer for a ring the file knows, is refused. New pointers get `seq = max(served + 1, recorded + 1, unix now)`.

| | |
|---|---|
| Location | `$XDG_STATE_HOME/halos/pointers.json`, else `~/.local/state/halos/pointers.json`; override with `--state-file` |
| Missing file | Treated as empty: nothing to compare against (no error, no warning) |
| Unparseable file | Refuses to sign |
| Writers | One signer per file; it is not locked |

**Stateless CI is the gap.** On a fresh runner there is no state file, so the replay check has nothing to compare against. Cache the file between runs (the example workflow does this with `actions/cache`, one entry per ring), or pass `--expect-digest sha256:<release digest>` on `refresh` and `promote` so the command refuses unless the ring serves exactly that release. Cache eviction is not silent: when the state file has no record of a pointer the registry already serves, `refresh`, `promote`, `publish` and `rollback` refuse unless you confirm it with `--expect-digest <the served release digest>` or `--adopt-existing` (first run, or after an eviction). A corrupt file also blocks signing. `--expect-digest` pins one release, so use it for a one-off or for a ring that should not move, not as a permanent setting on a ring you promote: it fails every legitimate promotion.

### Expired pointers

`refresh` refuses to re-sign an **expired** pointer (it cannot tell a lapsed schedule from a replayed pointer). Recover by pointing the ring at a release you choose:

```bash
halo rollback --ring ring3-ga --to 1.4.2 --registry ghcr.io/acme/halos --key "$RUNNER_TEMP/halo.key"
```

`--to <version>` resolves tag `v<version>` and refuses it unless the release's signed manifest carries that version, so a retagged `v` tag cannot redirect you. `--to sha256:<manifest digest>` is the **OCI manifest** digest (the `manifest` field of `halo release publish --output json`, or `crane digest <repo>:v<version>`), content-addressed. That is not the **release** digest that `publish` prints in text mode (JSON `digest`) and that `--expect-digest` and the `Signing ring ...` line use; `--expect-digest` on `rollback` checks the release digest the target resolves to.

**Check:** `halo release refresh` prints the `Signing ring ...` line, then `ok refreshed ring-<name>: seq ..., expires <7 days out>`.

## Signing key management

- **One trust root at a time.** Every `halod`, Dev Container Feature and MDM export verifies with an ed25519 public key (several only during rotation, see below). Whoever holds the private key can ship a hook to every developer, subject to `halod`'s path allowlist.
- **Generate:** `halo keys generate --name prod --out ./keys` writes `prod.key` (private, keep secret) and `prod.pub`.
- **Store the private key in CI secrets or a KMS-backed signer**, never on laptops. The primary signer must be ed25519 file key; KMS-backed **cosign** signatures (`--cosign-key awskms://...` or a file) and keyless (`--cosign-keyless`, which uploads the digest to the public Rekor log) are co-signatures that `halod` does not check.
- **Protect the branch.** Require review on ring pointers and profile changes, and restrict who can run the publish and refresh workflows.
- **Distribute the public key** by embedding it inline (Feature option `pubkeyPem`, Coder `pubkey_pem`, `halo export ... --pubkey`) or as a root-owned file that `halod.yaml` points at. The portal serves it at `/enroll/release.pub` for enrollment.

### Rotation and compromise

`halod` accepts a release signed by **any** key in `pubkey` plus `pubkeys: [..]`, so old and new keys overlap and rotation is not a flag day:

1. Generate the new key pair.
2. Add the new public key to `pubkeys` in `halod.yaml` (MDM, dev container rebuild; portal enrollment for new machines) while keeping the old one. Devices now trust both.
3. Once the fleet has the new key, publish every ring with it: `halo release publish ... --key new.key` per ring (re-signing a pointer alone is not enough: the release signature must also verify).
4. Drop the old key from `pubkey`/`pubkeys` and destroy the old private key. Watch `halod status` and the fleet view for stragglers.

```yaml
pubkey: /etc/halos/release-new.pub
pubkeys: [/etc/halos/release-old.pub]        # remove after the cutover
revokedKeys: ["sha256:<hex of raw ed25519 public key>"]   # never trusted, even if listed above
```

If the private key is **compromised**, add its fingerprint to `revokedKeys` (`halod` prints fingerprints at startup) on every device, which overrides any listing in `pubkey`/`pubkeys`, then publish with the new key. Also audit registry history for releases you did not publish, revoke device tokens for suspect devices (`POST /api/v1/devices/{id}/revoke`) and user sessions (`POST /api/v1/users/{id}/revoke-sessions`), and rotate the fleet token and session key. A machine that never receives the updated `halod.yaml` keeps trusting the old key, which is why config distribution should not depend on the registry.

## Backups and state

| Data | Location | Why it matters | Backup |
|---|---|---|---|
| Device store | `<data-dir>/devices.jsonl` | Losing it means every enrolled laptop's token is unknown and all must re-enroll. Contains SHA-256 of tokens, not tokens | Snapshot the PVC or copy the file. The chart keeps PVCs with `helm.sh/resource-policy: keep` |
| Request log | `<data-dir>/requests.jsonl` | Audit trail of access requests and decisions | Same |
| Fleet reports | `<data-dir>/reports.jsonl` | Last report per host; rebuilds itself as `halod` reports | Optional |
| Verdicts | file passed as `--verdicts-file` | Last analysis result per experiment | Recomputable from ClickHouse |
| Shadow pairs | halo-shadow `-out` file | Contains prompts and responses | Only if you need the evidence; encrypt (`-pair-key-file`) and set `-retention`. Back up the key separately or the pairs are unrecoverable |
| Policy repo | git | Source of truth for everything else | Your git host |
| Signing key | CI secret or KMS | Needed to publish and refresh | Sealed offline copy per your key policy |

The device and request stores are append-only JSONL files, last line per id wins, and are not compacted; plan to rotate them if `devices × lastSeen` writes grow (`lastSeen` is persisted at most every 10 minutes per device). Restore by putting the files back before starting `halo-server`.

## Before you go live

- [ ] `halo validate` is a required CI check; `halo plan` output is posted on PRs
- [ ] Publish and refresh run in CI with the key as a secret, on a daily schedule with alerting
- [ ] Nobody can push to the policy repo's default branch without review
- [ ] NetworkPolicy grants reviewed; TLS terminates in front of `halo-proxy` and `halo-server`
- [ ] `allowShellInstall` is not set on any `halod`
- [ ] `halo-proxy` is unreachable except through your ingress or gateway; if you use `trusted_header`, the CIDR pin is set
- [ ] `--dev-insecure-*` flags are not present anywhere
- [ ] Read the [threat model](/halos/reference/threat-model/) and the **UNVERIFIED** items in the [README](https://github.com/dshakes/halos#what-is-not-verified)
