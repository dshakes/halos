---
title: Operations
description: SLOs and Prometheus alerts, high availability, backup and restore of halo-server state and keys, and the runbook for the incidents that matter.
---

Everything here is checked against the code it describes; `file:line` references are to the repository at the commit that built these docs. Where a behaviour has only been exercised in the kind-based UAT (`make uat-k8s`), it says so.

## What is highly available and what is not

| Component | Replicas | Why | Chart |
|---|---|---|---|
| `halo-proxy` | 2+ (HPA 2 to 10 on CPU) | Stateless: policy snapshot from a ConfigMap or git-sync, kill list polled from `halo-server` | `RollingUpdate` with `maxUnavailable: 0, maxSurge: 1` (`deploy/helm/halos/templates/proxy.yaml:74`), readinessProbe `/readyz` and livenessProbe `/healthz` on the admin port (`proxy.yaml:114-115`), `preStop` sleep (`proxy.yaml:118`), HPA (`proxy.yaml:187`), PDB `maxUnavailable: 1` (`proxy.yaml:212`), zone and hostname topology spread (`_helpers.tpl:53`) |
| `halo-server` | **exactly 1** (`values.schema.json:23`) | Single writer over append-only JSONL files in `--data-dir` that are replayed into memory at start; no locking, no leader election; the controller loop would run once per replica | `Recreate` when persistence is on (`templates/server.yaml:107`), readinessProbe `/readyz` (policy loaded) and livenessProbe `/healthz` (`internal/server/server.go:168,172`) |
| `halo-shadow` | **exactly 1** (`values.schema.json:47`) | One pair file and an in-process spend counter; a second replica splits pairs and doubles the budget | `Recreate` |
| OTel collector | 1 by default (`otel.replicas`) | Stateless, can be raised | |

The honest consequence: a `halo-server` upgrade or reschedule is a short outage of the console, enrollment, fleet reports and the kill-list endpoint. That outage does not reach developers' CLIs: gateways keep serving with their last accepted kill list (`internal/gateway/killswitch.go:85`), `halod` keeps its last-good release and logs failed reports at WARN (`cmd/halod/agent.go:175`, `:622`). We chose a pinned single replica over leader election because the state is a handful of local files and the blast radius of a 30-second restart is nil for end users; a second replica would need shared storage and locking the code does not have.

`make uat-k8s` proves the proxy side on a kind cluster with `test/load` at 200 rps through the ingress (`scripts/uat-k8s.sh:141-215`): delete a proxy pod mid-traffic, roll the Deployment with `helm upgrade`, and evict both pods at once. Each must finish with zero client-visible errors and the second concurrent eviction must be refused by the PDB. A SIGKILLed proxy pod still drops its in-flight requests; only the graceful path (SIGTERM, drain) is covered.

Every container runs as 65532, read-only root filesystem, no capabilities, `RuntimeDefault` seccomp (`values.yaml:16-26`), with default-deny NetworkPolicy (`networkPolicy.enabled`, see [production deployment](/halos/guides/production-deployment/)).

## SLOs

Set these on the gateway: it is the only component in the developer's request path. Numbers below are a starting point for a team of a few hundred developers; adjust the thresholds, not the signals.

| SLI | Target | Source |
|---|---|---|
| Gateway availability: share of requests that are not 5xx | 99.9% over 30 days | `halo_proxy_requests_total{status}` (`cmd/halo-proxy/metrics.go:86`) |
| Gateway added latency: time to upstream response headers | p99 under 250 ms excluding upstream time is not measurable from the proxy alone; alert on `halo_proxy_upstream_ttfb_seconds` p99 against your own baseline | `halo_proxy_upstream_ttfb_seconds` (histogram, buckets 50 ms to 600 s, `metrics.go:15`) |
| Kill-switch propagation | 100% of gateways on the current list within 2 poll intervals (default 10 s) | No metric; `halo-proxy` logs each list change. `GET /api/v1/killswitch` on the server shows the list `version` |
| Pointer freshness | Every ring refreshed in the last 48 h (pointers expire after 7 days) | The refresh CI job; `halod` warns from 24 h before expiry |
| Controller health | Ticks every `--interval`, no sustained errors | `halo_controller_ticks_total`, `halo_controller_errors_total` (`server.metrics.enabled`) |

`halo-server` itself exposes no request metrics (only the controller counters). Measure its availability from your ingress controller or a blackbox probe of `GET /readyz` (returns 503 until policy is loaded and during drain).

## Alerts

Prometheus rules, written against the metric names and labels the binaries emit. Scrape with `serviceMonitor.enabled: true` (proxy admin port 9090, shadow 9091, server controller 9092; all unauthenticated, keep them inside `networkPolicy.metricsFrom`).

```yaml
groups:
  - name: halos-gateway
    rules:
      - alert: HaloProxyErrorRateHigh
        expr: |
          sum(rate(halo_proxy_requests_total{status=~"5.."}[5m]))
            / sum(rate(halo_proxy_requests_total[5m])) > 0.01
        for: 10m
        labels: {severity: page}
        annotations:
          summary: "halo-proxy 5xx rate above 1% for 10m (SLO 99.9% / 30d)"
      - alert: HaloProxyUpstreamFailing
        expr: |
          sum(rate(halo_proxy_upstream_attempts_total{outcome=~"failed|circuit_open"}[5m])) by (provider)
            / sum(rate(halo_proxy_upstream_attempts_total[5m])) by (provider) > 0.2
        for: 5m
        labels: {severity: page}
        annotations:
          summary: "{{ $labels.provider }} upstream: >20% of attempts failed or breaker open"
      - alert: HaloProxyTTFBRegression
        expr: |
          histogram_quantile(0.99, sum(rate(halo_proxy_upstream_ttfb_seconds_bucket[10m])) by (le))
            > 2 * histogram_quantile(0.99, sum(rate(halo_proxy_upstream_ttfb_seconds_bucket[10m] offset 1d)) by (le))
        for: 15m
        labels: {severity: ticket}
        annotations:
          summary: "p99 time-to-first-byte doubled vs 24h ago (upstream or proxy)"
      - alert: HaloProxyAuthFailuresSpike
        expr: sum(rate(halo_proxy_auth_failures_total[5m])) > 1
        for: 10m
        labels: {severity: ticket}
        annotations:
          summary: "callers failing identity verification: expired JWKS, wrong issuer/audience, or an attack"
      - alert: HaloProxyShadowDropping
        expr: sum(rate(halo_proxy_shadow_dropped_total[5m]) + rate(halo_proxy_shadow_failed_total[5m])) > 0
        for: 15m
        labels: {severity: ticket}
        annotations:
          summary: "shadow mirror dropping jobs: halo-shadow down, queue full or token mismatch (client traffic unaffected)"
      - alert: HaloProxyBelowTwoReplicas
        expr: |
          sum(kube_deployment_status_replicas_available{deployment=~".*-proxy"}) < 2
        for: 5m
        labels: {severity: page}
        annotations:
          summary: "fewer than 2 ready halo-proxy pods: no headroom for a drain or upgrade"

  - name: halos-control-plane
    rules:
      - alert: HaloServerDown
        expr: up{job=~".*halo-server.*"} == 0 or absent(up{job=~".*halo-server.*"})
        for: 5m
        labels: {severity: page}
        annotations:
          summary: "halo-server unreachable >5m: console, enrollment, reports and kill-list polls are failing (gateways keep the last list)"
      - alert: HaloControllerStalled
        expr: increase(halo_controller_ticks_total[20m]) == 0
        for: 0m
        labels: {severity: ticket}
        annotations:
          summary: "no controller tick in 20m (default interval 5m)"
      - alert: HaloControllerErrors
        expr: increase(halo_controller_errors_total[30m]) > 3
        labels: {severity: ticket}
        annotations:
          summary: "controller errors: ClickHouse, policy clone, PR, kill or notify failing; rollbacks may not be enforced"
      - alert: HaloShadowBudgetNearlyExhausted
        expr: halo_shadow_spend_usd / halo_shadow_budget_usd > 0.9
        labels: {severity: ticket}
        annotations:
          summary: "halo-shadow has spent 90% of its budget; mirroring stops at 100% (evidence gap, not an outage)"
```

Two things no exporter covers, so wire them from CI: the daily `halo release refresh` job failing twice in a row (page: pointers expire after 7 days), and the nightly [soak workflow](https://github.com/dshakes/halos/blob/main/.github/workflows/soak.yml) failing (ticket: a leak or p99 regression in `halo-proxy` reached `main`).

## Backup and restore

### What to back up

| Data | Path | Written by | Loss means |
|---|---|---|---|
| Device store | `<data-dir>/devices.jsonl` | `internal/server/devices.go:77` | Every enrolled machine must re-enroll (holds token SHA-256s, not tokens) |
| Access requests | `<data-dir>/requests.jsonl` | `internal/server/requests.go:75` | Pending requests and the decision trail |
| Audit log | `<data-dir>/audit.jsonl` | `internal/server/audit.go:81` | Hash-chained; a gap is detectable (`GET /api/v1/audit` reports `verified`) but not recoverable |
| Session revocations | `<data-dir>/session-revocations.jsonl` | `internal/server/sessions.go:40` | Revoked user sessions become valid again until they expire |
| Kill list | `<data-dir>/killswitch.jsonl` | `internal/controller/killstore.go:65` | Active kills are forgotten: gateways and `halod` get an **empty** list at the next poll and the killed change comes back. Treat this file as the one you cannot lose |
| Controller action log | `<data-dir>/controller-state.jsonl` | `internal/controller/state.go:68` | The controller may open duplicate PRs for verdicts it already acted on |
| Rollout state | `<data-dir>/rollouts/<name>.json` | `internal/rollout/state.go:151` | Rollout step and gate history |
| Fleet reports | `<data-dir>/reports.jsonl` | `internal/server/store.go:88` | Rebuilds itself as `halod` reports; optional |
| Verdicts | `--verdicts-file` | | Recomputable from ClickHouse |
| Shadow pairs | `halo-shadow -out` (default `pairs.jsonl`) | `cmd/halo-shadow/main.go:62` | Evidence only. Contains prompts; encrypt with `-pair-key-file` and back the key up separately or the file is unreadable |
| Release signing key | CI secret or KMS | | Cannot publish, promote, refresh or roll back any ring |
| Kill-switch signing key | Secret `server.killSwitch.existingSecret` | | `halo-server` cannot sign kill lists; gateways keep the last one |
| Signer state file | `~/.local/state/halos/pointers.json` on the signer | | Replay check has nothing to compare against; see [lost signer state](#lost-signer-state-file) |
| Policy repo | git | | Source of truth for everything above except device identity |

All `--data-dir` files are append-only JSONL, last line per id wins, never compacted. Files are opened with `O_APPEND` and written one line at a time, so a snapshot taken while the server runs is consistent at line granularity: at worst the last line is torn, and replay skips it (`internal/fsutil/jsonl.go:28-32`). The chart keeps the PVC on `helm uninstall` (`helm.sh/resource-policy: keep`).

### Backup

```bash
# Snapshot the PVC with your CSI driver (preferred), or copy the files:
kubectl -n halos exec deploy/halos-server -- tar czf - -C /data . > halo-server-data-$(date +%F).tgz
# Keys: export from your secret manager, never from the cluster; the Secrets hold the only copy
# of the kill-switch private key if you did not keep one.
```

Take the data backup at least daily and immediately before an upgrade. Keep the kill-switch public key and the release public key alongside: they are what every gateway and `halod` already trusts, and a restore that changes them is a key rotation, not a restore.

### Restore

1. Scale `halo-server` to 0 (`kubectl -n halos scale deploy/halos-server --replicas 0`). The server reads the files once at start (only the kill store re-reads on external appends, `internal/controller/killstore.go:88`); never write into a running server's directory.
2. Put the files back in `--data-dir` (restore the PVC snapshot, or `kubectl cp` into a helper pod mounting the claim). Ownership must be uid 65532 (`values.yaml:18`).
3. Recreate the Secrets if they were lost: `server.killSwitch.existingSecret` with the same private key, `proxy.killSwitch.pubkey.existingSecret` with the matching public key. A different kill key is a rotation; follow [rotate the kill-switch keys](#rotate-the-kill-switch-keys).
4. Scale back to 1 and check: `GET /readyz` returns 200 (policy loaded), `GET /api/v1/killswitch` lists the kills you expect, `GET /api/v1/audit?limit=1` returns `verified: true`, and the console shows the device count you had.
5. Gateways need nothing: on their next poll (10 s) they fetch the restored list and compare its `version` (`internal/gateway/killswitch.go:209`).

If `killswitch.jsonl` is gone for good, re-issue the kills you know about (`POST /api/v1/experiments/{name}/kill`, `halo toggle kill`) before gateways poll an empty list; the audit log tells you which ones were active.

## Runbook

### Kill a bad change

Fastest path, no PR, no merge: the signed kill switch. Gateways drop the experiment or toggle to control at their next poll (default 10 s); `halod` honours the same list for client-side changes.

```bash
halo toggle kill <toggle> --server https://halos.example.com --reason "..."   # or
curl -X POST -H "Authorization: Bearer $ADMIN" https://halos.example.com/api/v1/experiments/<name>/kill
```

Then open the pause PR so the policy repo agrees with reality; the kill holds until someone unkills, even if the PR is slow. Full walkthrough: [kill a bad change](/halos/tutorials/kill-a-bad-change/). Requires `server.killSwitch.existingSecret`; without it kill returns 501 and the only lever is merging the pause PR.

### Roll a ring back to a previous release

Rings point at immutable releases; rollback re-points (invariant 6).

```bash
halo rollback --ring ring3-ga --to 1.4.2 --registry ghcr.io/acme/halos --key "$KEY"
```

`--to <version>` refuses a tag whose signed manifest does not carry that version; `--to sha256:<manifest digest>` is content-addressed. `halod` picks the new pointer at its next poll and applies only after signature verification, so a bad rollback target cannot brick the fleet: verification failure keeps last-good (`cmd/halod/agent.go:175`). For a traffic-axis rollout use `halo rollout rollback` ([reference](/halos/reference/cli/rollout-rollback/)) and let the controller's auto-rollback stay the only automatic direction. Confirm with `halo rollout status` and the fleet view: every host should report the rolled-back digest within one poll interval.

### Rotate the release signing key

Not a flag day: `halod` trusts every key in `pubkey` plus `pubkeys`. Follow [rotation and compromise](/halos/guides/production-deployment/#rotation-and-compromise): add the new public key everywhere first, publish every ring with the new private key, then drop the old one. For a compromised key, add its fingerprint to `revokedKeys` on every device before anything else.

### Rotate the kill-switch keys

Both halves are read once at startup: `halo-server` from `--killswitch-key-file`, `halo-proxy` from `killSwitch.pubkeyFile` (`cmd/halo-proxy/killswitch.go:36-46`). There is one key on each side, no overlap list, so order the restarts so the window where signatures do not verify is short and safe:

1. `halo keys generate --name killswitch-2026 --out ./keys`.
2. Update the **proxy** Secret (`proxy.killSwitch.pubkey.existingSecret`, key `killswitch.pub`) with the new public key and roll the proxies (`kubectl -n halos rollout restart deploy/halos-proxy`). From now until step 3 they reject lists signed by the old key and **keep the last accepted list** (`internal/gateway/killswitch.go:85`): existing kills stay in force, new kills do not propagate yet. A fresh proxy pod that has never fetched a list kills nothing, so do this when no kill is pending.
3. Update the **server** Secret (`server.killSwitch.existingSecret`, key `signing-key`) with the new private key and restart `halo-server`. The kill list itself is in `killswitch.jsonl`, not in the key, so nothing is lost.
4. Check: `GET /api/v1/killswitch` on the server and a proxy log line showing a list fetched and verified. If `halod` is also on the kill switch, update its `killswitch` public key the same way you distribute `pubkeys`.
5. Rotate the gateway bearer token (`gateway-token` in the same Secret, `proxy.killSwitch.token`) in the same change if it was exposed; server and proxies must agree on it or polls return 401 and proxies keep the last list.

For Kong, the public key and token live in `HALO_KILLSWITCH_PUBKEY` / `HALO_KILLSWITCH_TOKEN` in the Kong deployment's environment; roll Kong between steps 2 and 3.

### Lost signer state file

The file (`pointers.json`) is the replay guard for `refresh`, `promote`, `publish` and `rollback`. Losing it is not an outage: the next signing command refuses with a message naming the ring and the `seq` the registry serves. Confirm the registry is serving what you expect, then re-adopt:

```bash
halo release refresh --ring ring3-ga --registry ghcr.io/acme/halos --key "$KEY" --expect-digest sha256:<release digest>   # one ring, pinned
halo release refresh --ring ring3-ga --registry ghcr.io/acme/halos --key "$KEY" --adopt-existing                        # trust what is served
```

Use `--expect-digest` when you know the release that should be live (the last promotion PR says); use `--adopt-existing` only after checking `crane` / the registry UI that nobody re-pointed the ring. Details and the CI caching that avoids this: [replay protection](/halos/guides/production-deployment/#replay-protection-the-signer-state-file).

### Gateway down: what the CLIs do

`halo-proxy` is in the request path. If every replica is down, or the ingress to it is, Claude Code / Codex / Gemini CLI requests to `ANTHROPIC_BASE_URL` (or the rendered provider URL) fail with a connection error and the CLI retries and surfaces it; there is no client-side fallback to the provider, by design (routing, identity and kill enforcement live in the gateway). Developers are blocked until it is back. What does **not** break: `halod` keeps polling the registry and applying releases, fleet reports keep flowing to `halo-server`, and nothing on disk changes. What to do, in order:

1. `kubectl -n halos get pods -l app.kubernetes.io/component=proxy` and `rollout status`; the readiness probe is `/healthz` on the admin port, so a pod that is Running but not Ready is failing to load its policy snapshot or kill-switch config (look for `halo-proxy: killSwitch.` or `policy` in its logs).
2. If a bad snapshot caused it, re-point `proxy.policy.existingConfigMap` (or the git ref for `gitSync`) at the previous compiled snapshot and roll; the HA checks in `make uat-k8s` show a rolling restart under load is error-free when at least one replica stays Ready.
3. If the upstream is the problem (`halo_proxy_upstream_attempts_total{outcome="failed"}` climbing while pods are Ready), the breaker is doing its job; fix the upstream or switch the route's upstream in policy and re-compile.

A single replica down is not an incident: the PDB and `maxUnavailable: 0` keep the other serving; alert `HaloProxyBelowTwoReplicas` is the early warning.

### halo-server down

Console, enrollment, access requests, fleet reports and the kill-list endpoint are unavailable; gateways keep their last list, `halod` keeps its release and retries reports at WARN. Nothing a developer runs stops working. Restore the pod (a `Recreate` strategy means a stuck old pod holds the RWO volume: `kubectl -n halos describe pod` for `Multi-Attach`). Do not raise `server.replicas`: the schema refuses it and the state model above is why.
