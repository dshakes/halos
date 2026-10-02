#!/usr/bin/env bash
# Kubernetes UAT: a throwaway kind cluster (halos-uat) running the Helm chart with
# locally built images, an in-cluster OCI registry, git remote, mock OIDC issuer,
# mock model upstreams, ClickHouse and a TLS ingress; then the user-story
# scenarios in test/uat/k8s (go test -tags uat), which write test/uat/REPORT.md.
#
#   make uat-k8s                 # create, test, delete
#   UAT_KEEP=1 make uat-k8s      # keep the cluster afterwards (kind delete cluster --name halos-uat)
#
# Only ever touches the kind-halos-uat context. Needs docker, kind, kubectl, helm, go, git, openssl.
set -euo pipefail
cd "$(dirname "$0")/.."
t0=$SECONDS
CLUSTER=halos-uat
CTX=kind-$CLUSTER
NS=halos-uat
K=(kubectl --context "$CTX")
H=(helm --kube-context "$CTX")

for tool in docker kind kubectl helm go git openssl; do
  command -v "$tool" >/dev/null || { echo "uat-k8s: $tool not found" >&2; exit 1; }
done
echo "uat-k8s: $(kind version) | $(helm version --short) | $(kubectl version --client 2>/dev/null | head -1) | docker $(docker version --format '{{.Server.Version}}')"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/halos-uat.XXXXXX")
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  rc=$?
  if [ "$rc" != 0 ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "uat-k8s: failed (exit $rc); pod state:" >&2
    "${K[@]}" get pods -A -o wide >&2 || true
  fi
  if [ "${UAT_KEEP:-0}" = 1 ]; then
    echo "uat-k8s: keeping cluster $CLUSTER and $WORK (UAT_KEEP=1)"
  else
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    rm -rf "$WORK"
  fi
  echo "uat-k8s: total $((SECONDS - t0))s"
}
trap cleanup EXIT

# ---- cluster ----
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  [ "${UAT_REUSE:-0}" = 1 ] || { echo "uat-k8s: cluster $CLUSTER already exists (delete it, or UAT_REUSE=1)" >&2; exit 1; }
  # Reuse keeps the cluster, never state: start from empty namespaces.
  "${K[@]}" delete namespace $NS uat-infra uat-device uat-outsider --ignore-not-found --wait --timeout 5m >/dev/null
else
  kind create cluster --config test/uat/k8s/manifests/kind.yaml --image "${UAT_KIND_IMAGE:-kindest/node:v1.32.2}" --wait 180s
fi

# ---- binaries + images ----
ARCH=$(docker version --format '{{.Server.Arch}}')
VERSION=uat
mkdir -p "$WORK/ctx/bin" "$WORK/ctx/linux/$ARCH" "$WORK/hostbin"
echo "uat-k8s: building linux/$ARCH binaries"
for p in cmd/halo-server cmd/halo-proxy cmd/halo-shadow cmd/halod cmd/halo deploy/compose/mockllm test/uat/k8s/uatidp; do
  b=$(basename "$p")
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$WORK/ctx/bin/$b" "./$p"
  cp "$WORK/ctx/bin/$b" "$WORK/ctx/linux/$ARCH/$b"
done
go build -o "$WORK/hostbin/halo" ./cmd/halo
go build -o "$WORK/hostbin/load" ./test/load
cp test/uat/k8s/gh "$WORK/ctx/gh" && chmod 0755 "$WORK/ctx/gh"
for b in halo-server halo-proxy halo-shadow; do
  docker build -q -f deploy/docker/Dockerfile.service --build-arg BINARY="$b" -t "ghcr.io/dshakes/$b:uat" "$WORK/ctx" >/dev/null
done
docker build -q -f test/uat/k8s/Dockerfile --target infra -t halos-uat/infra:uat "$WORK/ctx" >/dev/null
docker build -q -f test/uat/k8s/Dockerfile --target server-git -t ghcr.io/halos-uat/halo-server-git:uat "$WORK/ctx" >/dev/null
EXT=(registry:2 nginx:alpine clickhouse/clickhouse-server:26.9.7.9 otel/opentelemetry-collector-contrib:0.161.0 registry.k8s.io/git-sync/git-sync:v4.4.0)
for i in "${EXT[@]}"; do docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null; done
echo "uat-k8s: loading images into kind"
# Via a single-platform archive: `kind load docker-image` fails on multi-arch images
# from Docker's containerd store ("content digest ... not found").
IMGS=(ghcr.io/dshakes/halo-server:uat ghcr.io/dshakes/halo-proxy:uat ghcr.io/dshakes/halo-shadow:uat halos-uat/infra:uat ghcr.io/halos-uat/halo-server-git:uat "${EXT[@]}")
# (the classic image store, e.g. CI runners, has no --platform: it only holds one platform anyway)
docker save --platform "linux/$ARCH" -o "$WORK/images.tar" "${IMGS[@]}" 2>/dev/null || docker save -o "$WORK/images.tar" "${IMGS[@]}"
kind load image-archive --name "$CLUSTER" "$WORK/images.tar" >/dev/null
rm -f "$WORK/images.tar"

# ---- keys, TLS, secrets ----
"$WORK/hostbin/halo" keys generate --out "$WORK/keys" >/dev/null
"$WORK/hostbin/halo" keys generate --name killswitch --out "$WORK/keys" >/dev/null
rnd() { openssl rand -hex 24; }
( cd "$WORK" && openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=halos-uat-ca -keyout ca.key -out ca.crt 2>/dev/null &&
  openssl req -newkey rsa:2048 -nodes -subj /CN=portal -keyout tls.key -out tls.csr 2>/dev/null &&
  printf 'subjectAltName=DNS:portal.uat-infra.svc.cluster.local,DNS:localhost\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > ext.cnf &&
  openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out tls.crt 2>/dev/null )
"${K[@]}" apply -f test/uat/k8s/manifests/infra.yaml --dry-run=client -o name >/dev/null   # schema check before anything lands
for ns in uat-infra $NS uat-device uat-outsider; do "${K[@]}" create namespace "$ns" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null; done
CH_PASS=$(rnd); GW_TOKEN=$(rnd); OTEL_TOKEN=$(rnd)
printf '%s' "$CH_PASS" > "$WORK/clickhouse.password"; printf '%s' "$OTEL_TOKEN" > "$WORK/otel-gateway.token"; printf '%s' "$GW_TOKEN" > "$WORK/gateway.token"
sec() { "${K[@]}" -n "$1" create secret generic "$2" "${@:3}" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null; }
sec $NS halos-fleet-token --from-literal=token="$(rnd)"
sec $NS halos-session --from-literal=session-key="$(rnd)$(rnd)"
sec $NS halos-halo-shadow --from-literal=token="$(rnd)"
sec $NS halos-killswitch --from-file=signing-key="$WORK/keys/killswitch.key" --from-literal=gateway-token="$GW_TOKEN"
sec $NS halos-killswitch-pub --from-file=killswitch.pub="$WORK/keys/killswitch.pub"
sec $NS halos-release-pub --from-file=release.pub="$WORK/keys/halo.pub"
sec $NS halos-otel-gw --from-literal=token="$OTEL_TOKEN"
sec $NS clickhouse --from-literal=username=halo --from-literal=password="$CH_PASS"
"${K[@]}" -n uat-infra create secret tls portal-tls --cert="$WORK/tls.crt" --key="$WORK/tls.key" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" -n uat-device create configmap uat-ca --from-file=ca.crt="$WORK/ca.crt" --dry-run=client -o yaml | "${K[@]}" apply -f - >/dev/null
"${K[@]}" apply -f test/uat/k8s/manifests/infra.yaml >/dev/null
for d in registry git uatidp mock-a mock-b dl ingress; do "${K[@]}" -n uat-infra rollout status deploy/$d --timeout 180s >/dev/null; done
"${K[@]}" -n $NS rollout status deploy/clickhouse --timeout 300s >/dev/null

# ---- policy repo: examples/acme-corp + UAT overlay, pushed to the in-cluster git remote ----
POL="$WORK/policy"
cp -R examples/acme-corp "$POL"
cp -Rf test/uat/k8s/policy-overlay/. "$POL/"
sed -i.bak 's#https://acme.okta.com/oauth2/default#http://uatidp.uat-infra.svc.cluster.local:8080#' "$POL/halos.yaml"
sed -i.bak 's/upstream: orchestrator$/upstream: mock-b/' "$POL/experiments/opus-5-5-canary.yaml"
sed -i.bak 's/upstream: anthropic-direct/upstream: mock-b/' "$POL/toggles/sonnet-next-route.yaml"
find "$POL" -name '*.bak' -delete
"$WORK/hostbin/halo" validate --policy-dir "$POL"
"$WORK/hostbin/halo" gateway compile --policy-dir "$POL" -o "$POL/gateway.compiled.json"
git -C "$POL" init -q -b main
git -C "$POL" -c user.name=uat -c user.email=uat@halos.invalid add -A
git -C "$POL" -c user.name=uat -c user.email=uat@halos.invalid commit -qm "acme-corp + uat overlay"
git -C "$POL" remote add origin git://127.0.0.1:30418/policy.git
for _ in $(seq 30); do git -C "$POL" push -qf origin main 2>/dev/null && break; sleep 2; done
git -C "$POL" ls-remote origin main | grep -q main || { echo "uat-k8s: push to the in-cluster git remote failed" >&2; exit 1; }

# ---- helm install ----
SUM=$(shasum -a 256 "$WORK/ctx/bin/halod" | cut -d' ' -f1)
echo "uat-k8s: helm install"
"${H[@]}" upgrade --install halos deploy/helm/halos -n $NS -f test/uat/k8s/values-uat.yaml \
  --set-json "server.portal.halodSHA256={\"linux-$ARCH\":\"$SUM\"}" --wait --timeout 6m

# ---- ClickHouse schema (after the collector created the otel_* tables; same order as deploy/observability) ----
CH=("${K[@]}" -n "$NS" exec -i deploy/clickhouse -- clickhouse-client --user halo --password "$CH_PASS")
for _ in $(seq 90); do
  n=$("${CH[@]}" -q "SELECT count() FROM system.tables WHERE database='halo' AND name IN ('otel_metrics_sum','otel_metrics_gauge','otel_metrics_histogram','otel_logs')" 2>/dev/null || echo 0)
  [ "$n" = 4 ] && break; sleep 2
done
[ "$n" = 4 ] || { echo "uat-k8s: collector never created the otel tables" >&2; "${K[@]}" -n $NS logs deploy/halos-otel --tail=50 >&2; exit 1; }
"${CH[@]}" --multiquery < deploy/observability/clickhouse/schema.sql
echo "uat-k8s: stack up after $((SECONDS - t0))s"

# ---- HA checks: halo-proxy (2 replicas behind the ingress) under test/load traffic ----
# -rps 200 on purpose: the UAT nginx ingress opens a fresh TCP connection per request to the proxy Service, so
# ~1000 rps (an unthrottled load) exhausts its ~28k ephemeral ports within a minute (TIME_WAIT): 502s that are the harness, not the chart.
# These run BEFORE the scenarios because the ops scenario ends with `helm uninstall`. The load tool
# counts any non-200 or transport error as a failure; every disruption below must leave it at zero.
# Pod deletion is the graceful path (SIGTERM, preStop sleep, drain), i.e. what drains, evictions
# and rolling upgrades do; a SIGKILLed pod drops its in-flight requests and is NOT covered.
echo "uat-k8s: HA checks"
PXD=halos-proxy
PXSEL=app.kubernetes.io/component=proxy,app.kubernetes.io/instance=halos
LOADBIN="$WORK/hostbin/load"
HA_TOK=$(curl -fsS "http://127.0.0.1:30808/mint?user=ha@acme.com")
ha_rc=0
ha_result() { # name, ok(0|1), evidence
  if [ "$2" = 0 ]; then echo "  [PASS] $1: $3"; else echo "  [FAIL] $1: $3"; ha_rc=1; fi
}
proxy_ready() { # Ready proxy pods that are not terminating
  "${K[@]}" -n $NS get pods -l $PXSEL -o jsonpath='{range .items[*]}{.metadata.deletionTimestamp}|{.status.containerStatuses[?(@.name=="halo-proxy")].ready}{"\n"}{end}' | grep -c '^|true$' || true
}
await_proxies() { # until 2 Ready and none terminating
  for _ in $(seq 150); do
    [ "$(proxy_ready)" = 2 ] && [ "$("${K[@]}" -n $NS get pods -l $PXSEL -o name | wc -l | tr -d ' ')" = 2 ] && return 0
    sleep 2
  done
  return 1
}
load_start() { # outfile; sets LOAD_PID
  "$LOADBIN" -target "http://127.0.0.1:30088/v1/messages" -token "$HA_TOK" -model haiku -c 8 -rps 200 -duration 15m > "$1" 2>&1 &
  LOAD_PID=$!
  sleep 5   # steady state before the disruption
}
load_stop() { # outfile -> sets LOAD_RC, prints the load summary
  sleep 3   # keep driving after the disruption settles
  kill -INT "$LOAD_PID" 2>/dev/null || true
  LOAD_RC=0; wait "$LOAD_PID" || LOAD_RC=$?
  grep -E 'target load:|error:|PASS|FAIL' "$1" | sed 's/^/    /'
}
await_proxies || { echo "uat-k8s: proxies never became 2/2 Ready" >&2; exit 1; }
evict() { # pod -> prints the API answer
  printf '{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"%s","namespace":"%s"}}' "$1" "$NS" |
    "${K[@]}" create --raw "/api/v1/namespaces/$NS/pods/$1/eviction" -f - 2>&1 || true
}

# 1. kill a proxy pod mid-traffic
load_start "$WORK/ha-kill.txt"
victim=$("${K[@]}" -n $NS get pods -l $PXSEL -o jsonpath='{.items[0].metadata.name}')
"${K[@]}" -n $NS delete pod "$victim" --wait=false >/dev/null
rec=0; await_proxies || rec=1
load_stop "$WORK/ha-kill.txt"
ha_result "kill a proxy pod mid-traffic: no client errors" $((LOAD_RC != 0 || rec)) "deleted $victim, replacement Ready: $([ $rec = 0 ] && echo yes || echo NO); load exit $LOAD_RC"

# 2. rolling upgrade under traffic
before=$("${K[@]}" -n $NS get pods -l $PXSEL -o name | sort | tr '\n' ' ')
load_start "$WORK/ha-roll.txt"
up=0; "${H[@]}" upgrade halos deploy/helm/halos -n $NS --reuse-values --set-string "proxy.podAnnotations.uat-ha-roll=$SECONDS" --wait --timeout 6m >/dev/null || up=1
await_proxies || up=1
load_stop "$WORK/ha-roll.txt"
after=$("${K[@]}" -n $NS get pods -l $PXSEL -o name | sort | tr '\n' ' ')
roll_changed=0; [ "$before" != "$after" ] || roll_changed=1
ha_result "rolling upgrade: zero failed requests, both pods replaced" $((LOAD_RC != 0 || up || roll_changed)) "helm upgrade exit $up; pods [$before] -> [$after]; load exit $LOAD_RC"

# 3. PDB respected: the second concurrent eviction is refused until the first pod is replaced
allowed=$("${K[@]}" -n $NS get pdb $PXD -o jsonpath='{.status.disruptionsAllowed}/{.spec.maxUnavailable}' 2>&1 || true)
pdb_exists=1; [ "$allowed" != 1/1 ] || pdb_exists=0
ha_result "proxy PodDisruptionBudget exists (maxUnavailable 1, 1 disruption allowed)" "$pdb_exists" "disruptionsAllowed/maxUnavailable = $allowed"
load_start "$WORK/ha-pdb.txt"
read -r pod1 pod2 <<< "$("${K[@]}" -n $NS get pods -l $PXSEL -o jsonpath='{.items[*].metadata.name}')"
e1=$(evict "$pod1"); e2=$(evict "$pod2")
await_proxies || true
e3=$(evict "$("${K[@]}" -n $NS get pods -l $PXSEL -o jsonpath='{.items[0].metadata.name}')")   # budget restored: allowed again
await_proxies || true
load_stop "$WORK/ha-pdb.txt"
pdb_ok=1; echo "$e2" | grep -q 'disruption budget' && ! echo "$e1" | grep -qi 'error' && ! echo "$e3" | grep -qi 'error' && pdb_ok=0
ha_result "PDB respected: 1st eviction ok, 2nd refused (429), later eviction ok; no client errors" $((pdb_ok || LOAD_RC != 0)) "1st: $(echo "$e1" | head -1 | cut -c1-60) | 2nd: $(echo "$e2" | head -1 | cut -c1-110) | 3rd: $(echo "$e3" | head -1 | cut -c1-60) | load exit $LOAD_RC"
[ "$ha_rc" = 0 ] || { echo "uat-k8s: HA checks failed" >&2; exit 1; }

# ---- scenarios ----
export UAT_CONTEXT=$CTX UAT_NAMESPACE=$NS UAT_WORK=$WORK UAT_POLICY=$POL UAT_HALO=$WORK/hostbin/halo UAT_ARCH=$ARCH UAT_STARTED=$t0
rc=0
go test -tags uat ./test/uat/k8s/ -v -count=1 -timeout 45m "$@" || rc=$?
exit "$rc"
