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

# ---- scenarios ----
export UAT_CONTEXT=$CTX UAT_NAMESPACE=$NS UAT_WORK=$WORK UAT_POLICY=$POL UAT_HALO=$WORK/hostbin/halo UAT_ARCH=$ARCH UAT_STARTED=$t0
rc=0
go test -tags uat ./test/uat/k8s/ -v -count=1 -timeout 45m "$@" || rc=$?
exit "$rc"
