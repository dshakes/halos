//go:build uat

package uat

// Real-CLI UAT environment: Docker network with
//
//	registry  registry:2 over TLS (the signed release)
//	mock      test/uat/mock: OIDC issuer, Anthropic/OpenAI/Gemini upstreams,
//	          MCP servers, OTLP sink, halod download (https://mock:8443/files)
//	cli       node:22 + the Halos Dev Container Feature (install.sh -> halod once
//	          --install: pinned CLIs + managed settings) + halo-proxy on localhost:8088
//
// See scripts/uat-clis.sh and test/uat/CLI-REPORT.md.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	cliRing    = "ring3-ga"
	cliRelease = "uat.1"
	cliUser    = "dev@acme.example"
	// cliBase is the eval images' node base (evals/images/*), pinned by digest.
	cliBase = "node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c"
)

type cliEnv struct {
	t        *testing.T
	root     string // repo root
	dir      string // host scratch, mounted read-only at /uat in every container
	arch     string
	id       string
	net      string
	cli      string // CLI container
	pins     map[string]string
	rendered map[string]string // container path -> rendered content (halo render)
}

var (
	cliOnce   sync.Once
	cliShared *cliEnv
	cliErr    error
)

// cliSetup builds the environment once per `go test` process; later callers reuse it.
func cliSetup(t *testing.T) *cliEnv {
	t.Helper()
	cliOnce.Do(func() {
		cliShared, cliErr = newCLIEnv(t)
		t.Cleanup(cliShared.cleanup)
	})
	if cliErr != nil {
		t.Fatalf("uat setup: %v", cliErr)
	}
	return cliShared
}

func cliRun(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	err := cmd.Run()
	return b.String(), err
}

func cliDocker(args ...string) (string, error) { return cliRun("docker", args...) }

func newCLIEnv(t *testing.T) (*cliEnv, error) {
	root, err := filepath.Abs("../..")
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "halos-uat-clis-")
	if err != nil {
		return nil, err
	}
	arch, err := cliDocker("version", "-f", "{{.Server.Arch}}")
	if err != nil {
		return nil, fmt.Errorf("docker: %v: %s", err, arch)
	}
	arch = strings.NewReplacer("aarch64", "arm64", "x86_64", "amd64").Replace(strings.TrimSpace(arch))
	e := &cliEnv{t: t, root: root, dir: dir, arch: arch, id: fmt.Sprintf("halos-uat-clis-%d", time.Now().Unix()%100000)}
	e.net, e.cli = e.id+"-net", e.id+"-cli"
	t.Logf("uat scratch %s (KEEP=1 keeps it and the containers)", dir)
	// Cleanup must run after every test in the process; TestMain is avoided
	// (test/uat is shared with the k8s UAT), so the top-level test registers it.
	step := func(name string, f func() error) error {
		start := time.Now()
		if err := f(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		t.Logf("setup: %s (%s)", name, time.Since(start).Round(time.Second))
		return nil
	}
	for _, s := range []struct {
		name string
		f    func() error
	}{
		{"build linux binaries", e.build},
		{"tls", e.tls},
		{"policy", e.policy},
		{"containers", e.containers},
		{"publish signed release", e.publish},
		{"dev container feature install", e.feature},
		{"halo-proxy", e.proxy},
	} {
		if err := step(s.name, s.f); err != nil {
			return e, err
		}
	}
	return e, nil
}

// cleanup removes containers, the network and the scratch dir unless KEEP=1.
func (e *cliEnv) cleanup() {
	if e == nil || os.Getenv("KEEP") == "1" {
		return
	}
	if ids, _ := cliDocker("ps", "-aq", "--filter", "label=halos-uat-clis="+e.id); strings.TrimSpace(ids) != "" {
		_, _ = cliDocker(append([]string{"rm", "-f"}, strings.Fields(ids)...)...)
	}
	_, _ = cliDocker("network", "rm", e.net)
	_, _ = cliDocker("rmi", "halos-uat-clis:"+e.id) // eval images are kept: they are the pinned eval-<cli>:<v> tags
	_ = os.RemoveAll(e.dir)
}

func (e *cliEnv) build() error {
	for _, b := range []struct{ out, pkg, tags string }{
		{"bin/halo", "./cmd/halo", ""},
		{"bin/halo-proxy", "./cmd/halo-proxy", ""},
		{"bin/uatmock", "./test/uat/mock", "uat"},
		{"files/halod/linux-" + e.arch + "/halod", "./cmd/halod", ""},
	} {
		args := []string{"build", "-trimpath", "-o", filepath.Join(e.dir, b.out)}
		if b.tags != "" {
			args = append(args, "-tags", b.tags)
		}
		cmd := exec.Command("go", append(args, b.pkg)...)
		cmd.Dir = e.root
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+e.arch, "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build %s: %v: %s", b.pkg, err, out)
		}
	}
	return nil
}

// tls writes a CA and a leaf for mock/registry/localhost under tls/.
func (e *cliEnv) tls() error {
	d := filepath.Join(e.dir, "tls")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "halos-uat-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mock"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		DNSNames: []string{"mock", "registry", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	for name, b := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"leaf.pem": {Type: "CERTIFICATE", Bytes: der},
		"leaf.key": {Type: "EC PRIVATE KEY", Bytes: kb},
	} {
		if err := os.WriteFile(filepath.Join(d, name), pem.EncodeToMemory(b), 0o644); err != nil { //nolint:gosec // throwaway test key, read by containers
			return err
		}
	}
	return nil
}

// policy derives the UAT policy from examples/acme-corp: the same org, ring
// and CLI pins, with the issuer, gateway, MCP servers and OTLP endpoint
// pointed at the mock, plus a running traffic experiment so variants are stamped.
func (e *cliEnv) policy() error {
	src, dst := filepath.Join(e.root, "examples/acme-corp"), filepath.Join(e.dir, "policy")
	read := func(p string) (string, error) { b, err := os.ReadFile(filepath.Join(src, p)); return string(b), err }
	write := func(p, s string) error {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, p)), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, p), []byte(s), 0o644) //nolint:gosec // test fixture
	}
	replace := func(s string, pairs ...string) (string, error) {
		for i := 0; i < len(pairs); i += 2 {
			if !strings.Contains(s, pairs[i]) {
				return "", fmt.Errorf("examples/acme-corp changed: %q not found", pairs[i])
			}
			s = strings.ReplaceAll(s, pairs[i], pairs[i+1])
		}
		return s, nil
	}
	halos, err := read("halos.yaml")
	if err != nil {
		return err
	}
	if halos, err = replace(halos, "https://acme.okta.com/oauth2/default", "https://mock:8443"); err != nil {
		return err
	}
	base, err := read("profiles/base.yaml")
	if err != nil {
		return err
	}
	if base, err = replace(base,
		"https://mcp-docs.internal.acme.example/mcp", "https://mock:8443/mcp/docs",
		"https://mcp-tickets.internal.acme.example/mcp", "https://mock:8443/mcp/tickets",
		"    - ai.acme.example\n", "    - ai.acme.example\n    - localhost\n    - mock\n",
		"https://otel.internal.acme.example:4318", "http://mock:8080",
		// The audit hook binary does not exist in the UAT image; a failing Bash hook is not under test.
		"command: /usr/local/bin/acme-audit-hook", "command: /bin/true"); err != nil {
		return err
	}
	ring, err := read("rings/ring3-ga.yaml")
	if err != nil {
		return err
	}
	engRaw, err := os.ReadFile(filepath.Join(src, "profiles/engineering.yaml"))
	if err != nil {
		return err
	}
	var eng map[string]any
	if err := yaml.Unmarshal(engRaw, &eng); err != nil {
		return err
	}
	hs := eng["harnesses"].(map[string]any)
	e.pins = map[string]string{}
	for h, v := range hs {
		e.pins[h] = fmt.Sprint(v.(map[string]any)["version"])
	}
	// acme pins no Copilot CLI; pin the latest checked release so the adapter is exercised.
	e.pins["copilot"] = "1.0.90"
	hs["copilot-cli"] = map[string]any{"version": e.pins["copilot"]}
	// acme gives codex and gemini their own aliases (harnesses.<h>.model).
	engOut, err := yaml.Marshal(eng)
	if err != nil {
		return err
	}
	gateway := `apiVersion: halos.dev/v1alpha1
kind: Gateway
name: uat-gateway
baseURL: http://localhost:8088
protocols:
  claude-code: anthropic-messages
  codex: openai-responses
  gemini-cli: gemini
auth:
  helperCommand: /usr/local/bin/halo-uat-token
  ttlSeconds: 300
upstreams:
  anthropic-mock: {url: "http://mock:8080", kind: orchestrator}
  openai-mock: {url: "http://mock:8080", kind: openai}
  gemini-mock: {url: "http://mock:8080", kind: gemini}
models:
  sonnet: {upstream: anthropic-mock, model: claude-uat-sonnet-upstream}
  opus: {upstream: anthropic-mock, model: claude-uat-opus-upstream}
  haiku: {upstream: anthropic-mock, model: claude-uat-haiku-upstream}
  codex-default: {upstream: openai-mock, model: gpt-uat-upstream}
  gemini-default: {upstream: gemini-mock, model: gemini-uat-upstream}
`
	experiment := `apiVersion: halos.dev/v1alpha1
kind: Experiment
name: uat-route
type: canary
axis: traffic
status: running
rings: [ring3-ga]
variants:
  - {name: control, weight: 50, control: true}
  - name: uat-next
    weight: 50
    routes:
      sonnet: {upstream: anthropic-mock, model: claude-uat-sonnet-next}
      codex-default: {upstream: openai-mock, model: gpt-uat-next}
      gemini-default: {upstream: gemini-mock, model: gemini-uat-next}
metrics:
  primary: {metric: halo.api.error_rate, direction: decrease}
stopping: {method: msprt, alpha: 0.05, minSamples: 100, maxDays: 14, maxSpendUSD: 10}
`
	for p, s := range map[string]string{
		"halos.yaml": halos, "gateway.yaml": gateway, "profiles/base.yaml": base,
		"profiles/engineering.yaml": string(engOut), "rings/ring3-ga.yaml": ring, "experiments/uat-route.yaml": experiment,
	} {
		if err := write(p, s); err != nil {
			return err
		}
	}
	// The Feature under test, as shipped (example/ is documentation only).
	for _, f := range []string{"install.sh", "init-firewall.sh", "devcontainer-feature.json"} {
		b, err := os.ReadFile(filepath.Join(e.root, "features/halos", f))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(e.dir, "feature"), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(e.dir, "feature", f), b, 0o755); err != nil { //nolint:gosec // scripts
			return err
		}
	}
	return nil
}

func (e *cliEnv) containers() error {
	label := "--label=halos-uat-clis=" + e.id
	if out, err := cliDocker("network", "create", label, e.net); err != nil {
		return fmt.Errorf("network: %v: %s", err, out)
	}
	tlsDir := filepath.Join(e.dir, "tls")
	if out, err := cliDocker("run", "-d", label, "--name", e.id+"-reg", "--network", e.net, "--network-alias", "registry",
		"-v", tlsDir+":/certs:ro", "-e", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/leaf.pem", "-e", "REGISTRY_HTTP_TLS_KEY=/certs/leaf.key", "registry:2"); err != nil {
		return fmt.Errorf("registry: %v: %s", err, out)
	}
	if out, err := cliDocker("run", "-d", label, "--name", e.id+"-mock", "--network", e.net, "--network-alias", "mock",
		"-v", e.dir+":/uat:ro", "debian:bookworm-slim", "/uat/bin/uatmock", "-cert", "/uat/tls/leaf.pem", "-key", "/uat/tls/leaf.key",
		"-files", "/uat/files", "-issuer", "https://mock:8443"); err != nil {
		return fmt.Errorf("mock: %v: %s", err, out)
	}
	img := filepath.Join(e.dir, "img")
	if err := os.MkdirAll(img, 0o755); err != nil {
		return err
	}
	ca, err := os.ReadFile(filepath.Join(tlsDir, "ca.pem"))
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(img, "ca.pem"), ca, 0o644) //nolint:gosec // public cert
	// node from the official image is root-owned under /usr/local (the Feature's
	// documented "nodejs.org install"), which halod requires for npm installs.
	df := "FROM " + cliBase + `
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git python3 procps && rm -rf /var/lib/apt/lists/*
COPY ca.pem /usr/local/share/ca-certificates/halos-uat.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
`
	if err := os.WriteFile(filepath.Join(img, "Dockerfile"), []byte(df), 0o644); err != nil { //nolint:gosec // test fixture
		return err
	}
	if out, err := cliDocker("build", "-q", label, "-t", "halos-uat-clis:"+e.id, img); err != nil {
		return fmt.Errorf("image: %v: %s", err, out)
	}
	if out, err := cliDocker("run", "-d", label, "--name", e.cli, "--network", e.net, "-v", e.dir+":/uat:ro",
		"halos-uat-clis:"+e.id, "sleep", "infinity"); err != nil {
		return fmt.Errorf("cli: %v: %s", err, out)
	}
	for i := 0; ; i++ {
		if out, rc := e.sh(`curl -fsS https://mock:8443/.well-known/openid-configuration >/dev/null && curl -fsS https://registry:5000/v2/ >/dev/null`); rc == 0 {
			break
		} else if i > 50 {
			return fmt.Errorf("mock/registry not reachable over TLS: %s", out)
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil
}

// publish signs and pushes the release from inside the network (TLS registry, real vendor artifacts).
func (e *cliEnv) publish() error {
	out, rc := e.sh(`set -e; mkdir -p /root/k && /uat/bin/halo keys generate --out /root/k >/dev/null
/uat/bin/halo release publish /uat/policy --ring ` + cliRing + ` --release-version ` + cliRelease + ` --key /root/k/halo.key --registry registry:5000/halos/rel`)
	if rc != 0 {
		return fmt.Errorf("halo release publish: %s", out)
	}
	e.t.Logf("publish:\n%s", out)
	return nil
}

// feature runs the Dev Container Feature's install.sh as root with its options
// as upper-case env, exactly as the devcontainer CLI does at image build.
func (e *cliEnv) feature() error {
	sum, err := os.ReadFile(filepath.Join(e.dir, "files/halod/linux-"+e.arch, "halod"))
	if err != nil {
		return err
	}
	h := sha256.Sum256(sum)
	pub, rc := e.sh(`cat /root/k/halo.pub`)
	if rc != 0 {
		return fmt.Errorf("pubkey: %s", pub)
	}
	pem := strings.ReplaceAll(strings.TrimSpace(pub), "\n", `\n`)
	out, rc := e.shEnv([]string{
		"REGISTRY=registry:5000/halos/rel", "ORG=acme-corp", "RING=" + cliRing, "PUBKEYPEM=" + pem,
		"HALODURL=https://mock:8443/files/halod/linux-{arch}/halod", "HALODSHA256=" + e.arch + "=" + hex.EncodeToString(h[:]),
	}, `bash /uat/feature/install.sh 2>&1`)
	e.t.Logf("feature install.sh (rc=%d):\n%s", rc, tail(out, 40))
	if rc != 0 {
		return fmt.Errorf("feature install.sh exit %d", rc)
	}
	// What halod applied must be exactly `halo render` of the same release.
	if out, rc := e.sh(`/uat/bin/halo render /uat/policy --ring ` + cliRing + ` --os linux --release-version ` + cliRelease + ` --out /root/rendered >/dev/null 2>&1 && cd /root/rendered && find . -type f | sort`); rc != 0 {
		return fmt.Errorf("halo render: %s", out)
	} else {
		e.rendered = map[string]string{}
		for _, f := range strings.Fields(out) {
			e.rendered[strings.TrimPrefix(f, ".")], _ = e.sh("cat /root/rendered/" + strings.TrimPrefix(f, "./"))
		}
	}
	// Token helper the rendered apiKeyHelper / gateway.auth.helperCommand names.
	if out, rc := e.sh(`printf '#!/bin/sh\nexec curl -fsS "https://mock:8443/_uat/mint?email=` + cliUser + `&aud=halos-gateway&groups=eng"\n' >/usr/local/bin/halo-uat-token && chmod 755 /usr/local/bin/halo-uat-token && /usr/local/bin/halo-uat-token >/dev/null`); rc != 0 {
		return fmt.Errorf("token helper: %s", out)
	}
	return nil
}

func (e *cliEnv) proxy() error {
	if out, rc := e.sh(`/uat/bin/halo gateway compile --policy-dir /uat/policy -o /etc/halos/gateway-policy.json`); rc != 0 {
		return fmt.Errorf("gateway compile: %s", out)
	}
	if out, err := cliDocker("exec", "-d", e.cli, "sh", "-c",
		"/uat/bin/halo-proxy --policy /etc/halos/gateway-policy.json --listen 127.0.0.1:8088 --admin-listen 127.0.0.1:9090 >/var/log/halo-proxy.log 2>&1"); err != nil {
		return fmt.Errorf("start proxy: %v: %s", err, out)
	}
	for i := 0; i < 50; i++ {
		if _, rc := e.sh(`curl -fsS http://127.0.0.1:9090/healthz >/dev/null`); rc == 0 {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	log, _ := e.sh(`cat /var/log/halo-proxy.log`)
	return fmt.Errorf("halo-proxy not healthy: %s", log)
}

// sh runs a script in the CLI container through a login shell (so the
// Feature's /etc/profile.d gateway env applies, as in a developer terminal).
func (e *cliEnv) sh(script string) (string, int) { return e.shEnv(nil, script) }

func (e *cliEnv) shEnv(env []string, script string) (string, int) {
	args := []string{"exec", "-w", "/root"}
	for _, kv := range env {
		args = append(args, "-e", kv)
	}
	args = append(args, e.cli, "bash", "-lc", script)
	out, err := cliDocker(args...)
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		rc = -1
	}
	return out, rc
}

// mockReq is one request the mock recorded.
type mockReq struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func (r mockReq) header(k string) string {
	for n, v := range r.Headers {
		if strings.EqualFold(n, k) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// model is the body's model, or the path's for Gemini (/v1beta/models/<m>:...).
func (r mockReq) model() string {
	var m struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal([]byte(r.Body), &m)
	if m.Model == "" {
		if _, rest, ok := strings.Cut(r.Path, "/models/"); ok {
			m.Model, _, _ = strings.Cut(rest, ":")
		}
	}
	return m.Model
}

func (e *cliEnv) resetMock() { e.sh(`curl -fsS -XPOST http://mock:8080/_uat/reset`) }

func (e *cliEnv) mockRequests() []mockReq {
	out, _ := e.sh(`curl -fsS http://mock:8080/_uat/requests`)
	var rs []mockReq
	if err := json.Unmarshal([]byte(out), &rs); err != nil {
		e.t.Errorf("mock requests: %v: %s", err, tail(out, 5))
	}
	return rs
}

type otlpRec struct {
	Signal string            `json:"signal"`
	Attrs  map[string]string `json:"attrs"`
}

func (e *cliEnv) mockOTLP() []otlpRec {
	out, _ := e.sh(`curl -fsS http://mock:8080/_uat/otlp`)
	var rs []otlpRec
	_ = json.Unmarshal([]byte(out), &rs)
	return rs
}

func tail(s string, n int) string {
	l := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// --- report ---------------------------------------------------------------

type cliRow struct{ Harness, Assertion, Status, Evidence string }

var (
	cliRowsMu sync.Mutex
	cliRows   []cliRow
)

// check records PASS/FAIL. known names a documented product gap: its failure is
// reported but does not fail the run, and its unexpected success does (so the
// gap list stays honest).
func check(t *testing.T, harness, assertion string, ok bool, evidence, known string) {
	t.Helper()
	st := "PASS"
	switch {
	case !ok && known != "":
		st = "FAIL (known: " + known + ")"
	case !ok:
		st = "FAIL"
		t.Errorf("%s / %s: FAIL: %s", harness, assertion, evidence)
	case known != "":
		t.Errorf("%s / %s: passed but is listed as known gap %q; update the test and CLI-REPORT.md", harness, assertion, known)
	}
	t.Logf("%s | %s | %s | %s", harness, assertion, st, evidence)
	cliRowsMu.Lock()
	cliRows = append(cliRows, cliRow{harness, assertion, st, evidence})
	cliRowsMu.Unlock()
}

func unverified(t *testing.T, harness, assertion, reason string) {
	t.Helper()
	t.Logf("%s | %s | UNVERIFIED | %s", harness, assertion, reason)
	cliRowsMu.Lock()
	cliRows = append(cliRows, cliRow{harness, assertion, "UNVERIFIED", reason})
	cliRowsMu.Unlock()
}

// writeReport writes the results table to $UAT_CLI_RESULTS (default: scratch).
func writeReport(t *testing.T, e *cliEnv, versions map[string]string) {
	p := os.Getenv("UAT_CLI_RESULTS")
	if p == "" && e != nil {
		p = filepath.Join(e.dir, "cli-results.md")
	}
	if p == "" {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "<!-- generated by test/uat (make uat-clis) %s -->\n\n", time.Now().UTC().Format(time.RFC3339))
	b.WriteString("| CLI | version |\n|---|---|\n")
	for _, h := range []string{"claude-code", "codex", "gemini-cli", "copilot"} {
		v := strings.TrimSpace(versions[h])
		fmt.Fprintf(&b, "| %s | `%s` |\n", h, v[strings.LastIndex(v, "\n")+1:]) // gemini prints an OTEL notice first
	}
	b.WriteString("\n| Harness | Assertion | Result | Evidence |\n|---|---|---|---|\n")
	cliRowsMu.Lock()
	for _, r := range cliRows {
		ev := strings.NewReplacer("|", `\|`, "\n", " ").Replace(r.Evidence)
		if len(ev) > 400 {
			ev = ev[:400] + "..."
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", r.Harness, r.Assertion, r.Status, ev)
	}
	cliRowsMu.Unlock()
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil { //nolint:gosec // report
		t.Errorf("write report: %v", err)
	}
	t.Logf("results table: %s", p)
}
