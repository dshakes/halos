//go:build uat

// Package k8suat is the Kubernetes UAT (make uat-k8s): user stories run against
// the Halos Helm chart in a kind cluster built by scripts/uat-k8s.sh. The host
// reaches the cluster only through loopback NodePorts; in-cluster hostnames
// (the TLS portal, the mock IdP) are dialled through that mapping, so URLs,
// TLS names and OIDC redirects are exactly what an in-cluster client sees.
package k8suat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	portalURL = "https://portal.uat-infra.svc.cluster.local"
	idpURL    = "http://uatidp.uat-infra.svc.cluster.local:8080"
	proxyURL  = "http://127.0.0.1:30088" // ingress -> halo-proxy Service
	hostReg   = "127.0.0.1:30500/acme/halos"
	podReg    = "registry.uat-infra.svc.cluster.local:5000/acme/halos"
	chURL     = "http://127.0.0.1:30123"
	gitRemote = "git://127.0.0.1:30418/policy.git"
	audience  = "halos-gateway"
)

// in-cluster host:port -> loopback NodePort (manifests/kind.yaml).
var dialMap = map[string]string{
	"portal.uat-infra.svc.cluster.local:443":    "127.0.0.1:30443",
	"uatidp.uat-infra.svc.cluster.local:8080":   "127.0.0.1:30808",
	"registry.uat-infra.svc.cluster.local:5000": "127.0.0.1:30500",
}

type env struct {
	ctx, ns, work, policy, halo string
	ca                          *x509.CertPool
	stateDir                    string // halo signer state (XDG_STATE_HOME)
}

func setup(t *testing.T) *env {
	t.Helper()
	e := &env{ctx: os.Getenv("UAT_CONTEXT"), ns: os.Getenv("UAT_NAMESPACE"), work: os.Getenv("UAT_WORK"),
		policy: os.Getenv("UAT_POLICY"), halo: os.Getenv("UAT_HALO")}
	if e.ctx != "kind-halos-uat" || e.work == "" {
		t.Skip("run via scripts/uat-k8s.sh (make uat-k8s): needs UAT_CONTEXT=kind-halos-uat and UAT_WORK")
	}
	pem, err := os.ReadFile(filepath.Join(e.work, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	e.ca = x509.NewCertPool()
	e.ca.AppendCertsFromPEM(pem)
	e.stateDir = filepath.Join(e.work, "state")
	return e
}

// client follows redirects across the mapped in-cluster hosts with its own cookie jar.
func (e *env) client() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: e.ca, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true, // every request a new connection: spreads across proxy replicas
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if m, ok := dialMap[addr]; ok {
				addr = m
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{Transport: tr, Jar: jar, Timeout: 60 * time.Second}
}

func (e *env) file(name string) string {
	b, err := os.ReadFile(filepath.Join(e.work, name))
	if err != nil {
		panic(err)
	}
	return strings.TrimSpace(string(b))
}

// ---- process helpers ----

type res struct {
	out, err string
	code     int
}

func (r res) String() string { return fmt.Sprintf("exit=%d\n%s%s", r.code, r.out, r.err) }

func runCmd(t *testing.T, stdin string, env []string, name string, args ...string) res {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), env...)
	c.Stdin = strings.NewReader(stdin)
	var o, se bytes.Buffer
	c.Stdout, c.Stderr = &o, &se
	err := c.Run()
	r := res{out: o.String(), err: se.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.code = ee.ExitCode()
	} else if err != nil {
		r.code, r.err = -1, err.Error()
	}
	return r
}

// halo runs the host CLI with a per-run signer state file.
func (e *env) haloCLI(t *testing.T, args ...string) res {
	t.Helper()
	return runCmd(t, "", []string{"XDG_STATE_HOME=" + e.stateDir, "HALO_CLICKHOUSE_PASSWORD=" + e.file("clickhouse.password")}, e.halo, args...)
}

func (e *env) kubectl(t *testing.T, args ...string) res {
	t.Helper()
	return runCmd(t, "", nil, "kubectl", append([]string{"--context", e.ctx}, args...)...)
}

// sh runs a shell command in a pod (container optional).
func (e *env) sh(t *testing.T, ns, pod, container, script string) res {
	t.Helper()
	args := []string{"-n", ns, "exec", pod}
	if container != "" {
		args = append(args, "-c", container)
	}
	return e.kubectl(t, append(args, "--", "sh", "-c", script)...)
}

func (e *env) helm(t *testing.T, args ...string) res {
	t.Helper()
	return runCmd(t, "", nil, "helm", append([]string{"--kube-context", e.ctx, "-n", e.ns}, args...)...)
}

// ---- HTTP ----

func do(t *testing.T, c *http.Client, method, url, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// mint asks the mock IdP for a gateway JWT.
func (e *env) mint(t *testing.T, user string, groups ...string) string {
	t.Helper()
	_, tok := do(t, e.client(), "GET", idpURL+"/mint?user="+user+"&groups="+strings.Join(groups, ","), "", nil)
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("mint %s: %q", user, tok)
	}
	return tok
}

// login runs the portal's OIDC auth-code+PKCE flow against the mock IdP and returns the logged-in client.
func (e *env) login(t *testing.T, email string, groups ...string) *http.Client {
	t.Helper()
	c := e.client()
	if groups == nil {
		groups = []string{}
	}
	claims := fmt.Sprintf(`{"email":%q,"email_verified":true,"groups":[%s]}`, email, quoteAll(groups))
	if r, b := do(t, c, "PUT", idpURL+"/_uat/login", claims, nil); r.StatusCode != 200 {
		t.Fatalf("set idp login: %s %s", r.Status, b)
	}
	resp, _ := do(t, c, "GET", portalURL+"/auth/login", "", nil)
	if resp.Request.URL.Host != "portal.uat-infra.svc.cluster.local" || resp.Request.URL.Path != "/" {
		t.Fatalf("login ended at %s (%s)", resp.Request.URL, resp.Status)
	}
	return c
}

func session(c *http.Client) string {
	u, _ := http.NewRequest("GET", portalURL+"/", nil)
	for _, ck := range c.Jar.Cookies(u.URL) {
		if ck.Name == "halo_session" {
			return ck.Value
		}
	}
	return ""
}

func quoteAll(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ",")
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()
	t0 := time.Now()
	for time.Since(t0) < d {
		if cond() {
			return time.Since(t0)
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
	return 0
}

// ---- report ----

type row struct{ scenario, check, status, evidence string }

type report struct {
	mu   sync.Mutex
	rows []row
}

// check records one assertion (PASS/FAIL + evidence) and fails the test on FAIL.
func (r *report) check(t *testing.T, scenario, check string, ok bool, evidence string, args ...any) bool {
	t.Helper()
	ev := fmt.Sprintf(evidence, args...)
	st := "PASS"
	if !ok {
		st = "FAIL"
		t.Errorf("%s / %s: %s", scenario, check, ev)
	} else {
		t.Logf("PASS %s / %s: %s", scenario, check, ev)
	}
	r.mu.Lock()
	r.rows = append(r.rows, row{scenario, check, st, ev})
	r.mu.Unlock()
	return ok
}

func (r *report) write(t *testing.T, e *env, versions string, took time.Duration) {
	var b strings.Builder
	pass, fail := 0, 0
	for _, x := range r.rows {
		if x.status == "PASS" {
			pass++
		} else {
			fail++
		}
	}
	fmt.Fprintf(&b, "# Kubernetes UAT report\n\nGenerated by `make uat-k8s` (scripts/uat-k8s.sh, test/uat/k8s) on %s against kind cluster `halos-uat` "+
		"(Helm chart `deploy/helm/halos`, values `test/uat/k8s/values-uat.yaml`). Do not edit by hand.\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "**%d PASS, %d FAIL** in %s.\n\nTools: %s\n\n", pass, fail, took.Round(time.Second), versions)
	b.WriteString("| Scenario | Check | Result | Evidence |\n|---|---|---|---|\n")
	esc := strings.NewReplacer("|", `\|`, "\n", " ")
	for _, x := range r.rows {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", x.scenario, esc.Replace(x.check), x.status, esc.Replace(x.evidence))
	}
	b.WriteString(knownLimits)
	p := filepath.Join("..", "REPORT.md")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Errorf("write report: %v", err)
	}
	t.Logf("report: %s (%d PASS, %d FAIL)", p, pass, fail)
}

// knownLimits is appended to the report: what this UAT does not prove.
const knownLimits = `
## Limits (not covered here)

- Releases are published with ` + "`--no-artifacts`" + ` and halod runs with ` + "`--install=false`" + `: no vendor CLI binaries are downloaded or installed
  in the cluster (covered by ` + "`make smoke`" + ` / test/uat CLI UAT). Config files are applied and verified.
- The device trusts the UAT ingress CA via SSL_CERT_FILE; halod requires https for the portal (by design).
- Bedrock (SigV4) upstreams are not exercised: no AWS credentials in kind. Anthropic- and OpenAI-shaped mocks are.
- Controller PRs: the branch is really pushed to the in-cluster git remote; ` + "`gh pr create`" + ` is a recording stub (no GitHub).
- halo-server runs the UAT image with git (` + "`server.controller.policyRepo.image`" + `), as the chart requires for controller PRs.
`
