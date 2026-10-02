//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

// TestGatewayEnforcement: rings with posture: enforce and versionGate: enforce.
// A real halod enrolls through halo-server and reports; a real halo-proxy asks
// halo-server for the caller's device posture and parses the CLI version from
// the User-Agent. Refusals are 403s from the proxy, never reaching the upstream.
func TestGatewayEnforcement(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()
	up := newFake(t, "primary")

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	org := gatewayPolicy(t, pol, iss.URL, up.URL, up.URL)
	if err := os.Remove(filepath.Join(pol, "experiments/shadow.yaml")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"ring0-canary", "ring1-ga"} {
		f := filepath.Join(pol, "rings", r+".yaml")
		writeFile(t, f, readFile(t, f)+"posture: enforce\nversionGate: enforce\n")
	}
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("enforcing policy invalid: %s", r)
	}

	keys := filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	repo := repoName(t)
	for ring, ver := range map[string]string{"ring0-canary": "2.0.0", "ring1-ga": "1.0.0"} {
		must(t, nil, "halo", "release", "publish", pol, "--ring", ring, "--release-version", ver,
			"--key", filepath.Join(keys, "halo.key"), "--registry", repo, "--plain-http", "--no-artifacts")
	}

	// halo-server: portal (enrollment, registry for the release check) + gateway token (posture).
	addr := freeAddr(t)
	base := "http://" + addr
	writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
	writeFile(t, filepath.Join(dir, "session.key"), "e2e-session-key-0123456789abcdef0123456789abcdef\n")
	pc, _ := json.Marshal(map[string]any{
		"baseURL": base, "registry": repo, "registryPlainHTTP": true, "pubKeyFile": filepath.Join(keys, "halo.pub"),
		"halodURL": "https://downloads.example.com/halod-{os}-{arch}", "halodSHA256": map[string]string{"linux-amd64": strings.Repeat("a", 64)},
		"sessionKeyFile": filepath.Join(dir, "session.key"),
	})
	writeFile(t, filepath.Join(dir, "portal.json"), string(pc))
	start(t, nil, "halo-server", "--listen", addr, "--policy-dir", pol, "--token-file", filepath.Join(dir, "fleet.token"),
		"--portal-config", filepath.Join(dir, "portal.json"), "--data-dir", filepath.Join(dir, "data"),
		"--gateway-token-file", filepath.Join(dir, "gateway.token"))
	waitUp(t, base+"/healthz", 200)

	// Enroll a laptop for the ring0 user and run a real halod once.
	users := usersByRing(t, org)
	dev, other := users["ring0-canary"], users["ring1-ga"]
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	iss.SetLogin(map[string]any{"email": dev, "email_verified": true, "groups": []string{"eng"}})
	resp, err := c.Get(base + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Post(base+"/api/v1/launch/laptop", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var launch struct{ Token string }
	if err := json.NewDecoder(resp.Body).Decode(&launch); err != nil || launch.Token == "" {
		t.Fatalf("launch laptop: %s %v", resp.Status, err)
	}
	resp.Body.Close()
	resp, err = http.Post(base+"/api/v1/enroll", "application/json", strings.NewReader(`{"token":"`+launch.Token+`","os":"linux"}`))
	if err != nil {
		t.Fatal(err)
	}
	halodYAML, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var cfg map[string]any
	if resp.StatusCode != 200 || yaml.Unmarshal(halodYAML, &cfg) != nil {
		t.Fatalf("enroll: %s %s", resp.Status, halodYAML)
	}
	etc := filepath.Join(dir, "etc")
	writeFile(t, filepath.Join(etc, "release.pub"), readFile(t, filepath.Join(keys, "halo.pub")))
	cfg["pubkey"], cfg["plainHTTP"], cfg["os"] = filepath.Join(etc, "release.pub"), true, "linux"
	out, _ := yaml.Marshal(cfg)
	writeFile(t, filepath.Join(etc, "halod.yaml"), string(out))
	if err := os.Chmod(filepath.Join(etc, "halod.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	halod := func() {
		t.Helper()
		if r := run(t, []string{"SYD_TEST_TRUST_SELF=1"}, "", "halod", "once", "--config", filepath.Join(etc, "halod.yaml"), "--root", root,
			"--install=false", "--state", "/var/lib/halos/state.json"); r.code != 0 {
			t.Fatalf("halod once: %s", r)
		}
	}
	halod()

	// halo-proxy asking halo-server for posture; no verdict caching so each step is seen at once.
	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	pcfg := filepath.Join(dir, "proxy.yaml")
	writeFile(t, pcfg, "posture:\n  url: "+base+"/api/v1/gateway/posture\n  tokenFile: "+filepath.Join(dir, "gateway.token")+"\n  cacheTTL: 1ns\n")
	start(t, nil, "halo-proxy", "--config", pcfg, "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap)
	waitUp(t, "http://"+adminAddr+"/healthz", 200)

	pinnedUA := "claude-cli/" + pin + " (external, cli)" // Claude Code's UA format; see ParseUA
	send := func(user, ua string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/v1/messages",
			strings.NewReader(`{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer "+mint(t, iss, user))
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	expect := func(name, user, ua string, code int, body string) {
		t.Helper()
		got, b := send(user, ua)
		if got != code || !strings.Contains(b, body) {
			t.Fatalf("%s: %d %s, want %d containing %q", name, got, b, code, body)
		}
	}

	hits := up.hits.Load()
	expect("enrolled, compliant, pinned CLI", dev, pinnedUA, 200, `"ok":true`)
	expect("CLI off the ring pin", dev, "claude-cli/2.1.279 (external, cli)", 403, "version check failed")
	expect("unrecognised User-Agent", dev, "curl/8.7.1", 403, "unrecognised or missing User-Agent")
	expect("user without an enrolled device", other, pinnedUA, 403, "no enrolled device")

	// Drift: edit a managed file; halod restores it and reports the drift, and
	// the gateway refuses until a clean run is reported.
	managed := filepath.Join(root, "etc/claude-code/managed-settings.json")
	writeFile(t, managed, `{"permissions":{"defaultMode":"acceptEdits"}}`)
	halod()
	expect("drift reported", dev, pinnedUA, 403, "reported drift in /etc/claude-code/managed-settings.json")
	expect("refusal names the fix", dev, pinnedUA, 403, "halod status")
	halod()
	expect("clean run reported", dev, pinnedUA, 200, `"ok":true`)
	if n := up.hits.Load() - hits; n != 2 {
		t.Fatalf("upstream saw %d requests, want 2 (refusals must not reach it)", n)
	}

	mresp, err := http.Get("http://" + adminAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := io.ReadAll(mresp.Body)
	mresp.Body.Close()
	for _, want := range []string{
		`halo_proxy_gate_total{gate="version",ring="ring0-canary",outcome="enforce"} 2`,
		`halo_proxy_gate_total{gate="posture",ring="ring0-canary",outcome="enforce"} 2`,
	} {
		if !strings.Contains(string(m), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}
