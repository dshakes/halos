//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/toggle"
)

// TestToggles: feature toggles end to end. A client toggle (an env flag for 50%
// of ring1-ga) ships as a fragment inside the signed release; two enrolled
// devices run the real halod, which applies it only where the rule matches. A
// traffic toggle routes the sonnet alias to the candidate upstream at the real
// halo-proxy. An admin kill on halo-server turns both off, and the unkill turns
// them back on, with no new release published (the device digest never moves).
func TestToggles(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()
	primary, candidate := freeAddr(t), freeAddr(t)
	start(t, []string{"MOCK_NAME=primary", "LISTEN=" + primary}, "mockllm")
	start(t, []string{"MOCK_NAME=candidate", "LISTEN=" + candidate}, "mockllm")

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	gatewayPolicy(t, pol, iss.URL, "http://"+primary, "http://"+candidate)
	writeFile(t, filepath.Join(pol, "toggles/e2e-flag.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Toggle
name: e2e-flag
owner: e2e
expires: "2999-01-01"
default: false
axis: client
rules:
  - {name: half-of-ga, rings: [ring1-ga], percent: 50}
client:
  harnesses:
    claude-code:
      env: {E2E_FLAG: "on"}
`)
	writeFile(t, filepath.Join(pol, "toggles/e2e-route.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Toggle
name: e2e-route
owner: e2e
expires: "2999-01-01"
default: false
axis: traffic
rules:
  - {name: ga, rings: [ring1-ga]}
traffic:
  routes:
    sonnet: {upstream: candidate, model: claude-sonnet-next}
`)
	// group-targeted toggles: a client env flag, and a traffic route for a second alias
	replaceIn(t, filepath.Join(pol, "gateway.yaml"), "  sonnet: {upstream: primary, model: claude-sonnet-4-5}\n",
		"  sonnet: {upstream: primary, model: claude-sonnet-4-5}\n  haiku: {upstream: primary, model: claude-haiku-4-5}\n")
	writeFile(t, filepath.Join(pol, "toggles/e2e-group.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Toggle
name: e2e-group
owner: e2e
expires: "2999-01-01"
default: false
axis: client
rules:
  - {name: grp, groups: [e2e-grp]}
client:
  harnesses:
    claude-code:
      env: {E2E_GROUP: "on"}
`)
	writeFile(t, filepath.Join(pol, "toggles/e2e-route-grp.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Toggle
name: e2e-route-grp
owner: e2e
expires: "2999-01-01"
default: false
axis: traffic
rules:
  - {name: grp, groups: [e2e-grp]}
traffic:
  routes:
    haiku: {upstream: candidate, model: claude-haiku-next}
`)
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("toggle policy invalid: %s", r)
	}
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	// one GA user inside the 50% cohort, one outside, by the same hash everywhere
	var flagToggle *policy.Toggle
	for _, tg := range org.Toggles {
		if tg.Name == "e2e-flag" {
			flagToggle = tg
		}
	}
	var onUser, offUser, grpUser string
	for i := 0; i < 2000 && (onUser == "" || offUser == "" || grpUser == ""); i++ {
		u := fmt.Sprintf("dev%d@acme.com", i)
		if r := org.ResolveRing(policy.Subject{ID: u}); r == nil || r.Name != "ring1-ga" {
			continue
		}
		switch {
		case toggle.Eval("e2e-flag", false, flagToggle.Rules, toggle.Subject{ID: u, Ring: "ring1-ga"}, false).On:
			if onUser == "" {
				onUser = u
			}
		case offUser == "":
			offUser = u
		case grpUser == "": // outside the percent cohort: only its group can switch toggles on
			grpUser = u
		}
	}
	if onUser == "" || offUser == "" || grpUser == "" {
		t.Fatalf("no users on both sides of the rollout: on=%q off=%q grp=%q", onUser, offUser, grpUser)
	}

	keys := filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", keys)
	repo := repoName(t)
	out := must(t, nil, "halo", "release", "publish", pol, "--ring", "ring1-ga", "--release-version", "1.0.0",
		"--key", filepath.Join(keys, "halo.key"), "--registry", repo, "--plain-http", "--no-artifacts", "--output", "json").stdout
	if !strings.Contains(out, "1.0.0") {
		t.Fatalf("publish: %s", out)
	}

	// halo-server: enrollment, ring endpoint, kill API and signed kill list
	addr := freeAddr(t)
	base := "http://" + addr
	writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(dir, "session.key"), "e2e-session-key-0123456789abcdef0123456789abcdef\n")
	writeFile(t, filepath.Join(dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
	pc, _ := json.Marshal(map[string]any{
		"baseURL": base, "registry": repo, "pubKeyFile": filepath.Join(keys, "halo.pub"),
		"halodURL": "https://downloads.example.com/halod-{os}-{arch}", "halodSHA256": map[string]string{"linux-amd64": strings.Repeat("a", 64)},
		"sessionKeyFile": filepath.Join(dir, "session.key"),
	})
	writeFile(t, filepath.Join(dir, "portal.json"), string(pc))
	start(t, nil, "halo-server", "--listen", addr, "--policy-dir", pol, "--token-file", filepath.Join(dir, "fleet.token"),
		"--portal-config", filepath.Join(dir, "portal.json"), "--data-dir", filepath.Join(dir, "data"),
		"--killswitch-key-file", filepath.Join(keys, "killswitch.key"), "--gateway-token-file", filepath.Join(dir, "gateway.token"))
	waitUp(t, base+"/healthz", 200)

	// halo-proxy polls the same signed kill list, fast
	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	start(t, nil, "halo-proxy", "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap,
		"--killswitch-url", base+"/api/v1/gateway/killswitch", "--killswitch-token-file", filepath.Join(dir, "gateway.token"),
		"--killswitch-pubkey-file", filepath.Join(keys, "killswitch.pub"), "--killswitch-interval", "1s")
	waitUp(t, "http://"+primary+"/v1/models", 200)
	waitUp(t, "http://"+candidate+"/v1/models", 200)
	waitUp(t, "http://"+adminAddr+"/healthz", 200)

	post := func(c *http.Client, path, body string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	etc := filepath.Join(dir, "etc")
	writeFile(t, filepath.Join(etc, "release.pub"), readFile(t, filepath.Join(keys, "halo.pub")))
	writeFile(t, filepath.Join(etc, "killswitch.pub"), readFile(t, filepath.Join(keys, "killswitch.pub")))
	enroll := func(user string, groups ...string) string {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		iss.SetLogin(map[string]any{"email": user, "email_verified": true, "groups": append([]string{"eng"}, groups...)})
		resp, err := c.Get(base + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		code, body := post(c, "/api/v1/launch/laptop", "")
		var launch struct{ Token string }
		if code != 200 || json.Unmarshal([]byte(body), &launch) != nil || launch.Token == "" {
			t.Fatalf("launch laptop as %s: %d %s", user, code, body)
		}
		code, halodYAML := post(http.DefaultClient, "/api/v1/enroll", `{"token":"`+launch.Token+`","os":"linux"}`)
		if code != 200 {
			t.Fatalf("enroll %s: %d %s", user, code, halodYAML)
		}
		var cfg map[string]any
		if err := yaml.Unmarshal([]byte(halodYAML), &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["pubkey"], cfg["plainHTTP"], cfg["os"] = filepath.Join(etc, "release.pub"), true, "linux"
		ks, _ := cfg["killSwitch"].(map[string]any)
		ks["pubkey"], ks["interval"] = filepath.Join(etc, "killswitch.pub"), killPoll.String()
		cfg["interval"] = "1h" // `halod run` moves only on kill polls
		b, _ := yaml.Marshal(cfg)
		p := filepath.Join(etc, user+".yaml")
		writeFile(t, p, string(b))
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	type device struct{ cfg, root string }
	on := device{enroll(onUser), filepath.Join(dir, "root-on")}
	off := device{enroll(offUser), filepath.Join(dir, "root-off")}
	grp := device{enroll(grpUser, "e2e-grp"), filepath.Join(dir, "root-grp")}
	envOf := func(d device, key string) string {
		t.Helper()
		var m struct{ Env map[string]string }
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(d.root, "etc/claude-code/managed-settings.json"))), &m); err != nil {
			t.Fatal(err)
		}
		return m.Env[key]
	}
	flag := func(d device) string { return envOf(d, "E2E_FLAG") }
	digest := func(d device) string {
		t.Helper()
		var s struct{ Digest string }
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(d.root, "var/lib/halos/state.json"))), &s); err != nil {
			t.Fatal(err)
		}
		return s.Digest
	}

	t.Run("fragment applied only where the rule matches", func(t *testing.T) {
		for name, d := range map[string]device{"on": on, "off": off, "grp": grp} {
			if r := run(t, []string{"SYD_TEST_TRUST_SELF=1"}, "", "halod", "once", "--config", d.cfg, "--root", d.root,
				"--install=false", "--state", "/var/lib/halos/state.json"); r.code != 0 {
				t.Fatalf("halod once (%s): %s", name, r)
			}
		}
		if got := flag(on); got != "on" {
			t.Fatalf("in-cohort device: E2E_FLAG = %q", got)
		}
		if got := flag(off); got != "" {
			t.Fatalf("out-of-cohort device: E2E_FLAG = %q", got)
		}
		// group rule: enrolled through the portal with e2e-grp, the device gets the
		// group fragment; the others (no such group) do not; and the group user is
		// outside the percent cohort, so only the group explains it
		if got := envOf(grp, "E2E_GROUP"); got != "on" {
			t.Fatalf("group member: E2E_GROUP = %q (groups recorded at enrollment?)", got)
		}
		if flag(grp) != "" || envOf(on, "E2E_GROUP") != "" || envOf(off, "E2E_GROUP") != "" {
			t.Fatalf("group fragment leaked: grp flag=%q on=%q off=%q", flag(grp), envOf(on, "E2E_GROUP"), envOf(off, "E2E_GROUP"))
		}
	})

	send := func(user, alias string, groups ...string) *http.Response {
		t.Helper()
		body := `{"model":"` + alias + `","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/v1/messages", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("anthropic-version", "2023-06-01")
		req.Header.Set("Authorization", "Bearer "+mint(t, iss, user, groups...))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	// routed returns "<upstream>/<model>" the mock saw for alias, with the JWT carrying groups.
	routed := func(user, alias string, groups ...string) string {
		r := send(user, alias, groups...)
		if r.StatusCode != 200 {
			t.Fatalf("proxy status %d", r.StatusCode)
		}
		return r.Header.Get("X-Mock-Served-By") + "/" + r.Header.Get("X-Mock-Model")
	}

	t.Run("traffic toggles route the alias", func(t *testing.T) {
		if got := routed(onUser, "sonnet"); got != "candidate/claude-sonnet-next" {
			t.Fatalf("routed to %s", got)
		}
		// group rule at the gateway: the group comes from the verified JWT, so the
		// same user routes differently with and without the e2e-grp claim
		if got := routed(grpUser, "haiku", "e2e-grp"); got != "candidate/claude-haiku-next" {
			t.Fatalf("group member routed to %s", got)
		}
		if got := routed(grpUser, "haiku"); got != "primary/claude-haiku-4-5" {
			t.Fatalf("non-member routed to %s", got)
		}
	})

	t.Run("kill via halo-server turns both off without a release; unkill restores", func(t *testing.T) {
		before := digest(on)
		log := start(t, []string{"SYD_TEST_TRUST_SELF=1"}, "halod", "run", "--config", on.cfg, "--root", on.root,
			"--install=false", "--state", "/var/lib/halos/state.json")
		waitFor(t, 20*time.Second, "halod run first cycle", func() bool { return strings.Contains(log.String(), `"toggles":["e2e-flag"]`) })

		jar, _ := cookiejar.New(nil)
		admin := &http.Client{Jar: jar}
		iss.SetLogin(map[string]any{"email": "admin@acme.com", "email_verified": true, "groups": []string{"ai-platform"}})
		resp, err := admin.Get(base + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		for _, name := range []string{"e2e-flag", "e2e-route"} {
			if code, body := post(admin, "/api/v1/toggles/"+name+"/kill", `{"reason":"e2e"}`); code != 200 {
				t.Fatalf("kill %s: %d %s", name, code, body)
			}
		}
		waitFor(t, killPoll+4*time.Second, "device flag off", func() bool { return flag(on) == "" })
		waitFor(t, 6*time.Second, "gateway route off", func() bool { return routed(onUser, "sonnet") == "primary/claude-sonnet-4-5" })
		if got := routed(grpUser, "haiku", "e2e-grp"); got != "candidate/claude-haiku-next" {
			t.Fatalf("killing other toggles turned the group route off: %s", got)
		}
		if code, body := post(admin, "/api/v1/toggles/e2e-route-grp/kill", `{"reason":"e2e"}`); code != 200 {
			t.Fatalf("kill e2e-route-grp: %d %s", code, body)
		}
		waitFor(t, 6*time.Second, "group route off", func() bool { return routed(grpUser, "haiku", "e2e-grp") == "primary/claude-haiku-4-5" })
		if code, body := post(admin, "/api/v1/toggles/e2e-route-grp/unkill", `{"reason":"e2e done"}`); code != 200 {
			t.Fatalf("unkill e2e-route-grp: %d %s", code, body)
		}
		if got := digest(on); got != before {
			t.Fatalf("kill changed the release digest %s -> %s: it must not need a new release", before, got)
		}

		for _, name := range []string{"e2e-flag", "e2e-route"} {
			if code, body := post(admin, "/api/v1/toggles/"+name+"/unkill", `{"reason":"e2e done"}`); code != 200 {
				t.Fatalf("unkill %s: %d %s", name, code, body)
			}
		}
		waitFor(t, killPoll+4*time.Second, "device flag back on", func() bool { return flag(on) == "on" })
		waitFor(t, 6*time.Second, "gateway route back on", func() bool { return routed(onUser, "sonnet") == "candidate/claude-sonnet-next" })
	})
}
