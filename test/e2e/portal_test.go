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

	"github.com/halos-dev/halos/internal/identity/identitytest"
	"github.com/halos-dev/halos/internal/policy"
)

// TestPortalEnrollment: OIDC auth-code+PKCE login against the mock issuer ->
// kiosk laptop launch -> enrollment -> a real halod using the enrolled config
// (ring endpoint + report with its device token) -> admin sees the device.
func TestPortalEnrollment(t *testing.T) {
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	org := gatewayPolicy(t, pol, iss.URL, "http://127.0.0.1:1", "http://127.0.0.1:1") // traffic plane unused here

	keys := filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	repo := repoName(t)
	for ring, ver := range map[string]string{"ring0-canary": "2.0.0", "ring1-ga": "1.0.0"} {
		must(t, nil, "halo", "release", "publish", pol, "--ring", ring, "--release-version", ver,
			"--key", filepath.Join(keys, "halo.key"), "--registry", repo, "--plain-http", "--no-artifacts")
	}

	addr := freeAddr(t)
	base := "http://" + addr
	writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(dir, "session.key"), "e2e-session-key-0123456789abcdef0123456789abcdef\n")
	pc, _ := json.Marshal(map[string]any{
		"baseURL": base, "registry": repo, "pubKeyFile": filepath.Join(keys, "halo.pub"),
		"halodURL": "https://downloads.example.com/halod-{os}-{arch}", "halodSHA256": map[string]string{"linux-amd64": strings.Repeat("a", 64)},
		"sessionKeyFile": filepath.Join(dir, "session.key"),
	})
	writeFile(t, filepath.Join(dir, "portal.json"), string(pc))
	start(t, nil, "halo-server", "--listen", addr, "--policy-dir", pol, "--token-file", filepath.Join(dir, "fleet.token"),
		"--portal-config", filepath.Join(dir, "portal.json"), "--data-dir", filepath.Join(dir, "data"))
	waitUp(t, base+"/healthz", 200)

	type client struct{ *http.Client }
	login := func(t *testing.T, email string, groups ...string) client {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := client{&http.Client{Jar: jar}}
		iss.SetLogin(map[string]any{"email": email, "email_verified": true, "groups": groups})
		resp, err := c.Get(base + "/auth/login") // -> IdP /authorize -> /auth/callback -> /
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.Request.URL.Host != addr || resp.Request.URL.Path != "/" {
			t.Fatalf("login ended at %s (%s)", resp.Request.URL, resp.Status)
		}
		return c
	}
	call := func(t *testing.T, c *http.Client, method, path, body string, hdr map[string]string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := call(t, http.DefaultClient, "GET", "/api/v1/me", "", nil); code != 401 {
		t.Fatalf("anonymous /me: %d", code)
	}
	users := usersByRing(t, org)
	dev := users["ring0-canary"]
	wantRing := org.ResolveRing(policy.Subject{ID: dev}).Name
	devc := login(t, dev, "eng")

	code, body := call(t, devc.Client, "GET", "/api/v1/me", "", nil)
	var me struct {
		ID, Ring  string
		Admin     bool
		Launchers []string
		Profile   struct{ Harnesses map[string]string }
	}
	if code != 200 || json.Unmarshal([]byte(body), &me) != nil {
		t.Fatalf("/me: %d %s", code, body)
	}
	if me.ID != dev || me.Ring != wantRing || me.Admin || me.Profile.Harnesses["claude-code"] != pin || !strings.Contains(strings.Join(me.Launchers, ","), "laptop") {
		t.Fatalf("/me = %+v", me)
	}
	if code, _ := call(t, devc.Client, "GET", "/api/v1/fleet", "", nil); code != 403 {
		t.Fatalf("developer /fleet: %d, want 403", code)
	}

	code, body = call(t, devc.Client, "POST", "/api/v1/launch/laptop", "", nil)
	var launch struct{ Token, Bash string }
	if code != 200 || json.Unmarshal([]byte(body), &launch) != nil || launch.Token == "" {
		t.Fatalf("launch laptop: %d %s", code, body)
	}
	enrollBody := `{"token":"` + launch.Token + `","os":"linux"}`
	code, halodYAML := call(t, http.DefaultClient, "POST", "/api/v1/enroll", enrollBody, nil)
	if code != 200 {
		t.Fatalf("enroll: %d %s", code, halodYAML)
	}
	if code, body := call(t, http.DefaultClient, "POST", "/api/v1/enroll", enrollBody, nil); code != 401 {
		t.Fatalf("enrollment token reuse: %d %s", code, body)
	}
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(halodYAML), &cfg); err != nil {
		t.Fatal(err)
	}
	devTok, _ := cfg["deviceToken"].(string)
	if devTok == "" || cfg["registry"] != repo || cfg["org"] != "acme" || cfg["ringEndpoint"] != base+"/api/v1/fleet/ring" {
		t.Fatalf("enrolled halod.yaml:\n%s", halodYAML)
	}

	code, body = call(t, http.DefaultClient, "GET", "/api/v1/fleet/ring", "", map[string]string{"Authorization": "Bearer " + devTok})
	if code != 200 || !strings.Contains(body, `"ring":"`+wantRing+`"`) {
		t.Fatalf("fleet/ring: %d %s", code, body)
	}
	if code, _ := call(t, http.DefaultClient, "GET", "/api/v1/fleet/ring", "", map[string]string{"Authorization": "Bearer nope"}); code != 401 {
		t.Fatalf("fleet/ring with a bad token: %d", code)
	}
	if code, _ := call(t, http.DefaultClient, "POST", "/api/v1/fleet/report", `{"hostname":"x"}`, map[string]string{"Authorization": "Bearer nope"}); code != 401 {
		t.Fatalf("report with a bad token: %d", code)
	}

	// Real halod with the enrolled config: ring from the endpoint, report with the device token.
	etc := filepath.Join(dir, "etc")
	writeFile(t, filepath.Join(etc, "release.pub"), readFile(t, filepath.Join(keys, "halo.pub")))
	cfg["pubkey"] = filepath.Join(etc, "release.pub") // enrollment names the host path /etc/halos/release.pub
	cfg["plainHTTP"], cfg["os"] = true, "linux"       // local registry:2 speaks http
	out, _ := yaml.Marshal(cfg)
	writeFile(t, filepath.Join(etc, "halod.yaml"), string(out))
	if err := os.Chmod(filepath.Join(etc, "halod.yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root")
	r := run(t, []string{"SYD_TEST_TRUST_SELF=1"}, "", "halod", "once", "--config", filepath.Join(etc, "halod.yaml"), "--root", root,
		"--install=false", "--state", "/var/lib/halos/state.json")
	if r.code != 0 || strings.Contains(r.stderr, "report") {
		t.Fatalf("halod once with enrolled config: %s", r)
	}
	var st struct{ Ring, Digest string }
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(root, "var/lib/halos/state.json"))), &st); err != nil || st.Ring != wantRing {
		t.Fatalf("halod applied ring %q, want %q (%v)", st.Ring, wantRing, err)
	}

	admin := login(t, "admin@acme.com", "ai-platform")
	code, body = call(t, admin.Client, "GET", "/api/v1/fleet", "", nil)
	var fleet struct {
		Hosts []struct{ User, Device, Ring, Digest string }
	}
	if code != 200 || json.Unmarshal([]byte(body), &fleet) != nil {
		t.Fatalf("admin /fleet: %d %s", code, body)
	}
	found := false
	for _, h := range fleet.Hosts {
		found = found || (h.User == dev && h.Device != "" && h.Ring == wantRing && h.Digest == st.Digest)
	}
	if !found {
		t.Fatalf("device not in fleet (want user %s ring %s digest %s):\n%s", dev, wantRing, st.Digest, body)
	}
	code, body = call(t, admin.Client, "GET", "/api/v1/devices", "", nil)
	if code != 200 || !strings.Contains(body, `"userID":"`+dev+`"`) || strings.Contains(body, `"hash"`) {
		t.Fatalf("admin /devices: %d %s", code, body)
	}

	t.Run("IdP refusal does not log in", func(t *testing.T) {
		iss.SetLogin(nil)
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		resp, err := c.Get(base + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("login with IdP access_denied: %s", resp.Status)
		}
		if code, _ := call(t, c, "GET", "/api/v1/me", "", nil); code != 401 {
			t.Fatalf("/me after refused login: %d", code)
		}
	})
}
