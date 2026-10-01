//go:build e2e

package e2e

import (
	"context"
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
	"oras.land/oras-go/v2"

	"github.com/halos-dev/halos/internal/bundle"
	"github.com/halos-dev/halos/internal/identity/identitytest"
	"github.com/halos-dev/halos/internal/policy"
)

const pinNext = "2.1.312" // treatment pin of the client-axis experiment

// killPoll is halod's kill-switch poll interval in the e2e.
const killPoll = 2 * time.Second

// TestClientAxisExperiment: a "CLI upgrade A/B" end to end. `halo release
// publish` builds ring1-ga plus one signed channel per variant; two users
// enrolled through halo-server (one hashing to each variant) run the real
// halod, which learns its subject from the ring endpoint, picks the variant
// with the gateway's hash and applies that channel's release (version pin +
// OTEL attribution). A tampered channel pointer is refused; pausing the
// experiment and republishing converges both devices to the ring release.
func TestClientAxisExperiment(t *testing.T) {
	ctx := context.Background()
	iss, err := identitytest.NewIssuer("e2e")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()

	dir := t.TempDir()
	pol := filepath.Join(dir, "policy")
	gatewayPolicy(t, pol, iss.URL, "http://127.0.0.1:1", "http://127.0.0.1:1")
	writeFile(t, filepath.Join(pol, "profiles/cli-next.yaml"), `apiVersion: halos.dev/v1alpha1
kind: Profile
name: cli-next
extends: base
harnesses:
  claude-code:
    version: `+pinNext+`
`)
	expFile := filepath.Join(pol, "experiments/cli-upgrade.yaml")
	writeFile(t, expFile, `apiVersion: halos.dev/v1alpha1
kind: Experiment
name: cli-upgrade
type: ab
axis: client
status: running
rings: [ring1-ga]
variants:
  - {name: control, weight: 1, control: true, profile: base}
  - {name: treatment, weight: 1, profile: cli-next}
metrics:
  primary: {metric: halo.api.error_rate, direction: decrease}
stopping: {method: msprt, alpha: 0.05, minSamples: 10, maxDays: 14, maxSpendUSD: 50}
`)
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("experiment policy invalid: %s", r)
	}
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	var exp *policy.Experiment
	for _, e := range org.Experiments {
		if e.Name == "cli-upgrade" {
			exp = e
		}
	}
	// one GA user per variant, by the same functions the gateway uses
	users := map[string]string{}
	for i := 0; i < 2000 && len(users) < 2; i++ {
		u := fmt.Sprintf("dev%d@acme.com", i)
		r := org.ResolveRing(policy.Subject{ID: u})
		if r == nil || r.Name != "ring1-ga" {
			continue
		}
		if v := exp.ResolveVariant(policy.Subject{ID: u}, r.Name); v != nil && users[v.Name] == "" {
			users[v.Name] = u
		}
	}
	if users["control"] == "" || users["treatment"] == "" {
		t.Fatalf("no user per variant: %v", users)
	}

	keys, evilKeys := filepath.Join(dir, "keys"), filepath.Join(dir, "evil")
	must(t, nil, "halo", "keys", "generate", "--out", keys)
	must(t, nil, "halo", "keys", "generate", "--out", evilKeys)
	must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", keys)
	repo := repoName(t)
	publish := func(ver, key, repo string) result {
		return must(t, nil, "halo", "release", "publish", pol, "--ring", "ring1-ga", "--release-version", ver,
			"--key", key, "--registry", repo, "--plain-http", "--no-artifacts", "--output", "json")
	}
	out := publish("1.0.0", filepath.Join(keys, "halo.key"), repo).stdout
	for _, ch := range []string{"ring1-ga.x-cli-upgrade.control", "ring1-ga.x-cli-upgrade.treatment"} {
		if !strings.Contains(out, ch) {
			t.Fatalf("publish did not write channel %s:\n%s", ch, out)
		}
	}

	// halo-server: enrollment + ring endpoint (which returns the bound subject)
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
	{ // the kill-list key comes from the server, as enroll.sh fetches it
		resp, err := http.Get(base + "/enroll/killswitch.pub")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(b) != readFile(t, filepath.Join(keys, "killswitch.pub")) {
			t.Fatalf("/enroll/killswitch.pub: %s %s", resp.Status, b)
		}
		writeFile(t, filepath.Join(etc, "killswitch.pub"), string(b))
	}
	// enroll logs user in, launches a laptop enrollment and writes its halod.yaml.
	enroll := func(user string) string {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar}
		iss.SetLogin(map[string]any{"email": user, "email_verified": true, "groups": []string{"eng"}})
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
		if ks["url"] != base+"/api/v1/fleet/killswitch" || ks["pubkey"] != "/etc/halos/killswitch.pub" {
			t.Fatalf("enroll killSwitch = %v", cfg["killSwitch"])
		}
		ks["pubkey"], ks["interval"] = filepath.Join(etc, "killswitch.pub"), killPoll.String()
		cfg["interval"] = "1h" // `halod run` below moves only on kill polls
		b, _ := yaml.Marshal(cfg)
		p := filepath.Join(etc, user+".yaml")
		writeFile(t, p, string(b))
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	type device struct{ cfg, root string }
	devices := map[string]device{}
	for variant, user := range users {
		devices[variant] = device{enroll(user), filepath.Join(dir, "root-"+variant)}
	}
	halod := func(d device) result {
		return run(t, []string{"SYD_TEST_TRUST_SELF=1"}, "", "halod", "once", "--config", d.cfg, "--root", d.root,
			"--install=false", "--state", "/var/lib/halos/state.json")
	}
	settingsOf := func(d device) (pinMin, pinMax, attrs string) {
		t.Helper()
		var m struct {
			Min string            `json:"requiredMinimumVersion"`
			Max string            `json:"requiredMaximumVersion"`
			Env map[string]string `json:"env"`
		}
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(d.root, "etc/claude-code/managed-settings.json"))), &m); err != nil {
			t.Fatal(err)
		}
		return m.Min, m.Max, m.Env["OTEL_RESOURCE_ATTRIBUTES"]
	}
	type status struct {
		Experiment, Variant, ErrorCode string
		Killed                         bool
	}
	statusOf := func(d device) status {
		var s struct{ Status status }
		if err := json.Unmarshal([]byte(readFile(t, filepath.Join(d.root, "var/lib/halos/state.json"))), &s); err != nil {
			t.Fatal(err)
		}
		return s.Status
	}

	pins := map[string]string{"control": pin, "treatment": pinNext}
	for variant, d := range devices {
		if r := halod(d); r.code != 0 {
			t.Fatalf("halod once (%s, %s): %s", variant, users[variant], r)
		}
		lo, hi, attrs := settingsOf(d)
		if lo != pins[variant] || hi != pins[variant] {
			t.Fatalf("%s: version gate %s..%s, want %s", variant, lo, hi, pins[variant])
		}
		if !strings.Contains(attrs, "halo.experiment=cli-upgrade") || !strings.Contains(attrs, "halo.variant="+variant) || !strings.Contains(attrs, "halo.ring=ring1-ga") {
			t.Fatalf("%s: OTEL_RESOURCE_ATTRIBUTES = %q", variant, attrs)
		}
		if s := statusOf(d); s.Experiment != "cli-upgrade" || s.Variant != variant {
			t.Fatalf("%s: status %+v", variant, s)
		}
	}

	t.Run("refresh re-signs ring and channels", func(t *testing.T) {
		r := must(t, nil, "halo", "release", "refresh", "--ring", "ring1-ga", "--key", filepath.Join(keys, "halo.key"), "--registry", repo, "--plain-http")
		if !strings.Contains(r.stdout, "ring-ring1-ga.x-cli-upgrade.treatment") || !strings.Contains(r.stdout, "ring-ring1-ga.x-cli-upgrade.control") {
			t.Fatalf("refresh did not cover the channels:\n%s", r.stdout)
		}
	})

	t.Run("tampered channel pointer refused", func(t *testing.T) {
		d := devices["treatment"]
		before := readFile(t, filepath.Join(d.root, "etc/claude-code/managed-settings.json"))
		evilRepo := repoName(t) + "-evil"
		publish("6.6.6", filepath.Join(evilKeys, "halo.key"), evilRepo)
		src, err := bundle.Repository(repo, true)
		if err != nil {
			t.Fatal(err)
		}
		evil, err := bundle.Repository(evilRepo, true)
		if err != nil {
			t.Fatal(err)
		}
		tag := bundle.PointerTag("ring1-ga.x-cli-upgrade.treatment")
		genuine, err := src.Resolve(ctx, tag)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := oras.Copy(ctx, evil, tag, src, tag, oras.DefaultCopyOptions); err != nil {
			t.Fatal(err)
		}
		r := halod(d)
		if r.code == 0 || !strings.Contains(r.stderr, "keeping last-good") || !strings.Contains(r.stderr, "verify pointer ring1-ga.x-cli-upgrade.treatment") {
			t.Fatalf("tampered channel pointer not refused: %s", r)
		}
		if got := readFile(t, filepath.Join(d.root, "etc/claude-code/managed-settings.json")); got != before {
			t.Fatalf("managed settings changed after a refused channel:\n%s", got)
		}
		if err := src.Tag(ctx, genuine, tag); err != nil { // operator restores the genuine pointer
			t.Fatal(err)
		}
	})

	t.Run("kill switch reverts treatment devices between release pulls", func(t *testing.T) {
		d := devices["treatment"]
		log := start(t, []string{"SYD_TEST_TRUST_SELF=1"}, "halod", "run", "--config", d.cfg, "--root", d.root,
			"--install=false", "--state", "/var/lib/halos/state.json") // stopped when this subtest ends
		waitFor(t, 20*time.Second, "halod run first cycle", func() bool { return strings.Contains(log.String(), `"variant":"treatment"`) })
		jar, _ := cookiejar.New(nil)
		admin := &http.Client{Jar: jar}
		iss.SetLogin(map[string]any{"email": "admin@acme.com", "email_verified": true, "groups": []string{"ai-platform"}})
		resp, err := admin.Get(base + "/auth/login")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		converge := func(what string, want func() bool) {
			t.Helper()
			// one kill-poll tick, plus slack for process scheduling
			waitFor(t, killPoll+3*time.Second, what, want)
		}
		if code, body := post(admin, "/api/v1/experiments/cli-upgrade/kill", `{"reason":"e2e"}`); code != 200 {
			t.Fatalf("kill: %d %s", code, body)
		}
		converge("killed treatment device on control", func() bool {
			lo, hi, attrs := settingsOf(d)
			s := statusOf(d)
			return lo == pin && hi == pin && !strings.Contains(attrs, "halo.variant=treatment") &&
				s.Experiment == "cli-upgrade" && s.Variant == "" && s.Killed && s.ErrorCode == ""
		})
		if code, body := post(admin, "/api/v1/experiments/cli-upgrade/unkill", `{"reason":"e2e done"}`); code != 200 {
			t.Fatalf("unkill: %d %s", code, body)
		}
		converge("unkilled device back on treatment", func() bool {
			lo, hi, attrs := settingsOf(d)
			s := statusOf(d)
			return lo == pinNext && hi == pinNext && strings.Contains(attrs, "halo.variant=treatment") &&
				s.Variant == "treatment" && !s.Killed
		})
	})

	t.Run("paused experiment converges to the ring release", func(t *testing.T) {
		replaceIn(t, expFile, "status: running", "status: paused")
		out := publish("1.1.0", filepath.Join(keys, "halo.key"), repo).stdout
		if strings.Contains(out, ".x-cli-upgrade.") {
			t.Fatalf("paused experiment still published channels:\n%s", out)
		}
		for variant, d := range devices {
			if r := halod(d); r.code != 0 {
				t.Fatalf("halod once after pause (%s): %s", variant, r)
			}
			lo, hi, attrs := settingsOf(d)
			if lo != pin || hi != pin || strings.Contains(attrs, "halo.experiment") || !strings.Contains(attrs, "halo.release=1.1.0") {
				t.Fatalf("%s did not converge: %s..%s %q", variant, lo, hi, attrs)
			}
			if s := statusOf(d); s.Experiment != "" || s.Variant != "" || s.ErrorCode != "" {
				t.Fatalf("%s: status %+v", variant, s)
			}
		}
	})
}
