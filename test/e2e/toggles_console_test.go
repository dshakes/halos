//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/toggle"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.test", "GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestTogglesConsole: the console's toggle API against the real halo-server and
// halo-proxy. It lists toggles, previews who gets one, proposes a change (a branch
// is pushed to the policy remote, main and the served policy never move, an
// invalid change opens nothing), and kills a traffic toggle: the gateway stops
// routing it and the kill (who, why) shows in the API; restoring brings it back.
func TestTogglesConsole(t *testing.T) {
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
	writeFile(t, filepath.Join(pol, "toggles/e2e-flag.yaml"), `apiVersion: halos.dev/v1
kind: Toggle
name: e2e-flag
description: env flag for half of GA
owner: e2e
expires: "2999-01-01"
default: false
axis: client
rules:
  - name: half-of-ga
    rings: [ring1-ga]
    percent: 50
client:
  harnesses:
    claude-code:
      env: {E2E_FLAG: "on"}
`)
	writeFile(t, filepath.Join(pol, "toggles/e2e-route.yaml"), `apiVersion: halos.dev/v1
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
	if r := run(t, nil, "", "halo", "validate", pol); r.code != 0 {
		t.Fatalf("policy invalid: %s", r)
	}
	org, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}

	// The writer's clone and its remote: halo-server pushes proposal branches there.
	origin := filepath.Join(dir, "origin.git")
	gitIn(t, dir, "init", "-q", "--bare", "-b", "main", origin)
	seed := filepath.Join(dir, "seed")
	if err := os.CopyFS(seed, os.DirFS(pol)); err != nil {
		t.Fatal(err)
	}
	gitIn(t, seed, "init", "-q", "-b", "main")
	gitIn(t, seed, "add", ".")
	gitIn(t, seed, "commit", "-qm", "seed")
	gitIn(t, seed, "remote", "add", "origin", origin)
	gitIn(t, seed, "push", "-q", "origin", "main")
	writer := filepath.Join(dir, "writer")
	gitIn(t, dir, "clone", "-q", origin, writer)
	// `gh pr create` is faked (no GitHub here): it only prints a URL.
	writeFile(t, filepath.Join(dir, "bin/gh"), "#!/bin/sh\necho https://example.test/pull/42\n")
	if err := os.Chmod(filepath.Join(dir, "bin/gh"), 0o755); err != nil {
		t.Fatal(err)
	}

	keys := filepath.Join(dir, "keys")
	must(t, nil, "halo", "keys", "generate", "--name", "killswitch", "--out", keys)
	addr := freeAddr(t)
	base := "http://" + addr
	writeFile(t, filepath.Join(dir, "fleet.token"), "e2e-fleet-token\n")
	writeFile(t, filepath.Join(dir, "session.key"), "e2e-session-key-0123456789abcdef0123456789abcdef\n")
	writeFile(t, filepath.Join(dir, "gateway.token"), "e2e-gateway-token-0123456789\n")
	pc, _ := json.Marshal(map[string]any{
		"baseURL": base, "sessionKeyFile": filepath.Join(dir, "session.key"),
		"policyRepoDir": writer, "policyBase": "main",
	})
	writeFile(t, filepath.Join(dir, "portal.json"), string(pc))
	start(t, []string{"PATH=" + filepath.Join(dir, "bin") + ":" + os.Getenv("PATH"),
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.test", "GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.test"},
		"halo-server", "--listen", addr, "--policy-dir", pol, "--token-file", filepath.Join(dir, "fleet.token"),
		"--portal-config", filepath.Join(dir, "portal.json"), "--data-dir", filepath.Join(dir, "data"),
		"--killswitch-key-file", filepath.Join(keys, "killswitch.key"), "--gateway-token-file", filepath.Join(dir, "gateway.token"))
	waitUp(t, base+"/healthz", 200)

	snap := filepath.Join(dir, "policy.json")
	must(t, nil, "halo", "gateway", "compile", pol, "-o", snap)
	proxyAddr, adminAddr := freeAddr(t), freeAddr(t)
	start(t, nil, "halo-proxy", "--listen", proxyAddr, "--admin-listen", adminAddr, "--policy", snap,
		"--killswitch-url", base+"/api/v1/gateway/killswitch", "--killswitch-token-file", filepath.Join(dir, "gateway.token"),
		"--killswitch-pubkey-file", filepath.Join(keys, "killswitch.pub"), "--killswitch-interval", "1s")
	waitUp(t, "http://"+primary+"/v1/models", 200)
	waitUp(t, "http://"+candidate+"/v1/models", 200)
	waitUp(t, "http://"+adminAddr+"/healthz", 200)

	// sign in as an admin
	jar, _ := cookiejar.New(nil)
	admin := &http.Client{Jar: jar}
	iss.SetLogin(map[string]any{"email": "admin@acme.com", "email_verified": true, "groups": []string{"ai-platform"}})
	resp, err := admin.Get(base + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	api := func(method, path, body string) (int, []byte) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r, err := admin.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, b
	}
	type view struct {
		Name    string
		Default bool
		Kill    *struct{ By, Reason string }
	}
	listToggles := func() map[string]view {
		t.Helper()
		code, b := api("GET", "/api/v1/toggles", "")
		var out struct{ Toggles []view }
		if code != 200 || json.Unmarshal(b, &out) != nil {
			t.Fatalf("list toggles: %d %s", code, b)
		}
		m := map[string]view{}
		for _, v := range out.Toggles {
			m[v.Name] = v
		}
		return m
	}

	t.Run("list and preview", func(t *testing.T) {
		got := listToggles()
		if len(got) != 2 || got["e2e-flag"].Kill != nil || got["e2e-route"].Kill != nil {
			t.Fatalf("toggles = %+v", got)
		}
		// preview agrees with the library evaluator the gateway and halod run
		for i := 0; i < 10; i++ {
			u := "dev" + strings.Repeat("x", i) + "@acme.com"
			want := toggle.Eval("e2e-flag", false, org.Toggles[0].Rules, toggle.Subject{ID: u, Ring: "ring1-ga"}, false).On
			code, b := api("GET", "/api/v1/toggles/e2e-flag?ring=ring1-ga&user="+u, "")
			var out struct {
				Preview struct{ Decision struct{ On bool } }
			}
			if code != 200 || json.Unmarshal(b, &out) != nil || out.Preview.Decision.On != want {
				t.Fatalf("preview for %s: %d %s, want on=%v", u, code, b, want)
			}
		}
	})

	t.Run("proposal opens a branch, never touches main or the served policy", func(t *testing.T) {
		mainBefore := gitIn(t, origin, "rev-parse", "main")
		served := readFile(t, filepath.Join(pol, "toggles/e2e-flag.yaml"))
		code, b := api("POST", "/api/v1/toggles/e2e-flag/propose", `{"reason":"ramp to 25","rule":"half-of-ga","percent":25}`)
		if code != 200 || !strings.Contains(string(b), "https://example.test/pull/42") {
			t.Fatalf("propose: %d %s", code, b)
		}
		branches := gitIn(t, origin, "branch", "--list", "halos/toggle-e2e-flag-*")
		if branches == "" {
			t.Fatal("no proposal branch was pushed to the remote")
		}
		branch := strings.TrimSpace(strings.TrimPrefix(strings.Fields(branches)[len(strings.Fields(branches))-1], "*"))
		if f := gitIn(t, origin, "show", branch+":toggles/e2e-flag.yaml"); !strings.Contains(f, "percent: 25") {
			t.Fatalf("branch file lacks the change:\n%s", f)
		}
		if got := gitIn(t, origin, "rev-parse", "main"); got != mainBefore {
			t.Fatalf("main moved %s -> %s", mainBefore, got)
		}
		if got := readFile(t, filepath.Join(pol, "toggles/e2e-flag.yaml")); got != served {
			t.Fatal("served policy changed before a merge")
		}
		// a change that would make the policy invalid opens nothing
		before := gitIn(t, origin, "branch", "--list", "halos/*")
		if code, b := api("POST", "/api/v1/toggles/e2e-flag/propose", `{"reason":"x","rule":"half-of-ga","addRings":["ghost"]}`); code != 422 || !strings.Contains(string(b), "ghost") {
			t.Fatalf("invalid proposal: %d %s", code, b)
		}
		if after := gitIn(t, origin, "branch", "--list", "halos/*"); after != before {
			t.Fatalf("rejected proposal pushed a branch:\n%s\n--\n%s", before, after)
		}
	})

	t.Run("kill reaches the gateway and shows in the API; restore brings it back", func(t *testing.T) {
		user := usersByRing(t, org)["ring1-ga"]
		routed := func() string {
			body := `{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`
			req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/v1/messages", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("anthropic-version", "2023-06-01")
			req.Header.Set("Authorization", "Bearer "+mint(t, iss, user))
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			return r.Header.Get("X-Mock-Served-By") + "/" + r.Header.Get("X-Mock-Model")
		}
		if got := routed(); got != "candidate/claude-sonnet-next" {
			t.Fatalf("before kill routed to %s", got)
		}
		if code, b := api("POST", "/api/v1/toggles/e2e-route/kill", `{"reason":"candidate is slow"}`); code != 200 {
			t.Fatalf("kill: %d %s", code, b)
		}
		waitFor(t, 8*time.Second, "gateway stops routing the killed toggle", func() bool { return routed() == "primary/claude-sonnet-4-5" })
		if k := listToggles()["e2e-route"].Kill; k == nil || k.By != "admin@acme.com" || k.Reason != "candidate is slow" {
			t.Fatalf("kill state = %+v", k)
		}
		code, b := api("GET", "/api/v1/toggles/e2e-route", "")
		if code != 200 || !strings.Contains(string(b), `"toggle.kill"`) || !strings.Contains(string(b), "candidate is slow") {
			t.Fatalf("history lacks the kill: %d %s", code, b)
		}
		if code, b := api("POST", "/api/v1/toggles/e2e-route/unkill", `{"reason":"fixed"}`); code != 200 {
			t.Fatalf("unkill: %d %s", code, b)
		}
		waitFor(t, 8*time.Second, "gateway routes again after restore", func() bool { return routed() == "candidate/claude-sonnet-next" })
		if listToggles()["e2e-route"].Kill != nil {
			t.Fatal("restored toggle still shows a kill")
		}
	})
}
