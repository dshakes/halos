package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// gateEnv: ring ga pins claude-code 2.1.280 and has the given gate modes; the
// proxy asks a fake halo-server for posture.
func gateEnv(t *testing.T, posture, version string, verdict *atomic.Value) (*env, *seen) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gw-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(verdict.Load())
	}))
	t.Cleanup(srv.Close)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Posture = PostureConfig{URL: srv.URL + "/api/v1/gateway/posture", TokenFile: tokFile, CacheTTL: 1}
		o.Profiles = map[string]*policy.Profile{"base": {Meta: policy.Meta{Name: "base"}, Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.1.280"}}}}
		for _, r := range o.Rings {
			r.Profile, r.Posture, r.VersionGate = "base", posture, version
		}
	})
	return e, s
}

func TestGatesEnforce(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(gateway.PostureVerdict{Compliant: true})
	e, s := gateEnv(t, "enforce", "enforce", &verdict)
	tok := e.token(t, "alice@acme.com")
	ok := map[string]string{"User-Agent": "claude-cli/2.1.280 (external, cli)"}

	if resp := e.post(t, "/v1/messages", tok, msgBody, ok); resp.StatusCode != 200 {
		t.Fatalf("compliant, pinned version: %d", resp.StatusCode)
	}
	for name, ua := range map[string]string{"other version": "claude-cli/2.1.279 (external, cli)", "no UA": "", "unknown UA": "curl/8.7.1"} {
		resp := e.post(t, "/v1/messages", tok, msgBody, map[string]string{"User-Agent": ua})
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "version check failed") || !strings.Contains(string(b), "permission_error") {
			t.Fatalf("%s: %d %s", name, resp.StatusCode, b)
		}
	}

	verdict.Store(gateway.PostureVerdict{Reason: "device laptop-1 reported drift in /etc/claude-code/managed-settings.json"})
	resp := e.post(t, "/v1/messages", tok, msgBody, ok)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "halod status") || !strings.Contains(string(b), "drift") {
		t.Fatalf("non-compliant posture: %d %s", resp.StatusCode, b)
	}
	if hits, _, _, _ := s.get(); hits != 1 {
		t.Fatalf("refused requests reached the upstream: %d hits", hits)
	}

	w := httptest.NewRecorder()
	e.p.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`halo_proxy_gate_total{gate="version",ring="ga",outcome="enforce"} 3`, `halo_proxy_gate_total{gate="posture",ring="ga",outcome="enforce"} 1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("metrics missing %s:\n%s", want, w.Body.String())
		}
	}
}

func TestGatesWarnPassAndCount(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(gateway.PostureVerdict{Reason: "device laptop-1 last reported 2h0m0s ago"})
	e, s := gateEnv(t, "", "", &verdict) // defaults: warn
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, map[string]string{"User-Agent": "claude-cli/2.0.0 (external, cli)"})
	if resp.StatusCode != 200 {
		t.Fatalf("warn mode refused: %d", resp.StatusCode)
	}
	if hits, _, _, _ := s.get(); hits != 1 {
		t.Fatalf("upstream hits %d", hits)
	}
	w := httptest.NewRecorder()
	e.p.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`gate="version",ring="ga",outcome="warn"} 1`, `gate="posture",ring="ga",outcome="warn"} 1`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
}

func TestGatesOffAndUnreachableServer(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(gateway.PostureVerdict{Reason: "drift"})
	e, _ := gateEnv(t, "off", "off", &verdict)
	if resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("gates off refused: %d", resp.StatusCode)
	}

	// enforce, but halo-server unreachable and nothing cached: fail open, counted unknown
	up, _ := recordingServer(t)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	_ = os.WriteFile(tokFile, []byte("gw-token"), 0o600)
	e2 := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Posture = PostureConfig{URL: "http://127.0.0.1:1/api/v1/gateway/posture", TokenFile: tokFile}
		for _, r := range o.Rings {
			r.Posture, r.VersionGate = "enforce", "off"
		}
	})
	if resp := e2.post(t, "/v1/messages", e2.token(t, "alice@acme.com"), msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("unreachable halo-server refused traffic: %d", resp.StatusCode)
	}
	w := httptest.NewRecorder()
	e2.p.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `gate="posture",ring="ga",outcome="unknown"} 1`) {
		t.Errorf("unknown posture not counted:\n%s", w.Body.String())
	}
}

func TestPostureConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tok := filepath.Join(t.TempDir(), "t")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	if pc, err := (PostureConfig{}).build(log); pc != nil || err != nil {
		t.Fatalf("unset: %v %v", pc, err)
	}
	if pc, err := (PostureConfig{URL: "https://halo.test/api/v1/gateway/posture", TokenFile: tok}).build(log); pc == nil || err != nil {
		t.Fatalf("valid: %v %v", pc, err)
	}
	for name, c := range map[string]PostureConfig{
		"token without url": {TokenFile: tok},
		"url without token": {URL: "https://h"},
		"unreadable token":  {URL: "https://h", TokenFile: tok + ".none"},
		"plain http remote": {URL: "http://halo.test/x", TokenFile: tok},
	} {
		if _, err := c.build(log); err == nil || !strings.Contains(err.Error(), "halo-proxy") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
