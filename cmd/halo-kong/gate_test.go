package main

import (
	"encoding/json"
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

func TestAccessGates(t *testing.T) {
	var verdict atomic.Value
	verdict.Store(gateway.PostureVerdict{Compliant: true})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gw-token" || r.URL.Query().Get("subject") != "alice" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(verdict.Load())
	}))
	defer srv.Close()

	gatedPolicy := func(mode string) string {
		org := &policy.Org{
			Name: "acme",
			Gateway: &policy.Gateway{
				Models:    map[string]policy.ModelRoute{"sonnet": {Upstream: "up", Model: "claude-sonnet-4-5"}},
				Upstreams: map[string]policy.Upstream{"up": {URL: "https://up.internal", Kind: "anthropic"}},
			},
			Profiles: map[string]*policy.Profile{"base": {Meta: policy.Meta{Name: "base"}, Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: "2.1.280"}}}},
			Rings:    []*policy.Ring{{Meta: policy.Meta{Name: "ga"}, Profile: "base", Posture: mode, VersionGate: mode, Membership: policy.Membership{Default: true}}},
		}
		b, err := policy.Compile(org)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	call := func(pol, ua string) *fakeKong {
		c := trustedCfg(pol)
		c.PostureURL, c.PostureToken = srv.URL+"/api/v1/gateway/posture", "gw-token"
		k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn),
			hdrs: map[string][]string{"x-acme-user": {"alice"}, "User-Agent": {ua}, "X-Halo-Gate": {"spoofed"}}}
		c.access(k)
		return k
	}
	const pinned = "claude-cli/2.1.280 (external, cli)"

	enforce := gatedPolicy("enforce")
	if k := call(enforce, pinned); k.exitStatus != 0 || k.set["x-halo-gate"] != "" {
		t.Fatalf("compliant, pinned: exit %d gate %q", k.exitStatus, k.set["x-halo-gate"])
	}
	if k := call(enforce, "claude-cli/2.1.279 (external, cli)"); k.exitStatus != 403 || !strings.Contains(string(k.exitBody), "version check failed") {
		t.Fatalf("wrong version: %d %s", k.exitStatus, k.exitBody)
	}
	// the verdict cache (1m TTL) is process-wide: a new URL makes a fresh client
	verdict.Store(gateway.PostureVerdict{Reason: "device laptop-1 reported drift"})
	c := trustedCfg(enforce)
	c.PostureURL, c.PostureToken = srv.URL+"/api/v1/gateway/posture/", "gw-token"
	k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: map[string][]string{"x-acme-user": {"alice"}, "User-Agent": {pinned}}}
	c.access(k)
	if k.exitStatus != 403 || !strings.Contains(string(k.exitBody), "halod status") {
		t.Fatalf("non-compliant posture: %d %s", k.exitStatus, k.exitBody)
	}

	warn := gatedPolicy("warn")
	k = call(warn, "curl/8.7.1")
	if k.exitStatus != 0 || !strings.Contains(k.set["x-halo-gate"], "version=warn") {
		t.Fatalf("warn mode: exit %d gate %q", k.exitStatus, k.set["x-halo-gate"])
	}
	cleared := strings.Join(k.cleared, ",")
	if !strings.Contains(cleared, "x-halo-gate") {
		t.Fatalf("client x-halo-gate not cleared: %v", k.cleared)
	}
}
