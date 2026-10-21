package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// agentPolicy trusts the workload key and lets planner and reviewer act.
func agentPolicy(pub ed25519.PublicKey) func(*Config, *policy.Org) {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return func(c *Config, o *policy.Org) {
		c.Identity.workloadKeys = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		o.Agents = &policy.Agents{Actors: []policy.AgentActor{{Name: "planner"}, {Name: "reviewer"}}, DeniedTools: []string{"Bash"}}
		o.Experiments = []*policy.Experiment{{
			Meta: policy.Meta{Name: "all-in"}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
			Status: "running", Rings: []string{"ring0", "ga"},
			Variants: []policy.Variant{{Name: "control", Weight: 0, Control: true},
				{Name: "treat", Weight: 100, Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "up", Model: "treat-model"}}}},
		}}
	}
}

func mintAgent(t *testing.T, priv ed25519.PrivateKey, root string, groups []string, chain ...string) string {
	t.Helper()
	var actors []policy.Actor
	for _, a := range chain {
		actors = append(actors, policy.Actor{Agent: a, Harness: "claude-code"})
	}
	now := time.Now()
	tok, err := identity.SignDelegatedToken(priv, identity.DelegatedClaims{Issuer: identity.WorkloadIssuer, Subject: root, Audience: identity.WorkloadAudience,
		Groups: groups, Kind: identity.KindAgent, Act: identity.ActFromChain(actors), IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Expiry: now.Add(10 * time.Minute).Unix(), ID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestDelegatedCredentialAtTheProxy: the root's ring, the verified chain on
// x-halo-actor (a client copy is replaced), no experiment, no credential
// upstream; a forged chain and a denied tool never reach the upstream.
func TestDelegatedCredentialAtTheProxy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	up, s := recordingServer(t)
	e := testEnv(t, up, agentPolicy(pub))
	tok := mintAgent(t, priv, "alice@acme.com", []string{"ai-platform"}, "planner", "reviewer")
	resp := e.post(t, "/v1/messages", tok, msgBody, map[string]string{"X-Halo-Actor": "ceo", "x-halo-actor-depth": "0", "x-halo-ring": "ga"})
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}
	_, h, body, _ := s.get()
	if h.Get("x-halo-ring") != "ring0" || h.Get("x-halo-actor") != "planner>reviewer" || h.Get("x-halo-actor-depth") != "2" {
		t.Fatalf("upstream headers: %v", h)
	}
	if h.Get("x-halo-experiment") != "" || !strings.Contains(body, `"real-model"`) || h.Get("Authorization") != "" {
		t.Fatalf("agent enrolled or credential forwarded: %v %s", h, body)
	}
	hits, _, _, _ := s.get()
	parts := strings.Split(tok, ".")
	forged := parts[0] + "." + strings.Split(mintAgent(t, priv, "ceo@acme.com", []string{"ai-platform"}, "planner"), ".")[1] + "." + parts[2]
	if resp := e.post(t, "/v1/messages", forged, msgBody, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged act chain: %d", resp.StatusCode)
	}
	tools := `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"Bash"}]}`
	if resp := e.post(t, "/v1/messages", tok, tools, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("denied tool: %d", resp.StatusCode)
	}
	if after, _, _, _ := s.get(); after != hits {
		t.Fatalf("refused calls reached the upstream (%d -> %d)", hits, after)
	}
}

// TestDelegatedBudgetChargedToRoot: an agent's usage lands on its root's user
// budget, so the root (and every other agent of it) is then refused.
func TestDelegatedBudgetChargedToRoot(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	budgets := []policy.Budget{{Name: "dev-daily", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 100, Action: policy.BudgetEnforce}}
	hs := newFakeBudgetServer(t, budgets, clk.now)
	up, _ := usageUpstream(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		agentPolicy(pub)(c, o)
		c.Budgets = BudgetConfig{URL: hs.URL + "/api/v1/gateway/budget", TokenFile: tokFile}
		o.Gateway.Budgets = budgets
	})
	e.p.bc.Now = clk.now
	agent := mintAgent(t, priv, "alice@acme.com", nil, "planner")
	wait := e.awaitHandlers(t, 1) // usage is metered as the response body streams
	resp := e.post(t, "/v1/messages", agent, msgBody, nil)
	_, _ = io.ReadAll(resp.Body)
	wait()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first call: %d", resp.StatusCode)
	}
	if err := e.p.bc.FlushNow(t.Context()); err != nil {
		t.Fatal(err)
	}
	st := hs.l.Status(budgets, budget.Principal{Subject: "alice@acme.com", Ring: "ga"}, clk.now())
	if len(st) != 1 || st[0].SpentTokens != 110 {
		t.Fatalf("root's budget: %+v", st)
	}
	for name, tok := range map[string]string{"root": e.token(t, "alice@acme.com"), "another agent": mintAgent(t, priv, "alice@acme.com", nil, "reviewer")} {
		if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("%s after the agent spent the root's budget: %d", name, resp.StatusCode)
		}
	}
}

// TestDelegatedDeprovisionedRoot: with the SCIM directory configured, an agent
// acting for a deprovisioned user is refused like the user.
func TestDelegatedDeprovisionedRoot(t *testing.T) {
	var mu sync.Mutex
	var down atomic.Bool
	dir := map[string]gateway.DirectoryEntry{"alice@acme.com": {Active: true, Groups: []string{"ai-platform"}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(dir[r.URL.Query().Get("subject")])
	}))
	t.Cleanup(srv.Close)
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	up, s := recordingServer(t)
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		agentPolicy(pub)(c, o)
		c.Directory = DirectoryConfig{URL: srv.URL, TokenFile: tokFile, AllowInsecureInCluster: true}
	})
	var tick atomic.Int64                                                                                              // every lookup sees the clock a TTL later, so each request asks the fake server
	e.p.dir.Now = func() time.Time { return time.Unix(tick.Add(int64(gateway.DefaultDirectoryGrace/time.Second)), 0) } // past TTL and grace: never cached
	tok := mintAgent(t, priv, "alice@acme.com", nil, "planner")
	if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("active root: %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("x-halo-ring") != "ring0" || h.Get("x-halo-actor") != "planner" {
		t.Fatalf("directory groups and chain: %v", h)
	}
	// Directory outage, fail open: the caller keeps its identity with no
	// groups, and stays an agent: the chain and the agent policy still apply.
	down.Store(true)
	tools := `{"model":"sonnet","messages":[{"role":"user","content":"hi"}],"tools":[{"name":"Bash"}]}`
	if resp := e.post(t, "/v1/messages", tok, tools, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("directory outage turned the agent into its root: denied tool answered %d", resp.StatusCode)
	}
	if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("outage, fail open: %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("x-halo-actor") != "planner" {
		t.Fatalf("outage dropped the chain: %v", h)
	}
	down.Store(false)
	mu.Lock()
	dir["alice@acme.com"] = gateway.DirectoryEntry{}
	mu.Unlock()
	if resp := e.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("deprovisioned root's agent: %d, want 403", resp.StatusCode)
	}
}
