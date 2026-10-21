package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// fakeBudgetServer is halo-server's budget API over a real Ledger.
type fakeBudgetServer struct {
	*httptest.Server
	l       *budget.Ledger
	budgets []policy.Budget
	now     func() time.Time
	checks  atomic.Int64
	reports atomic.Int64
	down    atomic.Bool
}

func newFakeBudgetServer(t *testing.T, budgets []policy.Budget, now func() time.Time) *fakeBudgetServer {
	t.Helper()
	f := &fakeBudgetServer{l: budget.NewLedger(), budgets: budgets, now: now}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer gw-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/gateway/budget/check":
			f.checks.Add(1)
			var in gateway.BudgetCheck
			_ = json.NewDecoder(r.Body).Decode(&in)
			_ = json.NewEncoder(w).Encode(gateway.BudgetVerdict{Budgets: f.l.Status(f.budgets, in.Principal, f.now())})
		case "/api/v1/gateway/budget/usage":
			f.reports.Add(1)
			var in gateway.BudgetUsage
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.l.Apply(f.budgets, in.Batch, in.Records, f.now())
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// usageUpstream answers every model call with an Anthropic message using 60
// input and 50 output tokens, and records the request headers it saw.
func usageUpstream(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":60,"output_tokens":50}}`)
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func budgetEnv(t *testing.T, url, failMode string, budgets []policy.Budget, up *httptest.Server, clk *clock) *env {
	t.Helper()
	tokFile := filepath.Join(t.TempDir(), "gw.token")
	if err := os.WriteFile(tokFile, []byte("gw-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := testEnv(t, up, func(c *Config, o *policy.Org) {
		c.Budgets = BudgetConfig{URL: url, TokenFile: tokFile, FailMode: failMode}
		o.Gateway.Budgets = budgets
		o.Gateway.Pricing = map[string]policy.ModelPrice{"real-model": {InputPerMTok: 3, OutputPerMTok: 15}}
	})
	if e.p.bc != nil {
		e.p.bc.Now = clk.now
	}
	return e
}

func metricsText(t *testing.T, e *env) string {
	t.Helper()
	w := httptest.NewRecorder()
	e.p.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	return w.Body.String()
}

// One replica refuses a caller as soon as its own metered usage exhausts an
// enforce budget; a second replica learns it from halo-server after the first
// reports and its own cached verdict expires.
func TestBudgetEnforceAcrossReplicas(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	budgets := []policy.Budget{{Name: "dev-daily", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 100, Action: policy.BudgetEnforce}}
	hs := newFakeBudgetServer(t, budgets, clk.now)
	up, s := usageUpstream(t)
	url := hs.URL + "/api/v1/gateway/budget"
	a := budgetEnv(t, url, "", budgets, up, clk)
	b := budgetEnv(t, url, "", budgets, up, clk)
	writeSamePolicy(t, a, b) // both replicas trust a's IdP
	tok := a.token(t, "alice@acme.com")

	wait := a.awaitHandlers(t, 1)
	resp := a.post(t, "/v1/messages", tok, msgBody, map[string]string{"Accept-Encoding": "gzip"})
	_, _ = io.ReadAll(resp.Body)
	wait()
	if resp.StatusCode != 200 {
		t.Fatalf("first call: %d", resp.StatusCode)
	}
	if _, h, _, _ := s.get(); h.Get("Accept-Encoding") != "" {
		t.Fatalf("metered call forwarded Accept-Encoding %q: usage could arrive compressed", h.Get("Accept-Encoding"))
	}

	// Same replica: the 110 tokens it metered count before any report.
	resp = a.post(t, "/v1/messages", tok, msgBody, nil)
	body, _ := io.ReadAll(resp.Body)
	ra, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(body), "rate_limit_error") || !strings.Contains(string(body), `\"dev-daily\"`) ||
		ra != 12*3600 || !strings.Contains(resp.Header.Get("X-Halo-Budget"), "state=refused") {
		t.Fatalf("exhausted on replica a: %d retry-after=%q budget=%q %s", resp.StatusCode, resp.Header.Get("Retry-After"), resp.Header.Get("X-Halo-Budget"), body)
	}
	if n := s.hitCount(); n != 1 {
		t.Fatalf("refused call reached the upstream: %d hits", n)
	}

	if err := a.p.bc.FlushNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := metricsText(t, a)
	for _, want := range []string{`halo_proxy_budget_checks_total{budget="dev-daily",outcome="refused"} 1`, `halo_proxy_budget_responses_total{outcome="metered"} 1`,
		`halo_proxy_budget_tokens_total{kind="input"} 60`, `halo_proxy_budget_tokens_total{kind="output"} 50`, `halo_proxy_budget_reports_total{outcome="ok"} 1`,
		`halo_proxy_budget_spend_usd_total 0.00093`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s:\n%s", want, m)
		}
	}
	// Replica b never served alice: its verdict comes from halo-server's
	// counter, which holds a's report.
	if resp = b.post(t, "/v1/messages", tok, msgBody, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("replica b after a's report: %d", resp.StatusCode)
	}
	if n := s.hitCount(); n != 1 {
		t.Fatalf("upstream hits %d", n)
	}
	// Another user is unaffected; count_tokens is never refused or charged.
	if resp := a.post(t, "/v1/messages", a.token(t, "bob@acme.com"), msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("bob: %d", resp.StatusCode)
	}
	if resp := a.post(t, "/v1/messages/count_tokens", tok, msgBody, nil); resp.StatusCode != 200 {
		t.Fatalf("count_tokens refused: %d", resp.StatusCode)
	}
}

// A client that hangs up before the final usage event is charged a
// pessimistic estimate, never nothing: input from message_start, output from
// the bytes streamed so far capped at the request's max_tokens.
func TestBudgetChargesAbortedStream(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	budgets := []policy.Budget{{Name: "dev-daily", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 1 << 30, Action: policy.BudgetEnforce}}
	hs := newFakeBudgetServer(t, budgets, clk.now)
	const marker = "event: content_block_delta\n"
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"real-model\",\"usage\":{\"input_tokens\":500,\"output_tokens\":1}}}\n\n")
		for range 30 {
			io.WriteString(w, marker+"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\""+strings.Repeat("z", 100)+"\"}}\n\n")
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done() // message_delta (the final usage) never comes before the client leaves
	}))
	t.Cleanup(up.Close)
	e := budgetEnv(t, hs.URL+"/api/v1/gateway/budget", "", budgets, up, clk)
	wait := e.awaitHandlers(t, 1)
	resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), `{"model":"sonnet","max_tokens":100,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	got := 0
	buf := make([]byte, 4096)
	for got < 30*len(marker) {
		n, err := resp.Body.Read(buf)
		got += strings.Count(string(buf[:n]), marker) * len(marker)
		if err != nil {
			t.Fatalf("stream ended early: %v", err)
		}
	}
	_ = resp.Body.Close()
	wait()
	m := metricsText(t, e)
	for _, want := range []string{`halo_proxy_budget_responses_total{outcome="estimated"} 1`, `halo_proxy_budget_responses_total{outcome="metered"} 0`,
		"halo_proxy_budget_tokens_total{kind=\"input\"} 500\n", "halo_proxy_budget_tokens_total{kind=\"output\"} 100\n"} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s:\n%s", want, m)
		}
	}
}

// An upstream that compresses although Accept-Encoding was removed is still
// metered: gzip is decompressed for the usage scan only (the client gets the
// upstream's bytes); an encoding the stdlib cannot read (br) is estimated.
func TestBudgetMetersCompressedResponse(t *testing.T) {
	plain := `{"type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":60,"output_tokens":50}}`
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = io.WriteString(zw, plain)
	_ = zw.Close()
	for _, tc := range []struct {
		enc     string
		body    []byte
		outcome string
		input   string
	}{
		{"gzip", gz.Bytes(), "metered", "halo_proxy_budget_tokens_total{kind=\"input\"} 60\n"},
		{"br", []byte("\x1b\x2a\x00\xf8\xff\x1f\x01\x00"), "estimated", "halo_proxy_budget_tokens_total{kind=\"input\"} 27\n"}, // request bytes / 3 (82 after the model rewrite)
	} {
		t.Run(tc.enc, func(t *testing.T) {
			clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
			budgets := []policy.Budget{{Name: "u", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 1 << 30}}
			hs := newFakeBudgetServer(t, budgets, clk.now)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", tc.enc)
				_, _ = w.Write(tc.body)
			}))
			t.Cleanup(up.Close)
			e := budgetEnv(t, hs.URL+"/api/v1/gateway/budget", "", budgets, up, clk)
			wait := e.awaitHandlers(t, 1)
			req, _ := http.NewRequest("POST", e.proxy.URL+"/v1/messages", strings.NewReader(msgBody))
			req.Header.Set("Authorization", "Bearer "+e.token(t, "alice@acme.com"))
			req.Header.Set("Accept-Encoding", tc.enc) // set explicitly: the client then leaves the body as sent
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			wait()
			if resp.StatusCode != 200 || !bytes.Equal(got, tc.body) {
				t.Fatalf("status %d; client must get the upstream's bytes unchanged", resp.StatusCode)
			}
			m := metricsText(t, e)
			for _, want := range []string{`halo_proxy_budget_responses_total{outcome="` + tc.outcome + `"} 1`, tc.input} {
				if !strings.Contains(m, want) {
					t.Errorf("metrics missing %s:\n%s", want, m)
				}
			}
		})
	}
}

// writeSamePolicy points replica b at a's policy (one IdP for both).
func writeSamePolicy(t *testing.T, a, b *env) {
	t.Helper()
	raw, err := os.ReadFile(a.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.policy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b.p.snap = gateway.NewSnapshot(b.policy)
}

func TestBudgetWarnAndAlertHeaders(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	budgets := []policy.Budget{
		{Name: "team", Scope: policy.ScopeGroup, Groups: []string{"platform"}, Window: policy.WindowMonth, LimitTokens: 1000, AlertAt: []float64{0.1}},
		{Name: "org-usd", Scope: policy.ScopeOrg, Window: policy.WindowWeek, LimitUSD: 0.0001},
	}
	hs := newFakeBudgetServer(t, budgets, clk.now)
	up, s := usageUpstream(t)
	e := budgetEnv(t, hs.URL+"/api/v1/gateway/budget", "", budgets, up, clk)
	tok := e.token(t, "alice@acme.com", "platform")
	wait := e.awaitHandlers(t, 1)
	_, _ = io.ReadAll(e.post(t, "/v1/messages", tok, msgBody, nil).Body)
	wait()
	resp := e.post(t, "/v1/messages", tok, msgBody, nil)
	h := resp.Header.Values("X-Halo-Budget")
	if resp.StatusCode != 200 || len(h) != 2 || !strings.Contains(h[0], "team; scope=group; used=11%; state=alert") ||
		!strings.Contains(h[1], "org-usd; scope=org;") || !strings.Contains(h[1], "state=exceeded") {
		t.Fatalf("warn budgets: %d %q", resp.StatusCode, h)
	}
	if n := s.hitCount(); n != 2 {
		t.Fatalf("warn budgets must not refuse: %d hits", n)
	}
	m := metricsText(t, e)
	for _, want := range []string{`budget="team",outcome="alert"} 1`, `budget="org-usd",outcome="exceeded"} 1`, `budget="team",outcome="ok"} 1`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %s:\n%s", want, m)
		}
	}
}

func TestBudgetUnreachableServer(t *testing.T) {
	clk := &clock{t: time.Now()}
	enforce := []policy.Budget{{Name: "u", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitUSD: 1, Action: policy.BudgetEnforce}}
	warn := []policy.Budget{{Name: "u", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitUSD: 1}}
	for _, tc := range []struct {
		name, mode string
		budgets    []policy.Budget
		want       int
	}{
		{"fail open", "", enforce, 200},
		{"fail closed", failClosed, enforce, http.StatusServiceUnavailable},
		{"fail closed never blocks warn budgets", failClosed, warn, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hs := newFakeBudgetServer(t, tc.budgets, clk.now)
			hs.down.Store(true)
			up, _ := usageUpstream(t)
			e := budgetEnv(t, hs.URL+"/api/v1/gateway/budget", tc.mode, tc.budgets, up, clk)
			resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, nil)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.want, body)
			}
			if tc.want == http.StatusServiceUnavailable && (resp.Header.Get("Retry-After") != "30" || !strings.Contains(string(body), "cannot be checked")) {
				t.Fatalf("fail-closed answer: %q %s", resp.Header.Get("Retry-After"), body)
			}
			if !strings.Contains(metricsText(t, e), `halo_proxy_budget_checks_total{budget="u",outcome="unknown"} 1`) {
				t.Error("unknown verdict not counted")
			}
		})
	}
}

// Budgets in policy without budgets.url: requests pass, nothing is metered.
func TestBudgetUnconfiguredPasses(t *testing.T) {
	up, _ := usageUpstream(t)
	e := testEnv(t, up, func(_ *Config, o *policy.Org) {
		o.Gateway.Budgets = []policy.Budget{{Name: "u", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 1, Action: policy.BudgetEnforce}}
	})
	for range 2 {
		if resp := e.post(t, "/v1/messages", e.token(t, "alice@acme.com"), msgBody, nil); resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	}
}

func TestBudgetConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tok := filepath.Join(t.TempDir(), "t")
	_ = os.WriteFile(tok, []byte("x"), 0o600)
	if bc, err := (BudgetConfig{}).build(log); bc != nil || err != nil {
		t.Fatalf("unset: %v %v", bc, err)
	}
	if bc, err := (BudgetConfig{URL: "https://halo.test/api/v1/gateway/budget", TokenFile: tok, FailMode: failClosed}).build(log); bc == nil || err != nil {
		t.Fatalf("valid: %v %v", bc, err)
	}
	for name, c := range map[string]BudgetConfig{
		"token without url": {TokenFile: tok},
		"url without token": {URL: "https://h"},
		"unreadable token":  {URL: "https://h", TokenFile: tok + ".none"},
		"plain http remote": {URL: "http://halo.test/x", TokenFile: tok},
		"bad fail mode":     {URL: "https://h", TokenFile: tok, FailMode: "sometimes"},
	} {
		if _, err := c.build(log); err == nil || !strings.Contains(err.Error(), "halo-proxy") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
