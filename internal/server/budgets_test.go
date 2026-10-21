package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/budget"
	"github.com/dshakes/halos/internal/gateway"
)

// budgetEnv adds a per-user enforce budget and an org warn budget to the portal policy.
func budgetEnv(t *testing.T, dataDir string) *env {
	t.Helper()
	return newEnv(t, func(c *Config) {
		c.GatewayToken, c.DataDir = "gw-tok", dataDir
		f := filepath.Join(c.PolicyDir, "gateway.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, "\nbudgets:\n  - {name: dev-daily, scope: user, window: day, limitUSD: 10, action: enforce}\n"+
			"  - {name: org-month, scope: org, window: month, limitTokens: 1000000}\n"...)
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatal(err)
		}
	})
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGatewayBudgetAPI(t *testing.T) {
	dir := t.TempDir()
	e := budgetEnv(t, dir)
	alice := budget.Principal{Subject: "alice@acme.example", Groups: []string{"eng"}, Ring: "ga"}
	check := func(p budget.Principal) []budget.Status {
		t.Helper()
		w := do(e.h, "POST", "/api/v1/gateway/budget/check", "Bearer gw-tok", mustJSON(t, gateway.BudgetCheck{Principal: p}))
		if w.Code != http.StatusOK {
			t.Fatalf("check: %d %s", w.Code, w.Body)
		}
		return decode[gateway.BudgetVerdict](t, w).Budgets
	}
	usage := func(batch string, recs ...budget.Record) *httptest.ResponseRecorder {
		t.Helper()
		return do(e.h, "POST", "/api/v1/gateway/budget/usage", "Bearer gw-tok", mustJSON(t, gateway.BudgetUsage{Batch: batch, Records: recs}))
	}

	if st := check(alice); len(st) != 2 || st[0].Key != "user:alice@acme.example" || st[0].SpentUSD != 0 || st[1].Key != "org" {
		t.Fatalf("fresh verdict: %+v", st)
	}
	rec := budget.Record{Principal: alice, Spend: budget.Spend{USD: 12.5, Tokens: 4000}, At: *e.now}
	if w := usage("b-1", rec); w.Code != 200 || !strings.Contains(w.Body.String(), `"duplicate":false`) {
		t.Fatalf("usage: %d %s", w.Code, w.Body)
	}
	if w := usage("b-1", rec); w.Code != 200 || !strings.Contains(w.Body.String(), `"duplicate":true`) {
		t.Fatalf("retried batch: %d %s", w.Code, w.Body)
	}
	st := check(alice)
	if st[0].SpentUSD != 12.5 || !st[0].Exceeded() || st[0].Action != "enforce" || st[1].SpentTokens != 4000 {
		t.Fatalf("after usage: %+v", st)
	}
	if bob := check(budget.Principal{Subject: "bob@acme.example", Ring: "ga"}); bob[0].SpentUSD != 0 || bob[1].SpentTokens != 4000 {
		t.Fatalf("bob shares only the org counter: %+v", bob)
	}

	// Admin view; developers are refused.
	w := e.as(admin, "GET", "/api/v1/budgets", "")
	all := decode[BudgetsResponse](t, w)
	if w.Code != 200 || len(all.Budgets) != 2 || all.Budgets[0].Key != "user:alice@acme.example" || all.Budgets[1].Key != "org" {
		t.Fatalf("admin view: %d %+v", w.Code, all)
	}
	if f := decode[BudgetsResponse](t, e.as(admin, "GET", "/api/v1/budgets?budget=org-month", "")); len(f.Budgets) != 1 || f.Budgets[0].Budget != "org-month" {
		t.Fatalf("filter by budget: %+v", f)
	}
	if f := decode[BudgetsResponse](t, e.as(admin, "GET", "/api/v1/budgets?key=user:nobody", "")); len(f.Budgets) != 0 {
		t.Fatalf("filter by key: %+v", f)
	}
	if c := e.as(dev, "GET", "/api/v1/budgets", "").Code; c != http.StatusForbidden {
		t.Fatalf("developer read all budgets: %d", c)
	}

	// Counters survive a restart (Close writes the ledger).
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	e2 := budgetEnv(t, dir)
	e.h = e2.h
	if st := check(alice); st[0].SpentUSD != 12.5 {
		t.Fatalf("after restart: %+v", st)
	}
}

func TestGatewayBudgetAPIRejects(t *testing.T) {
	e := budgetEnv(t, "")
	long := strings.Repeat("g", 257)
	for _, tc := range []struct {
		name, path, auth, body string
		want                   int
	}{
		{"no token", "/api/v1/gateway/budget/check", "", `{}`, 401},
		{"wrong token", "/api/v1/gateway/budget/usage", "Bearer nope", `{}`, 401},
		{"bad json", "/api/v1/gateway/budget/check", "Bearer gw-tok", `{`, 400},
		{"trailing data", "/api/v1/gateway/budget/check", "Bearer gw-tok", `{} {}`, 400},
		{"long group", "/api/v1/gateway/budget/check", "Bearer gw-tok", `{"groups":["` + long + `"]}`, 422},
		{"no batch id", "/api/v1/gateway/budget/usage", "Bearer gw-tok", `{"records":[]}`, 422},
		{"negative spend", "/api/v1/gateway/budget/usage", "Bearer gw-tok", `{"batch":"x","records":[{"subject":"a","usd":-1}]}`, 422},
		{"negative tokens", "/api/v1/gateway/budget/usage", "Bearer gw-tok", `{"batch":"x","records":[{"subject":"a","tokens":-1}]}`, 422},
		{"oversize", "/api/v1/gateway/budget/usage", "Bearer gw-tok", `{"batch":"x","pad":"` + strings.Repeat("a", maxBudgetUsageBytes) + `"}`, 413},
	} {
		if w := do(e.h, "POST", tc.path, tc.auth, tc.body); w.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, w.Code, w.Body, tc.want)
		}
	}
	// Without a gateway token the endpoints do not exist.
	plain := newEnv(t, nil)
	if w := do(plain.h, "POST", "/api/v1/gateway/budget/check", "Bearer x", `{}`); w.Code != http.StatusNotFound {
		t.Fatalf("unconfigured: %d", w.Code)
	}
}
