package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBudgetStatus(t *testing.T) {
	var gotPath, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, _ := r.Cookie("halo_session"); c != nil {
			gotCookie = c.Value
		}
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"at":"2026-10-21T12:00:00Z","budgets":[` +
			`{"budget":"dev-daily","scope":"user","key":"user:alice@acme.com","window":"day","action":"enforce","limitUSD":25,"spentUSD":26.5,"spentTokens":9,"alertAt":[0.8],"resetAt":"2026-10-22T00:00:00Z"},` +
			`{"budget":"org-tokens","scope":"org","key":"org","window":"rolling","period":"24h","action":"warn","limitTokens":1000,"spentUSD":0,"spentTokens":850,"alertAt":[0.8],"resetAt":"2026-10-22T06:00:00Z"}]}`))
	}))
	defer srv.Close()
	t.Setenv("HALO_SESSION", "sess")

	code, out, errs := halo(t, "budget", "status", "--server", srv.URL, "--budget", "dev-daily", "--key", "user:alice@acme.com")
	if code != 0 {
		t.Fatalf("status: %d %s", code, errs)
	}
	if gotPath != "/api/v1/budgets?budget=dev-daily&key=user%3Aalice%40acme.com" || gotCookie != "sess" {
		t.Fatalf("request %q cookie %q", gotPath, gotCookie)
	}
	for _, want := range []string{"dev-daily", "$26.50", "$25.00", "106%", "2026-10-22T00:00:00Z", "rolling 24h", "850 tok", "1000 tok", "85%"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if code, out, _ := halo(t, "budget", "status", "--server", srv.URL, "--output", "json"); code != 0 || !strings.Contains(out, `"spentUSD": 26.5`) {
		t.Fatalf("json: %d %s", code, out)
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"budgets":[]}`)) }))
	defer empty.Close()
	if code, out, _ := halo(t, "budget", "status", "--server", empty.URL); code != 0 || !strings.Contains(out, "no budget counters") {
		t.Fatalf("empty: %d %s", code, out)
	}
	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "admin role required", http.StatusForbidden)
	}))
	defer deny.Close()
	if code, _, errs := halo(t, "budget", "status", "--server", deny.URL); code == 0 || !strings.Contains(errs, "403") {
		t.Fatalf("403 not surfaced: %d %s", code, errs)
	}
	if code, _, errs := halo(t, "budget", "status", "--server", "http://halo.example.com"); code == 0 || !strings.Contains(errs, "https") {
		t.Fatalf("plain http accepted: %d %s", code, errs)
	}
	t.Setenv("HALO_SESSION", "")
	if code, _, errs := halo(t, "budget", "status", "--server", srv.URL); code == 0 || !strings.Contains(errs, "HALO_SESSION") {
		t.Fatalf("no session: %d %s", code, errs)
	}
}
