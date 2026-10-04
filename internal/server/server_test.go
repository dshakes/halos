package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const tok = "s3cret"

func newTestServer(t *testing.T, verdicts string) http.Handler {
	t.Helper()
	s, err := New(Config{
		PolicyDir: "../../examples/acme-corp", Token: tok, VerdictsPath: verdicts,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) },
		DevUser: "admin@test", DevAdmin: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func do(h http.Handler, method, url, auth, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func report(host, ring, claude string, drift bool) string {
	d := "[]"
	if drift {
		d = `["claude-code"]`
	}
	return `{"hostname":"` + host + `","user":"u","ring":"` + ring + `","digest":"sha256:abc","harnesses":{"claude-code":{"want":"2.1.0","installed":"` + claude + `"}},"drift":` + d + `}`
}

func TestReportAuthAndLimits(t *testing.T) {
	h := newTestServer(t, "")
	ok := report("h1", "ring1-canary", "2.1.0", false)
	for _, c := range []struct {
		name, auth, body string
		want             int
	}{
		{"no token", "", ok, 401},
		{"wrong token", "Bearer nope", ok, 401},
		{"basic scheme", "Basic " + tok, ok, 401},
		{"too big", "Bearer " + tok, `{"hostname":"h","user":"` + strings.Repeat("a", MaxReportBytes) + `"}`, 413},
		{"bad json", "Bearer " + tok, `{`, 400},
		{"no hostname", "Bearer " + tok, `{"ring":"r"}`, 422},
		{"ok", "Bearer " + tok, ok, 204},
	} {
		if got := do(h, "POST", "/api/v1/fleet/report", c.auth, c.body).Code; got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

func TestFleetAggregation(t *testing.T) {
	h := newTestServer(t, "")
	for _, b := range []string{
		report("a", "ring3-ga", "2.1.0", false),
		report("b", "ring3-ga", "2.0.9", true),
		report("c", "ring1-canary", "2.1.0", false),
		report("a", "ring3-ga", "2.1.1", false), // replaces first "a"
	} {
		if c := do(h, "POST", "/api/v1/fleet/report", "Bearer "+tok, b).Code; c != 204 {
			t.Fatalf("report: %d", c)
		}
	}
	var f FleetResponse
	w := do(h, "GET", "/api/v1/fleet", "", "")
	if err := json.Unmarshal(w.Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if f.Total != 3 || f.Drift != 1 || len(f.Rings) != 2 {
		t.Fatalf("unexpected fleet: %+v", f)
	}
	if f.Rings[0].Ring != "ring1-canary" { // policy ring order, not alphabetical-by-host
		t.Errorf("ring order: %v", f.Rings[0].Ring)
	}
	ga := f.Rings[1]
	if ga.Hosts != 2 || ga.Versions["claude-code"]["2.1.1"] != 1 || ga.Versions["claude-code"]["2.0.9"] != 1 || ga.Drift != 1 {
		t.Errorf("ga stats: %+v", ga)
	}
	if ga.Percent < 66 || ga.Percent > 67 {
		t.Errorf("percent %v", ga.Percent)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Error("security headers missing")
	}
}

func TestLogStoreReplay(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenLogStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Put(Host{Report: Report{Hostname: "a", Ring: "r1"}})
	_ = st.Put(Host{Report: Report{Hostname: "a", Ring: "r2"}})
	_ = st.(io.Closer).Close() // the crashed process's handle is gone; Windows cannot rename over an open file
	f, _ := os.OpenFile(filepath.Join(dir, "reports.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{torn") // simulated crash mid-write
	f.Close()
	st2, err := OpenLogStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st2.(io.Closer).Close() })
	if all := st2.All(); len(all) != 1 || all[0].Ring != "r2" {
		t.Fatalf("replay: %+v", all)
	}
}

func TestPolicyExperimentsWhoAmI(t *testing.T) {
	dir := t.TempDir()
	vf := filepath.Join(dir, "v.json")
	_ = os.WriteFile(vf, []byte(`[{"experiment":"opus-5-5-canary","verdict":"continue","Reason":"x","guardrails":[{"metric":"m","result":{"status":"pass"}}]}]`), 0o600)
	h := newTestServer(t, vf)

	var pv PolicyView
	w := do(h, "GET", "/api/v1/policy", "", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &pv) != nil {
		t.Fatalf("policy: %d %s", w.Code, w.Body.String())
	}
	if len(pv.Rings) != 4 || pv.Rings[0].Resolved == nil || len(pv.Experiments) != 3 {
		t.Fatalf("policy view: rings=%d exps=%d", len(pv.Rings), len(pv.Experiments))
	}

	var ed ExperimentDetail
	w = do(h, "GET", "/api/v1/experiments/opus-5-5-canary", "", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &ed) != nil || ed.Verdict == nil || ed.Verdict.Reason != "x" || ed.Verdict.Guardrails[0].Result.Status != "pass" {
		t.Fatalf("experiment: %d %s", w.Code, w.Body.String())
	}
	if c := do(h, "GET", "/api/v1/experiments/nope", "", "").Code; c != 404 {
		t.Errorf("missing experiment: %d", c)
	}
	if c := do(h, "GET", "/api/v1/whoami", "", "").Code; c != 400 {
		t.Errorf("whoami without user: %d", c)
	}
	var wm WhoAmI
	w = do(h, "GET", "/api/v1/whoami?user=alice&groups=x,y", "", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &wm) != nil || wm.Ring == "" || len(wm.Assignments) != 3 {
		t.Fatalf("whoami: %d %s", w.Code, w.Body.String())
	}
	var hm map[string][]string
	w = do(h, "GET", "/api/v1/harnesses", "", "")
	if json.Unmarshal(w.Body.Bytes(), &hm) != nil || len(hm["claude-code"]) == 0 {
		t.Fatalf("harnesses: %s", w.Body.String())
	}
}

func TestPolicyMissingDir(t *testing.T) {
	s, _ := New(Config{PolicyDir: t.TempDir() + "/nope", Token: tok, DevUser: "d", DevAdmin: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if c := do(s.Handler(), "GET", "/api/v1/policy", "", "").Code; c != 503 {
		t.Errorf("got %d", c)
	}
}

func TestStaticAndHealth(t *testing.T) {
	h := newTestServer(t, "")
	if w := do(h, "GET", "/", "", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Halos") {
		t.Errorf("placeholder: %d", w.Code)
	}
	if do(h, "GET", "/healthz", "", "").Code != 200 || do(h, "GET", "/api/nope", "", "").Code != 404 {
		t.Error("healthz / api 404")
	}
	s, _ := New(Config{PolicyDir: "x", Token: tok, DevUser: "d", Web: fstest.MapFS{"index.html": {Data: []byte("SPA")}, "a.js": {Data: []byte("js")}}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	h = s.Handler()
	if w := do(h, "GET", "/fleet", "", ""); w.Body.String() != "SPA" {
		t.Errorf("spa fallback: %q", w.Body.String())
	}
	if w := do(h, "GET", "/a.js", "", ""); w.Body.String() != "js" {
		t.Errorf("asset: %q", w.Body.String())
	}
}

func TestReportErrorCodePassthrough(t *testing.T) {
	h := newTestServer(t, "")
	body := strings.Replace(report("h1", "ring1-canary", "2.1.0", false), `"drift":[]`, `"drift":[],"lastError":"x","errorCode":"sandbox_unavailable"`, 1)
	if c := do(h, "POST", "/api/v1/fleet/report", "Bearer "+tok, body).Code; c != 204 {
		t.Fatalf("report: %d", c)
	}
	var f FleetResponse
	if err := json.Unmarshal(do(h, "GET", "/api/v1/fleet", "", "").Body.Bytes(), &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Hosts) != 1 || f.Hosts[0].ErrorCode != "sandbox_unavailable" {
		t.Fatalf("errorCode not passed through: %+v", f.Hosts)
	}
	long := strings.Replace(body, "sandbox_unavailable", strings.Repeat("a", 65), 1)
	if c := do(h, "POST", "/api/v1/fleet/report", "Bearer "+tok, long).Code; c != 422 {
		t.Fatalf("oversized errorCode: %d", c)
	}
}
