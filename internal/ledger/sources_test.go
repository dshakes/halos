package ledger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/vendoradmin"
)

var win = Window{Since: t0.Add(-24 * time.Hour), Until: t0}

// fakeCH answers every query with rows (JSONEachRow) and records the SQL and
// parameters it was sent.
type fakeCH struct {
	mu     sync.Mutex
	sql    []string
	params []map[string]string
	rows   []string
}

func (f *fakeCH) server(t *testing.T) *promote.ClickHouse {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		p := map[string]string{}
		for k, v := range r.URL.Query() {
			p[k] = v[0]
		}
		f.mu.Lock()
		f.sql, f.params = append(f.sql, string(b)), append(f.params, p)
		f.mu.Unlock()
		if strings.HasPrefix(string(b), "INSERT") {
			return
		}
		_, _ = io.WriteString(w, strings.Join(f.rows, "\n")+"\n")
	}))
	t.Cleanup(srv.Close)
	return &promote.ClickHouse{URL: srv.URL, Database: "halo"}
}

func TestGatewaySource(t *testing.T) {
	f := &fakeCH{rows: []string{
		`{"trace":"4bf92f3577b34da6a3ce929d0e0e4736","unit":"9f2c1a","harness":"codex","ring":"ring1","release":"r-7","experiment":"exp-a","variant":"b","chain":"planner>reviewer","models":["gpt-5",""],"input_tokens":120,"output_tokens":30,"errors":0,"calls":2,"start_ms":1793091600000,"end_ms":1793091660000}`,
		`{"trace":"0af7651916cd43dd8448eb211c80319c","unit":"","harness":"","errors":1,"calls":1,"start_ms":1793091600000,"end_ms":1793091600500}`,
	}}
	recs, err := Gateway{CH: f.server(t)}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.sql[0], "SpanAttributes['halo.source'] = 'gateway'") || f.params[0]["param_since"] != "2026-10-26 09:00:00.000" ||
		f.params[0]["param_until"] != "2026-10-27 09:00:00.000" || f.params[0]["database"] != "halo" {
		t.Fatalf("query: %s %v", f.sql[0], f.params[0])
	}
	out, err := Normalize(recs, Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	a, b := out[0], out[1]
	if a.Harness != "codex" || a.Ring != "ring1" || a.Variant != "b" || a.Who.Unit != "9f2c1a" || !slices.Equal(a.Who.Agents, []string{"planner", "reviewer"}) ||
		!slices.Equal(a.Models, []string{"gpt-5"}) || a.InputTokens != 120 || a.Outcome != OutcomeCompleted || a.Confidence != High ||
		a.End.Sub(a.Start) != time.Minute {
		t.Fatalf("gateway record = %+v", a)
	}
	if b.Harness != "unknown" || b.Outcome != OutcomeError {
		t.Fatalf("failed trace = %+v", b)
	}
}

func TestClaudeOTelSource(t *testing.T) {
	f := &fakeCH{rows: []string{
		`{"session":"7c0e8a0e-1b2d-4f1e-9d55-0d1c2b3a4f5e","email":"dev@acme.example","account":"user_01","version":"2.1.310","ring":"ring2","release":"r-9","experiment":"","variant":"",` +
			`"models":["claude-sonnet-5"],"tools":["Edit","mcp__github__create_issue","Bash"],"mcp":["",""],"repos":["https://github.com/acme/payments",""],` +
			`"input_tokens":5000,"output_tokens":700,"cost_usd":0.42,"requests":3,"api_errors":0,"start_ms":1793091600000,"end_ms":1793095200000}`,
	}}
	recs, err := ClaudeOTel{CH: f.server(t)}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	// The query names attributes; it never selects prompt text, tool input,
	// error messages or the raw tool parameters.
	for _, banned := range []string{"['prompt']", "tool_input", "['error']", "LogAttributes['tool_parameters'] AS", "Body AS"} {
		if strings.Contains(f.sql[0], banned) {
			t.Fatalf("query selects %s", banned)
		}
	}
	out, err := Normalize(recs, Redaction{Paths: PathsHash, Salt: salt})
	if err != nil {
		t.Fatal(err)
	}
	r := out[0]
	if r.Harness != "claude-code" || r.HarnessVersion != "2.1.310" || r.Who.VendorUser != "dev@acme.example" || r.Ring != "ring2" ||
		!slices.Equal(r.MCPServers, []string{"github"}) || !slices.Equal(r.Tools, []string{"Bash", "Edit", "mcp__github__create_issue"}) ||
		len(r.Repos) != 1 || !hashedRE.MatchString(r.Repos[0]) || r.CostUSD != 0.42 || r.Confidence != Medium || r.Outcome != OutcomeUnknown {
		t.Fatalf("otel record = %+v", r)
	}
}

func TestClickHouseErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Code: 60. Table halo.otel_traces does not exist", http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := Gateway{CH: &promote.ClickHouse{URL: srv.URL}}.Fetch(context.Background(), win)
	if err == nil || !strings.Contains(err.Error(), "gateway source") || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("err = %v", err)
	}
}

const fakeKey = "fake-compliance-key-0123456789" // allowlist secret: test placeholder

func TestAnthropicSource(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeKey || r.Header.Get("anthropic-version") != AnthropicVersion {
			t.Errorf("headers: %v", r.Header)
		}
		q := r.URL.Query()
		calls = append(calls, q.Get("after_id"))
		if r.URL.Path != "/v1/compliance/activities" || q.Get("activity_types[]") != "ccr_session_created" || q.Get("order") != "asc" ||
			q.Get("created_at.gte") != "2026-10-26T09:00:00Z" || q.Get("created_at.lt") != "2026-10-27T09:00:00Z" {
			t.Errorf("request: %s", r.URL)
		}
		if q.Get("after_id") == "" {
			_, _ = io.WriteString(w, `{"data":[
			  {"id":"activity_01","type":"ccr_session_created","created_at":"2026-10-26T10:00:00Z","agent_id":"cagt_01","actor":{"type":"user_actor","email_address":"dev@acme.example","user_id":"user_01"}},
			  {"id":"activity_02","type":"claude_chat_created","created_at":"2026-10-26T10:01:00Z","actor":{"type":"user_actor","email_address":"x@acme.example"}}
			],"has_more":true,"first_id":"activity_01","last_id":"activity_02"}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"activity_03","type":"ccr_session_created","created_at":"2026-10-26T11:00:00Z","actor":{"type":"api_actor","api_key_id":"apikey_01"}}],"has_more":false,"last_id":"activity_03"}`)
	}))
	defer srv.Close()
	c := &vendoradmin.Client{Vendor: SourceAnthropic, BaseURL: srv.URL, Token: fakeKey, HTTP: srv.Client()}
	recs, err := Anthropic{Client: c}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"", "activity_02"}) {
		t.Fatalf("pagination: %q", calls)
	}
	out, err := Normalize(recs, Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].SessionID != "activity_01" || out[0].Who.VendorUser != "dev@acme.example" || !slices.Equal(out[0].Who.Agents, []string{"cagt_01"}) ||
		out[0].Confidence != High || out[1].Who.VendorUser != "api_key:apikey_01" {
		t.Fatalf("anthropic records = %+v", out)
	}
}

func TestVendorErrorsNeverCarryTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid key `+fakeKey+`"}`, http.StatusUnauthorized) // a vendor echoing the key
	}))
	defer srv.Close()
	c := &vendoradmin.Client{BaseURL: srv.URL, Token: fakeKey, HTTP: srv.Client()}
	for _, s := range []Source{Anthropic{Client: c}, GitHubAudit{Client: c, Enterprise: "acme"}} {
		_, err := s.Fetch(context.Background(), win)
		if err == nil || strings.Contains(err.Error(), fakeKey) || !strings.Contains(err.Error(), "401") {
			t.Fatalf("%s: err = %v", s.Name(), err)
		}
	}
}

func TestGitHubAuditSource(t *testing.T) {
	ts := func(d time.Duration) float64 { return float64(t0.Add(d).UnixMilli()) }
	var afters []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		afters = append(afters, q.Get("after"))
		if r.URL.Path != "/enterprises/acme/audit-log" || r.Header.Get("X-GitHub-Api-Version") != GitHubAPIVersion ||
			q.Get("phrase") != "action:agent_session created:2026-10-26..2026-10-27" || q.Get("order") != "asc" {
			t.Errorf("request: %s %v", r.URL, r.Header)
		}
		ev := func(d time.Duration, action, actor, user, repo, sid string, agent bool) map[string]any {
			return map[string]any{"@timestamp": ts(d), "action": action, "actor": actor, "user": user, "repo": repo, "agent_session_id": sid, "actor_is_agent": agent}
		}
		var evs []map[string]any
		if q.Get("after") == "" {
			// The next link names another host: only its cursor may be used.
			w.Header().Set("Link", `<https://evil.example/enterprises/acme/audit-log?after=CURSOR2&per_page=100>; rel="next"`)
			evs = []map[string]any{
				ev(-2*time.Hour, "agent_session.task", "Copilot", "octocat", "acme/payments", "as_1", true),
				ev(-time.Hour, "pull_request.create", "Copilot", "octocat", "acme/payments", "as_1", true),
				ev(-time.Hour, "repo.create", "octocat", "", "acme/new", "", false), // no session: ignored
				ev(-48*time.Hour, "agent_session.task", "Copilot", "octocat", "acme/x", "as_old", true),
			}
		} else {
			evs = []map[string]any{ev(-30*time.Minute, "agent_session.task", "hubot", "", "acme/web", "as_2", false)}
		}
		_ = json.NewEncoder(w).Encode(evs)
	}))
	defer srv.Close()
	c := &vendoradmin.Client{BaseURL: srv.URL, Token: "gh-placeholder", HTTP: srv.Client()}
	recs, err := GitHubAudit{Client: c, Enterprise: "acme"}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(afters, []string{"", "CURSOR2"}) {
		t.Fatalf("cursors: %q", afters)
	}
	out, err := Normalize(recs, Redaction{Paths: PathsHash, Salt: salt})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 sessions, got %+v", out)
	}
	a := out[0]
	if a.SessionID != "as_1" || a.Harness != "copilot-agent" || a.Who.VendorUser != "octocat" || !slices.Equal(a.Who.Agents, []string{"Copilot"}) ||
		len(a.Repos) != 1 || a.End.Sub(a.Start) != time.Hour || a.Confidence != High {
		t.Fatalf("as_1 = %+v", a)
	}
	if out[1].Who.VendorUser != "hubot" || len(out[1].Who.Agents) != 0 {
		t.Fatalf("as_2 = %+v", out[1])
	}
	if _, err := (GitHubAudit{Client: c, Enterprise: "acme/../x"}).Fetch(context.Background(), win); err == nil {
		t.Fatal("enterprise path injection accepted")
	}
}

func TestJSONLSource(t *testing.T) {
	good := `{"sessionId":"cur-1","harness":"cursor","who":{"vendorUser":"dev@acme.example","user":"ceo@acme.example"},"tools":["edit_file"],"files":["src/a.ts"],"start":"2026-10-26T12:00:00Z","outcome":"completed","sources":["gateway"],"confidence":"high"}`
	recs, err := JSONL{R: strings.NewReader("\n" + good + "\n")}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Normalize(recs, Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	// The file cannot claim gateway evidence or high confidence.
	if r := out[0]; !slices.Equal(r.Sources, []string{SourceJSONL}) || r.Confidence != Low || len(r.Files) != 0 || r.FilesTouched != 1 {
		t.Fatalf("jsonl record = %+v", r)
	}
	for name, line := range map[string]string{
		"a prompt field":   `{"sessionId":"x","harness":"cursor","start":"2026-10-26T12:00:00Z","prompt":"draft the layoff memo"}`,
		"a nested unknown": `{"sessionId":"x","harness":"cursor","start":"2026-10-26T12:00:00Z","who":{"transcript":"..."}}`,
		"two objects":      `{"sessionId":"x","harness":"cursor","start":"2026-10-26T12:00:00Z"} {}`,
		"not json":         `sessionId=x`,
	} {
		if _, err := (JSONL{R: strings.NewReader(line)}).Fetch(context.Background(), win); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// prose that decodes is still refused by Normalize
	recs, err = JSONL{R: strings.NewReader(`{"sessionId":"x","harness":"cursor","start":"2026-10-26T12:00:00Z","models":["summarise the board deck"]}`)}.Fetch(context.Background(), win)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := Normalize(recs, Redaction{}); err != nil || len(out[0].Models) != 0 || out[0].Redacted != 1 {
		t.Fatalf("prose model: %+v %v", out, err)
	}
}

func TestInsert(t *testing.T) {
	f := &fakeCH{}
	ch := f.server(t)
	out, err := Normalize([]Record{base()}, Redaction{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Insert(context.Background(), ch, out, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	body := f.sql[0]
	if !strings.HasPrefix(body, "INSERT INTO halo_session_ledger FORMAT JSONEachRow\n") {
		t.Fatalf("insert: %s", body)
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(strings.SplitN(body, "\n", 2)[1]), &row); err != nil {
		t.Fatal(err)
	}
	if row["stored_at"] != "2026-10-27 10:00:00.000" || len(row["record_sha256"].(string)) != 64 || row["started_at"] != "2026-10-27 09:00:00.000" || row["ended_at"] != "1970-01-01 00:00:00.000" ||
		fmt.Sprint(row["files"]) != "[]" || row["session_id"] != "s-1" {
		t.Fatalf("row = %v", row)
	}
	bad := base() // never normalized: no id, outcome or confidence
	if err := Insert(context.Background(), ch, []Record{bad}, t0); err == nil || len(f.sql) != 1 {
		t.Fatalf("unvalidated record inserted: %v", err)
	}
}
