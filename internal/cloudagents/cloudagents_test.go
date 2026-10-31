package cloudagents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/cloudagents/workflow"
	"github.com/dshakes/halos/internal/ledger"
	"github.com/dshakes/halos/internal/policy"
)

func sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// emptyKeyHMAC is HMAC-SHA256 with an empty key over {"action":"completed"},
// precomputed: FIPS 140-only mode refuses to compute it.
const emptyKeyHMAC = "sha256=34507afaec94c554378d4b72291cb80e820ef45641647d034d4d62fea859ba27"

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"action":"completed"}`)
	// GitHub's documented test vector: secret "It's a Secret to Everybody",
	// payload "Hello, World!".
	const vector = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
	tests := []struct {
		name    string
		secrets []string
		body    []byte
		header  string
		ok      bool
	}{
		{"github vector", []string{"It's a Secret to Everybody"}, []byte("Hello, World!"), vector, true},
		{"valid", []string{"s3cret-0123456789"}, body, sign("s3cret-0123456789", body), true},
		{"rotation: second secret", []string{"new-secret-0123456789", "s3cret-0123456789"}, body, sign("s3cret-0123456789", body), true},
		{"wrong secret", []string{"other-secret-0123456789"}, body, sign("s3cret-0123456789", body), false},
		{"tampered body", []string{"s3cret-0123456789"}, []byte(`{"action":"requested"}`), sign("s3cret-0123456789", body), false},
		{"missing header", []string{"s3cret-0123456789"}, body, "", false},
		{"sha1 header", []string{"s3cret-0123456789"}, body, "sha1=" + strings.Repeat("0", 40), false},
		{"not hex", []string{"s3cret-0123456789"}, body, "sha256=zz", false},
		{"truncated", []string{"s3cret-0123456789"}, body, sign("s3cret-0123456789", body)[:20], false},
		{"no secret configured", nil, body, emptyKeyHMAC, false},
		{"empty secret never matches", []string{""}, body, emptyKeyHMAC, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifySignature(tc.secrets, tc.body, tc.header)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func runJSON(id int64, path, status, conclusion, login string) map[string]any {
	return map[string]any{
		"id": id, "path": path, "status": status, "conclusion": conclusion, "event": "issue_comment",
		"html_url": "https://github.com/acme/app/actions/runs/1", "created_at": "2026-10-27T10:00:00Z", "updated_at": "2026-10-27T10:05:00Z",
		"run_started_at": "2026-10-27T10:00:05Z", "actor": map[string]any{"login": login}, "triggering_actor": map[string]any{"login": login},
		"repository": map[string]any{"full_name": "acme/app"},
	}
}

func TestParseGitHubEvent(t *testing.T) {
	ev := func(run map[string]any) []byte {
		b, _ := json.Marshal(map[string]any{"action": "in_progress", "workflow_run": run, "repository": map[string]any{"full_name": "acme/app"}})
		return b
	}
	tests := []struct {
		name, event string
		body        []byte
		ok          bool
		err         bool
		check       func(*testing.T, Task)
	}{
		{"claude running", "workflow_run", ev(runJSON(42, workflow.ClaudeWorkflow, "in_progress", "", "alice-gh")), true, false, func(t *testing.T, k Task) {
			if k.ID != "claude:acme/app:42" || k.Vendor != "claude" || !k.Managed || k.Status != StatusRunning || k.VendorUser != "alice-gh" || k.Ref != "42" || !k.End.IsZero() {
				t.Fatalf("%+v", k)
			}
		}},
		{"gemini cancelled", "workflow_run", ev(runJSON(7, workflow.GeminiWorkflow, "completed", "cancelled", "bob")), true, false, func(t *testing.T, k Task) {
			if k.Status != StatusCancelled || k.End.IsZero() {
				t.Fatalf("%+v", k)
			}
		}},
		{"copilot", "workflow_run", ev(runJSON(8, "dynamic/copilot-swe-agent/copilot", "queued", "", "alice-gh")), true, false, func(t *testing.T, k Task) {
			if k.Vendor != "copilot" || k.Status != StatusQueued {
				t.Fatalf("%+v", k)
			}
		}},
		{"unmanaged claude", "workflow_run", ev(runJSON(9, ".github/workflows/claude.yml", "completed", "failure", "x")), true, false, func(t *testing.T, k Task) {
			if k.Managed || k.Status != StatusFailed {
				t.Fatalf("%+v", k)
			}
		}},
		{"other workflow", "workflow_run", ev(runJSON(10, ".github/workflows/ci.yml", "in_progress", "", "x")), false, false, nil},
		{"ping", "ping", []byte(`{"zen":"x"}`), false, false, nil},
		{"bad json", "workflow_run", []byte(`{`), false, true, nil},
		{"no run", "workflow_run", []byte(`{}`), false, true, nil},
		{"repo injection", "workflow_run", func() []byte {
			r := runJSON(11, workflow.ClaudeWorkflow, "in_progress", "", "x")
			r["repository"] = map[string]any{"full_name": "acme/../../x\x1b[2J"}
			return ev(r)
		}(), false, true, nil},
		{"login injection", "workflow_run", ev(runJSON(12, workflow.ClaudeWorkflow, "in_progress", "", "a b\n")), false, true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, ok, err := ParseGitHubEvent(tc.event, tc.body)
			if (err != nil) != tc.err || ok != tc.ok {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if tc.check != nil {
				tc.check(t, k)
			}
		})
	}
}

func TestCursorNormalize(t *testing.T) {
	a := cursorAgent{ID: "bc-1", Status: "ACTIVE", URL: "https://cursor.com/agents/bc-1", LatestRun: "run-1", CreatedAt: time.Unix(100, 0)}
	a.Repos = append(a.Repos, struct {
		URL string `json:"url"`
	}{"https://github.com/acme/web"})
	k, err := taskFromCursor(a, "alice")
	if err != nil || k.ID != "cursor:bc-1" || k.Repo != "acme/web" || k.Status != StatusRunning || k.User != "alice" || k.RunRef != "run-1" {
		t.Fatalf("%+v %v", k, err)
	}
	for s, want := range map[string]string{"IDLE": StatusCompleted, "ARCHIVED": StatusCancelled, "NEW": StatusUnknown} {
		if got := cursorStatus(s); got != want {
			t.Errorf("%s -> %s, want %s", s, got, want)
		}
	}
	if _, err := taskFromCursor(cursorAgent{ID: "../x"}, ""); err == nil {
		t.Fatal("path-shaped id accepted")
	}
}

// fake is a GitHub + Cursor API that records every call.
type fake struct {
	mu    sync.Mutex
	calls []string
	auth  []string
}

func (f *fake) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.auth = append(f.auth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/app/actions/runs":
			if !strings.HasPrefix(r.URL.Query().Get("created"), ">=") {
				t.Errorf("created filter missing: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{
				runJSON(1, workflow.ClaudeWorkflow, "in_progress", "", "alice-gh"),
				runJSON(2, ".github/workflows/ci.yml", "in_progress", "", "alice-gh"),
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{
				map[string]any{"id": "bc-1", "status": "ACTIVE", "latestRunId": "run-1", "createdAt": "2026-10-27T10:00:00Z", "updatedAt": "2026-10-27T10:00:00Z"},
			}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents/bc-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "bc-1", "status": "ACTIVE", "latestRunId": "run-1", "createdAt": "2026-10-27T10:00:00Z", "repos": []any{map[string]any{"url": "https://github.com/acme/web"}}})
		case r.URL.Path == "/v1/agents/bc-1/usage":
			_ = json.NewEncoder(w).Encode(map[string]any{"totalUsage": map[string]any{"totalTokens": 900}})
		case r.URL.Path == "/repos/acme/app/actions/runs/1/cancel":
			w.WriteHeader(http.StatusAccepted)
		case r.URL.Path == "/repos/acme/app/actions/runs/3/cancel":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"message":"Cannot cancel a workflow run that is completed."}`))
		case r.URL.Path == "/v1/agents/bc-1/runs/run-1/cancel", r.URL.Path == "/v1/agents/bc-1/archive",
			r.URL.Path == "/repos/acme/app/actions/workflows/halos-claude.yml/disable":
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, "nope", http.StatusInternalServerError)
		}
	}))
}

func clients(t *testing.T, srv *httptest.Server) Clients {
	gh, err := NewClient("github", srv.URL, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	cu, err := NewClient("cursor", srv.URL, "cursor-token")
	if err != nil {
		t.Fatal(err)
	}
	return Clients{GitHub: gh, Cursor: cu, CursorUser: "bob"}
}

func fixtureOrg() *policy.Org {
	return &policy.Org{
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "canary"}, Order: 1, Membership: policy.Membership{Users: []string{"alice"}}},
			{Meta: policy.Meta{Name: "ga"}, Order: 2, Membership: policy.Membership{Default: true}},
		},
		Experiments: []*policy.Experiment{{Meta: policy.Meta{Name: "exp1"}, Status: "running", Rings: []string{"canary"}, Variants: []policy.Variant{{Name: "a", Weight: 1}}}},
		CloudAgents: &policy.CloudAgents{
			Identities: []policy.CloudIdentity{{User: "alice", GitHub: "alice-gh"}},
			Claude:     &policy.CloudAgent{Enabled: true, Repos: []string{"acme/app", "acme/*"}},
			Cursor:     &policy.CloudAgent{Enabled: true, Budgets: []policy.Budget{{Name: "d", Scope: policy.ScopeUser, Window: policy.WindowDay, LimitTokens: 500}}},
		},
	}
}

func TestFetchNormalizesAndAttributes(t *testing.T) {
	f := &fake{}
	srv := f.serve(t)
	defer srv.Close()
	tasks, warns, errs := clients(t, srv).Fetch(context.Background(), fixtureOrg(), time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if len(tasks) != 2 {
		t.Fatalf("tasks %+v: the ci.yml run is not a cloud agent", tasks)
	}
	if k := tasks[0]; k.ID != "claude:acme/app:1" || k.User != "alice" || k.Source != SourceGitHubAPI {
		t.Fatalf("github task %+v", k)
	}
	if k := tasks[1]; k.ID != "cursor:bc-1" || k.User != "bob" || k.Repo != "acme/web" || k.Tokens != 900 {
		t.Fatalf("cursor task %+v", k)
	}
	if !strings.Contains(strings.Join(warns, "\n"), "acme/*") {
		t.Fatalf("wildcard repo not warned: %v", warns)
	}
	for _, a := range f.auth {
		if !strings.HasPrefix(a, "Bearer ") {
			t.Fatalf("auth header %q", a)
		}
	}
}

func TestKillFanOut(t *testing.T) {
	org := fixtureOrg()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	tasks := []Task{
		{ID: "claude:acme/app:1", Vendor: "claude", Repo: "acme/app", Ref: "1", Workflow: workflow.ClaudeWorkflow, Managed: true, User: "alice", Status: StatusRunning, Start: now},
		{ID: "claude:acme/app:3", Vendor: "claude", Repo: "acme/app", Ref: "3", Workflow: workflow.ClaudeWorkflow, Managed: true, User: "alice", Status: StatusQueued, Start: now},
		{ID: "claude:acme/app:4", Vendor: "claude", Repo: "acme/app", Ref: "4", User: "alice", Status: StatusCompleted, Start: now},
		{ID: "cursor:bc-1", Vendor: "cursor", Ref: "bc-1", RunRef: "run-1", Managed: true, User: "bob", Status: StatusRunning, Start: now},
		{ID: "claude:acme/app:5", Vendor: "claude", Repo: "acme/app", Ref: "5", Status: StatusRunning, Start: now}, // unattributed
	}
	tests := []struct {
		scope, name string
		want        []string
		err         bool
	}{
		{ScopeUser, "alice", []string{"claude:acme/app:1", "claude:acme/app:3"}, false},
		{ScopeUser, "ALICE", []string{"claude:acme/app:1", "claude:acme/app:3"}, false},
		{ScopeRing, "canary", []string{"claude:acme/app:1", "claude:acme/app:3"}, false},
		{ScopeRing, "ga", []string{"cursor:bc-1"}, false},
		{ScopeExperiment, "exp1", []string{"claude:acme/app:1", "claude:acme/app:3"}, false},
		{ScopeRing, "nope", nil, true},
		{ScopeExperiment, "nope", nil, true},
		{"device", "x", nil, true},
		{ScopeUser, " ", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.scope+"/"+tc.name, func(t *testing.T) {
			hit, unattributed, err := Select(org, tasks, tc.scope, tc.name, nil)
			if (err != nil) != tc.err {
				t.Fatal(err)
			}
			var ids []string
			for _, k := range hit {
				ids = append(ids, k.ID)
			}
			if !slices.Equal(ids, tc.want) {
				t.Fatalf("hit %v, want %v", ids, tc.want)
			}
			if !tc.err && unattributed != 1 {
				t.Fatalf("unattributed %d", unattributed)
			}
		})
	}

	f := &fake{}
	srv := f.serve(t)
	defer srv.Close()
	hit, _, _ := Select(org, tasks, ScopeRing, "canary", nil)
	hit = append(hit, tasks[3])
	plan := Plan(hit, OpCancel)
	for _, a := range plan {
		if a.Result != ResultDryRun || a.Call == "" {
			t.Fatalf("plan %+v", a)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("planning called a vendor")
	}
	got := clients(t, srv).Execute(context.Background(), plan)
	want := map[string]string{"claude:acme/app:1": ResultDone, "claude:acme/app:3": ResultDone, "cursor:bc-1": ResultDone}
	for _, a := range got {
		if a.Result != want[a.Task.ID] {
			t.Errorf("%s: %s %s", a.Task.ID, a.Result, a.Error)
		}
	}
	if got[1].Error != "already finished" {
		t.Errorf("409 on cancel should read as already finished: %+v", got[1])
	}
	if !slices.Contains(f.calls, "POST /v1/agents/bc-1/runs/run-1/cancel") || !slices.Contains(f.calls, "POST /repos/acme/app/actions/runs/1/cancel") {
		t.Fatalf("calls %v", f.calls)
	}
	// Without the vendor's client nothing is sent.
	if a := (Clients{}).Execute(context.Background(), plan[:1]); a[0].Result != ResultNoClient {
		t.Fatalf("%+v", a[0])
	}
	// Copilot cancel is attempted with a manual note; pause has no API.
	cp := Plan([]Task{{ID: "c", Vendor: "copilot", Repo: "acme/app", Ref: "9", Status: StatusRunning}}, OpCancel)
	if cp[0].Call == "" || !strings.Contains(cp[0].Manual, "UNVERIFIED") {
		t.Fatalf("%+v", cp[0])
	}
	if cp := Plan([]Task{{ID: "c", Vendor: "copilot", Repo: "acme/app", Ref: "9"}}, OpPause); cp[0].Result != ResultManual {
		t.Fatalf("%+v", cp[0])
	}
	pa := clients(t, srv).Execute(context.Background(), Plan([]Task{tasks[0], tasks[3]}, OpPause))
	if pa[0].Result != ResultDone || pa[1].Result != ResultDone || !slices.Contains(f.calls, "PUT /repos/acme/app/actions/workflows/halos-claude.yml/disable") || !slices.Contains(f.calls, "POST /v1/agents/bc-1/archive") {
		t.Fatalf("pause %+v calls %v", pa, f.calls)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/enable") || strings.Contains(c, "unarchive") {
			t.Fatal("a resume was sent: resuming is a human's call")
		}
	}
}

func TestEvaluate(t *testing.T) {
	org := fixtureOrg()
	org.CloudAgents.Claude.MaxConcurrent.PerUser = 1
	org.CloudAgents.Claude.OnOverLimit = policy.OverLimitPause
	org.CloudAgents.Claude.Models = []string{"m1"}
	org.CloudAgents.Codex = &policy.CloudAgent{Enabled: false}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	tasks := []Task{
		{ID: "c1", Vendor: "claude", Repo: "acme/app", Managed: true, User: "alice", Status: StatusRunning, Start: now.Add(-2 * time.Hour)},
		{ID: "c2", Vendor: "claude", Repo: "acme/app", Managed: true, User: "alice", Status: StatusRunning, Start: now.Add(-time.Hour)},
		{ID: "c3", Vendor: "claude", Repo: "evil/app", Managed: true, User: "alice", Status: StatusCompleted, Start: now, Model: "m2"},
		{ID: "c4", Vendor: "claude", Repo: "acme/app", Managed: false, Workflow: ".github/workflows/claude.yml", VendorUser: "mallory", Status: StatusRunning, Start: now},
		{ID: "k1", Vendor: "codex", Status: StatusRunning, User: "alice", Start: now},
		{ID: "g1", Vendor: "gemini", Status: StatusRunning, User: "alice", Start: now},
		{ID: "u1", Vendor: "cursor", Managed: true, User: "bob", Status: StatusRunning, Tokens: 400, Start: now.Add(-time.Hour)},
		{ID: "u2", Vendor: "cursor", Managed: true, User: "bob", Status: StatusCompleted, Tokens: 200, Start: now.Add(-30 * time.Minute)},
		{ID: "u3", Vendor: "cursor", Managed: true, User: "bob", Status: StatusCompleted, Tokens: 9999, Start: now.Add(-48 * time.Hour)}, // yesterday's window
	}
	alerts := Evaluate(org, tasks, nil, now)
	kinds := map[string]Alert{}
	for _, a := range alerts {
		kinds[a.Vendor+"/"+a.Kind] = a
	}
	for _, k := range []string{"claude/concurrency", "claude/repo", "claude/model", "claude/unmanaged", "claude/unattributed", "codex/disabled", "gemini/ungoverned", "cursor/budget"} {
		if _, ok := kinds[k]; !ok {
			t.Errorf("missing %s alert in %+v", k, alerts)
		}
	}
	if c := kinds["claude/concurrency"]; c.Value != 2 || c.Limit != 1 || !slices.Equal(c.Pause, []string{"c2"}) {
		t.Errorf("concurrency pauses the newest task past the limit: %+v", c)
	}
	if b := kinds["cursor/budget"]; b.Value != 600 || len(b.Pause) != 0 {
		t.Errorf("budget counts today's window, and cursor here only alerts: %+v", b)
	}
	if m := kinds["claude/model"]; len(m.Pause) != 0 {
		t.Errorf("a finished task is never paused: %+v", m)
	}
	if got := PauseTasks(alerts, tasks); len(got) != 2 || got[0].ID != "c2" || got[1].ID != "c4" {
		t.Errorf("pause tasks %+v", got)
	}
	if Evaluate(&policy.Org{}, tasks, nil, now) != nil {
		t.Error("no cloudAgents, no alerts")
	}
}

func TestLedgerRecord(t *testing.T) {
	start := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	k := Task{ID: "claude:acme/app:42", Vendor: "claude", Repo: "acme/app", VendorUser: "alice-gh", User: "alice", Status: StatusCancelled, Start: start, End: start.Add(time.Minute), Model: "claude-sonnet-5"}
	r, ok := k.LedgerRecord()
	if !ok || r.Harness != "claude-code-action" || r.Outcome != ledger.OutcomeCancelled || r.Who.User != "alice" || r.Confidence != ledger.High || len(r.Repos) != 0 || r.Validate() != nil {
		t.Fatalf("%+v ok=%v err=%v", r, ok, r.Validate())
	}
	k.Status = StatusRunning
	if _, ok := k.LedgerRecord(); ok {
		t.Fatal("a running task has no ledger record yet")
	}
}
