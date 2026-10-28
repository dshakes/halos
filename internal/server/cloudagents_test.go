package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/cloudagents"
	"github.com/dshakes/halos/internal/cloudagents/workflow"
	"github.com/dshakes/halos/internal/ledger"
)

const webhookSecret = "whsec-0123456789abcdef"

// vendorFake records every vendor API call.
type vendorFake struct {
	mu    sync.Mutex
	calls []string
}

func (f *vendorFake) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
}

func (f *vendorFake) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newCloudServer(t *testing.T, roles []string, vendor *httptest.Server) (*Server, http.Handler) {
	t.Helper()
	cfg := Config{
		PolicyDir: "../../examples/acme-corp", Token: tok,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:     (&testClock{}).Now,
		DevUser: "op@test", DevRoles: roles,
		KillKey: nil, CloudWebhookSecrets: []string{webhookSecret},
	}
	if vendor != nil {
		gh, err := cloudagents.NewClient("github", vendor.URL, "gh-token")
		if err != nil {
			t.Fatal(err)
		}
		cfg.CloudClients.GitHub = gh
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, s.Handler()
}

func runEvent(id int, path, status, conclusion, login, updated string) []byte {
	b, _ := json.Marshal(map[string]any{"action": "x", "workflow_run": map[string]any{
		"id": id, "path": path, "status": status, "conclusion": conclusion,
		"created_at": "2026-01-01T00:00:00Z", "run_started_at": "2026-01-01T00:00:00Z", "updated_at": updated,
		"actor": map[string]any{"login": login}, "triggering_actor": map[string]any{"login": login},
		"repository": map[string]any{"full_name": "acme-corp/web"},
	}})
	return b
}

func deliver(h http.Handler, event string, body []byte, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/cloud-agents/webhooks/github", strings.NewReader(string(body)))
	r.Header.Set("X-GitHub-Event", event)
	r.Header.Set("X-GitHub-Delivery", "d-1")
	if secret != "" {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write(body)
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestCloudWebhook(t *testing.T) {
	s, h := newCloudServer(t, []string{RoleViewer}, nil)
	running := runEvent(42, workflow.ClaudeWorkflow, "in_progress", "", "alice-acme", "2026-01-01T00:05:00Z")
	tests := []struct {
		name, event, secret string
		body                []byte
		code                int
	}{
		{"unsigned", "workflow_run", "", running, http.StatusUnauthorized},
		{"wrong secret", "workflow_run", "other", running, http.StatusUnauthorized},
		{"ping", "ping", webhookSecret, []byte(`{"zen":"x"}`), http.StatusAccepted},
		{"other workflow", "workflow_run", webhookSecret, runEvent(1, ".github/workflows/ci.yml", "in_progress", "", "x", "2026-01-01T00:00:00Z"), http.StatusAccepted},
		{"malformed", "workflow_run", webhookSecret, []byte(`{}`), http.StatusBadRequest},
		{"running", "workflow_run", webhookSecret, running, http.StatusOK},
		{"completed", "workflow_run", webhookSecret, runEvent(42, workflow.ClaudeWorkflow, "completed", "success", "alice-acme", "2026-01-01T00:09:00Z"), http.StatusOK},
		// A replayed older delivery must not turn the finished task back on.
		{"stale replay", "workflow_run", webhookSecret, running, http.StatusAccepted},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if w := deliver(h, tc.event, tc.body, tc.secret); w.Code != tc.code {
				t.Fatalf("code %d, want %d: %s", w.Code, tc.code, w.Body)
			}
		})
	}
	w := do(h, "GET", "/api/v1/cloud-agents", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var v CloudAgentsView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Tasks) != 1 || v.Tasks[0].Status != cloudagents.StatusCompleted || v.Tasks[0].User != "alice@acme.com" || !v.Configured["githubWebhook"] {
		t.Fatalf("view %+v", v)
	}
	// The finished task is also a session ledger record, attributed.
	got, _, err := s.latestSessions(func(r *ledger.Record) bool { return r.Harness == "claude-code-action" })
	if err != nil || len(got) != 1 {
		t.Fatalf("ledger %v %v", got, err)
	}
	for _, st := range got {
		if st.Who.User != "alice@acme.com" || st.Outcome != ledger.OutcomeCompleted || st.Sources[0] != ledger.SourceCloudAgents {
			t.Fatalf("ledger record %+v", st.Record)
		}
	}
}

func TestCloudWebhookOffWithoutSecret(t *testing.T) {
	s, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DevUser: "u"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if w := deliver(s.Handler(), "workflow_run", []byte(`{}`), "x"); w.Code != http.StatusNotFound {
		t.Fatalf("code %d", w.Code)
	}
}

func TestCloudAgentsRBAC(t *testing.T) {
	_, auditor := newCloudServer(t, []string{RoleAuditor}, nil)
	if w := do(auditor, "GET", "/api/v1/cloud-agents", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("auditor read: %d", w.Code)
	}
	_, viewer := newCloudServer(t, []string{RoleViewer}, nil)
	if w := do(viewer, "POST", "/api/v1/cloud-agents/kill", "", `{"scope":"user","name":"alice@acme.com","reason":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("viewer kill: %d", w.Code)
	}
}

func TestCloudKill(t *testing.T) {
	f := &vendorFake{}
	vs := f.server()
	defer vs.Close()
	s, h := newCloudServer(t, []string{RoleOperator}, vs)
	for i, login := range []string{"alice-acme", "alice-acme", "bob-acme"} {
		if w := deliver(h, "workflow_run", runEvent(100+i, workflow.ClaudeWorkflow, "in_progress", "", login, "2026-01-01T00:05:00Z"), webhookSecret); w.Code != http.StatusOK {
			t.Fatalf("deliver: %d %s", w.Code, w.Body)
		}
	}
	// acme caps claude at 2 per user: alice's two runs alert, nothing pauses (onOverLimit alert).
	if c := f.seen(); len(c) != 0 {
		t.Fatalf("an alert-only policy called the vendor: %v", c)
	}
	tests := []struct {
		name, body string
		code       int
		calls      int
	}{
		{"reason required", `{"scope":"user","name":"alice@acme.com"}`, http.StatusUnprocessableEntity, 0},
		{"bad scope", `{"scope":"device","name":"x","reason":"r"}`, http.StatusBadRequest, 0},
		{"unknown ring", `{"scope":"ring","name":"nope","reason":"r"}`, http.StatusBadRequest, 0},
		{"dry run by default", `{"scope":"user","name":"alice@acme.com","reason":"incident"}`, http.StatusOK, 0},
		{"execute", `{"scope":"user","name":"alice@acme.com","reason":"incident","dryRun":false}`, http.StatusOK, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(f.seen())
			w := do(h, "POST", "/api/v1/cloud-agents/kill", "", tc.body)
			if w.Code != tc.code {
				t.Fatalf("code %d, want %d: %s", w.Code, tc.code, w.Body)
			}
			if got := len(f.seen()) - before; got != tc.calls {
				t.Fatalf("%d vendor calls, want %d: %v", got, tc.calls, f.seen())
			}
			if w.Code != http.StatusOK {
				return
			}
			var resp CloudKillResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if len(resp.Actions) != 2 {
				t.Fatalf("actions %+v", resp.Actions)
			}
			for _, a := range resp.Actions {
				want := cloudagents.ResultDryRun
				if tc.calls > 0 {
					want = cloudagents.ResultDone
				}
				if a.Result != want || !strings.HasSuffix(a.Call, "/cancel") {
					t.Fatalf("action %+v", a)
				}
			}
		})
	}
	for _, c := range f.seen() {
		if !strings.HasPrefix(c, "POST /repos/acme-corp/web/actions/runs/10") {
			t.Fatalf("unexpected vendor call %s (bob's run must not be cancelled)", c)
		}
	}
	// The executed kill is in the audit log with its reason (the dry run is not).
	snap, err := s.auditLog.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var kills []AuditEntry
	_ = snap.from(1, func(_ []byte, e AuditEntry) bool {
		if e.Action == actionCloudKill {
			kills = append(kills, e)
		}
		return true
	})
	snap.close()
	if len(kills) != 1 || kills[0].Details["reason"] != "incident" || kills[0].Actor != "op@test" || kills[0].Target != "user:alice@acme.com" {
		t.Fatalf("kill audit %+v", kills)
	}
	w := do(h, "GET", "/api/v1/cloud-agents?active=true", "", "")
	var v CloudAgentsView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	found := false
	for _, a := range v.Alerts {
		found = found || (a.Kind == cloudagents.AlertConcurrency && a.Key == "user:alice@acme.com")
	}
	if found {
		t.Fatal("acme allows 2 claude tasks per user: two must not alert")
	}
}

// An experiment kill reports its users' cloud tasks and how to cancel them;
// it cancels nothing itself.
func TestExperimentKillReportsCloudTasks(t *testing.T) {
	s, h, _ := newKillServer(t, true)
	s.cfg.CloudWebhookSecrets = []string{webhookSecret}
	w := do(h, "POST", "/api/v1/experiments/opus-5-5-canary/kill", "", `{"reason":"regression"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	ca, ok := out["cloudAgents"].(map[string]any)
	if !ok || ca["activeTasks"] != float64(0) || !strings.Contains(ca["next_steps"].([]any)[0].(string), `"dryRun":false`) {
		t.Fatalf("response %v", out)
	}
}

// Over the concurrency limit with onOverLimit: pause, halo-server disables
// the newest task's workflow (reversible) and never enables anything.
func TestCloudOverLimitPauses(t *testing.T) {
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS("../../examples/acme-corp")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "halos.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(b), "maxConcurrent: {perUser: 2}", "maxConcurrent: {perUser: 1}\n    onOverLimit: pause", 1)
	if y == string(b) {
		t.Fatal("fixture: acme claude limit not found")
	}
	if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &vendorFake{}
	vs := f.server()
	defer vs.Close()
	gh, err := cloudagents.NewClient("github", vs.URL, "gh-token")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{PolicyDir: dir, Token: tok, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: (&testClock{}).Now,
		DevUser: "u", CloudWebhookSecrets: []string{webhookSecret}, CloudClients: cloudagents.Clients{GitHub: gh}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	h := s.Handler()
	deliver(h, "workflow_run", runEvent(1, workflow.ClaudeWorkflow, "in_progress", "", "alice-acme", "2026-01-01T00:05:00Z"), webhookSecret)
	if c := f.seen(); len(c) != 0 {
		t.Fatalf("under the limit: %v", c)
	}
	deliver(h, "workflow_run", runEvent(2, workflow.ClaudeWorkflow, "in_progress", "", "alice-acme", "2026-01-01T00:06:00Z"), webhookSecret)
	c := f.seen()
	if len(c) != 1 || c[0] != "PUT /repos/acme-corp/web/actions/workflows/halos-claude.yml/disable" {
		t.Fatalf("calls %v", c)
	}
}
