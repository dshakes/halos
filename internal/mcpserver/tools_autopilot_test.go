package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/promote"
)

// Every tool the guide names must exist on a server with writes; the guide
// itself is served as a resource and as the autopilot prompt.
func TestAutopilotGuideNamesRealTools(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example, AllowWrites: true})
	have := toolNames(t, cs)
	for _, n := range []string{"status", "release_build", "wait_for", "kill_switch_status", "fleet_status", "audit_tail", "kill_switch", "eval_run"} {
		if !have[n] {
			t.Errorf("tool %s missing", n)
		}
	}
	r, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: guideURI})
	if err != nil || len(r.Contents) == 0 || r.Contents[0].Text != autopilotGuide {
		t.Fatalf("guide resource: %v", err)
	}
	p, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "autopilot", Arguments: map[string]string{"goal": "claude-code 2.1.300"}})
	if err != nil {
		t.Fatal(err)
	}
	txt := p.Messages[0].Content.(*mcp.TextContent).Text
	if !strings.Contains(txt, "claude-code 2.1.300") || !strings.Contains(txt, "## The loop") || strings.Contains(txt, "%!") {
		t.Fatalf("autopilot prompt not rendered: %.200s", txt)
	}
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(autopilotGuide, -1) {
		n := m[1]
		if strings.Contains(n, "_") && !have[n] && n != "dry_run" && n != "next_steps" && n != "open_pr" {
			t.Errorf("guide names tool %s, which is not registered", n)
		}
	}
	// A read-only server still previews everything: the gated tools exist and refuse real calls.
	ro := toolNames(t, connect(t, Options{PolicyDir: example}))
	for _, n := range []string{"status", "release_build", "wait_for", "kill_switch", "eval_run"} {
		if !ro[n] {
			t.Errorf("read-only server lacks %s", n)
		}
	}
}

func TestStatus(t *testing.T) {
	out, err := call(t, connect(t, Options{PolicyDir: example}), "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := out["policy"].(map[string]any)
	srvInfo := out["server"].(map[string]any)
	if pol["ok"] != true || len(out["rings"].([]any)) < 3 || len(out["experiments"].([]any)) < 1 || srvInfo["allow_writes"] != false || srvInfo["clickhouse"] != false {
		t.Fatalf("status: %v", out)
	}
	next := out["next_steps"].([]any)
	joined, _ := json.Marshal(next)
	for _, want := range []string{"--allow-writes", "--clickhouse", "HALO_SERVER", "opus-5-5-canary is running: wait_for"} {
		if !strings.Contains(string(joined), want) {
			t.Errorf("next_steps lack %q: %s", want, joined)
		}
	}
	w, err := call(t, connect(t, Options{PolicyDir: example, AllowWrites: true}), "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if j, _ := json.Marshal(w["next_steps"]); strings.Contains(string(j), "--allow-writes") {
		t.Fatalf("writes on, still asking for --allow-writes: %s", j)
	}
}

func TestReleaseBuild(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	out, err := call(t, cs, "release_build", map[string]any{"ring": "ring1-canary", "release_version": "1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := out["digest"].(string)
	if !strings.HasPrefix(d, "sha256:") || len(out["harnesses"].(map[string]any)) == 0 || len(out["files"].([]any)) == 0 || out["version"] != "1.2.3" {
		t.Fatalf("release_build: %v", out)
	}
	if j, _ := json.Marshal(out["next_steps"]); !strings.Contains(string(j), "halo release publish") || !strings.Contains(string(j), "--ring ring1-canary --release-version 1.2.3") {
		t.Fatalf("next_steps lack the publish command: %s", j)
	}
	if _, err := call(t, cs, "release_build", map[string]any{"ring": "nope"}); err == nil {
		t.Fatal("unknown ring accepted")
	}
}

func TestWaitFor(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	// Running experiment, no ClickHouse: returns at once, unsatisfied, with the fix.
	out, err := call(t, cs, "wait_for", map[string]any{"kind": "experiment", "name": "opus-5-5-canary", "timeout_seconds": 1})
	if err != nil {
		t.Fatal(err)
	}
	if out["satisfied"] != false || !strings.Contains(out["reason"].(string), "no evidence") || !strings.Contains(out["next_steps"].([]any)[0].(string), "--clickhouse") {
		t.Fatalf("wait experiment: %v", out)
	}
	// A draft experiment has nothing to wait for.
	out, err = call(t, cs, "wait_for", map[string]any{"kind": "experiment", "name": "sonnet-next-shadow"})
	if err != nil {
		t.Fatal(err)
	}
	if out["satisfied"] != true || out["outcome"] != "draft" {
		t.Fatalf("wait draft: %v", out)
	}
	// Rollout: one poll (timeout 1s, interval 10s) and a decision either way.
	out, err = call(t, cs, "wait_for", map[string]any{"kind": "rollout", "name": "opus-5-5-upgrade", "timeout_seconds": 1})
	if err != nil {
		t.Fatal(err)
	}
	if out["polls"].(float64) != 1 || out["outcome"] == "" || len(out["next_steps"].([]any)) == 0 {
		t.Fatalf("wait rollout: %v", out)
	}
	for _, args := range []map[string]any{
		{"kind": "ring", "name": "x"},
		{"kind": "experiment", "name": "nope"},
		{"kind": "rollout", "name": "nope"},
	} {
		if _, err := call(t, cs, "wait_for", args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// fakeServer stands in for halo-server's admin API.
type fakeServer struct {
	mu    sync.Mutex
	kills []string // "<kind>/<name>/<verb>:<reason>"
	seen  []string // cookie values seen
}

func (f *fakeServer) handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/v1/killswitch", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"version": 3, "killed": []map[string]any{{"experiment": "opus-5-5-canary", "reason": "bad"}}})
	})
	m.HandleFunc("/api/v1/fleet", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"total": 2, "drift": 1, "rings": []any{}, "hosts": []any{}})
	})
	m.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode([]map[string]any{{"id": "d1"}}) // halo-server answers a bare array
	})
	m.HandleFunc("/api/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": []map[string]any{{"seq": 7, "action": "kill", "q": r.URL.RawQuery}}})
	})
	m.HandleFunc("POST /api/v1/{kind}/{name}/{verb}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		var in struct{ Reason string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		key := r.PathValue("kind") + "/" + r.PathValue("name") + "/" + r.PathValue("verb")
		f.mu.Lock()
		changed := true
		for _, k := range f.kills {
			changed = changed && !strings.HasPrefix(k, key+":")
		}
		f.kills = append(f.kills, key+":"+in.Reason)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"killed": r.PathValue("verb") == "kill", "changed": changed})
	})
	return m
}

func (f *fakeServer) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, err := r.Cookie("halo_session"); err == nil {
		f.seen = append(f.seen, c.Value)
	} else {
		f.seen = append(f.seen, "")
	}
}

func TestFleetToolsNeedServer(t *testing.T) {
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	cs := connect(t, Options{PolicyDir: example, AllowWrites: true})
	out, err := call(t, cs, "kill_switch_status", nil)
	if err != nil || out["configured"] != false || !strings.Contains(out["next_steps"].([]any)[0].(string), "HALO_SESSION") {
		t.Fatalf("kill_switch_status without server: %v %v", out, err)
	}
	for _, tool := range []string{"fleet_status", "audit_tail"} {
		if _, err := call(t, cs, tool, nil); err == nil || !strings.Contains(err.Error(), "HALO_SERVER") {
			t.Errorf("%s without server: %v", tool, err)
		}
	}
	// Dry run needs no server; the real call does.
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "r"})
	if err != nil || out["dry_run"] != true || out["applied"] != false {
		t.Fatalf("kill dry run without server: %v %v", out, err)
	}
	if _, err := call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "r", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "HALO_SERVER") {
		t.Fatalf("real kill without server: %v", err)
	}
	// A session cookie must not travel over plain http off loopback.
	t.Setenv("HALO_SESSION", "s3cret")
	cs2 := connect(t, Options{PolicyDir: example, Server: "http://halo.example.com"})
	if _, err := call(t, cs2, "fleet_status", nil); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
}

func TestFleetToolsAndKillSwitch(t *testing.T) {
	f := &fakeServer{}
	hs := httptest.NewServer(f.handler())
	defer hs.Close()
	t.Setenv("HALO_SESSION", "admin-cookie")

	ro := connect(t, Options{PolicyDir: example, Server: hs.URL})
	out, err := call(t, ro, "kill_switch_status", nil)
	if err != nil || out["configured"] != true || len(out["killed"].([]any)) != 1 {
		t.Fatalf("kill_switch_status: %v %v", out, err)
	}
	st, err := call(t, ro, "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if st["kill_switch"] == nil || st["fleet"].(map[string]any)["drift"].(float64) != 1 || st["server"].(map[string]any)["admin_session"] != true {
		t.Fatalf("status lacks fleet plane: %v", st)
	}
	var killedFlag bool
	for _, e := range st["experiments"].([]any) {
		em := e.(map[string]any)
		if em["name"] == "opus-5-5-canary" {
			killedFlag, _ = em["killed"].(bool)
		}
	}
	if !killedFlag {
		t.Fatalf("status does not mark the killed experiment: %v", st["experiments"])
	}
	fl, err := call(t, ro, "fleet_status", nil)
	if err != nil || fl["total"].(float64) != 2 || len(fl["devices"].([]any)) != 1 {
		t.Fatalf("fleet_status: %v %v", fl, err)
	}
	au, err := call(t, ro, "audit_tail", map[string]any{"limit": 5, "since": "3"})
	if err != nil || !strings.Contains(au["entries"].([]any)[0].(map[string]any)["q"].(string), "limit=5") {
		t.Fatalf("audit_tail: %v %v", au, err)
	}
	// Read-only: kill_switch previews, refuses the real call.
	if _, err := call(t, ro, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "r", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("read-only kill accepted: %v", err)
	}
	if len(f.kills) != 0 {
		t.Fatalf("read-only server sent a kill: %v", f.kills)
	}

	cs := connect(t, Options{PolicyDir: example, Server: hs.URL, AllowWrites: true})
	for _, args := range []map[string]any{
		{"name": "opus-5-5-canary", "reason": " "},
		{"name": "nope", "reason": "r"},
		{"name": "opus-5-5-canary", "kind": "toggle", "reason": "r"},
	} {
		if _, err := call(t, cs, "kill_switch", args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	// Default is a dry run: nothing sent, command and request returned.
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "p95 up"})
	if err != nil || out["dry_run"] != true || out["applied"] != false || !strings.Contains(out["command"].(string), "halo kill opus-5-5-canary") || len(f.kills) != 0 {
		t.Fatalf("dry run: %v %v %v", out, err, f.kills)
	}
	// Real call: posts with the reason and the session cookie; a repeat is idempotent.
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "p95 up", "dry_run": false})
	if err != nil || out["applied"] != true || out["result"].(map[string]any)["changed"] != true {
		t.Fatalf("kill: %v %v", out, err)
	}
	if len(f.kills) != 1 || f.kills[0] != "experiments/opus-5-5-canary/kill:p95 up" || f.seen[len(f.seen)-1] != "admin-cookie" {
		t.Fatalf("server saw %v %v", f.kills, f.seen)
	}
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "p95 up", "dry_run": false})
	if err != nil || !strings.Contains(out["note"].(string), "idempotent") {
		t.Fatalf("second kill: %v %v", out, err)
	}
	// A rollout kills its backing experiment and points at the policy counterpart.
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-upgrade", "reason": "abort", "dry_run": false})
	if err != nil || out["kind"] != "experiment" || out["name"] != "opus-5-5-canary" {
		t.Fatalf("rollout kill: %v %v", out, err)
	}
	if j, _ := json.Marshal(out["next_steps"]); !strings.Contains(string(j), "propose_rollout_rollback opus-5-5-upgrade") {
		t.Fatalf("rollout kill next_steps: %s", j)
	}
	// Unkill clears it and never claims a policy follow-up.
	out, err = call(t, cs, "kill_switch", map[string]any{"name": "opus-5-5-canary", "reason": "fixed", "unkill": true, "dry_run": false})
	if err != nil || out["applied"] != true || f.kills[len(f.kills)-1] != "experiments/opus-5-5-canary/unkill:fixed" {
		t.Fatalf("unkill: %v %v %v", out, err, f.kills)
	}
}

func TestEvalRunDryRunAndGates(t *testing.T) {
	dir := copyExample(t)
	suite := filepath.Join(dir, "evals", "suite.yaml")
	if err := os.WriteFile(suite, []byte("name: smoke\ntasks: [x]\nmatrix: {harnesses: [{harness: codex, version: '1.0.0', models: [gpt]}]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ro := connect(t, Options{PolicyDir: dir})
	out, err := call(t, ro, "eval_run", map[string]any{"suite": "evals/suite.yaml", "matrix": true})
	if err != nil || out["dry_run"] != true || out["ran"] != false {
		t.Fatalf("eval_run dry: %v %v", out, err)
	}
	cmd, _ := out["command"].(string)
	if !strings.HasPrefix(cmd, "halo eval run ") || !strings.Contains(cmd, "--output json --scorecard ") || !strings.Contains(cmd, "--matrix") {
		t.Fatalf("command: %q", cmd)
	}
	if _, err := os.Stat(filepath.Join(dir, ".halos", "scorecards")); !os.IsNotExist(err) {
		t.Fatal("dry run created the scorecard dir")
	}
	if _, err := call(t, ro, "eval_run", map[string]any{"suite": "evals/suite.yaml", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("read-only real run accepted: %v", err)
	}
	for _, args := range []map[string]any{{"suite": "/etc/passwd"}, {"suite": "../outside.yaml"}, {"suite": "evals/missing.yaml"}, {}} {
		if _, err := call(t, ro, "eval_run", args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

type fakeOpener struct{ reqs []promote.PRRequest }

func (f *fakeOpener) OpenPR(_ context.Context, r promote.PRRequest) (string, error) {
	f.reqs = append(f.reqs, r)
	return "https://example.com/pr/1", nil
}

func TestRolloutOpenPR(t *testing.T) {
	dir := copyExample(t)
	f := &fakeOpener{}
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true, PROpener: f})
	// open_pr is ignored on a dry run.
	out, err := call(t, cs, "propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade", "reason": "r", "open_pr": true})
	if err != nil || out["dry_run"] != true || len(f.reqs) != 0 {
		t.Fatalf("dry run opened a PR: %v %v", out, err)
	}
	if j, _ := json.Marshal(out["next_steps"]); !strings.Contains(string(j), "human gate") || !strings.Contains(string(j), "kill_switch name=opus-5-5-upgrade") {
		t.Fatalf("next_steps: %s", j)
	}
	out, err = call(t, cs, "propose_rollout_rollback", map[string]any{"name": "opus-5-5-upgrade", "reason": "r", "open_pr": true, "dry_run": false, "base": "main"})
	if err != nil || out["applied"] != true || out["pr"] != "https://example.com/pr/1" || len(f.reqs) != 1 {
		t.Fatalf("open_pr: %v %v", out, err)
	}
	r := f.reqs[0]
	if r.Base != "main" || !strings.HasPrefix(r.Branch, "halos/") || r.Edit == nil || len(r.Files) == 0 || !strings.Contains(r.Body, "**Reason:** r") || r.CommitBody != "Reason: r" {
		t.Fatalf("PR request: %+v", r)
	}
	if j, _ := json.Marshal(out["next_steps"]); !strings.Contains(string(j), "merge") {
		t.Fatalf("next_steps: %s", j)
	}
}

// Every write tool's answer names the next step: the approval gate on a dry
// run, the push/PR command once applied.
func TestWriteToolsCarryNextSteps(t *testing.T) {
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	out, err := call(t, cs, "pause_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "r"})
	if err != nil || out["next_steps"].([]any)[0] != gateApprove {
		t.Fatalf("dry run next_steps: %v %v", out, err)
	}
	out, err = call(t, cs, "pause_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "r", "dry_run": false})
	if err != nil || !strings.Contains(out["next_steps"].([]any)[0].(string), "git -C "+dir+" push -u origin "+out["branch"].(string)) {
		t.Fatalf("applied next_steps: %v %v", out, err)
	}
	out, err = call(t, cs, "propose_promotion", map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "sha256:" + strings.Repeat("ab", 32), "reason": "r"})
	if err != nil || !strings.Contains(out["next_steps"].([]any)[0].(string), "--clickhouse") {
		t.Fatalf("promotion without evidence: %v %v", out, err)
	}
}
