package eval

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/shadow"
)

// Planted secrets: none may reach a case file.
const (
	plantedAWS   = "AKIAIOSFODNN7EXAMPLE"
	plantedJWT   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSFMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	plantedEmail = "jane.doe@acme-corp.com"
)

// ccSecretRequest is the Claude Code session of agentic_test.go with secrets
// in the developer's prompt and the raw session id in metadata.user_id, as
// Claude Code sends it.
func ccSecretRequest(n int) json.RawMessage {
	s := strings.Replace(string(ccRequest(n)), "make the tests pass",
		"make the tests pass; deploy key "+plantedAWS+", session token "+plantedJWT+", ask "+plantedEmail, 1)
	return json.RawMessage(strings.Replace(s, `{"model":"sonnet"`, `{"model":"sonnet","metadata":{"user_id":"user_1_account_2_session_raw-cc-session"}`, 1))
}

// Codex (OpenAI Responses): step 0 and step 1, whose history holds
// production's shell call. prompt_cache_key is Codex's conversation id.
const (
	cxTools = `[{"type":"function","name":"shell","parameters":{"required":["command"]}},{"type":"custom","name":"apply_patch"}]`
	cxStep0 = `{"model":"gpt-5-codex","prompt_cache_key":"raw-codex-session","tools":` + cxTools + `,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"why is the build red?"}]}]}`
	cxStep1 = `{"model":"gpt-5-codex","prompt_cache_key":"raw-codex-session","tools":` + cxTools + `,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"why is the build red?"}]},` +
		`{"type":"function_call","name":"shell","call_id":"c1","arguments":"{\"command\":[\"ls\"]}"},{"type":"function_call_output","call_id":"c1","output":"main.go"}]}`
	cxShellLs = `{"output":[{"type":"function_call","name":"shell","call_id":"x","arguments":"{\"command\": [\"ls\"]}"}]}`
	cxPatch   = `{"output":[{"type":"custom_tool_call","name":"apply_patch","call_id":"y","input":"*** Begin Patch"}]}`
)

// Gemini CLI: one step after a failing npm test.
const (
	gmStep1 = `{"tools":[{"functionDeclarations":[{"name":"run_shell_command","parameters":{"required":["command"]}}]}],` +
		`"contents":[{"role":"user","parts":[{"text":"fix the failing test, then mail ` + plantedEmail + `"}]},{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"npm test"}}}]},` +
		`{"role":"user","parts":[{"functionResponse":{"name":"run_shell_command","response":{"output":"1 failing: add()"}}}]}]}`
	gmRetest = `{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"run_shell_command","args":{"command":"npm test -- -g add"}}}]}}]}`
	gmBogus  = `{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"run_command","args":{"cmd":"npm test"}}}]}}]}`
)

const invalidCall = `{"type":"tool_use","id":"z","name":"RunTests","input":{}}`

// harvestPairs: three real-shaped sessions, one per harness.
func harvestPairs() fakePairs {
	cc := func(id string, n int, cand string) shadow.Pair {
		ctl := []string{bashTest, editFix, bashTest}[n]
		return shadow.Pair{ID: id, Experiment: "opus-shadow", SessionID: "raw-cc-session", Protocol: gateway.ProtoAnthropic,
			Request: ccSecretRequest(n), Control: okSide(ccResp(ctl)), Candidate: okSide(ccResp(cand))}
	}
	raw := func(id, session, proto, req, ctl, cand string) shadow.Pair {
		return shadow.Pair{ID: id, Experiment: "opus-shadow", SessionID: session, Protocol: proto, Request: json.RawMessage(req),
			Control: okSide(json.RawMessage(ctl)), Candidate: okSide(json.RawMessage(cand))}
	}
	return fakePairs{
		cc("cc0", 0, bashTest),    // agrees: not selected by default
		cc("cc1", 1, done),        // stops where production edited: diverged, premature-stop
		cc("cc2", 2, invalidCall), // a tool it was not offered: diverged, invalid-call
		raw("cx0", "raw-codex-session", gateway.ProtoResponses, cxStep0, cxShellLs, cxPatch), // diverged from production's shell call
		raw("cx1", "raw-codex-session", gateway.ProtoResponses, cxStep1, cxShellLs, cxShellLs),
		raw("gm1", "raw-gemini-session", gateway.ProtoGemini, gmStep1, gmRetest, gmBogus),  // diverged, invalid-call
		raw("other", "raw-x", gateway.ProtoAnthropic, string(ccRequest(1)), editFix, done), // another experiment: filtered out
	}
}

func harvestOpts(t *testing.T) HarvestOptions {
	t.Helper()
	r, err := NewRedactor(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return HarvestOptions{Experiment: "opus-shadow", Redactor: r, Now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }}
}

func TestRedactorText(t *testing.T) {
	r, err := NewRedactor([]string{`ACME-\d{6}`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, in, gone, want string
	}{
		{"aws key id", "export key " + plantedAWS + " now", plantedAWS, "[REDACTED:credential]"},
		{"jwt", "Cookie: session=" + plantedJWT, "eyJhbGci", "[REDACTED:jwt]"},
		{"email", "Author: Jane <" + plantedEmail + ">", plantedEmail, "[REDACTED:email]"},
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1\n-----END RSA PRIVATE KEY-----\nrest", "MIIEpAIBAAKCAQEA1", "[REDACTED:private-key]\nrest"},
		{"bearer", `curl -H "Authorization: Bearer abcdefghijklmnop1234"`, "abcdefghijklmnop1234", "Bearer [REDACTED:credential]"},
		{"vendor token", "ANTHROPIC_KEY sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "sk-ant-api03", "[REDACTED:credential]"},
		{"env assignment", "DB_PASSWORD=hunter2hunter2", "hunter2", "DB_PASSWORD=[REDACTED:credential]"},
		{"aws secret (entropy)", "aws_secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI", "[REDACTED:secret]"},
		{"custom", "ticket ACME-123456 closed", "ACME-123456", "[REDACTED:custom]"},
		{"plain output kept", "--- FAIL: TestAdd (0.00s)\n    add_test.go:9: got 3, want 4", "", "--- FAIL: TestAdd (0.00s)\n    add_test.go:9: got 3, want 4"},
	}
	for _, tc := range tests {
		got := r.Text(tc.in, true)
		if (tc.gone != "" && strings.Contains(got, tc.gone)) || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q -> %q", tc.name, tc.in, got)
		}
	}
	// Opaque provider fields keep high-entropy values (a thinking signature
	// must replay byte for byte) but never credential shapes.
	sig := "EqQBCkgIBRABGAIiQL2xY7NmWq9V3sRz8T4uKp0aJcDfGhIjKlMnOpQrStUvWxYz"
	if got := r.Text(sig, false); got != sig {
		t.Errorf("opaque field changed: %q", got)
	}
	if got := r.Text(plantedAWS, false); strings.Contains(got, plantedAWS) {
		t.Error("credential shape kept in an opaque field")
	}
}

func TestRedactorRequestAndVersion(t *testing.T) {
	r, err := NewRedactor(nil, []string{"service_tier"})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"model":"sonnet","metadata":{"user_id":"user_1_session_raw"},"service_tier":"auto","max_tokens":8192,"temperature":0.0,
	  "messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_01A09q90qw90lq917835lq9X","name":"Bash","input":{"command":"ls","api_key":"live-value-123"}}]}]}`
	out, err := r.Request([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, gone := range []string{"metadata", "user_1_session_raw", "live-value-123"} {
		if strings.Contains(s, gone) {
			t.Errorf("%q survived: %s", gone, s)
		}
	}
	for _, kept := range []string{`"toolu_01A09q90qw90lq917835lq9X"`, `"service_tier":"auto"`, `"temperature":0.0`, `"max_tokens":8192`, `"api_key":"[REDACTED:credential]"`} {
		if !strings.Contains(s, kept) {
			t.Errorf("%s missing: %s", kept, s)
		}
	}
	if _, err := r.Request([]byte(`not json`)); err == nil {
		t.Error("non-JSON request must fail closed")
	}
	if _, err := NewRedactor([]string{"("}, nil); err == nil {
		t.Error("bad regex accepted")
	}
	if _, err := NewRedactor([]string{""}, nil); err == nil {
		t.Error("empty pattern accepted")
	}
	plain, _ := NewRedactor(nil, nil)
	if plain.Version() != RedactionRulesVersion || r.Version() == RedactionRulesVersion {
		t.Errorf("versions %q %q: operator rules must change the recorded version", plain.Version(), r.Version())
	}
}

func TestHarvestSelection(t *testing.T) {
	ctx := context.Background()
	res, err := Harvest(ctx, harvestPairs(), harvestOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Steps != 6 || len(res.Cases) != 4 || res.Skipped != 0 {
		t.Fatalf("steps %d cases %d skipped %d, want 6 4 0", res.Steps, len(res.Cases), res.Skipped)
	}
	byPair := map[string]StepCase{}
	for _, c := range res.Cases {
		byPair[c.Provenance.PairID] = c
	}
	want := map[string]struct {
		reasons, from, tool string
		depth               int
	}{
		"cc1": {"diverged,premature-stop", FromProduction, "Edit", 1},
		"cc2": {"diverged,invalid-call", FromControl, "Bash", 2},
		"cx0": {"diverged", FromProduction, "shell", 0},
		"gm1": {"diverged,invalid-call", FromControl, "run_shell_command", 1},
	}
	for id, w := range want {
		c, ok := byPair[id]
		if !ok {
			t.Fatalf("pair %s not harvested", id)
		}
		if strings.Join(c.Reasons, ",") != w.reasons || c.ExpectedFrom != w.from || c.Provenance.Depth != w.depth ||
			len(c.Expected.Calls) != 1 || c.Expected.Calls[0].Name != w.tool {
			t.Errorf("%s: %+v", id, c)
		}
	}
	// cc1: the control replay agreed with production, so no alternative.
	if len(byPair["cc1"].Alternatives) != 0 || byPair["cc1"].Provenance.Session != SessionUnit("raw-cc-session") {
		t.Errorf("cc1 provenance/alternatives %+v", byPair["cc1"])
	}
	if p := byPair["cc1"].Provenance; p.RedactionRules != RedactionRulesVersion || !p.HarvestedAt.Equal(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("provenance %+v", p)
	}
	if res.ByReason[SelectDiverged] != 4 || res.ByReason[SelectInvalidCall] != 2 || res.ByReason[SelectPrematureStop] != 1 {
		t.Errorf("by reason %v", res.ByReason)
	}

	// Judge loss picks the agreeing step 0 the judge scored lower.
	o := harvestOpts(t)
	o.Select, o.Scores = []string{SelectJudgeLoss}, map[string]PairScore{"cc0": {ID: "cc0", Control: 0.9, Candidate: 0.4}, "cx1": {ID: "cx1", Control: 0.6, Candidate: 0.5}}
	if res, err = Harvest(ctx, harvestPairs(), o); err != nil || len(res.Cases) != 1 || res.Cases[0].Provenance.PairID != "cc0" {
		t.Fatalf("judge loss: %v %+v", err, res)
	}
	// Stratified sample: one step per non-empty depth bucket (0 and 1-4).
	o = harvestOpts(t)
	o.Select, o.PerDepth, o.Seed = []string{SelectSample}, 1, 7
	res, err = Harvest(ctx, harvestPairs(), o)
	if err != nil || len(res.Cases) != 2 || res.Cases[0].Provenance.Depth == res.Cases[1].Provenance.Depth && res.Cases[0].Provenance.Depth == 0 {
		t.Fatalf("sample: %v %+v", err, res)
	}
	again, _ := Harvest(ctx, harvestPairs(), o)
	if again.Cases[0].ID != res.Cases[0].ID || again.Cases[1].ID != res.Cases[1].ID {
		t.Fatal("seeded sample not reproducible")
	}
}

// A malformed candidate call is an invalid call; auxiliary (no tools),
// truncated and retried requests are not steps at all.
func TestHarvestNonSteps(t *testing.T) {
	malformed := `{"candidates":[{"content":{"role":"model","parts":[]},"finishReason":"MALFORMED_FUNCTION_CALL"}]}`
	pair := func(id, session, proto, req, ctl, cand string) shadow.Pair {
		return shadow.Pair{ID: id, Experiment: "opus-shadow", SessionID: session, Protocol: proto, Request: json.RawMessage(req),
			Control: okSide(json.RawMessage(ctl)), Candidate: okSide(json.RawMessage(cand))}
	}
	truncated := `{"content":[{"type":"text","text":"Let me"}],"stop_reason":"max_tokens"}`
	src := fakePairs{
		pair("gm", "g", gateway.ProtoGemini, gmStep1, gmRetest, malformed),
		pair("gm-retry", "g", gateway.ProtoGemini, gmStep1, gmRetest, malformed),
		pair("aux", "c", gateway.ProtoAnthropic, `{"model":"haiku","messages":[{"role":"user","content":"summarise"}]}`, string(ccResp(done)), string(ccResp(bashTest))),
		pair("cut", "c", gateway.ProtoAnthropic, string(ccRequest(1)), string(ccResp(editFix)), truncated),
	}
	res, err := Harvest(context.Background(), src, harvestOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Steps != 1 || len(res.Cases) != 1 || strings.Join(res.Cases[0].Reasons, ",") != "diverged,invalid-call" {
		t.Fatalf("steps %d cases %+v", res.Steps, res.Cases)
	}
}

func TestHarvestOptionErrors(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		mod  func(*HarvestOptions)
		want string
	}{
		{"no redactor", func(o *HarvestOptions) { o.Redactor = nil }, "redaction is mandatory"},
		{"unknown selection", func(o *HarvestOptions) { o.Select = []string{"vibes"} }, "unknown selection"},
		{"judge loss without history", func(o *HarvestOptions) { o.Select = []string{SelectJudgeLoss} }, "needs judge scores"},
		{"judge loss out of range", func(o *HarvestOptions) { o.JudgeLoss = 2 }, "judge loss"},
		{"negative sample", func(o *HarvestOptions) { o.PerDepth = -1 }, "per-depth"},
	}
	for _, tc := range tests {
		o := harvestOpts(t)
		tc.mod(&o)
		if _, err := Harvest(ctx, harvestPairs(), o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// A redaction that breaks the step fails the whole harvest; a case carrying
// a credential is never written, and nothing else is either.
func TestHarvestFailsClosed(t *testing.T) {
	o := harvestOpts(t)
	r, err := NewRedactor([]string{`assistant`}, nil) // rewrites the role: no longer the same step
	if err != nil {
		t.Fatal(err)
	}
	o.Redactor = r
	if _, err := Harvest(context.Background(), harvestPairs(), o); err == nil || !strings.Contains(err.Error(), "same step") {
		t.Fatalf("want fail-closed error, got %v", err)
	}
	res, err := Harvest(context.Background(), harvestPairs(), harvestOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := res.Cases[0]
	bad.ID = "step-leak"
	bad.Expected = Action{Calls: []Call{{Name: "Bash", Input: `{"command":"echo ` + plantedAWS + `"}`}}}
	dir := filepath.Join(t.TempDir(), "steps")
	if err := WriteStepCases(dir, []StepCase{res.Cases[1], bad}); err == nil {
		t.Fatal("credential written")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("a failed write left files behind")
	}
}

func TestGradeStep(t *testing.T) {
	edit := mustAction(t, editFix)
	bash := mustAction(t, bashTest)
	otherEdit := mustAction(t, `{"type":"tool_use","name":"Edit","input":{"file_path":"add.go","old_string":"-1","new_string":""}}`)
	c := StepCase{ID: "c", Tools: map[string][]string{"Bash": {"command"}, "Edit": {"file_path", "old_string", "new_string"}},
		Expected: edit, Alternatives: []Action{bash}, Match: MatchTools}
	calls := c
	calls.Match = MatchCalls
	tests := []struct {
		name               string
		c                  StepCase
		a                  Action
		pass, valid, early bool
	}{
		{"expected action", c, edit, true, true, false},
		{"allowed alternative", c, bash, true, true, false},
		{"same tool, other args, tools mode", c, otherEdit, true, true, false},
		{"same tool, other args, calls mode", calls, otherEdit, false, true, false},
		{"premature stop", c, Action{}, false, true, true},
		{"tool not offered", c, mustAction(t, invalidCall), false, false, false},
		{"missing required argument", c, mustAction(t, `{"type":"tool_use","name":"Edit","input":{"file_path":"a.go"}}`), false, false, false},
	}
	for _, tc := range tests {
		r := GradeStep(tc.c, tc.a)
		if r.Pass != tc.pass || r.Valid != tc.valid || r.PrematureStop != tc.early {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}

// fakeModel answers each harness the way a model would at that step, and
// records what it was sent.
type fakeModel struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
}

func (f *fakeModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies, f.paths = append(f.bodies, string(b)), append(f.paths, r.URL.Path)
	f.mu.Unlock()
	switch {
	case r.URL.Path == gateway.PathMessages:
		if r.Header.Get("x-api-key") != "k" || r.Header.Get("anthropic-version") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct{ Messages []json.RawMessage }
		_ = json.Unmarshal(b, &req)
		if len(req.Messages) == 3 { // step 1: give up after the failing test
			_, _ = w.Write(ccResp(done))
			return
		}
		_, _ = w.Write(ccResp(bashTest))
	case r.URL.Path == gateway.PathResponses:
		_, _ = w.Write([]byte(cxShellLs))
	case strings.HasSuffix(r.URL.Path, ":generateContent"):
		_, _ = w.Write([]byte(gmRetest))
	default:
		http.NotFound(w, r)
	}
}

// Harvest -> write -> load -> run -> scorecard, against an httptest model on
// all three wires.
func TestHarvestRunRoundTrip(t *testing.T) {
	ctx := context.Background()
	res, err := Harvest(ctx, harvestPairs(), harvestOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "steps")
	if err := WriteStepCases(dir, res.Cases); err != nil {
		t.Fatal(err)
	}
	posix := runtime.GOOS != "windows" // Windows has no POSIX mode bits to assert
	if st, err := os.Stat(dir); err != nil || (posix && st.Mode().Perm() != 0o700) {
		t.Fatalf("suite dir mode %v %v", st.Mode(), err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 4 {
		t.Fatalf("%d case files", len(files))
	}
	for _, f := range files {
		st, _ := os.Stat(f)
		if posix && st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", f, st.Mode().Perm())
		}
		b, _ := os.ReadFile(f)
		for _, leak := range []string{plantedAWS, "eyJhbGci", plantedEmail, "raw-cc-session", "raw-codex-session", "raw-gemini-session", "metadata", "prompt_cache_key"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s leaks %q", filepath.Base(f), leak)
			}
		}
	}
	cc, _ := os.ReadFile(filepath.Join(dir, res.Cases[0].ID+".json"))
	for _, marker := range []string{"[REDACTED:credential]", "[REDACTED:jwt]", "[REDACTED:email]"} {
		if !strings.Contains(string(cc), marker) {
			t.Errorf("Claude Code case lacks %s", marker)
		}
	}
	cases, err := LoadStepCases(dir)
	if err != nil || len(cases) != 4 {
		t.Fatalf("load: %v %d", err, len(cases))
	}

	fm := &fakeModel{}
	srv := httptest.NewServer(fm)
	defer srv.Close()
	sc, err := RunSteps(ctx, "steps", cases, &StepModel{URL: srv.URL, Model: "opus-next", APIKey: "k"}, StepRunOptions{Parallel: 2, Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	// cc1 stops where production edited; the other three reproduce the action.
	if sc.Cases != 4 || sc.Sessions != 3 || sc.Errors != 0 || sc.Pass.Mean != 0.75 || sc.Pass.N != 4 || sc.PrematureStop.Mean != 0.25 || sc.Valid.Mean != 1 {
		t.Fatalf("scorecard %+v", sc)
	}
	for _, x := range []Rate{sc.Pass, sc.SameTools, sc.SameCalls, sc.Valid} {
		if x.CILo > x.Mean || x.CIHi < x.Mean || math.IsNaN(x.CILo) {
			t.Fatalf("CI does not cover the mean: %+v", x)
		}
	}
	if !strings.Contains(sc.Table(), "PREMATURE STOP") || !strings.Contains(sc.Table(), "FAILED") {
		t.Fatalf("table:\n%s", sc.Table())
	}
	for i, b := range fm.bodies {
		if strings.Contains(b, plantedAWS) || strings.Contains(b, plantedEmail) {
			t.Errorf("model was sent an unredacted prefix: %s", b)
		}
		if p := fm.paths[i]; p != gateway.PathMessages && p != gateway.PathResponses && p != "/v1beta/models/opus-next:generateContent" {
			t.Errorf("path %s", p)
		}
		if !strings.HasSuffix(fm.paths[i], ":generateContent") && (!strings.Contains(b, `"model":"opus-next"`) || !strings.Contains(b, `"stream":false`)) {
			t.Errorf("not rewritten to the route's model, non-streaming: %s", b)
		}
	}

	// Errors fail the case and are counted; the rubric judge is secondary.
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "overloaded", 529) }))
	defer down.Close()
	sc, err = RunSteps(ctx, "steps", cases, &StepModel{URL: down.URL, Model: "m"}, StepRunOptions{})
	if err != nil || sc.Errors != 4 || sc.Pass.Mean != 0 || sc.SameTools.N != 0 {
		t.Fatalf("errored run: %v %+v", err, sc)
	}
	j := &Judge{LLM: &fakeLLM{reply: fixed(`{"scores": {"correctness": 1, "minimality": 0.5}, "rationale": "r"}`)}, Model: "judge-1"}
	sc, err = RunSteps(ctx, "steps", cases, &StepModel{URL: srv.URL, Model: "opus-next", APIKey: "k"}, StepRunOptions{Judge: j, Rubric: testRubric(t)})
	if err != nil || sc.Judge == nil || sc.Judge.N != 4 || math.Abs(sc.Judge.Mean-2.5/3) > 1e-9 || sc.Pass.Mean != 0.75 {
		t.Fatalf("judged run: %v %+v", err, sc)
	}
	if _, err := RunSteps(ctx, "steps", cases, &StepModel{URL: "http://example.com", Model: "m"}, StepRunOptions{}); err == nil {
		t.Fatal("plain http to a non-loopback host accepted")
	}
	if _, err := RunSteps(ctx, "steps", cases, &StepModel{URL: srv.URL}, StepRunOptions{}); err == nil {
		t.Fatal("missing model accepted")
	}
}

func TestLoadStepCasesErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadStepCases(dir); err == nil {
		t.Fatal("empty suite accepted")
	}
	for name, body := range map[string]string{
		"unknown-field.json": `{"id":"a","bogus":1}`,
		"bad-match.json":     `{"id":"a","protocol":"anthropic-messages","request":{"messages":[]},"match":"vibes","provenance":{"session":"s:1"}}`,
	} {
		d := t.TempDir()
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadStepCases(d); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// History keeps per-pair judge scores so harvest can read them back.
func TestHistoryScores(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.jsonl")
	if s, err := HistoryScores(p); err != nil || len(s) != 0 {
		t.Fatalf("missing file: %v %v", s, err)
	}
	r := OnlineResult{Experiment: "e", PairIDs: []string{"a"}, Scores: []PairScore{{ID: "a", Control: 0.9, Candidate: 0.3}}}
	if err := AppendHistory(p, HistoryEntry{Kind: "online", Online: &r}); err != nil {
		t.Fatal(err)
	}
	s, err := HistoryScores(p)
	if err != nil || s["a"].Control != 0.9 || s["a"].Candidate != 0.3 {
		t.Fatalf("%v %v", s, err)
	}
	if g, err := GradedPairs(p); err != nil || !g["a"] {
		t.Fatalf("graded %v %v", g, err)
	}
}
