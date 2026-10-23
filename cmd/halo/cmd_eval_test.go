package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/shadow"
	"github.com/dshakes/halos/internal/upgrade"
)

func TestEvalRunFlags(t *testing.T) {
	if code, _, e := halo(t, "eval", "run", "../../evals/suites/cli-upgrade.yaml", "--matrix"); code != 1 || !strings.Contains(e, "no matrix defined") {
		t.Fatalf("code %d stderr %q", code, e)
	}
	dir := t.TempDir()
	m := filepath.Join(dir, "m.yaml")
	_ = os.WriteFile(m, []byte("name: m\ntasks: [x]\nmatrix: {harnesses: [{harness: codex, version: '1.0.0', models: [gpt]}]}\n"), 0o644)
	if code, _, e := halo(t, "eval", "run", m); code != 1 || !strings.Contains(e, "run it with --matrix") {
		t.Fatalf("code %d stderr %q", code, e)
	}
	a := &app{out: &strings.Builder{}}
	if err := a.writeScorecard(&eval.Scorecard{}, evalRunFlags{failOn: "sometimes"}); err == nil {
		t.Fatal("want --fail-on validation error")
	}
	sc := &eval.Scorecard{Suite: "s", Gate: &eval.Gate{Verdict: eval.GateHold}}
	err := a.writeScorecard(sc, evalRunFlags{failOn: eval.GateHold, report: filepath.Join(dir, "r.md"), scorecard: filepath.Join(dir, "s.json"), history: filepath.Join(dir, "h.jsonl")})
	if ee, ok := err.(*exitErr); !ok || ee.code != exitGate {
		t.Fatalf("want exit %d, got %v", exitGate, err)
	}
	for _, f := range []string{"r.md", "s.json", "h.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	if err := a.writeScorecard(sc, evalRunFlags{failOn: eval.GateBlock}); err != nil {
		t.Fatalf("hold must pass --fail-on block: %v", err)
	}
}

func TestCandidateSuite(t *testing.T) {
	s, err := eval.LoadSuite("../../evals/suites/upgrade-gate.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cs, err := candidateSuite(s, upgrade.Candidate{Kind: upgrade.KindCLI, Harness: "claude-code", From: "2.1.312", To: "2.1.330"})
	if err != nil || cs.Variants[0].Version != "2.1.312" || cs.Variants[1].Version != "2.1.330" || cs.Control != "current" || cs.Matrix != nil {
		t.Fatalf("%+v %v", cs, err)
	}
	// codex has no variant: falls back to its matrix harness.
	cs, err = candidateSuite(s, upgrade.Candidate{Kind: upgrade.KindCLI, Harness: "codex", From: "0.100.0", To: "0.101.0"})
	if err != nil || cs.Variants[1].Harness != "codex" || cs.Variants[1].Model != "codex-default" || cs.Variants[1].Version != "0.101.0" {
		t.Fatalf("%+v %v", cs, err)
	}
	cs, err = candidateSuite(s, upgrade.Candidate{Kind: upgrade.KindModel, Provider: "p", From: "gpt-5-codex", To: "gpt-5.1-codex"})
	if err != nil || cs.Variants[0].Model != "sonnet" || cs.Variants[1].Model != "gpt-5.1-codex" {
		t.Fatalf("%+v %v", cs, err)
	}
	if _, err := candidateSuite(s, upgrade.Candidate{Kind: upgrade.KindCLI, Harness: "copilot"}); err == nil {
		t.Fatal("copilot has no eval driver: want error")
	}
}

// halo upgrade check --dry-run end to end against a fake npm registry. The
// registry is plain http, so the release resolver (https only) refuses to
// verify artifacts: the candidate is listed as UNVERIFIED, with no network.
func TestUpgradeCheckDryRun(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/@openai/codex/latest" {
			_, _ = w.Write([]byte(`{"name":"@openai/codex","version":"0.101.0"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer npm.Close()
	dir := copyDir(t, example)
	cfg := filepath.Join(dir, ".halos", "codex-only.yaml")
	_ = os.WriteFile(cfg, []byte("profile: engineering-next\nsuite: x.yaml\nharnesses: [codex]\n"), 0o644)
	code, out, e := halo(t, "upgrade", "check", "--dry-run", "--policy-dir", dir, "--config", cfg, "--npm-registry", npm.URL)
	if code != 0 || !strings.Contains(out, "codex") || !strings.Contains(out, "0.101.0") || !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("code %d\nstdout:\n%s\nstderr:\n%s", code, out, e)
	}
	t.Logf("halo upgrade check --dry-run:\n%s", out)
	if _, err := os.Stat(filepath.Join(dir, ".halos", "upgrade-state.json")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote state")
	}
}

// halo eval online end to end: plaintext pair store, a fake gateway judge on
// the Anthropic Messages wire, a fake OTLP collector, and the history file.
func TestEvalOnline(t *testing.T) {
	dir := t.TempDir()
	store, err := shadow.NewFileStore(filepath.Join(dir, "pairs.jsonl"), shadow.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for i, txt := range [][2]string{{"meh", "great"}, {"meh", "great"}, {"great", "great"}} {
		p := shadow.Pair{ID: string(rune('a' + i)), Experiment: "sonnet-next-shadow", Request: json.RawMessage(`{}`),
			Control:   shadow.Side{Target: shadow.Target{Variant: "control"}, Status: 200, Response: json.RawMessage(`"` + txt[0] + `"`)},
			Candidate: shadow.Side{Target: shadow.Target{Variant: "sonnet-next"}, Status: 200, Response: json.RawMessage(`"` + txt[1] + `"`)}}
		if err := store.Append(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.Close()
	judge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		score := "0.4"
		if strings.Contains(string(b), "great") {
			score = "0.9"
		}
		reply := `{"scores": {"correctness": ` + score + `, "minimality": ` + score + `, "idiom": ` + score + `}, "rationale": "r"}`
		out, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": reply}}})
		_, _ = w.Write(out)
	}))
	defer judge.Close()
	var exported atomic.Int32
	otlp := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { exported.Add(1) }))
	defer otlp.Close()
	hist := filepath.Join(dir, "history.jsonl")
	args := []string{"eval", "online", "--pairs", filepath.Join(dir, "pairs.jsonl"), "--rubric", "../../evals/rubrics/code-change-quality.yaml",
		"--judge-url", judge.URL, "--judge-model", "claude-sonnet-5-5", "--history", hist, "--otlp", otlp.URL}
	code, out, e := halo(t, args...)
	if code != 0 || !strings.Contains(out, "sonnet-next-shadow") || !strings.Contains(out, "code-change-quality@1") || exported.Load() != 1 {
		t.Fatalf("code %d exported %d\nstdout:\n%s\nstderr:\n%s", code, exported.Load(), out, e)
	}
	t.Logf("halo eval online:\n%s", out)
	if code, out, _ = halo(t, args...); code != 0 || !strings.Contains(out, "no new pairs") {
		t.Fatalf("history must skip graded pairs: %d %s", code, out)
	}
}

// halo eval harvest -> halo eval steps run end to end: an encrypted pair store
// holding a Claude Code session with planted secrets, and a fake model route.
func TestEvalHarvestAndSteps(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	keyFile := filepath.Join(dir, "pair.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := shadow.NewFileStore(filepath.Join(dir, "pairs.jsonl"), shadow.StoreOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	const tools = `"tools":[{"name":"Bash","input_schema":{"type":"object","required":["command"]}},{"name":"Edit","input_schema":{"type":"object","required":["file_path"]}}]`
	const user = `{"role":"user","content":"fix the tests; the deploy key is AKIAIOSFODNN7EXAMPLE, mail ops@acme-corp.com"}`
	const call = `[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"go test ./..."}}]`
	bash, stop := `{"content":`+call+`}`, `{"content":[{"type":"text","text":"Done."}]}`
	steps := []string{
		`{"model":"sonnet","metadata":{"user_id":"session_raw-session-1"},` + tools + `,"messages":[` + user + `]}`,
		`{"model":"sonnet","metadata":{"user_id":"session_raw-session-1"},` + tools + `,"messages":[` + user + `,{"role":"assistant","content":` + call +
			`},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"FAIL"}]}]}`,
	}
	for i, req := range steps {
		p := shadow.Pair{ID: "p" + string(rune('0'+i)), Experiment: "opus-shadow", SessionID: "raw-session-1", Protocol: "anthropic-messages", Request: json.RawMessage(req),
			Control: shadow.Side{Status: 200, Response: json.RawMessage(bash)}, Candidate: shadow.Side{Status: 200, Response: json.RawMessage(stop)}}
		if err := store.Append(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	_ = store.Close()
	suite := filepath.Join(dir, "steps")
	args := []string{"eval", "harvest", "--pairs", filepath.Join(dir, "pairs.jsonl"), "--pair-key-file", keyFile, "--out", suite}
	code, out, e := halo(t, append(args, "--dry-run")...)
	if code != 0 || !strings.Contains(out, "2 selected") {
		t.Fatalf("dry run: code %d\n%s\n%s", code, out, e)
	}
	if _, err := os.Stat(suite); !os.IsNotExist(err) {
		t.Fatal("dry run wrote cases")
	}
	if code, out, e = halo(t, args...); code != 0 || !strings.Contains(out, "wrote 2 cases") {
		t.Fatalf("harvest: code %d\n%s\n%s", code, out, e)
	}
	t.Logf("halo eval harvest:\n%s", out)
	files, _ := filepath.Glob(filepath.Join(suite, "*.json"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "ops@acme-corp.com", "raw-session-1"} {
			if strings.Contains(string(b), leak) {
				t.Fatalf("%s leaks %s", f, leak)
			}
		}
	}
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "route-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(bash))
	}))
	defer model.Close()
	t.Setenv("ROUTE_KEY", "route-key")
	sc := filepath.Join(dir, "scorecard.json")
	// Step 0 expects production's Bash (recovered from step 1); step 1 has no
	// later step, so the control's Bash is expected.
	code, out, e = halo(t, "eval", "steps", "run", "--suite", suite, "--model", "opus-next", "--url", model.URL, "--key-env", "ROUTE_KEY", "--scorecard", sc)
	if code != 0 || !strings.Contains(out, "PASS              100%") {
		t.Fatalf("steps run: code %d\n%s\n%s", code, out, e)
	}
	t.Logf("halo eval steps run:\n%s", out)
	var card eval.StepScorecard
	if b, err := os.ReadFile(sc); err != nil || json.Unmarshal(b, &card) != nil || card.Cases != 2 || card.Sessions != 1 {
		t.Fatalf("scorecard %v %+v", err, card)
	}
	if code, _, e = halo(t, "eval", "harvest", "--pairs", filepath.Join(dir, "pairs.jsonl"), "--pair-key-file", keyFile); code == 0 || !strings.Contains(e, "--out") {
		t.Fatalf("missing --out: %d %s", code, e)
	}
	if code, _, e = halo(t, "eval", "harvest", "--pairs", filepath.Join(dir, "pairs.jsonl"), "--out", suite); code == 0 {
		t.Fatalf("encrypted store read without a key: %s", e)
	}
}
