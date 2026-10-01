package main

import (
	"context"
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
	cs, err = candidateSuite(s, upgrade.Candidate{Kind: upgrade.KindCLI, Harness: "codex", From: "0.60.0", To: "0.61.0"})
	if err != nil || cs.Variants[1].Harness != "codex" || cs.Variants[1].Model != "codex-default" || cs.Variants[1].Version != "0.61.0" {
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
