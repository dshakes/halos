package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitCopy(t *testing.T) string {
	t.Helper()
	dir := copyDir(t, example)
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@t"}, {"add", "."}, {"commit", "-qm", "base"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

func TestCopilotDraftOfflineApply(t *testing.T) {
	dir := gitCopy(t)
	code, out, errs := halo(t, "copilot", "draft", "--offline", "--policy-dir", dir, "set claude-code version 2.1.300 in profile engineering")
	if code != 0 || !strings.Contains(out, "+    version: 2.1.300") || !strings.Contains(out, "nothing written") {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if b, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(b) != 0 {
		t.Fatalf("dry draft changed the tree: %s", b)
	}
	code, out, errs = halo(t, "copilot", "draft", "--offline", "--apply", "--output", "json", "--policy-dir", dir, "set claude-code version 2.1.300 in profile engineering")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	var res struct {
		Branch string `json:"branch"`
		Draft  struct {
			OK bool `json:"ok"`
		} `json:"draft"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || !res.Draft.OK || !strings.HasPrefix(res.Branch, "halos/copilot-") {
		t.Fatalf("%v %s", err, out)
	}
	if head, _ := exec.Command("git", "-C", dir, "rev-parse", "--abbrev-ref", "HEAD").Output(); strings.TrimSpace(string(head)) == res.Branch {
		t.Fatal("apply switched the user's branch")
	}

	// an offline intent it does not understand is an error, not a guess
	if code, _, errs := halo(t, "copilot", "draft", "--offline", "--policy-dir", dir, "make it faster"); code != 1 || !strings.Contains(errs, "--offline understands only") {
		t.Fatalf("exit %d %s", code, errs)
	}
}

// TestCopilotDraftModelRefusesInvalid: a model that keeps proposing an
// invalid policy is stopped by --max-iterations; nothing is applied, exit 2.
func TestCopilotDraftModelRefusesInvalid(t *testing.T) {
	dir := gitCopy(t)
	eng, err := os.ReadFile(filepath.Join(dir, "profiles", "engineering.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	bad, _ := json.Marshal(map[string]any{"summary": "x", "risks": []string{}, "files": []map[string]string{
		{"path": "profiles/engineering.yaml", "content": strings.Replace(string(eng), "extends: base", "extends: nope", 1)}}})
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("x-api-key") != "sk-cli-secret" {
			http.Error(w, "no key", 401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"content": []map[string]any{{"type": "text", "text": string(bad)}},
			"usage": map[string]int{"input_tokens": 1000, "output_tokens": 200}})
	}))
	defer srv.Close()
	t.Setenv("COPILOT_CLI_KEY", "sk-cli-secret")
	code, out, errs := halo(t, "copilot", "draft", "--policy-dir", dir, "--llm-url", srv.URL, "--api-key-env", "COPILOT_CLI_KEY",
		"--max-iterations", "2", "--apply", "bump the CLI")
	if code != 2 || calls != 2 || !strings.Contains(out, "nope") || !strings.Contains(errs, "nothing was written") {
		t.Fatalf("exit %d calls %d\n%s%s", code, calls, out, errs)
	}
	if strings.Count(errs, "copilot: llm call") != 2 || strings.Contains(out+errs, "sk-cli-secret") {
		t.Fatalf("token log lines / key leak:\n%s", errs)
	}
	if b, _ := exec.Command("git", "-C", dir, "branch", "--list", "halos/*").Output(); len(strings.TrimSpace(string(b))) != 0 {
		t.Fatalf("invalid draft applied: %s", b)
	}

	t.Setenv("COPILOT_CLI_KEY", "")
	if code, _, errs := halo(t, "copilot", "draft", "--policy-dir", dir, "--api-key-env", "COPILOT_CLI_KEY", "x"); code != 1 || !strings.Contains(errs, "$COPILOT_CLI_KEY is not set") {
		t.Fatalf("missing key: exit %d %s", code, errs)
	}
	if code, _, errs := halo(t, "copilot", "draft", "--policy-dir", dir, "--llm-url", "http://example.com", "--api-key-env", "", "x"); code != 1 || !strings.Contains(errs, "plain http") {
		t.Fatalf("plain http: exit %d %s", code, errs)
	}
}

func TestCopilotExperimentExplainNext(t *testing.T) {
	code, out, errs := halo(t, "copilot", "experiment", "--offline", "--output", "json", "--policy-dir", example, "cli-next raises accept rate",
		"--name", "cli-next-accept", "--ring", "ring1-canary", "--control", "engineering", "--treatment", "engineering-next",
		"--metric", "halo.edit.accept_rate", "--baseline", "0.3", "--mde", "0.1", "--daily-units", "500")
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	var ex struct {
		Experiment struct {
			OK    bool `json:"ok"`
			Stats struct {
				PerArm int `json:"perArm"`
				Days   int `json:"days"`
			} `json:"stats"`
		} `json:"experiment"`
	}
	if err := json.Unmarshal([]byte(out), &ex); err != nil || !ex.Experiment.OK || ex.Experiment.Stats.PerArm != 3663 || ex.Experiment.Stats.Days != 15 {
		t.Fatalf("%v %s", err, out)
	}
	if code, _, errs := halo(t, "copilot", "experiment", "--offline", "--policy-dir", example, "h"); code != 1 || !strings.Contains(errs, "--offline needs") {
		t.Fatalf("exit %d %s", code, errs)
	}

	code, out, errs = halo(t, "copilot", "explain", "experiment", "opus-5-5-canary", "--offline", "--policy-dir", example)
	if code != 0 || !strings.Contains(out, "experiment.metrics.primary.metric") || !strings.Contains(out, "facts used:") {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
	if code, _, errs := halo(t, "copilot", "explain", "nonsense", "x", "--offline", "--policy-dir", example); code != 1 || !strings.Contains(errs, "want release, diff or experiment") {
		t.Fatalf("exit %d %s", code, errs)
	}

	verdicts := filepath.Join(t.TempDir(), "verdicts.json")
	if err := os.WriteFile(verdicts, []byte(`[{"experiment":"opus-5-5-canary","verdict":"rollback","reason":"api errors up","evaluatedAt":"2026-10-27T00:00:00Z"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	code, out, errs = halo(t, "copilot", "next", "--policy-dir", example, "--verdicts-file", verdicts)
	if code != 0 || !strings.Contains(out, "$ halo exp pause opus-5-5-canary") || !strings.Contains(out, "api errors up") || !strings.Contains(out, "[human gate]") {
		t.Fatalf("exit %d\n%s%s", code, out, errs)
	}
}
