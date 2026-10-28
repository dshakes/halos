package copilot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/eval"
)

const example = "../../examples/acme-corp"

// gitPolicy copies the example policy into a temp git repo.
func gitPolicy(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "policy")
	if err := os.CopyFS(dir, os.DirFS(example)); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "t"}, {"config", "user.email", "t@t"}, {"add", "."}, {"commit", "-qm", "init"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// fakeLLM is an Anthropic Messages endpoint replying with scripted texts,
// one per call (the last repeats), reporting usage.
type fakeLLM struct {
	mu      sync.Mutex
	replies []string
	usage   eval.TokenUsage
	calls   int
	bodies  []map[string]any
	keys    []string
}

func (f *fakeLLM) server(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.bodies = append(f.bodies, body)
		f.keys = append(f.keys, r.Header.Get("x-api-key"))
		text := f.replies[min(f.calls, len(f.replies)-1)]
		f.calls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"usage":   map[string]any{"input_tokens": f.usage.InputTokens, "output_tokens": f.usage.OutputTokens},
		})
	}))
	t.Cleanup(s.Close)
	return s
}

func (f *fakeLLM) client(t *testing.T, b Budget, log *bytes.Buffer) *Client {
	t.Helper()
	t.Setenv("COPILOT_TEST_KEY", "sk-test-secret")
	llm, err := eval.NewHTTPLLM(&eval.JudgeConfig{URL: f.server(t).URL, Wire: eval.WireAnthropic, Model: DefaultModel, APIKeyEnv: "COPILOT_TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{LLM: llm, Model: DefaultModel, Budget: b}
	if log != nil {
		c.Log = log
	}
	return c
}

func reply(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readExample(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(example, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDecodeStrict(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		ok       bool
	}{
		{"plain", `{"summary":"s","risks":[],"files":[]}`, true},
		{"fenced", "```json\n{\"summary\":\"s\",\"risks\":[],\"files\":[]}\n```", true},
		{"unknown field", `{"summary":"s","risks":[],"files":[],"merge":true}`, false},
		{"prose before", `Sure! {"summary":"s"}`, false},
		{"trailing", `{"summary":"s"} and more`, false},
		{"two objects", `{"summary":"s"}{"summary":"t"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d DraftReply
			if err := decodeStrict(tc.in, &d); (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestCheckPath(t *testing.T) {
	for p, ok := range map[string]bool{
		"profiles/x.yaml": true, "halos.yaml": true, "rings/r.yml": true,
		"../x.yaml": false, "/etc/x.yaml": false, "a/../b.yaml": false, ".git/config.yaml": false,
		"x.json": false, `a\b.yaml`: false, "C:x.yaml": false, "": false, "./x.yaml": false,
	} {
		if err := checkPath(p); (err == nil) != ok {
			t.Errorf("checkPath(%q) = %v, want ok %v", p, err, ok)
		}
	}
}

func TestBudgetCeilings(t *testing.T) {
	bad := `{"nope":1}`
	for _, tc := range []struct {
		name      string
		budget    Budget
		usage     eval.TokenUsage
		wantCalls int
		wantMsg   string
	}{
		{"iterations", Budget{MaxIterations: 2}, eval.TokenUsage{InputTokens: 10, OutputTokens: 10}, 2, "--max-iterations"},
		// the policy prompt alone is ~20k tokens: the first call is refused up front
		{"tokens", Budget{MaxIterations: 5, MaxTokens: 1000}, eval.TokenUsage{}, 0, "--max-tokens"},
		// worst case of one call: ~20k in + 8192 out at 5/25 = ~$0.31
		{"cost", Budget{MaxIterations: 5, MaxCostUSD: 0.1}, eval.TokenUsage{}, 0, "--max-cost-usd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeLLM{replies: []string{bad}, usage: tc.usage}
			var log bytes.Buffer
			res, err := f.client(t, tc.budget, &log).Draft(context.Background(), example, "pin claude-code 2.1.300 for ring1")
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || f.calls != tc.wantCalls || !strings.Contains(res.Stopped, tc.wantMsg) {
				t.Fatalf("ok=%v calls=%d stopped=%q; want %d calls stopped by %s", res.OK, f.calls, res.Stopped, tc.wantCalls, tc.wantMsg)
			}
			if res.Spend.Calls != tc.wantCalls {
				t.Fatalf("spend %+v", res.Spend)
			}
		})
	}
}

// TestTokenCeilingCountsReportedUsage: each call reports 400 tokens; with a
// 1000-token ceiling the third call (200 left, under the 256 floor) is refused
// before it is sent, and so is everything after it.
func TestTokenCeilingCountsReportedUsage(t *testing.T) {
	f := &fakeLLM{replies: []string{`{}`}, usage: eval.TokenUsage{InputTokens: 300, OutputTokens: 100}}
	c := f.client(t, Budget{MaxIterations: 10, MaxTokens: 1000, MaxOutputTokens: 300}, nil)
	var errs []error
	for range 4 {
		var v struct{}
		errs = append(errs, c.ask(context.Background(), "s", "p", &v, func() error { return nil }))
	}
	if errs[0] != nil || errs[1] != nil || !errors.Is(errs[2], ErrBudget) || !errors.Is(errs[3], ErrBudget) || f.calls != 2 {
		t.Fatalf("errs %v, calls %d", errs, f.calls)
	}
	if got := f.bodies[1]["max_tokens"]; got != float64(300) {
		t.Fatalf("max_tokens = %v", got)
	}
	if s := c.Spend(); s.InputTokens != 600 || s.OutputTokens != 200 {
		t.Fatalf("spend %+v", s)
	}
}

func TestDraftRepairLoop(t *testing.T) {
	eng := readExample(t, "profiles/engineering.yaml")
	good := strings.Replace(eng, "version: 2.1.280", "version: 2.1.300", 1)
	broken := strings.Replace(eng, "extends: base", "extends: no-such-profile", 1)
	f := &fakeLLM{usage: eval.TokenUsage{InputTokens: 100, OutputTokens: 50}, replies: []string{
		`not json at all`, // schema failure: fed back, never used
		reply(t, DraftReply{Summary: "bump", Risks: []string{}, Files: []File{{Path: "profiles/engineering.yaml", Content: broken}}}),
		reply(t, DraftReply{Summary: "bump claude-code", Risks: []string{"ring members get a new CLI"}, Files: []File{{Path: "profiles/engineering.yaml", Content: good}}}),
	}}
	var log bytes.Buffer
	dir := gitPolicy(t)
	c := f.client(t, Budget{MaxIterations: 3}, &log)
	res, err := c.Draft(context.Background(), dir, "bump claude-code to 2.1.300 in engineering")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Iterations != 3 || f.calls != 3 {
		t.Fatalf("ok=%v iterations=%d calls=%d stopped=%q check=%+v", res.OK, res.Iterations, f.calls, res.Stopped, res.Check)
	}
	if !strings.Contains(res.Check.Diff, "+    version: 2.1.300") || len(res.Check.Plans) == 0 {
		t.Fatalf("diff/plan missing: %q %+v", res.Check.Diff, res.Check.Plans)
	}
	changed := false
	for _, p := range res.Check.Plans {
		changed = changed || p.Changed
	}
	if !changed || res.Check.Impact == nil || len(res.Check.Risks) == 0 {
		t.Fatalf("want a changed ring, impact and risks: %+v", res.Check)
	}
	// feedback reached the model: the 2nd prompt carries the schema error, the 3rd the validation error
	p2, p3 := promptOf(f.bodies[1]), promptOf(f.bodies[2])
	if !strings.Contains(p2, "schema validation") || !strings.Contains(p3, "no-such-profile") {
		t.Fatalf("feedback not sent:\n2: %.300s\n3: %.300s", p2, p3)
	}
	// logs: token counts per call, never prompt text or the key
	if got := strings.Count(log.String(), "copilot: llm call"); got != 3 {
		t.Fatalf("want 3 call log lines:\n%s", log.String())
	}
	if strings.Contains(log.String(), "engineering.yaml") || strings.Contains(log.String(), "sk-test-secret") {
		t.Fatalf("log leaks prompt or key:\n%s", log.String())
	}
	if f.keys[0] != "sk-test-secret" || f.bodies[0]["model"] != DefaultModel {
		t.Fatalf("key/model not sent: %v %v", f.keys[0], f.bodies[0]["model"])
	}
	if res.Spend.InputTokens != 300 || res.Spend.OutputTokens != 150 {
		t.Fatalf("spend %+v", res.Spend)
	}

	// --apply commits the verified draft to a local branch and leaves the checkout alone
	branch, commit, _, err := Apply(context.Background(), nil, dir, res.Files, res.Intent, "halo copilot: bump", "Intent: x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(branch, "halos/copilot-bump-claude-code") || commit == "" {
		t.Fatalf("branch %q commit %q", branch, commit)
	}
	show, err := exec.Command("git", "-C", dir, "show", branch+":profiles/engineering.yaml").Output()
	if err != nil || !strings.Contains(string(show), "version: 2.1.300") {
		t.Fatalf("branch content: %v %s", err, show)
	}
	if wt, _ := os.ReadFile(filepath.Join(dir, "profiles/engineering.yaml")); string(wt) != eng {
		t.Fatal("working tree changed by apply")
	}
}

func promptOf(body map[string]any) string {
	msgs, _ := body["messages"].([]any)
	if len(msgs) == 0 {
		return ""
	}
	m, _ := msgs[0].(map[string]any)
	s, _ := m["content"].(string)
	return s
}

func TestBypassTokenRejectedEvenFromModel(t *testing.T) {
	eng := readExample(t, "profiles/engineering.yaml")
	evil := eng + "# permissions: bypassPermissions\n" // a comment: validation alone would not see it
	f := &fakeLLM{replies: []string{reply(t, DraftReply{Summary: "x", Risks: []string{}, Files: []File{{Path: "profiles/engineering.yaml", Content: evil}}})}}
	dir := gitPolicy(t)
	res, err := f.client(t, Budget{MaxIterations: 2}, nil).Draft(context.Background(), dir, "anything")
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || f.calls != 2 || !strings.Contains(strings.Join(res.Check.Errors, "\n"), "bypassPermissions") {
		t.Fatalf("bypass token not rejected: ok=%v calls=%d %+v", res.OK, f.calls, res.Check)
	}
	if _, _, _, err := Apply(context.Background(), nil, dir, res.Files, "x", "s", "b"); err == nil || !strings.Contains(err.Error(), "refusing to apply") {
		t.Fatalf("apply of a bypass token: %v", err)
	}
	if out, _ := exec.Command("git", "-C", dir, "branch", "--list", "halos/*").Output(); len(bytes.TrimSpace(out)) != 0 {
		t.Fatalf("a branch was created: %s", out)
	}
}

func TestApplyRefusals(t *testing.T) {
	dir := gitPolicy(t)
	eng := readExample(t, "profiles/engineering.yaml")
	good := []File{{Path: "profiles/engineering.yaml", Content: strings.Replace(eng, "2.1.280", "2.1.300", 1)}}
	for _, tc := range []struct {
		name  string
		files []File
		prep  func()
		want  string
	}{
		{"invalid policy", []File{{Path: "profiles/engineering.yaml", Content: strings.Replace(eng, "extends: base", "extends: nope", 1)}}, nil, "refusing to apply"},
		{"outside dir", []File{{Path: "../evil.yaml", Content: "x: 1"}}, nil, "refusing to apply"},
		{"uncommitted", good, func() {
			if err := os.WriteFile(filepath.Join(dir, "profiles/engineering.yaml"), []byte(eng+"# local edit\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "uncommitted changes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.prep != nil {
				tc.prep()
			}
			_, _, _, err := Apply(context.Background(), nil, dir, tc.files, "x", "s", "b")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOfflineDraft(t *testing.T) {
	c := &Client{}
	res, err := c.Draft(context.Background(), example, "set claude-code version 2.1.300 in profile engineering")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Offline || len(res.Files) != 1 || !strings.Contains(res.Check.Diff, "+    version: 2.1.300") || res.Spend.Calls != 0 {
		t.Fatalf("%+v", res)
	}
	if _, err := c.Draft(context.Background(), example, "make it better"); err == nil || !strings.Contains(err.Error(), "--offline understands only") {
		t.Fatalf("unknown offline intent: %v", err)
	}
	if _, err := c.Draft(context.Background(), example, "set claude-code version 1 in profile nope"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}

func TestModelHTTPErrorIsAnError(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "overloaded", 529) }))
	defer s.Close()
	llm, err := eval.NewHTTPLLM(&eval.JudgeConfig{URL: s.URL, Wire: eval.WireAnthropic, Model: DefaultModel})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&Client{LLM: llm, Model: DefaultModel}).Draft(context.Background(), example, "x")
	if err == nil || errors.Is(err, ErrSchema) || !strings.Contains(err.Error(), "529") {
		t.Fatalf("err = %v", err)
	}
}
