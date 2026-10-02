package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/promote"
)

const example = "../../examples/acme-corp"

// copyExample copies the example policy into a temp git repo.
func copyExample(t *testing.T) string {
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

func connect(t *testing.T, o Options) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, error) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	if res.IsError {
		return nil, &toolErr{res.Content[0].(*mcp.TextContent).Text}
	}
	b, _ := json.Marshal(res.StructuredContent)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

type toolErr struct{ msg string }

func (e *toolErr) Error() string { return e.msg }

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]bool{}
	for _, tl := range res.Tools {
		m[tl.Name] = true
	}
	return m
}

func TestWriteToolsAbsentWithoutAllowWrites(t *testing.T) {
	names := toolNames(t, connect(t, Options{PolicyDir: example}))
	for _, n := range []string{"validate", "plan", "render_preview", "whoami", "list_rings", "list_experiments",
		"show_experiment", "harness_matrix", "explain_release_diff", "eval_scorecard"} {
		if !names[n] {
			t.Errorf("read tool %s missing", n)
		}
	}
	for _, n := range []string{"start_experiment", "pause_experiment", "conclude_experiment", "propose_promotion", "propose_rollback", "analyze_experiment"} {
		if names[n] {
			t.Errorf("tool %s must not be registered", n)
		}
	}
	w := toolNames(t, connect(t, Options{PolicyDir: example, AllowWrites: true}))
	for _, n := range []string{"start_experiment", "pause_experiment", "conclude_experiment", "propose_promotion", "propose_rollback"} {
		if !w[n] {
			t.Errorf("write tool %s missing with --allow-writes", n)
		}
	}
	for _, n := range []string{"publish", "promote", "merge", "retag"} {
		if w[n] {
			t.Errorf("forbidden tool %s registered", n)
		}
	}
}

func TestReadTools(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	tests := []struct {
		name string
		tool string
		args map[string]any
		key  string
		want func(v any) bool
	}{
		{"validate ok", "validate", nil, "ok", func(v any) bool { return v == true }},
		{"rings", "list_rings", nil, "rings", func(v any) bool { return len(v.([]any)) >= 3 }},
		{"experiments", "list_experiments", nil, "experiments", func(v any) bool { return len(v.([]any)) >= 1 }},
		{"show", "show_experiment", map[string]any{"name": "opus-5-5-canary"}, "name", func(v any) bool { return v == "opus-5-5-canary" }},
		{"matrix", "harness_matrix", nil, "harnesses", func(v any) bool { return len(v.(map[string]any)) > 0 }},
		{"whoami", "whoami", map[string]any{"user": "alice@acme.com"}, "ring", func(v any) bool { return v != "" }},
		{"render", "render_preview", map[string]any{"ring": "ring1-canary", "os": "linux"}, "files", func(v any) bool {
			fs := v.([]any)
			return len(fs) > 0 && fs[0].(map[string]any)["content"] != ""
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := call(t, cs, tc.tool, tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.want(out[tc.key]) {
				t.Fatalf("unexpected %s: %v", tc.key, out[tc.key])
			}
		})
	}
	errCases := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"unknown ring", "render_preview", map[string]any{"ring": "nope", "os": "linux"}},
		{"bad os", "render_preview", map[string]any{"ring": "ring1-canary", "os": "plan9"}},
		{"unknown experiment", "show_experiment", map[string]any{"name": "nope"}},
		{"scorecard outside", "eval_scorecard", map[string]any{"path": "/etc/passwd"}},
		{"plan missing baseline", "plan", map[string]any{"ring": "ring1-canary", "against": "/nonexistent.tar"}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := call(t, cs, tc.tool, tc.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPlanAgainstSelfIsEmpty(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	rel, err := (&srv{dir: mustAbs(t, example)}).buildRelease("ring1-canary", "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "release.tar")
	if err := os.WriteFile(p, rel.Tar, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := call(t, cs, "plan", map[string]any{"ring": "ring1-canary", "against": p})
	if err != nil {
		t.Fatal(err)
	}
	if out["changed"] != false {
		t.Fatalf("expected no change, got %v", out["diff"])
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestResources(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	res, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var policyURI, schemaURI string
	for _, r := range res.Resources {
		if strings.HasPrefix(r.URI, policyPrefix+"experiments/") {
			policyURI = r.URI
		}
		if r.URI == schemaPrefix+"experiment" {
			schemaURI = r.URI
		}
	}
	if policyURI == "" || schemaURI == "" {
		t.Fatalf("missing resources: policy=%q schema=%q", policyURI, schemaURI)
	}
	for _, u := range []string{policyURI, schemaURI} {
		r, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: u})
		if err != nil || len(r.Contents) == 0 || r.Contents[0].Text == "" {
			t.Fatalf("read %s: %v", u, err)
		}
	}
	if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: policyPrefix + "../../go.mod"}); err == nil {
		t.Fatal("path traversal must fail")
	}
}

func TestPrompts(t *testing.T) {
	cs := connect(t, Options{PolicyDir: example})
	res, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "triage-experiment", Arguments: map[string]string{"experiment": "opus-5-5-canary"}})
	if err != nil {
		t.Fatal(err)
	}
	if txt := res.Messages[0].Content.(*mcp.TextContent).Text; !strings.Contains(txt, "opus-5-5-canary") {
		t.Fatalf("argument not interpolated: %s", txt)
	}
	ps, err := cs.ListPrompts(context.Background(), nil)
	if err != nil || len(ps.Prompts) != 4 {
		t.Fatalf("want 4 prompts, got %v %v", ps, err)
	}
	// onboard: path is optional (the agent asks); every tool it names must exist.
	res, err = cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "onboard"})
	if err != nil {
		t.Fatal(err)
	}
	txt := res.Messages[0].Content.(*mcp.TextContent).Text
	ts, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tl := range ts.Tools {
		have[tl.Name] = true
	}
	for _, name := range []string{"doctor", "detect_harnesses", "init_policy", "plan", "local_install", "local_proxy", "verify_harness",
		"onboard_company", "validate", "harness_matrix", "eval_scorecard"} {
		if !strings.Contains(txt, name) || !have[name] {
			t.Fatalf("onboard prompt: %s mentioned=%t registered=%t", name, strings.Contains(txt, name), have[name])
		}
	}
}

func TestDryRunLeavesFilesUntouched(t *testing.T) {
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	f := filepath.Join(dir, "experiments", "opus-5-5-canary.yaml")
	before, _ := os.ReadFile(f)

	for _, dry := range []any{nil, true} { // default and explicit
		args := map[string]any{"name": "opus-5-5-canary", "reason": "guardrail check"}
		if dry != nil {
			args["dry_run"] = dry
		}
		out, err := call(t, cs, "pause_experiment", args)
		if err != nil {
			t.Fatal(err)
		}
		if out["dry_run"] != true || out["applied"] != false {
			t.Fatalf("expected dry run, got %v", out)
		}
		if p, _ := out["patch"].(string); !strings.Contains(p, "-status: running") || !strings.Contains(p, "+status: paused") {
			t.Fatalf("patch lacks status change:\n%s", p)
		}
		if after, _ := os.ReadFile(f); string(after) != string(before) {
			t.Fatal("dry run modified the file")
		}
	}
}

func TestApplyCommitsReasonOnBranch(t *testing.T) {
	dir := copyExample(t)
	ctx := context.Background()
	f := filepath.Join(dir, "experiments", "opus-5-5-canary.yaml")
	head, _ := git(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	// A staged, unrelated change in the user's checkout must not be committed.
	if err := os.WriteFile(filepath.Join(dir, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := git(ctx, dir, "add", "stray.txt"); err != nil {
		t.Fatal(err)
	}
	// An uncommitted edit to the very file being changed must not be committed.
	const wip = "\n# local wip, uncommitted\n"
	f0, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f0.WriteString(wip); err != nil {
		t.Fatal(err)
	}
	if err := f0.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(f)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	out, err := call(t, cs, "pause_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "p95 latency regression", "dry_run": false})
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "halos/pause-opus-5-5-canary-"
	br, _ := out["branch"].(string)
	if out["applied"] != true || !strings.HasPrefix(br, prefix) || len(br) != len(prefix)+6 {
		t.Fatalf("unexpected result %v", out)
	}
	if b, _ := git(ctx, dir, "show", br+":experiments/opus-5-5-canary.yaml"); strings.Contains(b, "local wip") {
		t.Fatal("uncommitted edit was committed")
	}
	// A second apply gets a different branch (random suffix).
	if out2, err := call(t, cs, "pause_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "again", "dry_run": false}); err != nil || out2["branch"] == br {
		t.Fatalf("second apply: %v %v", out2, err)
	}
	msg, err := git(ctx, dir, "log", "-1", "--format=%B", br)
	if err != nil || !strings.Contains(msg, "Reason: p95 latency regression") {
		t.Fatalf("reason not in commit message: %q %v", msg, err)
	}
	if b, _ := git(ctx, dir, "show", br+":experiments/opus-5-5-canary.yaml"); !strings.Contains(b, "status: paused") {
		t.Fatal("status not updated on the branch")
	}
	if files, _ := git(ctx, dir, "show", "--name-only", "--format=", br); files != "experiments/opus-5-5-canary.yaml" {
		t.Fatalf("commit touched %q", files)
	}
	if now, _ := git(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD"); now != head {
		t.Fatalf("current branch changed %s -> %s", head, now)
	}
	if after, _ := os.ReadFile(f); string(after) != string(before) {
		t.Fatal("user's working tree was modified")
	}
	if st, _ := git(ctx, dir, "status", "--porcelain"); st != "M experiments/opus-5-5-canary.yaml\nA  stray.txt" { // wip stays unstaged (TrimSpace eats the leading blank)
		t.Fatalf("user's index changed: %q", st)
	}
	if wts, _ := git(ctx, dir, "worktree", "list"); strings.Count(wts, "\n") != 0 {
		t.Fatalf("temporary worktree left behind:\n%s", wts)
	}
}

func git(ctx context.Context, dir string, args ...string) (string, error) {
	out, err := promote.Run(ctx, dir, "git", args...)
	return strings.TrimSpace(string(out)), err
}

func TestWriteToolErrors(t *testing.T) {
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{"missing reason", "pause_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "  "}},
		{"bad transition", "start_experiment", map[string]any{"name": "opus-5-5-canary", "reason": "x"}}, // already running
		{"unknown experiment", "pause_experiment", map[string]any{"name": "nope", "reason": "x"}},
		{"rollback release without ring", "propose_rollback", map[string]any{"experiment": "opus-5-5-canary", "release": "sha256:abc", "reason": "x"}},
		{"promotion without release", "propose_promotion", map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "", "reason": "x"}},
		{"promotion PR without evidence", "propose_promotion", map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "sha256:abc", "reason": "x", "dry_run": false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := call(t, cs, tc.tool, tc.args); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRollbackDryRun(t *testing.T) {
	dir := copyExample(t)
	cs := connect(t, Options{PolicyDir: dir, AllowWrites: true})
	out, err := call(t, cs, "propose_rollback", map[string]any{"experiment": "opus-5-5-canary", "ring": "ring1-canary", "release": "sha256:deadbeef", "reason": "rollback"})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := out["patch"].(string)
	if !strings.Contains(p, "+status: paused") || !strings.Contains(p, "sha256:deadbeef") {
		t.Fatalf("patch missing edits:\n%s", p)
	}
}

func TestResourcesIgnoreSymlinks(t *testing.T) {
	dir := copyExample(t)
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(outside, []byte("token: hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"hosts.yaml": "/etc/hosts", "secret.yaml": outside, "linkdir": filepath.Dir(outside)} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "x.yaml"), []byte("a: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cs := connect(t, Options{PolicyDir: dir})
	res, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res.Resources {
		if strings.Contains(r.URI, "hosts") || strings.Contains(r.URI, "secret") || strings.Contains(r.URI, "linkdir") {
			t.Errorf("symlink listed: %s", r.URI)
		}
	}
	for _, rel := range []string{"hosts.yaml", "secret.yaml", "linkdir/secret.yaml", ".git/x.yaml", ".git/config"} {
		if r, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: policyPrefix + rel}); err == nil {
			t.Errorf("%s readable: %q", rel, r.Contents[0].Text)
		}
	}
	if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: policyPrefix + "halos.yaml"}); err != nil {
		t.Errorf("regular file: %v", err)
	}
}
