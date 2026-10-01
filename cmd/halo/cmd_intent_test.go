package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/policy"
)

const simpleEx = "../../examples/simple"

func TestSimpleExampleRendersRelease(t *testing.T) {
	if code, out, errs := halo(t, "validate", simpleEx); code != 0 {
		t.Fatalf("validate %d\n%s%s", code, out, errs)
	}
	out := filepath.Join(t.TempDir(), "rel.tar")
	code, stdout, errs := halo(t, "release", "build", simpleEx, "--ring", "ring3-ga", "--no-artifacts", "-o", out, "--output", "json")
	if code != 0 {
		t.Fatalf("release build %d %s", code, errs)
	}
	var res struct{ Digest string }
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || !strings.HasPrefix(res.Digest, "sha256:") {
		t.Fatalf("release build output %q: %v", stdout, err)
	}
	rendered := t.TempDir()
	if code, _, errs := halo(t, "render", simpleEx, "--ring", "ring0-team", "--os", "linux", "--out", rendered); code != 0 {
		t.Fatalf("render %d %s", code, errs)
	}
	b, err := os.ReadFile(filepath.Join(rendered, "etc/claude-code/managed-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m["disableBypassPermissionsMode"] != "disable" {
		t.Fatalf("managed settings: %v %s", err, b)
	}
	if strings.Contains(strings.ToLower(string(b)), "bypasspermissions\"") {
		t.Fatalf("rendered a bypass mode:\n%s", b)
	}
}

func TestInitSimpleFlagsAndInteractive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	code, out, errs := halo(t, "init", dir, "--org", "globex", "--tools", "claude-code@2.1.280,codex@0.58.0",
		"--provider", "bedrock", "--model", "default=anthropic.claude-sonnet-4-5", "--model", "strong=anthropic/claude-opus-4-1",
		"--safety", "strict", "--rollout", "careful")
	if code != 0 {
		t.Fatalf("init %d\n%s%s", code, out, errs)
	}
	if !strings.Contains(out, "create "+filepath.Join(dir, "halos.yaml")) {
		t.Errorf("init did not list the file it created:\n%s", out)
	}
	if code, out, errs := halo(t, "status", "--policy-dir", dir); code != 0 || !strings.Contains(out, "ring4-ga") || !strings.Contains(out, "simple (safety strict, rollout careful)") {
		t.Fatalf("status %d\n%s%s", code, out, errs)
	}
	if code, _, _ := halo(t, "init", dir, "--model", "strong=x"); code != 1 {
		t.Errorf("init over an existing repo: want 1, got %d", code)
	}
	// codex on anthropic: init adds a codex alias on OpenAI, notes it on stderr, and the result validates.
	q := filepath.Join(t.TempDir(), "q")
	code, out, errs = halo(t, "init", q, "--tools", "claude-code@2.1.280,codex@0.99.0", "--model", "strong=claude-opus-4-1")
	if code != 0 || !strings.Contains(errs, "note: codex: added model alias codex = openai/gpt-5-codex") {
		t.Fatalf("init codex on anthropic: %d\n%s%s", code, out, errs)
	}
	b, err := os.ReadFile(filepath.Join(q, "halos.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"codex: {version: 0.99.0, model: codex}", "default: claude-sonnet-4-5", "codex: openai/gpt-5-codex"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("halos.yaml lacks %q:\n%s", want, b)
		}
	}
	if code, out, errs := halo(t, "validate", q); code != 0 {
		t.Fatalf("validate %d\n%s%s", code, out, errs)
	}
	// --model codex=<id> wins; vertex needs --project.
	code, _, errs = halo(t, "init", filepath.Join(t.TempDir(), "r"), "--tools", "codex@0.99.0", "--model", "codex=gpt-5.1-codex")
	if code != 0 || strings.Contains(errs, "note:") {
		t.Errorf("explicit codex model: %d %s", code, errs)
	}
	if code, _, errs := halo(t, "init", filepath.Join(t.TempDir(), "v"), "--provider", "vertex"); code != 1 || !strings.Contains(errs, "--project") {
		t.Errorf("vertex without project: %d %s", code, errs)
	}

	// interactive: answer two questions, accept the rest
	idir := filepath.Join(t.TempDir(), "i")
	var o, e bytes.Buffer
	root := newRoot(&o, &e)
	root.SetIn(strings.NewReader("initech\n\n\n\n\n\nrelaxed\nfast\n"))
	root.SetArgs([]string{"init", idir, "-i"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("interactive init: %v\n%s%s", err, o.String(), e.String())
	}
	b, err = os.ReadFile(filepath.Join(idir, "halos.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"org: initech", "safety: relaxed", "rollout: fast", "gateway: https://ai.initech.example"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("interactive halos.yaml lacks %q:\n%s", want, b)
		}
	}
	root = newRoot(&o, &e)
	root.SetIn(strings.NewReader("short\n"))
	root.SetArgs([]string{"init", filepath.Join(t.TempDir(), "j"), "-i"})
	if err := root.ExecuteContext(context.Background()); err == nil {
		t.Error("interactive init with truncated input should fail")
	}
}

func TestIntentCommandsDryRunAndWrite(t *testing.T) {
	dir := copyDir(t, simpleEx)
	sha := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	code, out, errs := halo(t, "upgrade", "start", "claude-code", "2.1.300", "--policy-dir", dir, "--release", sha("b"), "--baseline", sha("a"), "--dry-run")
	if code != 0 || !strings.Contains(out, "would create") || !strings.Contains(out, "dry run: nothing written") {
		t.Fatalf("dry run %d\n%s%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "rollouts")); err == nil {
		t.Fatal("--dry-run wrote files")
	}
	code, out, errs = halo(t, "upgrade", "start", "claude-code", "2.1.300", "--policy-dir", dir, "--release", sha("b"), "--baseline", sha("a"), "--output", "json")
	var res struct {
		Created, Changed, Notes []string
		DryRun                  bool
	}
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil || len(res.Created) != 7 || res.DryRun {
		t.Fatalf("upgrade start %d %v\n%s%s", code, err, out, errs)
	}
	for _, args := range [][]string{
		{"model", "switch", "strong", "claude-opus-5", "--canary"},
		{"model", "switch", "default", "claude-sonnet-5"},
		{"enable", "mcp", "github", "--url", "https://api.githubcopilot.com/mcp/", "--header", "Authorization=Bearer ${GITHUB_MCP_TOKEN}", "--for", "10%"},
		{"enable", "hook", "fmt", "--event", "PostToolUse", "--matcher", "Edit|Write", "--command", "/usr/local/bin/fmt", "--for", "all"},
	} {
		code, out, errs := halo(t, append(args, "--policy-dir", dir)...)
		if code != 0 || !strings.Contains(out, "create ") && !strings.Contains(out, "update ") {
			t.Fatalf("%v: %d\n%s%s", args, code, out, errs)
		}
	}
	if code, out, errs := halo(t, "validate", dir); code != 0 {
		t.Fatalf("validate after intents %d\n%s%s", code, out, errs)
	}
	code, out, _ = halo(t, "status", "--policy-dir", dir)
	for _, want := range []string{"claude-code-2.1.300", "strong-claude-opus-5", "github", "(not started, 7 steps)"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = halo(t, "explain", "--policy-dir", dir, "--kind", "gateway")
	if code != 0 || !strings.Contains(out, "# source: halos.yaml (simple mode), overlaid by gateway.yaml") || !strings.Contains(out, "model: claude-sonnet-5") {
		t.Errorf("explain:\n%s", out)
	}
	// a change that would not validate is refused and writes nothing
	code, _, errs = halo(t, "enable", "mcp", "leaky", "--url", "https://x.example/mcp", "--header", "Authorization=Bearer literal-value", "--for", "10%", "--policy-dir", dir)
	if code != exitValidation || !strings.Contains(errs, "nothing written") {
		t.Errorf("invalid change: %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "toggles", "leaky.yaml")); err == nil {
		t.Error("invalid change was written")
	}
	if code, out, errs := halo(t, "eject", "--policy-dir", dir); code != 0 || !strings.Contains(out, "create "+filepath.Join(dir, "gateway.yaml")) && !strings.Contains(out, "update "+filepath.Join(dir, "gateway.yaml")) {
		t.Fatalf("eject %d\n%s%s", code, out, errs)
	}
	if code, out, errs := halo(t, "validate", dir); code != 0 {
		t.Fatalf("validate after eject %d\n%s%s", code, out, errs)
	}
}

func TestKill(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		c, _ := r.Cookie("halo_session")
		got = append(got, r.Method+" "+r.URL.Path+" "+string(b)+" "+c.Value)
		_, _ = w.Write([]byte(`{"killed":true,"changed":true}`))
	}))
	defer srv.Close()
	t.Setenv("HALO_SESSION", "sess")
	t.Setenv("HALO_SERVER", srv.URL)
	tests := []struct {
		args       []string
		code       int
		path, want string
	}{
		{[]string{"opus-5-5-canary"}, 0, "/api/v1/experiments/opus-5-5-canary/kill", "experiment opus-5-5-canary: killed=true"},
		{[]string{"github-mcp"}, 0, "/api/v1/toggles/github-mcp/kill", "toggle github-mcp"},
		{[]string{"opus-5-5-upgrade"}, 0, "/api/v1/experiments/opus-5-5-canary/kill", "halo rollout rollback opus-5-5-upgrade"},
		{[]string{"github-mcp", "--unkill"}, 0, "/api/v1/toggles/github-mcp/unkill", "toggle github-mcp"},
		{[]string{"engineering-settings-2026-10"}, 1, "", ""},
		{[]string{"nope"}, 1, "", ""},
		{[]string{"github-mcp", "--kind", "experiment"}, 1, "", ""},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			got = nil
			args := append([]string{"kill", "--policy-dir", example}, tt.args...)
			if !strings.Contains(strings.Join(tt.args, " "), "--unkill") {
				args = append(args, "--reason", "test")
			}
			code, out, errs := halo(t, args...)
			if code != tt.code {
				t.Fatalf("code %d want %d\n%s%s", code, tt.code, out, errs)
			}
			if tt.path == "" {
				if len(got) != 0 {
					t.Fatalf("server called: %v", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], "POST "+tt.path) || !strings.HasSuffix(got[0], " sess") || !strings.Contains(out, tt.want) {
				t.Fatalf("calls %v\nout %s", got, out)
			}
		})
	}
	if code, _, errs := halo(t, "kill", "--policy-dir", example, "opus-5-5-canary"); code != 1 || !strings.Contains(errs, "--reason") {
		t.Errorf("kill without reason: %d %s", code, errs)
	}
}

// TestUpgradeStartSeamless: start builds and publishes the candidate with no
// ring pointer moving and fills both digests; --no-publish writes the same
// digest and `upgrade publish` pushes exactly it.
func TestUpgradeStartSeamless(t *testing.T) {
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Cleanup(func() { dialRegistry = old })
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	keys := t.TempDir()
	if code, _, errs := halo(t, "keys", "generate", "--out", keys); code != 0 {
		t.Fatalf("keys: %s", errs)
	}
	reg := []string{"--registry", "registry.test/acme/halos", "--key", filepath.Join(keys, "halo.key")}
	pem, err := os.ReadFile(filepath.Join(keys, "halo.pub"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := bundle.ParseEd25519Verifier(pem)
	if err != nil {
		t.Fatal(err)
	}
	served := func(ring string) string {
		p, found, err := bundle.ReadPointer(ctx, store, ring, v)
		if err != nil || !found {
			return ""
		}
		return p.Digest
	}

	dir := copyDir(t, simpleEx)
	start := []string{"upgrade", "start", "claude-code", "2.1.300", "--policy-dir", dir, "--no-artifacts"}
	if code, _, errs := halo(t, append(start, reg...)...); code != 1 || !strings.Contains(errs, "never been published") {
		t.Fatalf("start before the GA ring was published: %d %s", code, errs)
	}
	code, out, errs := halo(t, append([]string{"--output", "json", "release", "publish", dir, "--ring", "ring3-ga", "--release-version", "1.0.0", "--no-artifacts"}, reg...)...)
	var pub struct{ Digest string }
	if code != 0 || json.Unmarshal([]byte(out), &pub) != nil {
		t.Fatalf("publish ga: %d %s", code, errs)
	}

	offline := copyDir(t, dir)
	code, out, errs = halo(t, "upgrade", "start", "claude-code", "2.1.300", "--policy-dir", offline, "--no-artifacts", "--no-publish", "--baseline", pub.Digest)
	if code != 0 || !strings.Contains(out, "halo upgrade publish claude-code-2.1.300") {
		t.Fatalf("--no-publish: %d\n%s%s", code, out, errs)
	}

	code, out, errs = halo(t, append(start, reg...)...)
	if code != 0 || !strings.Contains(out, "no ring pointer moved") || !strings.Contains(out, "published channel ring1-canary.x-claude-code-2.1.300-canary.next") {
		t.Fatalf("start: %d\n%s%s", code, out, errs)
	}
	org, err := policy.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ro := org.Rollouts[0]
	if ro.Baseline.Release != pub.Digest || ro.Change.Release == pub.Digest || ro.Change.Version != "claude-code-2.1.300" {
		t.Fatalf("digests: %+v", ro)
	}
	if served("ring3-ga") != pub.Digest || served("ring0-team") != "" || served("ring1-canary") != "" {
		t.Fatal("upgrade start moved a ring pointer")
	}
	if served("ring1-canary.x-claude-code-2.1.300-canary.next") == "" {
		t.Fatal("treatment channel not published")
	}
	if _, err := store.Resolve(ctx, "vclaude-code-2.1.300"); err != nil {
		t.Fatalf("candidate tag: %v", err)
	}
	offOrg, err := policy.Load(offline)
	if err != nil {
		t.Fatal(err)
	}
	if offOrg.Rollouts[0].Change.Release != ro.Change.Release {
		t.Fatalf("--no-publish digest %s != published %s", offOrg.Rollouts[0].Change.Release, ro.Change.Release)
	}
	// publish from the offline repo pushes the identical, already-present release
	if code, out, errs := halo(t, append([]string{"upgrade", "publish", "claude-code-2.1.300", "--policy-dir", offline, "--no-artifacts"}, reg...)...); code != 0 || !strings.Contains(out, ro.Change.Release) {
		t.Fatalf("upgrade publish: %d\n%s%s", code, out, errs)
	}
	// drift: the policy no longer builds the named release -> nothing pushed
	replace(t, filepath.Join(offline, "profiles", "claude-code-2.1.300.yaml"), "version: 2.1.300", "version: 2.1.301")
	if code, _, errs := halo(t, append([]string{"upgrade", "publish", "claude-code-2.1.300", "--policy-dir", offline, "--no-artifacts"}, reg...)...); code != 1 || !strings.Contains(errs, "nothing pushed") {
		t.Fatalf("drifted publish: %d %s", code, errs)
	}
	if code, _, errs := halo(t, "upgrade", "start", "codex", "0.77.0", "--policy-dir", dir); code != 1 || !strings.Contains(errs, "--no-publish") {
		t.Fatalf("start without registry: %d %s", code, errs)
	}
}

func replace(t *testing.T, p, old, nw string) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), old) {
		t.Fatalf("%s: %v (no %q)", p, err, old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(string(b), old, nw, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}
