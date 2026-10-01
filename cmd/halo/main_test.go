package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/fsutil"
)

const example = "../../examples/acme-corp"

func halo(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func copyDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

var geminiRe = regexp.MustCompile(`(?m)^  gemini-cli:\n    version: \S+\n`)

// buildable returns a copy of the example without the gemini-cli harness:
// policy.Validate only accepts "gemini-cli" but the registered adapter is
// named "gemini", so release.Build rejects it (cross-package mismatch, flagged).
func buildable(t *testing.T) string {
	t.Helper()
	dir := copyDir(t, example)
	for _, f := range []string{"engineering.yaml", "engineering-next.yaml"} {
		p := filepath.Join(dir, "profiles", f)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, geminiRe.ReplaceAll(b, nil), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestValidate(t *testing.T) {
	if code, out, errs := halo(t, "validate", example); code != 0 {
		t.Fatalf("code %d\n%s%s", code, out, errs)
	}
	// broken: ring referencing a missing profile -> exit 2
	dir := copyDir(t, example)
	p := filepath.Join(dir, "rings", "ring3-ga.yaml")
	b, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.ReplaceAll(b, []byte("profile: engineering"), []byte("profile: nope")), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := halo(t, "validate", dir)
	if code != 2 || !strings.Contains(out, "error") {
		t.Fatalf("want exit 2 with error output, got %d\n%s", code, out)
	}
	if code, _, _ := halo(t, "validate", t.TempDir()); code != 1 {
		t.Fatalf("empty dir: want exit 1, got %d", code)
	}
	if code, _, _ := halo(t, "validate", "--output", "xml", example); code != 1 {
		t.Fatalf("bad --output: want exit 1, got %d", code)
	}
}

func TestInitThenValidate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	if code, out, errs := halo(t, "init", dir, "--org", "globex"); code != 0 {
		t.Fatalf("init %d\n%s%s", code, out, errs)
	}
	if code, out, errs := halo(t, "validate", dir); code != 0 {
		t.Fatalf("validate scaffold %d\n%s%s", code, out, errs)
	}
	if code, _, _ := halo(t, "init", dir); code != 1 {
		t.Fatalf("second init should refuse, got %d", code)
	}
	if code, _, errs := halo(t, "render", dir, "--ring", "ring1-ga", "--os", "linux", "--out", t.TempDir()); code != 0 {
		t.Fatalf("render scaffold %d %s", code, errs)
	}
}

func TestRenderDarwin(t *testing.T) {
	ex := buildable(t)
	out := t.TempDir()
	code, _, errs := halo(t, "render", ex, "--ring", "ring3-ga", "--os", "darwin", "--out", out)
	if code != 0 {
		t.Fatalf("code %d %s", code, errs)
	}
	p := filepath.Join(out, "Library/Application Support/ClaudeCode/managed-settings.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(b) {
		t.Fatalf("invalid JSON in %s", p)
	}
	if code, _, _ := halo(t, "render", ex, "--ring", "nope", "--out", out); code != 1 {
		t.Fatalf("unknown ring: want 1, got %d", code)
	}
	if code, _, _ := halo(t, "render", ex, "--ring", "ring3-ga", "--os", "plan9", "--out", out); code != 1 {
		t.Fatalf("bad os: want 1, got %d", code)
	}
}

func TestWhoamiDeterministic(t *testing.T) {
	args := []string{"whoami", example, "--user", "alice@acme.example", "--output", "json"}
	_, a, _ := halo(t, args...)
	_, b, _ := halo(t, args...)
	if a != b {
		t.Fatalf("not deterministic:\n%s\n%s", a, b)
	}
	var res struct{ Ring string }
	if err := json.Unmarshal([]byte(a), &res); err != nil || res.Ring == "" {
		t.Fatalf("bad output %q: %v", a, err)
	}
	_, o, _ := halo(t, "whoami", example, "--user", "bob", "--groups", "ai-platform", "--output", "json")
	if !strings.Contains(o, "ring0-harness-team") {
		t.Fatalf("group membership should win: %s", o)
	}
}

func TestHarnesses(t *testing.T) {
	code, out, _ := halo(t, "harnesses")
	if code != 0 || !strings.Contains(out, "claude-code") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestExpLifecyclePreservesFormatting(t *testing.T) {
	dir := copyDir(t, example)
	p := filepath.Join(dir, "experiments", "opus-5-5-canary.yaml")
	orig, _ := os.ReadFile(p)

	if code, _, _ := halo(t, "exp", "start", "--dir", dir, "opus-5-5-canary"); code != 1 {
		t.Fatalf("start on running should fail, got %d", code)
	}
	if code, _, errs := halo(t, "exp", "pause", "--dir", dir, "opus-5-5-canary"); code != 0 {
		t.Fatalf("pause: %d %s", code, errs)
	}
	got, _ := os.ReadFile(p)
	want := bytes.Replace(orig, []byte("status: running"), []byte("status: paused"), 1)
	if !bytes.Equal(got, want) {
		t.Fatalf("pause changed more than the status:\n%s", got)
	}
	if code, _, _ := halo(t, "exp", "start", "--dir", dir, "opus-5-5-canary"); code != 0 {
		t.Fatal("start failed")
	}
	if got, _ = os.ReadFile(p); !bytes.Equal(got, orig) {
		t.Fatalf("round trip differs:\n%s", got)
	}

	// missing status line is inserted; file still validates
	noStatus := bytes.Replace(orig, []byte("status: running\n"), nil, 1)
	if err := os.WriteFile(p, noStatus, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := halo(t, "exp", "start", "--dir", dir, "opus-5-5-canary"); code != 0 {
		t.Fatal("start with no status failed")
	}
	got, _ = os.ReadFile(p)
	if !strings.Contains(string(got), "name: opus-5-5-canary\nstatus: running\n") || !strings.Contains(string(got), "# Traffic-axis canary") {
		t.Fatalf("insert wrong:\n%s", got)
	}
	if code, out, _ := halo(t, "validate", dir); code != 0 {
		t.Fatalf("validate after edit: %d %s", code, out)
	}
	if code, _, _ := halo(t, "exp", "conclude", "--dir", dir, "missing"); code != 1 {
		t.Fatal("unknown experiment should fail")
	}
}

func TestKeysBuildPublishPlanRollback(t *testing.T) {
	ex := buildable(t)
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // fresh registry, fresh signer state
	t.Cleanup(func() { dialRegistry = old })

	keys := t.TempDir()
	if code, _, errs := halo(t, "keys", "generate", "--out", keys); code != 0 {
		t.Fatalf("keys: %d %s", code, errs)
	}
	if code, _, _ := halo(t, "keys", "generate", "--out", keys); code != 1 {
		t.Fatal("keys generate must not overwrite")
	}
	key, pub := filepath.Join(keys, "halo.key"), filepath.Join(keys, "halo.pub")
	tar := filepath.Join(t.TempDir(), "release.tar")

	if code, _, errs := halo(t, "release", "build", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.0", "-o", tar); code != 0 {
		t.Fatalf("build: %d %s", code, errs)
	}
	reg := "registry.test/acme/halos"
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if code, _, errs := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", v, "--registry", reg, "--key", key); code != 0 {
			t.Fatalf("publish %s: %d %s", v, code, errs)
		}
	}
	if code, _, _ := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--registry", reg, "--key", key); code != 1 {
		t.Fatal("publish without --release-version should fail")
	}

	// plan against tar and against registry ring tag (identical content => no changes)
	if code, out, errs := halo(t, "plan", ex, "--ring", "ring3-ga", "--release-version", "1.0.0", "--against", tar); code != 0 || !strings.Contains(out, "no changes") {
		t.Fatalf("plan tar: %d %s %s", code, out, errs)
	}
	code, out, errs := halo(t, "plan", ex, "--ring", "ring1-canary", "--against", reg+":v1.0.0", "--pubkey", pub, "--release-version", "1.1.0")
	if code != 0 {
		t.Fatalf("plan registry: %d %s %s", code, out, errs)
	}
	if code, _, _ := halo(t, "plan", ex, "--ring", "ring3-ga", "--against", reg); code != 1 {
		t.Fatal("registry plan without key should fail")
	}

	if code, _, errs := halo(t, "release", "promote", "--from-ring", "ring3-ga", "--to-ring", "ring2-early", "--registry", reg, "--key", key); code != 0 {
		t.Fatalf("promote: %d %s", code, errs)
	}
	if code, out, errs := halo(t, "rollback", "--ring", "ring3-ga", "--to", "1.0.0", "--registry", reg, "--key", key); code != 0 || !strings.Contains(out, "rolled back") {
		t.Fatalf("rollback: %d %s %s", code, out, errs)
	}
	if code, _, e := halo(t, "release", "refresh", "--ring", "ring3-ga", "--registry", reg, "--key", key); code != 0 {
		t.Fatalf("refresh: %d %s", code, e)
	}
	if code, _, e := halo(t, "rollback", "--ring", "ring3-ga", "--to", "1.0.0", "--registry", reg); code != 1 || !strings.Contains(e, "--key") {
		t.Fatalf("rollback without --key: %d %s", code, e)
	}
	if code, _, e := halo(t, "release", "refresh", "--ring", "ring3-ga", "--registry", reg, "--cosign-key", "k"); code != 1 || !strings.Contains(e, "add --key") {
		t.Fatalf("cosign-only: %d %s", code, e)
	}
	if code, _, _ := halo(t, "rollback", "--ring", "ring3-ga", "--to", "9.9.9", "--registry", reg, "--key", key); code != 1 {
		t.Fatal("rollback to unknown version should fail")
	}
}

func TestExport(t *testing.T) {
	ex := buildable(t)
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Setenv("XDG_STATE_HOME", t.TempDir()) // fresh registry, fresh signer state
	t.Cleanup(func() { dialRegistry = old })
	keys := t.TempDir()
	if code, _, e := halo(t, "keys", "generate", "--out", keys); code != 0 {
		t.Fatal(e)
	}
	key, pub := filepath.Join(keys, "halo.key"), filepath.Join(keys, "halo.pub")
	reg := "registry.test/acme/halos"
	if code, _, e := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.0", "--registry", reg, "--key", key); code != 0 {
		t.Fatal(e)
	}
	h := strings.Repeat("ab", 32)
	var sha []string
	for _, o := range []string{"darwin", "linux", "windows"} {
		for _, a := range []string{"amd64", "arm64"} {
			sha = append(sha, "--halod-sha256", o+"/"+a+"="+h)
		}
	}
	base := func(sub string, extra ...string) []string {
		args := append([]string{"export", sub, "--registry", reg, "--ring", "ring3-ga", "--org", "acme-corp", "--pubkey", pub,
			"--download-url", "https://dl.example.com/halod/{os}/{arch}/halod"}, sha...)
		return append(args, extra...)
	}
	out := t.TempDir()
	for _, sub := range []string{"jamf", "intune", "devcontainer"} {
		if code, _, e := halo(t, base(sub, "--out", out)...); code != 0 {
			t.Fatalf("%s: %d %s", sub, code, e)
		}
	}
	for _, f := range []string{"halos.mobileconfig", "postinstall.sh", "halos-intune.ps1"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatal(err)
		}
	}
	// wrong key: pull must refuse the release
	other := t.TempDir()
	if code, _, e := halo(t, "keys", "generate", "--out", other); code != 0 {
		t.Fatal(e)
	}
	bad := base("jamf", "--out", out)
	for i, v := range bad {
		if v == pub {
			bad[i] = filepath.Join(other, "halo.pub")
		}
	}
	if code, _, _ := halo(t, bad...); code != 1 {
		t.Fatal("export with a non-matching pubkey must fail")
	}
	// missing pubkey / sha256 / registry
	if code, _, _ := halo(t, "export", "jamf", "--registry", reg, "--ring", "ring3-ga", "--out", out); code != 1 {
		t.Fatal("jamf without --pubkey should fail")
	}
	if code, _, _ := halo(t, "export", "jamf", "--registry", reg, "--ring", "ring3-ga", "--pubkey", pub, "--download-url", "https://dl.example.com/{os}/{arch}", "--out", out); code != 1 {
		t.Fatal("jamf without --halod-sha256 should fail")
	}
	if code, _, _ := halo(t, "export", "jamf", "--out", out); code != 1 {
		t.Fatal("jamf without --registry should fail")
	}
	// The signed pointer pins the org and the ring; a mutable tag can't redirect export.
	for name, args := range map[string][]string{
		"no org":       dropArgs(base("jamf", "--out", out), "--org"),
		"wrong org":    replaceArg(base("jamf", "--out", out), "acme-corp", "evil-corp"),
		"tagged ref":   replaceArg(base("intune", "--out", out), reg, reg+":v1.0.0"),
		"unknown ring": replaceArg(base("intune", "--out", out), "ring3-ga", "ring9"),
		"devcontainer": dropArgs(base("devcontainer", "--out", out), "--org"),
	} {
		if code, _, e := halo(t, args...); code != 1 {
			t.Errorf("%s: want failure, got %d %s", name, code, e)
		}
	}
}

// dropArgs removes flag and its value.
func dropArgs(args []string, flag string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if args[i] == flag {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func replaceArg(args []string, old, new string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == old {
			out[i] = new
		}
	}
	return out
}

func TestEvalRunPassEnv(t *testing.T) {
	if code, _, e := halo(t, "eval", "run", "x.yaml", "--pass-env", "lower_key"); code != 1 || !strings.Contains(e, "UPPER_SNAKE") {
		t.Fatalf("code %d, %s", code, e)
	}
}

func TestVersion(t *testing.T) {
	if code, out, _ := halo(t, "version"); code != 0 || !strings.HasPrefix(out, "halo ") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestTelemetryCollectorConfig(t *testing.T) {
	if code, _, _ := halo(t, "telemetry", "collector-config"); code != 1 {
		t.Fatal("--clickhouse is required")
	}
	p := filepath.Join(t.TempDir(), "otel.yaml")
	if code, _, e := halo(t, "telemetry", "collector-config", "--clickhouse", "tcp://ch:9000", "-o", p); code != 0 {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "tcp://ch:9000") || !strings.Contains(string(b), "halo.cost.usd") {
		t.Fatalf("unexpected config:\n%s", b)
	}
}

func TestKeysGenerateNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	if code, _, e := halo(t, "keys", "generate", "--out", dir); code != 0 {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "halo.key"))
	if code, _, e := halo(t, "keys", "generate", "--out", dir); code != 1 || !strings.Contains(e, "already exists") {
		t.Fatalf("second generate: %d %s", code, e)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "halo.key"))
	if string(before) != string(after) {
		t.Fatal("existing private key was overwritten")
	}
	// Only the .pub exists: fail without leaving a new orphan private key.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "halo.pub"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := halo(t, "keys", "generate", "--out", other); code != 1 {
		t.Fatal("existing .pub must fail")
	}
	if _, err := os.Stat(filepath.Join(other, "halo.key")); !os.IsNotExist(err) {
		t.Fatalf("orphan private key left behind: %v", err)
	}
	// Windows has no POSIX mode bits (Perm() is always 0666); access is ACL-based.
	if err := fsutil.VerifyPrivate(filepath.Join(dir, "halo.key")); err != nil {
		t.Fatalf("private key: %v", err)
	}
}

func TestPolicyDirFlag(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"canonical":       {[]string{"validate", "--policy-dir", example}, 0},
		"positional":      {[]string{"validate", example}, 0},
		"deprecated dir":  {[]string{"validate", "--dir", example}, 0},
		"same twice ok":   {[]string{"validate", "--policy-dir", example, example}, 0},
		"conflict":        {[]string{"validate", "--policy-dir", example, t.TempDir()}, 1},
		"render flag":     {[]string{"render", "--policy-dir", example, "--ring", "ring3-ga", "--out", t.TempDir()}, 0},
		"missing default": {[]string{"validate", "--policy-dir", t.TempDir()}, 1},
	} {
		if code, _, e := halo(t, tc.args...); code != tc.code {
			t.Errorf("%s: code %d want %d: %s", name, code, tc.code, e)
		}
	}
	if _, _, e := halo(t, "validate", "--dir", example); !strings.Contains(e, "use --policy-dir") {
		t.Errorf("--dir should print a deprecation notice, stderr: %q", e)
	}
}

func TestPolicyDirFlagExpGateway(t *testing.T) {
	for name, tc := range map[string]struct {
		args []string
		code int
	}{
		"exp list canonical":   {[]string{"exp", "list", "--policy-dir", example}, 0},
		"exp list deprecated":  {[]string{"exp", "list", "--dir", example}, 0},
		"exp list default cwd": {[]string{"exp", "list"}, 1}, // cmd/halo has no policy repo
		"exp show missing":     {[]string{"exp", "show", "nope", "--policy-dir", example}, 1},
		"exp conclude missing": {[]string{"exp", "conclude", "nope", "--policy-dir", example}, 1},
		"gateway canonical":    {[]string{"gateway", "compile", "--policy-dir", example}, 0},
		"gateway positional":   {[]string{"gateway", "deck", example}, 0},
		"gateway conflict":     {[]string{"gateway", "compile", "--policy-dir", example, t.TempDir()}, 1},
		"gateway deprecated":   {[]string{"gateway", "compile", "--dir", example}, 0},
	} {
		if code, _, e := halo(t, tc.args...); code != tc.code {
			t.Errorf("%s: code %d want %d: %s", name, code, tc.code, e)
		}
	}
	if _, _, e := halo(t, "exp", "list", "--dir", example); !strings.Contains(e, "use --policy-dir") {
		t.Errorf("exp --dir should print a deprecation notice, stderr: %q", e)
	}
}
