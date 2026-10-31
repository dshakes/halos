package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/shadow"
)

// eval_harvest previews without --allow-writes, never returns request
// content, and writes 0600 cases under the policy dir only when allowed.
func TestEvalHarvest(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, "pair.key"), []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := shadow.NewFileStore(filepath.Join(dir, "pairs.jsonl"), shadow.StoreOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	req := `{"model":"sonnet","tools":[{"name":"Bash","input_schema":{"type":"object","required":["command"]}}],` +
		`"messages":[{"role":"user","content":"run the tests, token AKIAIOSFODNN7EXAMPLE"}]}`
	p := shadow.Pair{ID: "p1", Experiment: "opus-shadow", SessionID: "raw-session", Protocol: "anthropic-messages", Request: json.RawMessage(req),
		Control:   shadow.Side{Status: 200, Response: json.RawMessage(`{"content":[{"type":"tool_use","id":"a","name":"Bash","input":{"command":"go test ./..."}}]}`)},
		Candidate: shadow.Side{Status: 200, Response: json.RawMessage(`{"content":[{"type":"text","text":"Done."}]}`)}}
	if err := store.Append(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	args := map[string]any{"pairs": "pairs.jsonl", "pair_key_files": []string{"pair.key"}}

	ro := connect(t, Options{PolicyDir: dir})
	out, err := call(t, ro, "eval_harvest", args)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if out["dry_run"] != true || out["selected"] != float64(1) || strings.Contains(string(b), "AKIA") || strings.Contains(string(b), "raw-session") {
		t.Fatalf("preview: %s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "evals")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote cases")
	}
	args["dry_run"] = false
	if _, err := call(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}), "eval_harvest", args); err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("write without a reason: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evals")); !os.IsNotExist(err) {
		t.Fatal("write without a reason wrote cases")
	}
	args["reason"] = "candidate regressed on tool calls"
	if _, err := call(t, ro, "eval_harvest", args); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("write without --allow-writes: %v", err)
	}
	args["out"] = "../outside"
	if _, err := call(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}), "eval_harvest", args); err == nil {
		t.Fatal("wrote outside the policy dir")
	}
	delete(args, "out")
	out, err = call(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}), "eval_harvest", args)
	if err != nil || out["written"] != true || out["reason"] != "candidate regressed on tool calls" {
		t.Fatalf("write: %v %v", out, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "evals", "steps", "*.json"))
	if len(files) != 1 {
		t.Fatalf("files %v", files)
	}
	if st, _ := os.Stat(files[0]); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // no POSIX mode bits on Windows
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}

// R5: an unsealed row in a sealed store is refused, and the error names the
// MCP argument (not the CLI flag); allow_plaintext_pairs: true migrates, and
// the copy-paste command carries the CLI flag.
func TestEvalHarvestPlaintextRows(t *testing.T) {
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(filepath.Join(dir, "pair.key"), []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	row := `{"id":"p1","experiment":"exp","protocol":"anthropic-messages","request":{"model":"m","messages":[{"role":"user","content":"hi"}]}}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "pairs.jsonl"), []byte(row), 0o600); err != nil {
		t.Fatal(err)
	}
	ro := connect(t, Options{PolicyDir: dir})
	args := map[string]any{"pairs": "pairs.jsonl", "pair_key_files": []string{"pair.key"}}
	_, err := call(t, ro, "eval_harvest", args)
	if err == nil || !strings.Contains(err.Error(), "allow_plaintext_pairs") || strings.Contains(err.Error(), "--allow-plaintext-pairs") {
		t.Fatalf("plaintext row, default: %v", err)
	}
	args["allow_plaintext_pairs"] = true
	out, err := call(t, ro, "eval_harvest", args)
	if err != nil {
		t.Fatalf("migration: %v", err)
	}
	if cmd, _ := out["command"].(string); !strings.Contains(cmd, "--allow-plaintext-pairs") {
		t.Fatalf("command lacks the CLI flag: %q", cmd)
	}
}

// The preview's copy-paste command must survive a POSIX shell intact: every
// interpolated value is quoted, so a pattern or path cannot inject a command.
func TestEvalHarvestCommandIsShellQuoted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX sh")
	}
	dir := filepath.Join(t.TempDir(), "policy dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := shadow.NewFileStore(filepath.Join(dir, "pairs.jsonl"), shadow.StoreOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	pattern := `x'; touch pwned; echo '$(id) "a b"`
	out, err := call(t, connect(t, Options{PolicyDir: dir}), "eval_harvest", map[string]any{
		"pairs": "pairs.jsonl", "redact_patterns": []string{pattern}, "keep_fields": []string{"a b"}, "experiment": "e;id"})
	if err != nil {
		t.Fatal(err)
	}
	argv := shArgv(t, out["command"].(string))
	want := []string{"--redact-pattern", pattern, "--keep-field", "a b", "--experiment", "e;id"}
	for i := 0; i < len(want); i += 2 {
		if j := slices.Index(argv, want[i]); j < 0 || j+1 >= len(argv) || argv[j+1] != want[i+1] {
			t.Errorf("%s: argv %q, want %q", want[i], argv, want[i+1])
		}
	}
	if !slices.Contains(argv, filepath.Join(dir, "pairs.jsonl")) {
		t.Errorf("pairs path with a space split: %q", argv)
	}
}

// shArgv is the argv a POSIX shell parses cmd into (nothing runs: the words
// are only printed).
func shArgv(t *testing.T, cmd string) []string {
	t.Helper()
	b, err := exec.Command("sh", "-c", "set -- "+cmd+"; printf '%s\\0' \"$@\"").Output()
	if err != nil {
		t.Fatalf("sh parse %q: %v", cmd, err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
}
