package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	if _, err := call(t, ro, "eval_harvest", args); err == nil || !strings.Contains(err.Error(), "--allow-writes") {
		t.Fatalf("write without --allow-writes: %v", err)
	}
	args["out"] = "../outside"
	if _, err := call(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}), "eval_harvest", args); err == nil {
		t.Fatal("wrote outside the policy dir")
	}
	delete(args, "out")
	out, err = call(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}), "eval_harvest", args)
	if err != nil || out["written"] != true {
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
