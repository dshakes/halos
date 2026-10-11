package mcpserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/onboard"
)

// fakeMachine has claude 2.1.280 on PATH and no credential variables.
func fakeMachine() *onboard.Env {
	return &onboard.Env{
		GOOS:   "linux",
		Getenv: func(string) string { return "" },
		LookPath: func(b string) (string, error) {
			if b == "claude" {
				return "/usr/bin/claude", nil
			}
			return "", errors.New("not found")
		},
		Run: func(context.Context, string, ...string) ([]byte, error) { return []byte("2.1.280 (Claude Code)"), nil },
	}
}

func TestOnboardToolsFromEmptyDir(t *testing.T) {
	dir := t.TempDir()
	ro := connect(t, Options{PolicyDir: dir, Onboard: fakeMachine()})
	names := toolNames(t, ro)
	for _, n := range []string{"doctor", "detect_harnesses", "init_policy", "local_install", "local_proxy", "verify_harness", "onboard_company", "plan"} {
		if !names[n] {
			t.Errorf("tool %s missing", n)
		}
	}

	d, err := call(t, ro, "doctor", nil)
	if err != nil || d["ok"] != true {
		t.Fatalf("doctor: %v %v", err, d)
	}
	h, err := call(t, ro, "detect_harnesses", nil)
	if err != nil || h["suggested_provider"] != "anthropic" {
		t.Fatalf("detect: %v %v", err, h)
	}

	// Preview: tools default to the CLI on PATH; nothing is written.
	p, err := call(t, ro, "init_policy", map[string]any{"org": "me"})
	if err != nil {
		t.Fatal(err)
	}
	pol := p["policy"].(map[string]any)
	if pol["action"] != "create" || p["valid"] != true || !strings.Contains(pol["content"].(string), "claude-code: 2.1.280") {
		t.Fatalf("preview: %v", p)
	}
	if _, err := os.Stat(filepath.Join(dir, "halos.yaml")); !os.IsNotExist(err) {
		t.Fatal("preview wrote halos.yaml")
	}
	if _, err := call(t, ro, "init_policy", map[string]any{"org": "me", "dry_run": false}); err == nil || !strings.Contains(err.Error(), "halo onboard local") {
		t.Fatalf("read-only server must refuse to write and name the CLI: %v", err)
	}

	rw := connect(t, Options{PolicyDir: dir, AllowWrites: true, Onboard: fakeMachine()})
	if p, err = call(t, rw, "init_policy", map[string]any{"org": "me", "dry_run": false}); err != nil || p["policy"].(map[string]any)["action"] != "create" {
		t.Fatalf("write: %v %v", err, p)
	}
	if p, err = call(t, rw, "init_policy", map[string]any{"org": "me", "dry_run": false}); err != nil || p["policy"].(map[string]any)["action"] != "unchanged" {
		t.Fatalf("idempotent: %v %v", err, p)
	}
	v, err := call(t, rw, "validate", nil)
	if err != nil || v["ok"] != true {
		t.Fatalf("validate: %v %v", err, v)
	}
	pl, err := call(t, rw, "plan", map[string]any{"ring": "ring3-ga"})
	if err != nil || pl["changed"] != true {
		t.Fatalf("plan without baseline: %v %v", err, pl)
	}

	root := t.TempDir()
	in, err := call(t, rw, "local_install", map[string]any{"root": root})
	if err != nil || in["dry_run"] != true {
		t.Fatalf("install preview: %v %v", err, in)
	}
	files := in["plan"].(map[string]any)["files"].([]any)
	if len(files) == 0 || files[0].(map[string]any)["action"] != "create" {
		t.Fatalf("plan files: %v", files)
	}
	if in, err = call(t, rw, "local_install", map[string]any{"root": root, "dry_run": false}); err != nil || len(in["written"].([]any)) != len(files) {
		t.Fatalf("install: %v %v", err, in)
	}
	if in, err = call(t, rw, "local_install", map[string]any{"root": root, "dry_run": false}); err != nil || len(in["written"].([]any)) != 0 {
		t.Fatalf("install not idempotent: %v %v", err, in)
	}
	// A file someone else rewrote is refused, nothing is written, and the plan
	// still comes back so the agent can show which file is foreign.
	dest := files[0].(map[string]any)["dest"].(string)
	if err := os.WriteFile(dest, []byte("mdm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err = call(t, rw, "local_install", map[string]any{"root": root, "dry_run": false})
	if err != nil || len(in["written"].([]any)) != 0 || !strings.Contains(in["note"].(string), "refused") ||
		in["plan"].(map[string]any)["files"].([]any)[0].(map[string]any)["action"] != "foreign" {
		t.Fatalf("foreign refusal: %v %v", err, in)
	}
	if b, _ := os.ReadFile(dest); string(b) != "mdm\n" {
		t.Fatalf("refused install touched the file: %q", b)
	}

	px, err := call(t, rw, "local_proxy", nil)
	if err != nil || px["dryRun"] != true || !strings.HasPrefix(px["command"].(string), "halo-proxy --config ") {
		t.Fatalf("proxy: %v %v", err, px)
	}

	vr, err := call(t, rw, "verify_harness", map[string]any{"harness": "claude-code", "assume_auth": true})
	if err != nil || vr["status"] != onboard.VerifyDryRun {
		t.Fatalf("verify: %v %v", err, vr)
	}
	if vr, err = call(t, rw, "verify_harness", map[string]any{"harness": "claude-code"}); err != nil || vr["status"] != onboard.VerifySkipped {
		t.Fatalf("verify without credentials: %v %v", err, vr)
	}
	// A real run spawns the CLI and spends the human's credentials: read-only refuses it, --allow-writes runs it.
	real := map[string]any{"harness": "claude-code", "assume_auth": true, "dry_run": false}
	if vr, err = call(t, ro, "verify_harness", real); err == nil || !strings.Contains(err.Error(), "halo onboard verify claude-code") {
		t.Fatalf("read-only verify_harness must refuse a real run: %v %v", err, vr)
	}
	if vr, err = call(t, rw, "verify_harness", real); err != nil || vr["status"] != onboard.VerifyFail || !strings.Contains(vr["detail"].(string), "HALOS_OK") {
		t.Fatalf("verify with --allow-writes must run the fake CLI: %v %v", err, vr)
	}
}

func TestOnboardCompanyTool(t *testing.T) {
	dir := t.TempDir()
	args := map[string]any{"org": "acme", "tools": map[string]any{"claude-code": "2.1.280"}, "gateway": "https://ai.acme.example",
		"gateway_kind": "kong", "issuer": "https://login.acme.example", "admin_groups": []any{"ai-platform"}, "delivery": []any{"mdm"},
		"registry": "ghcr.io/acme/halos-releases", "policy_repo": "https://github.com/acme/halos-policy.git", "portal_url": "https://halos.acme.example"}
	ro := connect(t, Options{PolicyDir: dir, Onboard: fakeMachine()})
	r, err := call(t, ro, "onboard_company", args)
	if err != nil || r["valid"] != true || r["dryRun"] != true {
		t.Fatalf("%v %v", err, r)
	}
	if _, err := os.Stat(filepath.Join(dir, "halos.yaml")); !os.IsNotExist(err) {
		t.Fatal("dry run wrote")
	}
	args["dry_run"] = false
	if _, err := call(t, ro, "onboard_company", args); err == nil {
		t.Fatal("read-only server wrote")
	}
	rw := connect(t, Options{PolicyDir: dir, AllowWrites: true, Onboard: fakeMachine()})
	if r, err = call(t, rw, "onboard_company", args); err != nil || r["valid"] != true {
		t.Fatalf("%v %v", err, r)
	}
	if v, err := call(t, rw, "validate", nil); err != nil || v["ok"] != true {
		t.Fatalf("generated repo does not validate: %v %v", err, v)
	}
}
