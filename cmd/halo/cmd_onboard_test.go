package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnboardLocalE2E drives the my-machine path non-interactively from an
// empty directory: preview, write the policy, validate, plan, a dry-run and a
// staged install, each rerun idempotent.
func TestOnboardLocalE2E(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policy")
	root := t.TempDir()
	flags := []string{"--policy-dir", dir, "--org", "me", "--tools", "claude-code@2.1.280,codex@0.99.0", "--provider", "anthropic", "--output", "json"}

	code, out, errOut := halo(t, append([]string{"onboard", "local"}, flags...)...)
	if code != 0 {
		t.Fatalf("preview exit %d: %s", code, errOut)
	}
	var r struct {
		DryRun  bool
		Valid   bool
		Policy  struct{ Action, Content string }
		Install struct {
			Gateway string
			Files   []struct{ Harness, Dest, Action string }
		}
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err, out)
	}
	if !r.DryRun || !r.Valid || r.Policy.Action != "create" || r.Install.Gateway != "http://127.0.0.1:8088" || len(r.Install.Files) == 0 {
		t.Fatalf("preview: %+v", r)
	}
	if !strings.Contains(r.Policy.Content, "codex: {version: 0.99.0, model: codex}") {
		t.Fatalf("codex needs its own model alias on anthropic:\n%s", r.Policy.Content)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("preview wrote")
	}

	if code, _, errOut = halo(t, append([]string{"onboard", "local", "--apply"}, flags...)...); code != 0 {
		t.Fatalf("apply exit %d: %s", code, errOut)
	}
	if code, _, _ = halo(t, "validate", "--policy-dir", dir); code != 0 {
		t.Fatal("generated policy does not validate")
	}
	_, out, _ = halo(t, append([]string{"onboard", "local", "--apply"}, flags...)...)
	if !strings.Contains(out, `"action": "unchanged"`) {
		t.Fatalf("rerun not idempotent: %s", out)
	}

	code, out, errOut = halo(t, "onboard", "install", "--policy-dir", dir, "--root", root)
	if code != 0 || !strings.Contains(out, "would create") || !strings.Contains(out, "dry run: nothing written") {
		t.Fatalf("install preview exit %d:\n%s%s", code, out, errOut)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatal("install dry run wrote")
	}
	if code, out, errOut = halo(t, "onboard", "install", "--policy-dir", dir, "--root", root, "--apply"); code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("install exit %d:\n%s%s", code, out, errOut)
	}
	var plan struct {
		Plan struct {
			Files []struct{ Harness, Dest string }
		}
	}
	_, out, _ = halo(t, "onboard", "install", "--policy-dir", dir, "--root", root, "--output", "json")
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, f := range plan.Plan.Files {
		if f.Harness != "claude-code" || !strings.HasSuffix(f.Dest, "managed-settings.json") {
			continue
		}
		b, err := os.ReadFile(f.Dest)
		if err != nil || !strings.Contains(string(b), "http://127.0.0.1:8088") {
			t.Fatalf("%s does not point claude at the local proxy (%v):\n%s", f.Dest, err, b)
		}
		checked = true
	}
	if !checked {
		t.Fatalf("no claude-code managed-settings.json installed: %s", out)
	}
	code, out, _ = halo(t, "onboard", "install", "--policy-dir", dir, "--root", root, "--apply", "--output", "json")
	if code != 0 || !strings.Contains(out, `"written": []`) {
		t.Fatalf("second install wrote files: %s", out)
	}

	if code, out, _ = halo(t, "onboard", "proxy", "--policy-dir", dir); code != 0 || !strings.Contains(out, "halo-proxy --config") {
		t.Fatalf("proxy: %s", out)
	}
	if code, out, _ = halo(t, "doctor", "--policy-dir", dir, "--output", "json"); !strings.Contains(out, `"id": "policy"`) {
		t.Fatalf("doctor exit %d: %s", code, out)
	}
}

func TestOnboardCompanyCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	args := []string{"onboard", "company", "--policy-dir", dir, "--org", "acme", "--gateway", "https://ai.acme.example",
		"--issuer", "https://login.acme.example", "--admin-group", "ai-platform", "--delivery", "halod,devcontainer",
		"--registry", "ghcr.io/acme/halos-releases", "--policy-repo", "https://github.com/acme/halos-policy.git",
		"--portal-url", "https://halos.acme.example"}
	code, out, errOut := halo(t, args...)
	if code != 0 || !strings.Contains(out, "would create") {
		t.Fatalf("exit %d:\n%s%s", code, out, errOut)
	}
	if code, _, errOut = halo(t, append(args, "--apply")...); code != 0 {
		t.Fatal(errOut)
	}
	if code, _, _ = halo(t, "validate", "--policy-dir", dir); code != 0 {
		t.Fatal("company repo does not validate")
	}
	// The generated CI workflow and README run plan with no baseline (the first release).
	if code, out, errOut = halo(t, "plan", "--policy-dir", dir, "--ring", "ring3-ga"); code != 0 || !strings.Contains(out, "+") {
		t.Fatalf("plan without --against: exit %d\n%s%s", code, out, errOut)
	}
	if code, _, errOut = halo(t, append(args, "--apply")...); code != 0 {
		t.Fatalf("rerun: %s", errOut)
	}
	if code, _, _ = halo(t, "onboard", "company", "--policy-dir", dir, "--org", "acme"); code == 0 {
		t.Fatal("missing required answers accepted")
	}
}

func TestQuickstartDryRun(t *testing.T) {
	code, out, _ := halo(t, "quickstart", "--src", "../..", "--dry-run")
	if code != 0 || !strings.Contains(out, "./scripts/demo.sh") || strings.Contains(out, "git clone") {
		t.Fatalf("exit %d: %s", code, out)
	}
	code, out, _ = halo(t, "quickstart", "down", "--src", t.TempDir(), "--dry-run")
	if code != 0 || !strings.Contains(out, "git clone --depth 1 https://github.com/dshakes/halos") || !strings.Contains(out, "demo.sh down") {
		t.Fatalf("exit %d: %s", code, out)
	}
}
