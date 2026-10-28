package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var pinned = regexp.MustCompile(`uses: [a-z-]+/[a-z-]+@[0-9a-f]{40} # v`)

func TestCloudAgentsRender(t *testing.T) {
	out := t.TempDir()
	code, stdout, stderr := halo(t, "cloud-agents", "render", "--policy-dir", example, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	for _, f := range []string{"halos-claude.yml", "halos-gemini.yml", "copilot-setup-steps.yml"} {
		b, err := os.ReadFile(filepath.Join(out, ".github", "workflows", f))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "permissions: {}") || !pinned.MatchString(string(b)) {
			t.Fatalf("%s:\n%s", f, b)
		}
	}
	if !strings.Contains(stdout, "cursor: configured in the vendor console") {
		t.Fatalf("warnings missing:\n%s", stdout)
	}
	code, stdout, _ = halo(t, "--output", "json", "cloud-agents", "render", "--policy-dir", example)
	var res struct {
		Files []struct {
			Vendor, Path, Content string
		}
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &res) != nil || len(res.Files) != 3 || res.Files[0].Content == "" {
		t.Fatalf("json render: %d %s", code, stdout)
	}
}

func TestCloudAgentsListDirect(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-test" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		run := map[string]any{"id": 7, "path": ".github/workflows/halos-claude.yml", "status": "in_progress", "created_at": "2026-10-27T10:00:00Z",
			"updated_at": "2026-10-27T10:00:00Z", "actor": map[string]any{"login": "alice-acme"}, "repository": map[string]any{"full_name": strings.TrimPrefix(strings.TrimSuffix(r.URL.Path, "/actions/runs"), "/repos/")}}
		_ = json.NewEncoder(w).Encode(map[string]any{"workflow_runs": []any{run}})
	}))
	defer gh.Close()
	t.Setenv("HALO_CLOUD_GITHUB_TOKEN", "gh-test")
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	code, stdout, stderr := halo(t, "cloud-agents", "list", "--policy-dir", example, "--github-base-url", gh.URL)
	// The fake answers one running claude run per listed repo: alice runs two,
	// acme allows 2 per user, so no alert.
	if code != 0 {
		t.Fatalf("exit %d:\n%s\n%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "claude:acme-corp/web:7") || !strings.Contains(stdout, "alice@acme.com") || !strings.Contains(stderr, "acme-corp/*") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", stdout, stderr)
	}

	t.Setenv("HALO_CLOUD_GITHUB_TOKEN", "")
	if code, _, stderr := halo(t, "cloud-agents", "list", "--policy-dir", example); code == 0 || !strings.Contains(stderr, "no credential") {
		t.Fatalf("no credential: %d %s", code, stderr)
	}
}

func TestCloudAgentsKillNeedsReasonAndServer(t *testing.T) {
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSION", "")
	if code, _, stderr := halo(t, "cloud-agents", "kill", "--name", "alice@acme.com"); code == 0 || !strings.Contains(stderr, "--reason") {
		t.Fatalf("%d %s", code, stderr)
	}
	if code, _, stderr := halo(t, "cloud-agents", "kill", "--name", "alice@acme.com", "--reason", "x"); code == 0 || !strings.Contains(stderr, "HALO_SESSION") {
		t.Fatalf("%d %s", code, stderr)
	}
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"dryRun":true,"actions":[],"unattributed":0,"next_steps":["re-run"]}`))
	}))
	defer srv.Close()
	t.Setenv("HALO_SESSION", "s")
	code, stdout, stderr := halo(t, "cloud-agents", "kill", "--scope", "ring", "--name", "ring1-canary", "--reason", "incident", "--server", srv.URL)
	if code != 0 || got["dryRun"] != true || got["scope"] != "ring" || !strings.Contains(stdout, "dry run") {
		t.Fatalf("%d %v %s %s", code, got, stdout, stderr)
	}
}
