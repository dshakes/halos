package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/release"
)

func TestPostureDrift(t *testing.T) {
	const req = "allowed_sandbox_modes = ['read-only', 'workspace-write']\n"
	tests := []struct {
		name    string
		files   map[string]string
		home    string
		harness string
		want    []string // drift entries (prefix match)
	}{
		{"user escapes managed sandbox", map[string]string{"etc/codex/requirements.toml": req, "home/alice/.codex/config.toml": `sandbox_mode = "danger-full-access"`},
			"/home/alice", "codex", []string{`posture:codex: ~/.codex/config.toml sets sandbox_mode = "danger-full-access"; fix: remove`}},
		{"clean user config", map[string]string{"etc/codex/requirements.toml": req, "home/alice/.codex/config.toml": `model = "x"`}, "/home/alice", "codex", nil},
		{"no managed sandbox, no finding", map[string]string{"home/alice/.codex/config.toml": `sandbox_mode = "danger-full-access"`}, "/home/alice", "codex", nil},
		{"unknown home skips", map[string]string{"etc/codex/requirements.toml": req, "home/alice/.codex/config.toml": `sandbox_mode = "danger-full-access"`}, "", "codex", nil},
		{"oversized file ignored", map[string]string{"etc/codex/requirements.toml": req, "home/alice/.codex/config.toml": `sandbox_mode = "danger-full-access"` + strings.Repeat("\n", maxPostureFile)}, "/home/alice", "codex", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for p, data := range tt.files {
				fp := filepath.Join(root, filepath.FromSlash(p))
				if err := os.MkdirAll(filepath.Dir(fp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fp, []byte(data), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			a := &Agent{Root: root, User: "alice", Cfg: Config{OS: "linux"}, Home: func(string) string { return tt.home }}
			rel := &release.Release{Manifest: release.Manifest{Harnesses: map[string]release.HarnessEntry{tt.harness: {}}}}
			st := &Status{}
			a.postureDrift(rel, st)
			if len(st.Drift) != len(tt.want) {
				t.Fatalf("drift = %q, want %d entries", st.Drift, len(tt.want))
			}
			for i, w := range tt.want {
				if !strings.HasPrefix(st.Drift[i], w) {
					t.Errorf("drift[%d] = %q, want prefix %q", i, st.Drift[i], w)
				}
			}
			if slices.ContainsFunc(st.Drift, func(d string) bool { return strings.Contains(d, "\n") }) {
				t.Error("drift entry contains a newline")
			}
		})
	}
}
