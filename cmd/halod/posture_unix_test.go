//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// A FIFO where a user settings file belongs must not hang halod's cycle.
func TestReadSettingsFIFO(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "config.toml")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	a := &Agent{}
	done := make(chan error, 1)
	go func() { _, err := a.readSettings(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO as a settings file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSettings blocked on a FIFO")
	}
	_ = os.Remove(p)
}

// MCP drift reads user configs as root: a symlink (to a file only root can
// read) is not followed, so its servers are never echoed into findings, and a
// FIFO does not hang the cycle.
func TestMCPDriftUserFileSafety(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "dev")
	if err := os.MkdirAll(filepath.Join(home, ".gemini"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "root-only.json")
	if err := os.WriteFile(secret, []byte(`{"mcpServers":{"leak":{"command":"tool","args":["--token","s3cr3t"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(home, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(home, ".gemini", "settings.json"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	a := &Agent{Home: func(string) string { return home }}
	rel := &release.Release{Manifest: release.Manifest{Ring: "ga", MCPMode: policy.MCPModeAllowlist,
		Harnesses: map[string]release.HarnessEntry{"claude-code": {}, "gemini-cli": {}}}}
	done := make(chan []policy.MCPFinding, 1)
	go func() { done <- a.mcpDrift(rel, nil) }()
	select {
	case f := <-done:
		if len(f) != 0 {
			t.Fatalf("read through a symlink or FIFO: %+v", f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mcpDrift blocked on a FIFO")
	}
}
