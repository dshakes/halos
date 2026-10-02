//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The state file halod writes must pass the SYSTEM-side trust check even when an admin user wrote
// it (enrollment runs `halod once` interactively, then the SYSTEM task reads it).
func TestStateFileIsTrustedBySystem(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "var")
	if err := mkdirManaged(dir); err != nil {
		t.Fatal(err)
	}
	a := &Agent{StatePath: filepath.Join(dir, "state.json")}
	if err := a.saveState(State{}); err != nil {
		t.Fatal(err)
	}
	saved := testTrustedSID
	testTrustedSID = "" // the production rule: only SYSTEM, Administrators, TrustedInstaller
	defer func() { testTrustedSID = saved }()
	fi, err := os.Stat(a.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkTrusted(a.StatePath, fi); err != nil {
		if errors.Is(err, errUntrustedOwner) {
			t.Skipf("runner process is not elevated, so it owns its files: %v", err)
		}
		t.Fatal(err)
	}
}
