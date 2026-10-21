package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/server"
)

func TestAuditVerify(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	add := func(n int) {
		for range n {
			if err := server.AppendAuditOffline(dir, "alice", "experiment.kill", "exp", map[string]string{"reason": "r"}, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(2)
	// a rotated segment (what halo-server's rotation leaves), then more in the active one
	if err := os.Rename(filepath.Join(dir, "audit.jsonl"), filepath.Join(dir, "audit-00000000000000000001.jsonl")); err != nil {
		t.Fatal(err)
	}
	add(2)

	code, out, errOut := halo(t, "audit", "verify", "--data-dir", dir)
	if code != 0 || !strings.Contains(out, "OK: 4 entries in 2 segments") {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	}
	code, out, _ = halo(t, "--output", "json", "audit", "verify", "--data-dir", dir)
	var r struct {
		OK       bool   `json:"ok"`
		Entries  int    `json:"entries"`
		Segments int    `json:"segments"`
		Head     string `json:"head"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || code != 0 || !r.OK || r.Entries != 4 || r.Segments != 2 || len(r.Head) != 64 {
		t.Fatalf("json: %d %q %v", code, out, err)
	}

	// tamper with the rotated segment: exit 2 and the reason
	seg := filepath.Join(dir, "audit-00000000000000000001.jsonl")
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seg, []byte(strings.Replace(string(b), `"actor":"alice"`, `"actor":"mallory"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = halo(t, "audit", "verify", "--data-dir", dir)
	if code != exitValidation || !strings.Contains(out, "BROKEN") || !strings.Contains(out, "hash mismatch") {
		t.Fatalf("tampered: %d %q", code, out)
	}

	// a missing segment breaks the chain at the boundary
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if code, out, _ = halo(t, "audit", "verify", "--data-dir", dir); code != exitValidation || !strings.Contains(out, "out of order") {
		t.Fatalf("missing segment: %d %q", code, out)
	}

	if code, _, errOut = halo(t, "audit", "verify"); code != exitError || !strings.Contains(errOut, "data-dir") {
		t.Fatalf("no --data-dir: %d %q", code, errOut)
	}
	if code, _, errOut = halo(t, "audit", "verify", "--data-dir", filepath.Join(dir, "nope")); code != exitError || !strings.Contains(errOut, "audit") {
		t.Fatalf("missing dir: %d %q", code, errOut)
	}
}
