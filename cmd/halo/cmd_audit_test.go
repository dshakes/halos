package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/bundle"
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

	// a missing oldest segment no audit.retention entry records (ADR-0040) breaks the chain
	if err := os.Remove(seg); err != nil {
		t.Fatal(err)
	}
	if code, out, _ = halo(t, "audit", "verify", "--data-dir", dir); code != exitValidation || !strings.Contains(out, "oldest entries were removed") {
		t.Fatalf("missing segment: %d %q", code, out)
	}

	if code, _, errOut = halo(t, "audit", "verify"); code != exitError || !strings.Contains(errOut, "data-dir") {
		t.Fatalf("no --data-dir: %d %q", code, errOut)
	}
	if code, _, errOut = halo(t, "audit", "verify", "--data-dir", filepath.Join(dir, "nope")); code != exitError || !strings.Contains(errOut, "audit") {
		t.Fatalf("missing dir: %d %q", code, errOut)
	}
}

// TestAuditVerifySigned: --public-key checks the checkpoints halo-server
// signed (ADR-0041) and --anchor, the newest one a SIEM holds, catches a log
// cut back behind it; both exit 2 on tamper.
func TestAuditVerifySigned(t *testing.T) {
	dir, keys := t.TempDir(), t.TempDir()
	priv, pub, err := bundle.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	k, err := bundle.ParseSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubFile := filepath.Join(keys, "audit.pub")
	if err := os.WriteFile(pubFile, pub, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{PolicyDir: "../../examples/acme-corp", Token: "t", DataDir: dir, DevUser: "admin@test", DevAdmin: true,
		AuditSigner: k, AuditSigningEnable: true, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range 3 {
		srv.Audit(ctx, "alice", "experiment.kill", "exp", nil)
	}
	if ok, err := srv.Checkpoint(ctx); !ok || err != nil {
		t.Fatalf("checkpoint: %v %v", ok, err)
	}
	srv.Audit(ctx, "alice", "experiment.unkill", "exp", nil)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(dir, "audit.jsonl")
	b, err := os.ReadFile(active)
	if err != nil {
		t.Fatal(err)
	}
	siem := filepath.Join(keys, "siem.jsonl") // the SIEM's copy
	if err := os.WriteFile(siem, b, 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile, "--anchor", siem)
	if code != 0 || !strings.Contains(out, "OK: 6 entries") || !strings.Contains(out, "1 signed checkpoints, last at seq 5") || !strings.Contains(out, "anchored") {
		t.Fatalf("verify: %d %q %q", code, out, errOut)
	}
	if code, out, _ := halo(t, "audit", "verify", "--file", siem, "--public-key", pubFile, "--public-key", pubFile); code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("verify export: %d %q", code, out)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--compare-export", siem); code != 0 {
		t.Fatalf("compare with the export: %d %q", code, out)
	}
	// R4-A(3): the key alone warns that deletion is not detected; --strict
	// needs an external anchor.
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile); code != 0 || !strings.Contains(out, "warning: no external anchor") {
		t.Fatalf("key only: %d %q", code, out)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile, "--strict"); code != exitValidation || !strings.Contains(out, "--strict needs") {
		t.Fatalf("strict without an anchor: %d %q", code, out)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile, "--compare-export", siem, "--strict"); code != 0 {
		t.Fatalf("strict with the export: %d %q", code, out)
	}
	// R4-C: an empty log does not pass --public-key.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, "audit.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", empty, "--public-key", pubFile); code != exitValidation || !strings.Contains(out, "no signed checkpoint") {
		t.Fatalf("empty log with the key: %d %q", code, out)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile, "--max-unsigned-tail", "0"); code != exitValidation || !strings.Contains(out, "max-unsigned-tail") {
		t.Fatalf("unsigned tail over the limit: %d %q", code, out)
	}

	// Cut the log back before the checkpoint: the chain alone still verifies,
	// the anchor does not.
	lines := strings.SplitAfter(string(b), "\n")
	if err := os.WriteFile(active, []byte(strings.Join(lines[:3], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir); code != 0 || !strings.Contains(out, "not authenticated") {
		t.Fatalf("truncated log, links only: %d %q", code, out)
	}
	// With the key, a log that carries no signed checkpoint at all fails (L2).
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile); code != exitValidation || !strings.Contains(out, "no signed checkpoint") {
		t.Fatalf("truncated log with the key: %d %q", code, out)
	}
	// --compare-export catches the cut too, by content.
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--compare-export", siem); code != exitValidation || !strings.Contains(out, "cut from the end") {
		t.Fatalf("truncated log against the export: %d %q", code, out)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile, "--anchor", siem); code != exitValidation || !strings.Contains(out, "cut from the end") {
		t.Fatalf("truncated log with the anchor: %d %q", code, out)
	}

	// A forged checkpoint signature exits 2.
	forged := strings.Replace(string(b), `"sig":"`, `"sig":"AAAA`, 1)
	if err := os.WriteFile(active, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := halo(t, "audit", "verify", "--data-dir", dir, "--public-key", pubFile); code != exitValidation || !strings.Contains(out, "BROKEN") {
		t.Fatalf("forged signature: %d %q", code, out)
	}
	if code, _, errOut := halo(t, "audit", "verify", "--data-dir", dir, "--anchor", pubFile); code != exitError || !strings.Contains(errOut, "no audit.checkpoint") {
		t.Fatalf("anchor file without a checkpoint: %d %q", code, errOut)
	}
}
