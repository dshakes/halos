//go:build !windows

package signer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// L3: the signer sees PATH, HOME, HALOS_SIGNER_* and the env= names only;
// nothing else from Halos' environment (cloud credentials, tokens) leaks.
func TestExecSignerEnvironmentAllowlist(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := writeKey(t, k)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
	t.Setenv("HALO_TOKEN", "do-not-leak")
	t.Setenv("HSM_PIN", "1234")
	t.Setenv("HALOS_SIGNER_SLOT", "0")
	_, err := Open(context.Background(), execURI(t, key, "dumpenv", "&env=HSM_PIN"), Options{})
	if err == nil {
		t.Fatal("dumpenv answers an error")
	}
	got := map[string]bool{}
	for _, n := range strings.Split(strings.TrimPrefix(err.Error()[strings.Index(err.Error(), "env:"):], "env:"), ",") {
		got[n] = true
	}
	for _, want := range []string{"PATH", "HOME", "HSM_PIN", "HALOS_SIGNER_SLOT", "HALOS_SIGNER_FAKE_MODE"} {
		if !got[want] {
			t.Errorf("signer did not get %s (got %v)", want, got)
		}
	}
	for _, leak := range []string{"AWS_SECRET_ACCESS_KEY", "HALO_TOKEN"} {
		if got[leak] {
			t.Errorf("signer received %s", leak)
		}
	}
	if _, err := parseExecURI("exec:///bin/s?env=BAD-NAME"); err == nil {
		t.Fatal("bad env= name accepted")
	}
}

// L3: stderr never reaches an error string (it may carry a PIN or a key
// handle); it is logged at debug level, truncated.
func TestExecSignerStderrNotInErrors(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, err := Open(context.Background(), execURI(t, writeKey(t, k), "exit1", ""), Options{Log: log})
	if err == nil || strings.Contains(err.Error(), "PIN=123456") || strings.Contains(err.Error(), "hsm unavailable") {
		t.Fatalf("stderr in the error: %v", err)
	}
	if !strings.Contains(logs.String(), "hsm unavailable") {
		t.Fatalf("stderr not logged at debug: %q", logs.String())
	}
}

// L4: on timeout the signer's whole process group dies, so a helper it
// spawned cannot keep running (and holding the key session).
func TestExecSignerTimeoutKillsProcessGroup(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	marker := filepath.Join(t.TempDir(), "helper-survived")
	t.Setenv("HALOS_SIGNER_FAKE_MARKER", marker)
	start := time.Now()
	_, err := Open(context.Background(), execURI(t, writeKey(t, k), "spawn", "&timeout=200ms"), Options{})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("timeout took %s: the hung signer was not killed", d)
	}
	time.Sleep(1500 * time.Millisecond) // the helper would touch the marker after 1s
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("helper process outlived the signer's timeout")
	}
}

// L5: a signer binary (or symlink target) that is group- or world-writable
// is refused before it is ever run.
func TestExecSignerBinaryPermissions(t *testing.T) {
	dir := t.TempDir()
	script := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho '{\"protocol\":\"halos.signer.v1\",\"error\":\"ran\"}'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // not subject to the umask
			t.Fatal(err)
		}
		return p
	}
	ok := script("ok.sh", 0o700)
	world := script("world.sh", 0o777)
	group := script("group.sh", 0o770)
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(world, link); err != nil {
		t.Fatal(err)
	}
	goodLink := filepath.Join(dir, "good-link.sh")
	if err := os.Symlink(ok, goodLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, want string
	}{
		{ok, "ran"},
		{goodLink, "ran"},
		{world, "writable"},
		{group, "writable"},
		{link, "writable"},
		{filepath.Join(dir, "missing.sh"), "no such file"},
	} {
		_, err := Open(context.Background(), "exec://"+tc.path, Options{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", filepath.Base(tc.path), err, tc.want)
		}
	}
	if err := checkSignerBinary("/bin/sh"); err != nil { // root-owned system binary
		t.Errorf("/bin/sh: %v", err)
	}
}
