//go:build !windows

package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// copySigner copies the test binary (the fake signer) into a fresh 0700
// directory and returns its path and sha256.
func copySigner(t *testing.T) (string, string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "signer")
	if err := os.WriteFile(p, b, 0o700); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return p, hex.EncodeToString(h[:])
}

func fakeKey(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return writeKey(t, k)
}

// R2: a helper the signer backgrounds is killed when the signer exits 0.
func TestExecSignerNormalExitKillsHelpers(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "helper-survived")
	t.Setenv("HALOS_SIGNER_FAKE_MARKER", marker)
	if _, err := Open(context.Background(), execURI(t, fakeKey(t), "bgexit", ""), Options{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3500 * time.Millisecond) // the helper would touch the marker after 3s; ponytail: timing margin, the signer must exit and be reaped within 3s of starting its helper (a slow CI runner took most of 1s)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a helper backgrounded by the signer outlived its normal exit")
	}
}

// R3: the signer runs in / with only absolute PATH entries.
func TestExecSignerCwdAndPath(t *testing.T) {
	t.Setenv("PATH", "/usr/bin::.:relative/bin:/bin:")
	_, err := Open(context.Background(), execURI(t, fakeKey(t), "dumpcwd", ""), Options{})
	if err == nil {
		t.Fatal("dumpcwd answers an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cwd=/ ") {
		t.Errorf("signer cwd: %s", msg)
	}
	if !strings.Contains(msg, "path=/usr/bin:/bin") || strings.Contains(msg, "relative") || strings.Contains(msg, ":.:") || strings.Contains(msg, "::") {
		t.Errorf("signer PATH: %s", msg)
	}
	if got := absolutePath("/a::.:b/c:/d:"); got != "/a:/d" {
		t.Errorf("absolutePath = %q", got)
	}
}

// R4: an ancestor directory others could write is refused unless sticky.
func TestExecSignerAncestorDirectories(t *testing.T) {
	base := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		d := filepath.Join(base, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, mode); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, "s.sh")
		if err := os.WriteFile(p, []byte("#!/bin/sh\necho '{\"protocol\":\"halos.signer.v1\",\"error\":\"ran\"}'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	open := mk("open", 0o777)
	sticky := mk("sticky", os.ModeSticky|0o777)
	group := mk("group", 0o770)
	for _, tc := range []struct{ path, want string }{
		{open, "not sticky"},
		{group, "not sticky"},
		{sticky, "ran"},
	} {
		if _, err := Open(context.Background(), ExecURI(tc.path, nil), Options{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", filepath.Base(filepath.Dir(tc.path)), err, tc.want)
		}
	}
}

// R4: the checks run before every exec, so a signer made writable after
// Open is refused at the next Sign.
func TestExecSignerSwapAfterOpen(t *testing.T) {
	bin, _ := copySigner(t)
	key := fakeKey(t)
	t.Setenv("HALOS_SIGNER_FAKE_KEY", key)
	t.Setenv("HALOS_SIGNER_FAKE_MODE", "")
	s, err := Open(context.Background(), ExecURI(bin, nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), "sha256:ab"); err != nil {
		t.Fatalf("sign before the swap: %v", err)
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(context.Background(), "sha256:ab"); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("sign after the signer became world-writable: %v", err)
	}
}

// R4: sha256= pins the binary: a mismatch is refused at Open, and a binary
// changed after Open is refused at the next Sign.
func TestExecSignerSHA256Pin(t *testing.T) {
	bin, sum := copySigner(t)
	key := fakeKey(t)
	t.Setenv("HALOS_SIGNER_FAKE_KEY", key)
	t.Setenv("HALOS_SIGNER_FAKE_MODE", "")
	wrong := strings.Repeat("0", 64)
	if _, err := Open(context.Background(), ExecURI(bin, url.Values{"sha256": {wrong}}), Options{}); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("wrong pin: %v", err)
	}
	s, err := Open(context.Background(), ExecURI(bin, url.Values{"sha256": {sum}}), Options{})
	if err != nil {
		t.Fatalf("right pin: %v", err)
	}
	f, err := os.OpenFile(bin, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte{0})
	_ = f.Close()
	if _, err := s.Sign(context.Background(), "sha256:ab"); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("sign after the binary changed: %v", err)
	}
	for _, bad := range []string{"abc", strings.Repeat("A", 64)} {
		if _, err := parseExecURI("exec:///bin/s?sha256=" + bad); err == nil {
			t.Errorf("sha256=%s accepted", bad)
		}
	}
}
