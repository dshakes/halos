package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/shadow"
)

func TestLoadUpstreamHeaders(t *testing.T) {
	t.Setenv("TEST_HALO_SHADOW_KEY", "sk-1")
	f := filepath.Join(t.TempDir(), "h.yaml")
	if err := os.WriteFile(f, []byte("anthropic:\n  x-api-key: ${TEST_HALO_SHADOW_KEY}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := loadUpstreamHeaders(f)
	if err != nil || m["anthropic"]["x-api-key"] != "sk-1" {
		t.Fatalf("%v %v", m, err)
	}
	if m, err := loadUpstreamHeaders(""); m != nil || err != nil {
		t.Fatal("empty path => nil")
	}
	if _, err := loadUpstreamHeaders(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file must error")
	}
	if err := os.WriteFile(f, []byte("anthropic: [1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUpstreamHeaders(f); err == nil {
		t.Fatal("bad yaml must error")
	}
}

func TestRunConfigErrors(t *testing.T) {
	dir := t.TempDir()
	badKey := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(badKey, []byte("not base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
		want string
	}{
		"no token":       {nil, nil, "HALO_SHADOW_TOKEN is required"},
		"legacy auth":    {nil, map[string]string{"HALO_SHADOW_TOKEN": "t", "HALO_SHADOW_AUTH_HEADER": "x"}, "no longer supported"},
		"no policy":      {nil, map[string]string{"HALO_SHADOW_TOKEN": "t"}, "-policy is required"},
		"zero budget":    {[]string{"-policy", "p.json", "-budget-usd", "0"}, map[string]string{"HALO_SHADOW_TOKEN": "t"}, "must be > 0"},
		"bad flag":       {[]string{"-nope"}, nil, "not defined"},
		"missing hdrs":   {[]string{"-policy", "p.json", "-upstream-headers", filepath.Join(dir, "none")}, map[string]string{"HALO_SHADOW_TOKEN": "t"}, "read upstream headers"},
		"missing key":    {[]string{"-policy", "p.json", "-pair-key-file", filepath.Join(dir, "none")}, map[string]string{"HALO_SHADOW_TOKEN": "t"}, "read pair key"},
		"bad key":        {[]string{"-policy", "p.json", "-pair-key-file", badKey}, map[string]string{"HALO_SHADOW_TOKEN": "t"}, "not base64"},
		"policy via env": {[]string{"-pair-key-file", badKey}, map[string]string{"HALO_SHADOW_TOKEN": "t", "HALO_SHADOW_POLICY": "p.json"}, "not base64"},
	} {
		getenv := func(k string) string { return tc.env[k] }
		err := run(context.Background(), tc.args, getenv)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v want %q", name, err, tc.want)
		}
	}
}

// run serves until ctx is cancelled; the metrics listener needs no token.
func TestRunServesAndStops(t *testing.T) {
	dir := t.TempDir()
	addr, maddr := freeAddr(t), freeAddr(t)
	env := map[string]string{"HALO_SHADOW_TOKEN": "t"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-policy", filepath.Join(dir, "missing.json"), "-out", filepath.Join(dir, "p.jsonl"),
			"-listen", addr, "-metrics-listen", maddr}, func(k string) string { return env[k] })
	}()
	get := func(url string) int {
		for i := 0; i < 200; i++ {
			if resp, err := http.Get(url); err == nil {
				_ = resp.Body.Close()
				return resp.StatusCode
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s never came up", url)
		return 0
	}
	if c := get("http://" + maddr + "/metrics"); c != 200 {
		t.Fatalf("metrics listener %d", c)
	}
	if c := get("http://" + addr + "/metrics"); c != 401 {
		t.Fatalf("main listener metrics without token %d", c)
	}
	if c := get("http://" + maddr + "/healthz"); c != 404 {
		t.Fatalf("metrics listener must serve only /metrics, got %d", c)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A listener that can't bind fails run instead of hanging.
	if err := run(context.Background(), []string{"-policy", "p.json", "-out", filepath.Join(dir, "q.jsonl"), "-listen", "256.0.0.1:1"},
		func(k string) string { return env[k] }); err == nil {
		t.Fatal("bad listen address must fail")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type fakePruner struct{ calls atomic.Int64 }

func (f *fakePruner) Prune(time.Time) (int, error) {
	if f.calls.Add(1)%2 == 0 {
		return 0, errors.New("disk full")
	}
	return 1, nil
}

func TestPruneLoop(t *testing.T) {
	f := &fakePruner{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { prune(ctx, f, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil))); close(done) }()
	for f.calls.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done // exits on cancel, errors don't stop it
}

func TestDecryptPairs(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	keyFile := filepath.Join(dir, "k")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.jsonl")
	fs, err := shadow.NewFileStore(path, shadow.StoreOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Append(context.Background(), shadow.Pair{ID: "a", Request: json.RawMessage(`{"secret":"prompt"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := decryptPairs([]string{"-pair-key-file", keyFile, path}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "prompt") || !strings.Contains(out.String(), `"id":"a"`) {
		t.Fatalf("out %s", out.String())
	}
	// Via run's subcommand dispatch, without the key: the sealed row can't be opened.
	if err := run(context.Background(), []string{"decrypt-pairs", path}, os.Getenv); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("no key: %v", err)
	}
	for _, args := range [][]string{nil, {"a", "b"}, {filepath.Join(dir, "missing")}, {"-pair-key-file", filepath.Join(dir, "nokey"), path}} {
		if err := decryptPairs(args, io.Discard); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}
