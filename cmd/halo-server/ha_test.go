package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/server"
)

func TestSubcommandUsage(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{[]string{"migrate"}, "usage: halo-server migrate"},
		{[]string{"migrate", "--nope"}, "not defined"},
		{[]string{"migrate", "--database-url-file", "/nonexistent/url"}, "--database-url-file"},
		{[]string{"import", "--database-url-file", "u"}, "usage: halo-server import"},
		{[]string{"import", "--nope"}, "not defined"},
		{[]string{"import", "--from-data-dir", "/nonexistent/dir", "--database-url-file", "u"}, "not a directory"},
	} {
		if err := run(ctx, tc.args); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%v: want %q, got %v", tc.args, tc.err, err)
		}
	}
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openDB(ctx, empty, false); err == nil || !strings.Contains(err.Error(), "empty database URL") {
		t.Fatalf("empty URL file: %v", err)
	}
}

// TestHA runs migrate, import and two serving replicas with the controller
// against Postgres (HALO_TEST_PG_DSN), then fails the leader over.
func TestHA(t *testing.T) {
	other := pgtest.Schema(t) // empty: migrate has work to do
	dir := t.TempDir()
	urlFile := filepath.Join(dir, "url")
	if err := os.WriteFile(urlFile, []byte(pgtest.URL(other)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Serving against an unmigrated database is refused with the fix.
	tokFile := filepath.Join(dir, "tok")
	if err := os.WriteFile(tokFile, []byte("fleet-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"--policy-dir", "../../examples/acme-corp", "--token-file", tokFile, "--dev-insecure-user", "dev", "--database-url-file", urlFile}
	if err := run(ctx, append(common, "--listen", "127.0.0.1:0")); err == nil || !strings.Contains(err.Error(), "halo-server migrate") {
		t.Fatalf("unmigrated database: %v", err)
	}
	var out bytes.Buffer
	if err := runMigrate(ctx, []string{"--database-url-file", urlFile}, &out); err != nil || !strings.Contains(out.String(), "schema at v") {
		t.Fatalf("migrate: %v %s", err, out.String())
	}

	// Import a data dir written by a single-replica server.
	data := t.TempDir()
	srv, err := server.New(server.Config{PolicyDir: "../../examples/acme-corp", Token: "t", DevUser: "d", DataDir: data})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := srv.AuditStrict(ctx, "ops", "test", "x", nil); err != nil {
			t.Fatal(err)
		}
	}
	_ = srv.Close()
	out.Reset()
	if err := runImport(ctx, []string{"--from-data-dir", data, "--database-url-file", urlFile}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "copied audit") || !strings.Contains(out.String(), "verified") {
		t.Fatalf("import output: %s", out.String())
	}

	// Two replicas with the controller: exactly one leads; stop it and the other takes over.
	ha := append(common, "--controller", "--clickhouse-url", "http://127.0.0.1:1", "--leader-lease-ttl", "3s")
	start := func() (context.CancelFunc, chan error, string) {
		metrics := freePort(t)
		c, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- run(c, append(ha, "--listen", freePort(t), "--metrics-listen", metrics)) }()
		return cancel, done, metrics
	}
	stopA, doneA, mA := start()
	stopB, doneB, mB := start()
	defer stopB()
	leaders := func() (a, b bool) {
		return scrape(mA, `halo_leader{lease="controller"} 1`), scrape(mB, `halo_leader{lease="controller"} 1`)
	}
	waitUntil(t, 10*time.Second, func() bool { a, b := leaders(); return a != b })
	if a, b := leaders(); a && b {
		t.Fatal("two leaders")
	}
	aLed, _ := leaders()
	if !scrape(mA, "halo_db_errors_total") {
		t.Fatal("database metrics not served")
	}
	// Stop the leader: the follower takes over.
	stopLeader, leaderDone, follower := stopA, doneA, mB
	if !aLed {
		stopLeader, leaderDone, follower = stopB, doneB, mA
	}
	stopLeader()
	if err := <-leaderDone; err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 10*time.Second, func() bool { return scrape(follower, `halo_leader{lease="controller"} 1`) })
	stopA()
	stopB()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func scrape(addr, want string) bool {
	r, err := http.Get("http://" + addr + "/metrics") //nolint:noctx // test scrape of a local listener
	if err != nil {
		return false
	}
	defer func() { _ = r.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(r.Body)
	return strings.Contains(b.String(), want)
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
