package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/pgstore/pgtest"
	"github.com/dshakes/halos/internal/shadow"
)

func TestDatabaseConfigErrors(t *testing.T) {
	env := func(k string) string { return map[string]string{"HALO_SHADOW_TOKEN": "t"}[k] }
	missing := filepath.Join(t.TempDir(), "none")
	if err := run(context.Background(), []string{"-policy", "p.json", "-database-url-file", missing}, env); err == nil || !strings.Contains(err.Error(), "-database-url-file") {
		t.Fatalf("missing URL file: %v", err)
	}
	for _, args := range [][]string{{"export-pairs"}, {"export-pairs", "-nope"}, {"export-pairs", "-database-url-file", missing}} {
		if err := run(context.Background(), args, env); err == nil {
			t.Errorf("%v: want error", args)
		}
	}
}

// TestDatabaseMode serves on Postgres (HALO_TEST_PG_DSN): readiness checks
// the database, and export-pairs writes rows decrypt-pairs reads.
func TestDatabaseMode(t *testing.T) {
	schema := pgtest.Schema(t)
	dir := t.TempDir()
	urlFile := filepath.Join(dir, "url")
	if err := os.WriteFile(urlFile, []byte(pgtest.URL(schema)), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string { return map[string]string{"HALO_SHADOW_TOKEN": "t"}[k] }
	// Not migrated: refused with the fix.
	if err := run(context.Background(), []string{"-policy", "p.json", "-database-url-file", urlFile}, env); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("unmigrated: %v", err)
	}
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-policy", filepath.Join(dir, "missing.json"), "-database-url-file", urlFile, "-auto-migrate", "-listen", addr}, env)
	}()
	var code int
	for range 200 {
		if r, err := http.Get("http://" + addr + "/readyz"); err == nil {
			code = r.StatusCode
			_ = r.Body.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code != http.StatusServiceUnavailable { // database fine, policy missing
		t.Fatalf("readyz %d", code)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A pair stored by DBStore round-trips through export-pairs and decrypt-pairs.
	db, _ := pgtest.OpenTest(t, schema)
	key := bytes.Repeat([]byte{7}, 32)
	st, err := shadow.NewDBStore(db, shadow.StoreOptions{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), shadow.Pair{ID: "p1", Time: time.Now().UTC(), Experiment: "exp"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := exportPairs(context.Background(), []string{"-database-url-file", urlFile}, &out); err != nil {
		t.Fatal(err)
	}
	pairs := filepath.Join(dir, "pairs.jsonl")
	keyFile := filepath.Join(dir, "k")
	if err := os.WriteFile(pairs, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := decryptPairs([]string{"-pair-key-file", keyFile, pairs}, &plain); err != nil || !strings.Contains(plain.String(), `"experiment":"exp"`) {
		t.Fatalf("decrypt exported pairs: %v %s", err, plain.String())
	}
}
