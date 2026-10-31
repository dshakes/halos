package hmackey

import (
	"bytes"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/hmackey/hmackeytest"
)

// Info (b): the FIPS-mode override lives in hmackeytest, and only test files
// may import it: production code must not be able to switch the check off.
func TestHmackeytestOnlyInTests(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	const imp = `"github.com/dshakes/halos/internal/hmackey/hmackeytest"`
	var bad []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(imp)) {
			bad = append(bad, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("production files import hmackeytest: %v", bad)
	}
}

// Info (a): the messages describe FIPS mode accurately (fips140=on or only),
// not only fips140=only.
func TestMessagesNameFIPSMode(t *testing.T) {
	restore := hmackeytest.SetFIPS(true)
	err := Check(nil, "--x", []byte("short"))
	restore()
	if err == nil || !strings.Contains(err.Error(), "fips140=on or only") {
		t.Fatalf("error: %v", err)
	}
	defer hmackeytest.SetFIPS(false)()
	var buf bytes.Buffer
	if err := Check(newLogger(&buf), "--x", []byte("short")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "fips140=on or only") {
		t.Fatalf("warning: %q", buf.String())
	}
}

func newLogger(w *bytes.Buffer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }
