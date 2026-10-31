package eval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dshakes/halos/internal/shadow"
)

// Info (d): with pair keys, FilePairs refuses an unsealed row unless
// AllowPlaintext (halo eval --allow-plaintext-pairs) is set.
func TestFilePairsPlaintextRows(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pairs.jsonl")
	if err := os.WriteFile(p, []byte(`{"id":"p1","experiment":"exp"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := (FilePairs{Path: p, Keys: [][]byte{key}}).Pairs(context.Background()); !errors.Is(err, shadow.ErrPlaintextRow) {
		t.Fatalf("plaintext row with keys: %v", err)
	}
	got, err := (FilePairs{Path: p, Keys: [][]byte{key}, AllowPlaintext: true}).Pairs(context.Background())
	if err != nil || len(got) != 1 {
		t.Fatalf("migration: %v %v", got, err)
	}
	if got, err := (FilePairs{Path: p}).Pairs(context.Background()); err != nil || len(got) != 1 {
		t.Fatalf("no keys: %v %v", got, err)
	}
}
