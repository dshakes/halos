package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/shadow"
)

// R5: the CLI names its own switch; other errors pass through unchanged.
func TestPlaintextPairsHint(t *testing.T) {
	err := plaintextPairsHint(fmt.Errorf("pair store p line 1: %w", shadow.ErrPlaintextRow))
	if !errors.Is(err, shadow.ErrPlaintextRow) || !strings.Contains(err.Error(), "--allow-plaintext-pairs") || strings.Contains(err.Error(), "allow_plaintext_pairs") {
		t.Fatalf("hint: %v", err)
	}
	other := errors.New("boom")
	if plaintextPairsHint(other) != other || plaintextPairsHint(nil) != nil {
		t.Fatal("unrelated errors must pass through")
	}
}
