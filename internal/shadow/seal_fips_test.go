package shadow

import (
	"strings"
	"testing"
)

// Rows sealed before the switch to cipher.NewGCMWithRandomNonce (FIPS 140-3
// only mode refuses caller-chosen GCM nonces) have the same nonce ||
// ciphertext layout and still decrypt. The vector was sealed with
// cipher.NewGCM and the explicit nonce "halos-nonce1" under key 00..1f.
func TestLegacySealedRowStillDecrypts(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	row := `{"id":"legacy-1","time":"2026-01-01T00:00:00Z","kid":"` + KeyID(key) +
		`","enc":"aGFsb3Mtbm9uY2UxF7Z/JKgpLTUhcg24B4s4hXmCKxDSKsarwZy4BYABdAhBfwmTXdysLITmoZO5"}`
	p, err := DecodePair([]byte(row), key)
	if err != nil || p.ID != "legacy-1" {
		t.Fatalf("legacy row: %+v %v", p, err)
	}
	// the AAD binds the row id: a swapped id does not decrypt
	if _, err := DecodePair([]byte(strings.Replace(row, `"id":"legacy-1"`, `"id":"other"`, 1)), key); err == nil {
		t.Fatal("row decrypted under another id")
	}
	// and a new row round-trips
	s, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.row(Pair{ID: "new-1"})
	if err != nil {
		t.Fatal(err)
	}
	if p, err := DecodePair(b, key); err != nil || p.ID != "new-1" {
		t.Fatalf("new row: %+v %v", p, err)
	}
	// truncated ciphertext is refused, not sliced out of range
	if _, err := DecodePair([]byte(`{"id":"x","kid":"`+KeyID(key)+`","enc":"aGFsbw=="}`), key); err == nil {
		t.Fatal("short ciphertext accepted")
	}
}
