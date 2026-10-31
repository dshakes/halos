package shadow

import (
	"errors"
	"testing"
)

// Info (d): with pair keys configured an unsealed row is refused, so whoever
// can write the store cannot inject plaintext rows into a sealed one; the
// migration path reads them only when asked.
func TestPlaintextRowsInSealedStore(t *testing.T) {
	key := make([]byte, 32)
	row := []byte(`{"id":"p1","experiment":"exp"}`)
	if p, err := DecodePair(row); err != nil || p.ID != "p1" {
		t.Fatalf("no keys: plaintext store must read: %+v %v", p, err)
	}
	if _, err := DecodePair(row, key); !errors.Is(err, ErrPlaintextRow) {
		t.Fatalf("keys configured: plaintext row accepted: %v", err)
	}
	if p, err := DecodePairAllowPlaintext(row, key); err != nil || p.Experiment != "exp" {
		t.Fatalf("migration switch: %+v %v", p, err)
	}
	// sealed rows still open either way
	s, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	sealedRow, err := s.row(Pair{ID: "p2"})
	if err != nil {
		t.Fatal(err)
	}
	for _, decode := range []func([]byte, ...[]byte) (Pair, error){DecodePair, DecodePairAllowPlaintext} {
		if p, err := decode(sealedRow, key); err != nil || p.ID != "p2" {
			t.Fatalf("sealed row: %+v %v", p, err)
		}
	}
}
