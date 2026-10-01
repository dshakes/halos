package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Signer-side pointer continuity. ReadPointer only proves a pointer was signed
// by our key for the ring; a registry can still serve an OLD signed pointer. If
// the signer then refreshes or promotes from it, the replay is laundered into a
// fresh pointer with a higher seq and devices accept the rollback. PointerState
// remembers the last pointer this signer wrote per registry repo + ring so every
// write can refuse a served pointer that is older than what we already signed.

// PointerMark is the last pointer the signer wrote for one ring or channel.
type PointerMark struct {
	Seq      uint64    `json:"seq"`
	Digest   string    `json:"digest"`
	IssuedAt time.Time `json:"issuedAt"`
}

// PointerState is the on-disk signer state (a JSON file; CI can cache it).
// Keys are "<registry repo>#<ring>". Not safe for concurrent writers: run one
// signer per state file.
type PointerState struct {
	path  string
	scope string
	marks map[string]PointerMark
}

// DefaultPointerStatePath is $XDG_STATE_HOME/halos/pointers.json
// (~/.local/state/halos/pointers.json when XDG_STATE_HOME is unset).
func DefaultPointerStatePath() (string, error) {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("bundle: locate pointer state (set --state-file or XDG_STATE_HOME): %w", err)
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "halos", "pointers.json"), nil
}

// LoadPointerState reads path (a missing file is empty state) scoped to the
// registry repo scope.
func LoadPointerState(path, scope string) (*PointerState, error) {
	s := &PointerState{path: path, scope: scope, marks: map[string]PointerMark{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("bundle: read pointer state %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &s.marks); err != nil {
		return nil, fmt.Errorf("bundle: parse pointer state %s (refusing to sign without it; restore it or pass --expect-digest with a fresh --state-file): %w", path, err)
	}
	return s, nil
}

func (s *PointerState) key(ring string) string { return s.scope + "#" + ring }

// Mark returns the recorded pointer for ring.
func (s *PointerState) Mark(ring string) (PointerMark, bool) {
	m, ok := s.marks[s.key(ring)]
	return m, ok
}

// check refuses a served pointer older than (or forked from) what this signer wrote.
func (s *PointerState) check(ring string, cur Pointer, found bool) error {
	m, ok := s.Mark(ring)
	switch {
	case !ok:
		return nil
	case !found:
		return fmt.Errorf("bundle: ring %s has no pointer but %s records seq %d (digest %s) written by this signer; registry reset or tag deleted? refusing", ring, s.path, m.Seq, m.Digest)
	case cur.Seq < m.Seq:
		return fmt.Errorf("bundle: registry serves ring %s pointer seq %d (digest %s) but this signer already wrote seq %d (digest %s) per %s: replayed/rolled-back pointer refused",
			ring, cur.Seq, cur.Digest, m.Seq, m.Digest, s.path)
	case cur.Seq == m.Seq && cur.Digest != m.Digest:
		return fmt.Errorf("bundle: ring %s pointer seq %d names digest %s but this signer wrote %s at that seq (per %s): refused", ring, cur.Seq, cur.Digest, m.Digest, s.path)
	}
	return nil
}

// record stores p as ring's latest pointer and saves the file atomically.
func (s *PointerState) record(ring string, p Pointer) error {
	s.marks[s.key(ring)] = PointerMark{Seq: p.Seq, Digest: p.Digest, IssuedAt: p.IssuedAt}
	b, err := json.MarshalIndent(s.marks, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("bundle: create pointer state dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".pointers-*.json")
	if err != nil {
		return fmt.Errorf("bundle: write pointer state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bundle: write pointer state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bundle: write pointer state: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("bundle: save pointer state %s: %w", s.path, err)
	}
	return nil
}
