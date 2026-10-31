// Package shadow implements the mirror pipeline: halo-kong posts a Job for
// sampled first-turn requests, halo-shadow replays it against control and
// candidate (non-streaming) and stores the pair for later LLM-judge grading.
package shadow

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
)

// TokenHeader authenticates halo-kong to halo-shadow.
const TokenHeader = "X-Halo-Shadow-Token" //nolint:gosec // header name, not a credential

// Target is one side of a pair, as resolved by halo-shadow from its own policy.
type Target struct {
	Variant  string `json:"variant,omitempty"`
	Upstream string `json:"upstream"` // policy upstream name
	Model    string `json:"model"`
}

// Job is what halo-kong / halo-proxy post. It deliberately carries NO upstream
// URLs or models: halo-shadow resolves both sides from its own policy snapshot
// (experiment + variant + the alias in Body/Path), so a caller holding the
// token can't point halo-shadow (and its credentials) anywhere else. Body is the
// ORIGINAL client body (alias model). Only allowlisted Headers are replayed.
// Ring/SessionID are recorded metadata only; they never affect routing.
type Job struct {
	Experiment string            `json:"experiment"`
	Variant    string            `json:"variant"`
	Ring       string            `json:"ring,omitempty"`
	SessionID  string            `json:"session_id,omitempty"`
	Protocol   string            `json:"protocol"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       json.RawMessage   `json:"body"`
}

// Side is one response, flattened for the judge.
type Side struct {
	Target       Target          `json:"target"`
	Status       int             `json:"status"`
	LatencyMS    int64           `json:"latency_ms"`
	InputTokens  int64           `json:"input_tokens"`
	OutputTokens int64           `json:"output_tokens"`
	Response     json.RawMessage `json:"response,omitempty"`
	Error        string          `json:"error,omitempty"`
}

// Pair is one JSONL row. Request + both responses are everything a judge needs.
type Pair struct {
	ID         string          `json:"id"`
	Time       time.Time       `json:"time"`
	Experiment string          `json:"experiment"`
	Ring       string          `json:"ring,omitempty"`
	SessionID  string          `json:"session_id,omitempty"`
	Protocol   string          `json:"protocol"`
	Request    json.RawMessage `json:"request"`
	Control    Side            `json:"control"`
	Candidate  Side            `json:"candidate"`
	CostUSD    float64         `json:"cost_usd_estimate"`
}

// Store persists pairs.
type Store interface {
	Append(ctx context.Context, p Pair) error
}

// StoreOptions tunes FileStore. Zero value: plaintext, kept forever.
type StoreOptions struct {
	// Key (32 bytes) enables AES-256-GCM at rest. Rows become
	// {"id","time","kid","enc"}; id/time stay clear for retention pruning.
	Key []byte
	// Retention: Prune drops rows older than this (0 = keep forever).
	Retention time.Duration
}

// sealed is the at-rest form of an encrypted row.
type sealed struct {
	ID   string    `json:"id"`
	Time time.Time `json:"time"`
	KID  string    `json:"kid"`
	Enc  []byte    `json:"enc"` // nonce || ciphertext; AAD = id
}

// KeyID names a key in sealed rows: first 8 bytes of sha256(key), hex.
func KeyID(key []byte) string { h := sha256.Sum256(key); return hex.EncodeToString(h[:8]) }

// newGCM is AES-GCM with a random 96-bit nonce prepended to the ciphertext
// (nonce || ciphertext || tag, the row format since sealing began). The
// nonce is generated inside the AEAD, which GODEBUG=fips140=only requires:
// it refuses Seal with a caller-supplied GCM nonce.
func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("shadow: pair key: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(b)
}

// ReadKeyFile loads a base64 pair key file, the -pair-key-file format.
func ReadKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
	if err != nil {
		return nil, fmt.Errorf("shadow: read pair key: %w", err)
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("shadow: pair key %s is not base64: %w", path, err)
	}
	return k, nil
}

// ErrPlaintextRow is a plaintext (unsealed) pair row read with pair keys
// configured. Whoever can write the store could otherwise inject unsealed
// rows into a store that is supposed to be encrypted; reading rows written
// before sealing was turned on needs the explicit migration switch
// (DecodePairAllowPlaintext); each front end names its own switch.
var ErrPlaintextRow = errors.New("shadow: plaintext pair row in a sealed store")

// DecodePair reads one JSONL row, decrypting it with keys (by key id) when
// sealed. With no keys it reads plaintext rows; with keys it refuses them
// (ErrPlaintextRow).
func DecodePair(line []byte, keys ...[]byte) (Pair, error) {
	return decodePair(line, false, keys)
}

// DecodePairAllowPlaintext is DecodePair that also accepts plaintext rows
// when keys are configured: the migration path for a store sealed part way
// through its life. Off unless an operator asks for it.
func DecodePairAllowPlaintext(line []byte, keys ...[]byte) (Pair, error) {
	return decodePair(line, true, keys)
}

func decodePair(line []byte, allowPlaintext bool, keys [][]byte) (Pair, error) {
	var p Pair
	var s sealed
	if err := json.Unmarshal(line, &s); err != nil {
		return p, fmt.Errorf("shadow: decode pair row: %w", err)
	}
	if s.KID == "" {
		if len(keys) > 0 && !allowPlaintext {
			return p, fmt.Errorf("%w: pair %s", ErrPlaintextRow, s.ID)
		}
		err := json.Unmarshal(line, &p)
		return p, err
	}
	for _, k := range keys {
		if KeyID(k) != s.KID {
			continue
		}
		g, err := newGCM(k)
		if err != nil {
			return p, err
		}
		if len(s.Enc) < 12+g.Overhead() { // nonce || tag at least
			return p, fmt.Errorf("shadow: pair %s: short ciphertext", s.ID)
		}
		pt, err := g.Open(nil, nil, s.Enc, []byte(s.ID))
		if err != nil {
			return p, fmt.Errorf("shadow: pair %s: decrypt: %w", s.ID, err)
		}
		err = json.Unmarshal(pt, &p)
		return p, err
	}
	return p, fmt.Errorf("shadow: pair %s: no key for kid %s", s.ID, s.KID)
}

// sealer encodes a pair as its at-rest row: plain JSON, or sealed with
// AES-256-GCM when a key is configured. FileStore and DBStore share it, so a
// row means the same thing (and DecodePair reads it) wherever it is stored.
type sealer struct {
	gcm cipher.AEAD // nil = plaintext
	kid string
}

func newSealer(key []byte) (sealer, error) {
	if key == nil {
		return sealer{}, nil
	}
	if len(key) != 32 {
		return sealer{}, fmt.Errorf("shadow: pair key must be 32 bytes, got %d", len(key))
	}
	g, err := newGCM(key)
	if err != nil {
		return sealer{}, err
	}
	return sealer{g, KeyID(key)}, nil
}

func (s sealer) row(p Pair) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("shadow: marshal pair %s: %w", p.ID, err)
	}
	if s.gcm == nil {
		return b, nil
	}
	if b, err = json.Marshal(sealed{ID: p.ID, Time: p.Time, KID: s.kid, Enc: s.gcm.Seal(nil, nil, b, []byte(p.ID))}); err != nil { //nolint:gosec // G407 false positive: NewGCMWithRandomNonce draws the nonce itself and requires nil
		return nil, fmt.Errorf("shadow: marshal sealed pair %s: %w", p.ID, err)
	}
	return b, nil
}

// FileStore appends JSONL to a file (mode 0600).
type FileStore struct {
	mu   sync.Mutex
	path string
	f    *os.File
	seal sealer
	ttl  time.Duration
}

func NewFileStore(path string, o StoreOptions) (*FileStore, error) {
	seal, err := newSealer(o.Key)
	if err != nil {
		return nil, err
	}
	s := &FileStore{path: path, ttl: o.Retention, seal: seal}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileStore) open() error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("shadow: open pair store %s: %w", s.path, err)
	}
	if err := fsutil.RestrictToOwner(s.path); err != nil {
		_ = f.Close()
		return fmt.Errorf("shadow: %w", err)
	}
	s.f = f
	return nil
}

func (s *FileStore) Append(ctx context.Context, p Pair) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := s.seal.row(p)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("shadow: write pair %s: %w", p.ID, err)
	}
	return nil
}

// Prune rewrites the file without rows older than Retention (no-op if 0).
// Rows whose time can't be read are kept: pruning never destroys data it
// doesn't understand.
func (s *FileStore) Prune(now time.Time) (removed int, err error) {
	if s.ttl <= 0 {
		return 0, nil
	}
	cutoff := now.Add(-s.ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	in, err := os.Open(s.path)
	if err != nil {
		return 0, fmt.Errorf("shadow: prune open %s: %w", s.path, err)
	}
	defer func() { _ = in.Close() }()                                 // read-only
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".pairs-prune-*") // 0600
	if err != nil {
		return 0, fmt.Errorf("shadow: prune temp: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after rename
	r, w := bufio.NewReader(in), bufio.NewWriter(tmp)
	for {
		line, rerr := r.ReadBytes('\n')
		if len(line) > 0 {
			var row struct {
				Time time.Time `json:"time"`
			}
			if json.Unmarshal(line, &row) == nil && row.Time.Before(cutoff) {
				removed++
			} else if _, err := w.Write(line); err != nil {
				_ = tmp.Close() // already failing; temp is removed
				return 0, fmt.Errorf("shadow: prune write: %w", err)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			_ = tmp.Close() // already failing; temp is removed
			return 0, fmt.Errorf("shadow: prune read %s: %w", s.path, rerr)
		}
	}
	if err := errors.Join(w.Flush(), tmp.Sync(), tmp.Close()); err != nil {
		return 0, fmt.Errorf("shadow: prune flush: %w", err)
	}
	if err := fsutil.RestrictToOwner(tmp.Name()); err != nil {
		return 0, fmt.Errorf("shadow: prune: %w", err)
	}
	// Windows cannot rename over a file we hold open: close first, reopen either way.
	_ = in.Close()
	_ = s.f.Close()
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return 0, errors.Join(fmt.Errorf("shadow: prune replace %s: %w", s.path, err), s.open())
	}
	return removed, s.open()
}

func (s *FileStore) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.f.Close() }
