package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/halos-dev/halos/internal/fsutil"
)

// KillSwitch trips the traffic-plane kill switch for an experiment.
type KillSwitch interface {
	// Kill marks experiment killed; changed is false when it already was.
	Kill(ctx context.Context, experiment, by, reason string) (changed bool, err error)
}

// KillFunc adapts a function (e.g. server.KillExperiment, which also
// audit-logs) to KillSwitch.
type KillFunc func(ctx context.Context, experiment, by, reason string) (bool, error)

func (f KillFunc) Kill(ctx context.Context, experiment, by, reason string) (bool, error) {
	return f(ctx, experiment, by, reason)
}

// KillRecord is one line of killswitch.jsonl; the last line per experiment wins.
type KillRecord struct {
	Experiment string    `json:"experiment"`
	Killed     bool      `json:"killed"`
	By         string    `json:"by"`
	Reason     string    `json:"reason,omitempty"`
	At         time.Time `json:"at"`
}

// KillStore is the persisted kill state halo-server serves to gateways: an
// append-only JSONL log (killswitch.jsonl in the data dir) replayed into
// memory. Appends from another process sharing the file (`halo controller
// run` against halo-server's data dir) are picked up on the next read.
// ponytail: whole-file re-read when the size changes; kills are rare. Cross-process
// appends rely on O_APPEND single-line writes (local filesystem).
type KillStore struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	size    int64
	version uint64
	state   map[string]KillRecord
	Now     func() time.Time
}

// OpenKillStore opens dir/killswitch.jsonl ("" = memory only).
func OpenKillStore(dir string) (*KillStore, error) {
	s := &KillStore{state: map[string]KillRecord{}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("killswitch: %w", err)
	}
	s.path = filepath.Join(dir, "killswitch.jsonl")
	f, err := fsutil.OpenJSONL(s.path, s.replay)
	if err != nil {
		return nil, fmt.Errorf("killswitch: %w", err)
	}
	s.f = f
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("killswitch: stat: %w", err)
	}
	s.size = st.Size()
	return s, nil
}

func (s *KillStore) replay(line []byte) {
	var r KillRecord
	if json.Unmarshal(line, &r) == nil && r.Experiment != "" { // torn line: skip
		s.state[r.Experiment] = r
		s.version++
	}
}

// refresh re-reads the file if another process appended (caller holds mu).
func (s *KillStore) refresh() error {
	if s.f == nil {
		return nil
	}
	st, err := os.Stat(s.path)
	if err != nil {
		return fmt.Errorf("killswitch: stat %s: %w", s.path, err)
	}
	if st.Size() == s.size {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("killswitch: read %s: %w", s.path, err)
	}
	s.state, s.version = map[string]KillRecord{}, 0
	for _, line := range bytes.Split(b, []byte{'\n'}) {
		s.replay(line)
	}
	s.size = int64(len(b))
	return nil
}

func (s *KillStore) set(ctx context.Context, experiment, by, reason string, killed bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if experiment == "" {
		return false, fmt.Errorf("killswitch: empty experiment name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return false, err
	}
	if s.state[experiment].Killed == killed {
		return false, nil
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	r := KillRecord{Experiment: experiment, Killed: killed, By: by, Reason: reason, At: now().UTC()}
	if s.f != nil {
		b, err := json.Marshal(r)
		if err != nil {
			return false, fmt.Errorf("killswitch: encode: %w", err)
		}
		n, err := s.f.Write(append(b, '\n'))
		s.size += int64(n)
		if err != nil {
			return false, fmt.Errorf("killswitch: append %s: %w", s.path, err)
		}
		if err := s.f.Sync(); err != nil { // a kill must survive a crash right after we report it
			return false, fmt.Errorf("killswitch: sync %s: %w", s.path, err)
		}
	}
	s.state[experiment] = r
	s.version++
	return true, nil
}

// Kill implements KillSwitch.
func (s *KillStore) Kill(ctx context.Context, experiment, by, reason string) (bool, error) {
	return s.set(ctx, experiment, by, reason, true)
}

// Unkill lifts a kill; changed is false when experiment was not killed.
func (s *KillStore) Unkill(ctx context.Context, experiment, by, reason string) (bool, error) {
	return s.set(ctx, experiment, by, reason, false)
}

// Killed returns the active kills sorted by experiment, and the state version.
func (s *KillStore) Killed() ([]KillRecord, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refresh(); err != nil {
		return nil, 0, err
	}
	out := []KillRecord{}
	for _, r := range s.state {
		if r.Killed {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Experiment < out[j].Experiment })
	return out, s.version, nil
}

// Close closes the log file.
func (s *KillStore) Close() error {
	if s.f == nil {
		return nil
	}
	return s.f.Close()
}
