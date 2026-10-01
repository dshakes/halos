package gateway

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Snapshot serves a compiled org policy (policy.Compile output, or a bare
// json.Marshal of *policy.Org) from a
// file and reloads it when the mtime/size changes. A failed reload keeps
// serving the last good policy.
type Snapshot struct {
	path string
	mu   sync.Mutex
	org  *policy.Org
	mod  time.Time
	size int64
	next time.Time // don't stat more than once per interval
}

const statInterval = time.Second

func NewSnapshot(path string) *Snapshot { return &Snapshot{path: path} }

// Get returns the current org. err is non-nil if the latest load/reload
// failed; org may still be the previous good snapshot (nil if none ever loaded).
func (s *Snapshot) Get() (*policy.Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now := time.Now(); now.Before(s.next) && s.org != nil {
		return s.org, nil
	} else {
		s.next = now.Add(statInterval)
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		return s.org, fmt.Errorf("gateway: stat policy snapshot: %w", err)
	}
	if s.org != nil && fi.ModTime().Equal(s.mod) && fi.Size() == s.size {
		return s.org, nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return s.org, fmt.Errorf("gateway: read policy snapshot: %w", err)
	}
	o, err := policy.ParseSnapshot(b)
	if err != nil {
		s.mod, s.size = fi.ModTime(), fi.Size() // don't re-parse a broken file every second
		return s.org, fmt.Errorf("gateway: load policy snapshot %s: %w", s.path, err)
	}
	for _, is := range policy.TrafficOverlaps(o) {
		slog.Warn("policy snapshot: overlapping traffic experiments; the first by name routes", "path", s.path, "issue", is.Message)
	}
	s.org, s.mod, s.size = o, fi.ModTime(), fi.Size()
	return s.org, nil
}
