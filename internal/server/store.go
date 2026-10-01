// Package server is the Halos console backend: fleet ingest, policy and
// experiment read APIs, and the embedded web console.
package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
)

// HarnessStatus mirrors cmd/halod's per-harness report.
type HarnessStatus struct {
	Want      string `json:"want"`
	Installed string `json:"installed"`
}

// Report is the status payload halod POSTs (cmd/halod.Status).
type Report struct {
	Time      time.Time                `json:"time"`
	Hostname  string                   `json:"hostname"`
	User      string                   `json:"user"`
	Device    string                   `json:"device,omitempty"` // set by the server for device-token reports
	Ring      string                   `json:"ring"`
	Digest    string                   `json:"digest"`
	Harnesses map[string]HarnessStatus `json:"harnesses"`
	Drift     []string                 `json:"drift"`
	LastError string                   `json:"lastError,omitempty"`
	ErrorCode string                   `json:"errorCode,omitempty"` // classifies LastError, e.g. untrusted_owner, sandbox_unavailable, no_subject_for_experiment
	// Experiment/Variant: the client-axis experiment variant the host applied.
	Experiment string `json:"experiment,omitempty"`
	Variant    string `json:"variant,omitempty"`
	Killed     bool   `json:"killed,omitempty"` // Experiment is kill-switched; the host runs the ring release
}

// Host is the latest report for one machine plus when the server saw it.
type Host struct {
	Report
	LastSeen time.Time `json:"lastSeen"`
}

// Store keeps the latest report per reporter: per device ID for device-token
// reports, per hostname for fleet-token reports (see Host.key).
type Store interface {
	Put(Host) error
	All() []Host // sorted by hostname
	// History returns up to MaxHistory recent reports for key (see Host.key), newest first.
	History(key string) []Host
}

// MaxHistory bounds the per-reporter report history.
const MaxHistory = 50

// key: a device can only ever overwrite its own row; hostname (self-reported)
// keys only fleet-token reports, which cannot collide with device rows.
func (h Host) key() string {
	if h.Device != "" {
		return "device:" + h.Device
	}
	return "host:" + h.Hostname
}

// logStore is an in-memory map persisted as an append-only JSONL log.
// ponytail: one line per report, compacted only on open; add rotation or a DB if report volume gets large.
type logStore struct {
	mu    sync.RWMutex
	hosts map[string]Host
	hist  map[string][]Host // per-key ring buffer, oldest first; in memory only (compaction drops it on restart)
	f     *os.File          // nil = memory only
}

// NewMemStore returns a non-persistent Store.
func NewMemStore() Store { return &logStore{hosts: map[string]Host{}, hist: map[string][]Host{}} }

// OpenLogStore replays dir/reports.jsonl (last line per host wins), rewrites it
// compacted, and appends from then on.
func OpenLogStore(dir string) (Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "reports.jsonl")
	s := &logStore{hosts: map[string]Host{}, hist: map[string][]Host{}}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			var h Host
			if json.Unmarshal(sc.Bytes(), &h) == nil && h.Hostname != "" { // torn/corrupt line: skip
				s.hosts[h.key()] = h
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("replay %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	for _, h := range s.All() {
		if err := enc.Encode(h); err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := fsutil.RestrictToOwner(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	if s.f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the report log. A held handle blocks deleting or renaming the file on Windows.
func (s *logStore) Close() error { return closeFile(&s.mu, s.f) }

func (s *logStore) Put(h Host) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		b, err := json.Marshal(h)
		if err != nil {
			return err
		}
		if _, err := s.f.Write(append(b, '\n')); err != nil {
			return err // not stored in memory either: caller returns 500, halod retries
		}
	}
	s.hosts[h.key()] = h
	hh := append(s.hist[h.key()], h)
	if len(hh) > MaxHistory {
		hh = append([]Host(nil), hh[len(hh)-MaxHistory:]...) // copy so the dropped head can be collected
	}
	s.hist[h.key()] = hh
	return nil
}

func (s *logStore) History(key string) []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hh := s.hist[key]
	out := make([]Host, len(hh))
	for i, h := range hh {
		out[len(hh)-1-i] = h
	}
	return out
}

func (s *logStore) All() []Host {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Host, 0, len(s.hosts))
	for _, h := range s.hosts {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].key() < out[j].key()
	})
	return out
}

// closeFile closes f under mu; a nil f (memory only) is a no-op.
func closeFile(mu sync.Locker, f *os.File) error {
	mu.Lock()
	defer mu.Unlock()
	if f == nil {
		return nil
	}
	return f.Close()
}
