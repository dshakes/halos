// Package storage is the persistence seam under halo-server's stores: an
// append-only record log each store replays into memory, and a small
// expiring key-value space for short-lived single-use state. The file
// backend (Dir, MemKV) is the single-replica default; internal/pgstore
// implements the same interfaces on Postgres so several replicas share state.
package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
)

// Log is an append-only record log. A store replays it into memory when it
// opens (the replay func passed to Opener.OpenLog) and appends one record per
// change. On a shared backend other replicas append too: Catchup applies
// their records, in log order, through the same replay func, and Append
// applies every foreign record that precedes the new one before it returns,
// so the caller applying its own record afterwards keeps the log order.
// Callers serialize Append and Catchup (they hold the store's mutex), which
// is also what makes calling replay from inside them safe.
type Log interface {
	// Append durably adds rec (one JSON value, no trailing newline). A
	// non-empty key lets a shared backend drop older records with the same
	// key: use it only where the last record per key is all replay needs.
	Append(ctx context.Context, key string, rec []byte) error
	// Catchup replays records other writers appended since the last call.
	Catchup(ctx context.Context) error
	Close() error
}

// Opener opens named logs, replaying what is already there into replay.
type Opener interface {
	OpenLog(ctx context.Context, name string, replay func([]byte)) (Log, error)
}

// Dir opens <dir>/<name>.jsonl. The empty Dir opens nothing: OpenLog returns
// a nil Log and the store stays in memory only.
type Dir string

// OpenLog implements Opener.
func (d Dir) OpenLog(_ context.Context, name string, replay func([]byte)) (Log, error) {
	if d == "" {
		return nil, nil
	}
	if err := os.MkdirAll(string(d), 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(string(d), name+".jsonl")
	f, err := fsutil.OpenJSONL(path, replay)
	if err != nil {
		return nil, err
	}
	return &fileLog{f: f, path: path}, nil
}

// fileLog is a JSONL file with a single writer: Catchup has nothing to do.
type fileLog struct {
	f    *os.File
	path string
}

func (l *fileLog) Append(_ context.Context, _ string, rec []byte) error {
	if _, err := l.f.Write(append(rec, '\n')); err != nil {
		return fmt.Errorf("append %s: %w", l.path, err)
	}
	if err := l.f.Sync(); err != nil { // durable before the change is acknowledged
		return fmt.Errorf("sync %s: %w", l.path, err)
	}
	return nil
}

func (l *fileLog) Catchup(context.Context) error { return nil }

// SingleWriter marks the log as written by this process alone: Catchup never
// has anything to apply.
func (l *fileLog) SingleWriter() bool { return true }

// SingleWriter reports whether l is a log no other process appends to, so
// Catchup is a no-op and a caller can skip it (and the lock it would take).
func SingleWriter(l Log) bool {
	s, ok := l.(interface{ SingleWriter() bool })
	return ok && s.SingleWriter()
}
func (l *fileLog) Close() error { return l.f.Close() }

// CloseLog closes l under mu; a nil Log (memory only) is a no-op.
func CloseLog(mu sync.Locker, l Log) error {
	mu.Lock()
	defer mu.Unlock()
	if l == nil {
		return nil
	}
	return l.Close()
}

// OpTimeout bounds one store operation against a shared backend when the
// caller has no request context to pass down.
const OpTimeout = 5 * time.Second

// Ctx returns a context bounded by OpTimeout.
func Ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), OpTimeout)
}

// KV is a namespaced key-value space whose entries expire. Expired entries
// are invisible to Get, Add and Take. It holds short-lived, single-use state
// (enrollment tokens, consumed login states, approval claims) that every
// replica must see.
type KV interface {
	// Put sets ns/key, replacing any existing entry.
	Put(ctx context.Context, ns, key string, val []byte, exp time.Time) error
	// Add sets ns/key only if it is absent or expired; added reports whether it did.
	Add(ctx context.Context, ns, key string, val []byte, exp time.Time) (added bool, err error)
	// Get returns an unexpired entry.
	Get(ctx context.Context, ns, key string) ([]byte, bool, error)
	// Take deletes ns/key and returns its value if it had not expired. Of
	// concurrent Takes of one key, at most one gets ok.
	Take(ctx context.Context, ns, key string) ([]byte, bool, error)
	// Delete removes ns/key (no error if absent).
	Delete(ctx context.Context, ns, key string) error
	// TryLock takes ns/key for owner until ttl from now on the store's own
	// clock (for Postgres the database's, never a replica's). It succeeds when
	// the key is absent, expired, or already owner's (which extends it).
	TryLock(ctx context.Context, ns, key, owner string, ttl time.Duration) (bool, error)
	// Unlock releases ns/key only if owner still holds it: a holder whose
	// lock expired and was taken over cannot release the new holder's.
	Unlock(ctx context.Context, ns, key, owner string) error
	// Raise sets ns/key to the decimal at unless a live entry already holds a
	// larger value (an epoch that never moves backwards); the entry lives
	// until exp, or longer if it already did.
	Raise(ctx context.Context, ns, key string, at int64, exp time.Time) error
}

// ErrUnavailable wraps shared-backend failures that a handler reports as
// 503 rather than as a client error.
var ErrUnavailable = errors.New("state store unavailable")

// ErrFenced means a write was refused because the writer no longer holds the
// lease it was fenced by (another replica leads now). Shared backends wrap it;
// callers skip the side effect the write was guarding.
var ErrFenced = errors.New("lease lost: write fenced off")

type memEntry struct {
	val []byte
	exp time.Time
}

// MemKV is the in-process KV (single replica). Now defaults to time.Now.
type MemKV struct {
	mu  sync.Mutex
	m   map[string]memEntry
	Now func() time.Time
}

func (m *MemKV) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// sweep drops expired entries (caller holds mu).
// ponytail: O(n) per write; fine for login/enrollment volume.
func (m *MemKV) sweep(now time.Time) {
	if m.m == nil {
		m.m = map[string]memEntry{}
	}
	for k, e := range m.m {
		if now.After(e.exp) {
			delete(m.m, k)
		}
	}
}

func memKey(ns, key string) string { return ns + "\x00" + key }

// Put implements KV.
func (m *MemKV) Put(_ context.Context, ns, key string, val []byte, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.now())
	m.m[memKey(ns, key)] = memEntry{append([]byte(nil), val...), exp}
	return nil
}

// Add implements KV.
func (m *MemKV) Add(_ context.Context, ns, key string, val []byte, exp time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.now())
	k := memKey(ns, key)
	if _, ok := m.m[k]; ok {
		return false, nil
	}
	m.m[k] = memEntry{append([]byte(nil), val...), exp}
	return true, nil
}

// Get implements KV.
func (m *MemKV) Get(_ context.Context, ns, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.m[memKey(ns, key)]
	if !ok || m.now().After(e.exp) {
		return nil, false, nil
	}
	return append([]byte(nil), e.val...), true, nil
}

// Take implements KV.
func (m *MemKV) Take(_ context.Context, ns, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(ns, key)
	e, ok := m.m[k]
	delete(m.m, k)
	if !ok || m.now().After(e.exp) {
		return nil, false, nil
	}
	return e.val, true, nil
}

// Delete implements KV.
func (m *MemKV) Delete(_ context.Context, ns, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, memKey(ns, key))
	return nil
}

// TryLock implements KV.
func (m *MemKV) TryLock(_ context.Context, ns, key, owner string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweep(now)
	k := memKey(ns, key)
	if e, ok := m.m[k]; ok && string(e.val) != owner {
		return false, nil
	}
	m.m[k] = memEntry{[]byte(owner), now.Add(ttl)}
	return true, nil
}

// Unlock implements KV.
func (m *MemKV) Unlock(_ context.Context, ns, key, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(ns, key)
	if e, ok := m.m[k]; ok && string(e.val) == owner {
		delete(m.m, k)
	}
	return nil
}

// Raise implements KV.
func (m *MemKV) Raise(_ context.Context, ns, key string, at int64, exp time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(m.now())
	k := memKey(ns, key)
	if e, ok := m.m[k]; ok {
		if cur, err := strconv.ParseInt(string(e.val), 10, 64); err == nil && cur >= at {
			if exp.After(e.exp) {
				e.exp = exp
				m.m[k] = e
			}
			return nil
		}
		if e.exp.After(exp) {
			exp = e.exp
		}
	}
	m.m[k] = memEntry{[]byte(strconv.FormatInt(at, 10)), exp}
	return nil
}

// Coalescer merges concurrent catch-ups of one shared log: a caller is
// satisfied by a catch-up that started after it arrived (so it sees every
// write committed before it asked), and every caller waiting meanwhile
// shares the same one. N concurrent requests cost about two database round
// trips, not N, and no store lock is held while they wait. Zero value ready.
type Coalescer struct {
	mu      sync.Mutex
	cond    *sync.Cond
	running bool
	started uint64 // catch-ups started
	done    uint64 // start number of the last finished catch-up
	err     error  // its result
}

// Do runs fn (or waits for a run that started after this call) and returns its error.
func (c *Coalescer) Do(fn func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cond == nil {
		c.cond = sync.NewCond(&c.mu)
	}
	need := c.started + 1 // a run that starts after now
	for {
		if c.done >= need {
			return c.err
		}
		if !c.running {
			c.running = true
			c.started++
			mine := c.started
			c.mu.Unlock()
			err := fn()
			c.mu.Lock()
			c.running, c.done, c.err = false, mine, err
			c.cond.Broadcast()
			continue
		}
		c.cond.Wait()
	}
}

// ValidName reports whether name is usable as a log or KV namespace:
// lowercase letters, digits and dashes.
func ValidName(name string) bool {
	return name != "" && len(name) <= 64 && strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
