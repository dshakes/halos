package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/storage"
)

// flakyLog fails Append on demand (a sync error after the write) and keeps
// what it accepted.
type flakyLog struct {
	mu   sync.Mutex
	fail bool
	recs []string
}

func (l *flakyLog) Append(_ context.Context, _ string, rec []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fail {
		return errors.New("sync: input/output error")
	}
	l.recs = append(l.recs, string(rec))
	return nil
}
func (l *flakyLog) Catchup(context.Context) error { return nil }
func (l *flakyLog) Close() error                  { return nil }
func (l *flakyLog) SingleWriter() bool            { return true }
func (l *flakyLog) setFail(v bool)                { l.mu.Lock(); l.fail = v; l.mu.Unlock() }
func (l *flakyLog) revoked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.recs {
		if strings.Contains(r, `"revoked":true`) {
			n++
		}
	}
	return n
}

type flakyOpener struct{ l *flakyLog }

func (o flakyOpener) OpenLog(context.Context, string, func([]byte)) (storage.Log, error) {
	return o.l, nil
}

func flakyStore(t *testing.T) (*deviceStore, *flakyLog, []string) {
	t.Helper()
	l := &flakyLog{}
	d, err := openDeviceStore(flakyOpener{l}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var toks []string
	for _, u := range []string{"a@example.com", "a@example.com", "b@example.com"} {
		tok, _, err := d.mint(Principal{ID: u}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		toks = append(toks, tok)
	}
	return d, l, toks
}

func deviceID(t *testing.T, d *deviceStore, tok string) string {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.byHash[hashDeviceToken(tok)].ID
}

// A revocation whose log write fails stays in force (fail closed): the log may
// hold it anyway, and a device that works until a restart is the unsafe
// outcome. The retry persists it, once.
func TestRevokeWriteFailureStaysRevoked(t *testing.T) {
	d, l, toks := flakyStore(t)
	id := deviceID(t, d, toks[0])
	l.setFail(true)
	if _, err := d.revoke(id); err == nil {
		t.Fatal("revoke reported success although the write failed")
	}
	if _, err := d.lookup(toks[0], time.Now()); !errors.Is(err, errNoDevice) {
		t.Fatalf("device whose revocation failed to persist still authenticates: %v", err)
	}
	l.setFail(false)
	if _, err := d.revoke(id); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := l.revoked(); n != 1 {
		t.Fatalf("%d revocation records after the retry, want 1", n)
	}
	if _, err := d.lookup(toks[0], time.Now()); !errors.Is(err, errNoDevice) {
		t.Fatalf("revoked device authenticates: %v", err)
	}
}

func TestRevokeUserWriteFailureStaysRevoked(t *testing.T) {
	d, l, toks := flakyStore(t)
	l.setFail(true)
	if _, err := d.revokeUser("a@example.com"); err == nil {
		t.Fatal("revokeUser reported success although the write failed")
	}
	for _, tok := range toks[:2] {
		if _, err := d.lookup(tok, time.Now()); err == nil && tok == toks[0] {
			t.Fatal("device whose revocation failed to persist still authenticates")
		}
	}
	if _, err := d.lookup(toks[2], time.Now()); err != nil {
		t.Fatalf("another user's device was refused: %v", err)
	}
	l.setFail(false)
	n, err := d.revokeUser("a@example.com")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n != 2 || l.revoked() != 2 {
		t.Fatalf("retry revoked %d, log holds %d revocation records, want 2 and 2", n, l.revoked())
	}
	if n, err := d.revokeUser("a@example.com"); err != nil || n != 0 {
		t.Fatalf("second retry = %d, %v; want nothing left to do", n, err)
	}
	for _, tok := range toks[:2] {
		if _, err := d.lookup(tok, time.Now()); !errors.Is(err, errNoDevice) {
			t.Fatalf("revoked device authenticates: %v", err)
		}
	}
}
