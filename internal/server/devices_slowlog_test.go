package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/storage"
)

// gateLog is a storage.Log whose Append can be held, like an fsync or a
// database round trip that is slow under load.
type gateLog struct {
	mu      sync.Mutex
	hold    chan struct{} // non-nil: Append waits for it to close
	entered chan struct{} // receives once per held Append
}

func (g *gateLog) Append(context.Context, string, []byte) error {
	g.mu.Lock()
	hold := g.hold
	g.mu.Unlock()
	if hold != nil {
		g.entered <- struct{}{}
		<-hold
	}
	return nil
}
func (g *gateLog) Catchup(context.Context) error { return nil }
func (g *gateLog) Close() error                  { return nil }
func (g *gateLog) SingleWriter() bool            { return true } // like the file log

type gateOpener struct{ l *gateLog }

func (o gateOpener) OpenLog(context.Context, string, func([]byte)) (storage.Log, error) {
	return o.l, nil
}

// A device authentication must not queue behind another device's slow write
// (an enrollment's fsync, a revocation, a lastSeen persist): under a morning
// enrollment rush that serialized every ring, report and kill-list request
// behind the log.
func TestDeviceLookupNotBlockedBySlowWrite(t *testing.T) {
	g := &gateLog{entered: make(chan struct{}, 4)}
	d, err := openDeviceStore(gateOpener{g}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, _, err := d.mint(Principal{ID: "a@example.com"}, now)
	if err != nil {
		t.Fatal(err)
	}

	hold := make(chan struct{})
	g.mu.Lock()
	g.hold = hold
	g.mu.Unlock()
	minted := make(chan error, 1)
	go func() { _, _, err := d.mint(Principal{ID: "b@example.com"}, now); minted <- err }()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the second enrollment never reached the log")
	}

	looked := make(chan error, 1)
	go func() { _, err := d.lookup(tok, now); looked <- err }()
	select {
	case err := <-looked:
		if err != nil {
			t.Fatalf("lookup while another device is being written: %v", err)
		}
	case <-time.After(2 * time.Second):
		close(hold)
		t.Fatal("lookup blocked behind another device's slow write")
	}
	select {
	case <-minted:
		t.Fatal("the held enrollment finished before the log released it")
	default:
	}
	close(hold)
	if err := <-minted; err != nil {
		t.Fatal(err)
	}
	if _, err := d.lookup(tok, now); err != nil {
		t.Fatalf("lookup after the write: %v", err)
	}
	if _, err := d.lookup("not-a-token", now); !errors.Is(err, errNoDevice) {
		t.Fatalf("unknown token: %v, want errNoDevice", err)
	}
}
