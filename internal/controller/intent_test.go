package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/storage"
)

// fencingOpener opens a memory log whose appends fail with storage.ErrFenced
// once fenced is set: the controller's state log on a replica that lost the
// leader lease.
type fencingOpener struct {
	mu         sync.Mutex
	recs       [][]byte
	fenced     bool
	fenceAfter int // >0: appends beyond this many are fenced
}

type fencingLog struct{ o *fencingOpener }

func (o *fencingOpener) OpenLog(_ context.Context, _ string, replay func([]byte)) (storage.Log, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, r := range o.recs {
		replay(r)
	}
	return fencingLog{o}, nil
}

func (o *fencingOpener) fence() { o.mu.Lock(); o.fenced = true; o.mu.Unlock() }

func (l fencingLog) Append(_ context.Context, _ string, rec []byte) error {
	l.o.mu.Lock()
	defer l.o.mu.Unlock()
	if l.o.fenced || (l.o.fenceAfter > 0 && len(l.o.recs) >= l.o.fenceAfter) {
		return fmt.Errorf("pgstore: %w (lease controller token 1)", storage.ErrFenced)
	}
	l.o.recs = append(l.o.recs, append([]byte(nil), rec...))
	return nil
}
func (fencingLog) Catchup(context.Context) error { return nil }
func (fencingLog) Close() error                  { return nil }

type countKill struct{ n int }

func (k *countKill) Kill(context.Context, string, string, string) (bool, error) {
	k.n++
	return true, nil
}

// TestDeposedLeaderTakesNoSideEffects: once the state log is fenced (another
// replica took the lease), a rollback verdict trips no kill, opens no PR and
// sends no notification from this replica.
func TestDeposedLeaderTakesNoSideEffects(t *testing.T) {
	r := newRig(t, promote.Rollback)
	o := &fencingOpener{}
	st, err := OpenStateLogOn(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	k := &countKill{}
	r.c.State, r.c.Kill = st, k
	o.fence()
	err = r.c.Tick(context.Background())
	if !errors.Is(err, storage.ErrFenced) {
		t.Fatalf("tick on a fenced state log: %v, want ErrFenced", err)
	}
	if k.n != 0 || len(r.w.calls) != 0 || len(r.n.events) != 0 {
		t.Fatalf("deposed leader acted: kills=%d PRs=%d notifications=%d", k.n, len(r.w.calls), len(r.n.events))
	}
}

// TestFencedAfterKillStopsPRAndNotify: the lease is lost between the kill
// and the PR: the PR and notification are skipped (the new leader finishes
// from the recorded rollback).
func TestFencedAfterKillStopsPRAndNotify(t *testing.T) {
	r := newRig(t, promote.Rollback)
	o := &fencingOpener{}
	st, err := OpenStateLogOn(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	r.c.State = st
	r.c.Kill = KillFunc(func(context.Context, string, string, string) (bool, error) {
		o.fence() // the lease moves on right after the kill
		return true, nil
	})
	if err := r.c.Tick(context.Background()); !errors.Is(err, storage.ErrFenced) {
		t.Fatalf("tick: %v, want ErrFenced", err)
	}
	if len(r.w.calls) != 0 || len(r.n.events) != 0 {
		t.Fatalf("PR/notify after losing the lease: PRs=%d notifications=%d", len(r.w.calls), len(r.n.events))
	}
}

// findingWriter is a PR writer that can find PRs by intent marker.
type findingWriter struct {
	fakeWriter
	open map[string]string // marker -> url of a PR "already on the forge"
}

func (w *findingWriter) FindPR(_ context.Context, marker string) (string, bool, error) {
	u, ok := w.open[marker]
	return u, ok, nil
}

// TestNewLeaderFindsPRInsteadOfReopening: a previous leader recorded the PR
// intent and opened the PR, then died before recording the result. The next
// leader finds it by the intent marker and does not open a second one.
func TestNewLeaderFindsPRInsteadOfReopening(t *testing.T) {
	r := newRig(t, promote.Promote)
	w := &findingWriter{open: map[string]string{}}
	r.c.Writer = w
	// The first leader: intent recorded, PR opened (its body carries the marker), result lost.
	key, prior, err := r.c.intend("exp-a", string(promote.Promote), ActionPR)
	if err != nil || prior {
		t.Fatal(err, prior)
	}
	w.open[intentMarker(key)] = "https://github.test/pr/opened-by-old-leader"
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.calls) != 0 {
		t.Fatalf("second PR opened: %+v", w.calls)
	}
	if u, ok := r.c.State.Done("exp-a", string(promote.Promote), ActionPR); !ok || u != "https://github.test/pr/opened-by-old-leader" {
		t.Fatalf("PR result not recorded from the found PR: %q %v", u, ok)
	}
	if len(r.n.events) != 1 || r.n.events[0].PRURL != "https://github.test/pr/opened-by-old-leader" || r.n.events[0].ID == "" {
		t.Fatalf("notification: %+v", r.n.events)
	}
}

// TestIntentKeysTravelWithEffects: the PR body carries the intent marker and
// the notification an event id, so a later leader can recognise them.
func TestIntentKeysTravelWithEffects(t *testing.T) {
	r := newRig(t, promote.Promote)
	if err := r.c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	key, prior, _ := r.c.intend("exp-a", string(promote.Promote), ActionPR)
	if !prior || len(r.w.calls) != 1 || !strings.Contains(r.w.calls[0].body, intentMarker(key)) {
		t.Fatalf("PR body lacks the intent marker %q", intentMarker(key))
	}
	if len(r.n.events) != 1 || r.n.events[0].ID == "" {
		t.Fatalf("notification without an event id: %+v", r.n.events)
	}
}

// TestRolloutFencedSkipsNotify: a rollout notification whose intent cannot be
// persisted because the lease moved on is not sent.
func TestRolloutFencedSkipsNotify(t *testing.T) {
	r := newRig(t, promote.Continue)
	st := rollout.NewState("r")
	ro := &policy.Rollout{Meta: policy.Meta{Name: "r"}}
	persist := func() error { return fmt.Errorf("pgstore: %w", storage.ErrFenced) }
	err := r.c.rolloutNotify(context.Background(), ro, &st, Event{Verdict: "awaiting_approval"}, rollout.Decision{}, persist)
	if !errors.Is(err, storage.ErrFenced) || len(r.n.events) != 0 {
		t.Fatalf("fenced rollout notify: err=%v events=%d", err, len(r.n.events))
	}
	ok := func() error { return nil }
	if err := r.c.rolloutNotify(context.Background(), ro, &st, Event{Verdict: "awaiting_approval"}, rollout.Decision{}, ok); err != nil || len(r.n.events) != 1 || r.n.events[0].ID == "" {
		t.Fatalf("leader rollout notify: err=%v events=%+v", err, r.n.events)
	}
}

// TestLeaseLostBeforeKill: the rollback was recorded, then the lease moved
// on before the kill: the kill intent is refused and no kill, PR or
// notification happens (each external call has its own fenced intent).
func TestLeaseLostBeforeKill(t *testing.T) {
	r := newRig(t, promote.Rollback)
	o := &fencingOpener{fenceAfter: 1} // the rollback record lands, the kill intent does not
	st, err := OpenStateLogOn(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	k := &countKill{}
	r.c.State, r.c.Kill = st, k
	if err := r.c.Tick(context.Background()); !errors.Is(err, storage.ErrFenced) {
		t.Fatalf("tick: %v, want ErrFenced", err)
	}
	if _, done := st.Done("exp-a", string(promote.Rollback), ActionRollback); !done {
		t.Fatal("setup: the rollback record should have landed")
	}
	if k.n != 0 || len(r.w.calls) != 0 || len(r.n.events) != 0 {
		t.Fatalf("acted after losing the lease: kills=%d PRs=%d notifications=%d", k.n, len(r.w.calls), len(r.n.events))
	}
}
