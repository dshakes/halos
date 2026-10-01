package rollout

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/policy"
)

// History events.
const (
	EventEnter  = "enter"  // a merged step was observed live (Index, Step)
	EventHalt   = "halt"   // the controller rolled back or paused (Detail = action, Source, Reason)
	EventResume = "resume" // the policy left "active"; the halt is acknowledged
	EventAction = "action" // Key was done at step Index (Detail: e.g. a PR URL)
)

// Entry is one hash-chained history record.
type Entry struct {
	Seq    int       `json:"seq"`
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	Index  int       `json:"index"` // step index for enter
	Step   string    `json:"step,omitempty"`
	Detail string    `json:"detail,omitempty"`
	Key    string    `json:"key,omitempty"`    // action entries: what was done
	Source string    `json:"source,omitempty"` // halt entries: evidence source of the breach
	Reason string    `json:"reason,omitempty"` // halt entries: why
	Prev   string    `json:"prev"`             // previous entry's Hash ("" for the first)
	Hash   string    `json:"hash"`             // sha256 over this entry with Hash empty
}

// State is a rollout's controller state. Everything the controller acts on
// (Step, StepName, EnteredAt, Halted, HaltSource, HaltReason, Done) is derived
// by replaying History; the header copies are only checked against it. Last
// is display-only and never acted on.
//
// The hash chain is unkeyed: it detects partial edits (a changed, dropped or
// reordered entry, or a header that disagrees with the history), not an
// attacker who can rewrite the whole file and recompute every hash. Protect
// the data dir like the kill switch and audit log it sits next to.
type State struct {
	Rollout   string    `json:"rollout"`
	Step      int       `json:"step"` // -1 = not started
	StepName  string    `json:"stepName,omitempty"`
	EnteredAt time.Time `json:"enteredAt"`
	// Halted is "rollback" or "pause" once the controller acted on a breach;
	// it holds the rollout until the policy leaves "active".
	Halted     string `json:"halted,omitempty"`
	HaltSource string `json:"haltSource,omitempty"`
	HaltReason string `json:"haltReason,omitempty"`
	// Done maps idempotency keys (see Key) to details such as PR URLs.
	Done    map[string]string `json:"done,omitempty"`
	Last    *Decision         `json:"last,omitempty"` // last decision: status views only
	LastAt  time.Time         `json:"lastAt"`
	History []Entry           `json:"history"`
}

// NewState is the state of a rollout that has not started.
func NewState(name string) State { return State{Rollout: name, Step: -1, History: []Entry{}} }

func (e Entry) sum() string {
	e.Hash = ""
	b, _ := json.Marshal(e) // plain fields: cannot fail
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Record appends a chained entry and applies it.
func (s *State) Record(event string, index int, step, detail string, at time.Time) {
	s.add(Entry{At: at, Event: event, Index: index, Step: step, Detail: detail})
}

// Halt records that the controller rolled back or paused (action) at the
// current step, on evidence from source.
func (s *State) Halt(action, source, reason string, at time.Time) {
	s.add(Entry{At: at, Event: EventHalt, Index: s.Step, Step: s.StepName, Detail: action, Source: source, Reason: reason})
}

func (s *State) add(e Entry) {
	e.Seq, e.At = len(s.History)+1, e.At.UTC()
	if n := len(s.History); n > 0 {
		e.Prev = s.History[n-1].Hash
	}
	e.Hash = e.sum()
	s.History = append(s.History, e)
	s.apply(e)
}

func (s *State) apply(e Entry) {
	switch e.Event {
	case EventEnter:
		s.Step, s.StepName, s.EnteredAt, s.Done = e.Index, e.Step, e.At, nil
		s.Halted, s.HaltSource, s.HaltReason = "", "", ""
	case EventHalt:
		s.Halted, s.HaltSource, s.HaltReason = e.Detail, e.Source, e.Reason
	case EventResume:
		s.Halted, s.HaltSource, s.HaltReason, s.Done = "", "", "", nil
	case EventAction:
		if s.Done == nil {
			s.Done = map[string]string{}
		}
		s.Done[fmt.Sprintf("%d/%s", e.Index, e.Key)] = e.Detail
	}
}

// Key is the idempotency key of an action taken at the current step.
func (s *State) Key(action string) string { return fmt.Sprintf("%d/%s", s.Step, action) }

// Mark records an action as done (once per step) with its detail.
func (s *State) Mark(action, detail string, at time.Time) {
	s.add(Entry{At: at, Event: EventAction, Index: s.Step, Step: s.StepName, Key: action, Detail: detail})
}

// Did reports whether action was done at the current step, and its detail.
func (s *State) Did(action string) (string, bool) {
	d, ok := s.Done[s.Key(action)]
	return d, ok
}

// Sync folds the merged policy into the state: a new live step is entered
// (now: the controller first sees the merge), and a halt is acknowledged once
// the policy is no longer active (a human merged the pause or rollback).
// It reports whether anything changed.
func (s *State) Sync(r *policy.Rollout, now time.Time) bool {
	changed := false
	if i := r.StepIndex(r.Step); i != s.Step { // -1: a human reset the rollout
		s.Record(EventEnter, i, r.Step, "", now)
		changed = true
	}
	if s.Halted != "" && r.EffectiveStatus() != policy.RolloutActive {
		s.Record(EventResume, s.Step, s.StepName, "policy status "+r.EffectiveStatus(), now)
		changed = true
	}
	return changed
}

// ErrTampered is returned by LoadState when the history chain does not verify.
var ErrTampered = errors.New("rollout state: history hash chain does not verify")

// StatePath is <dir>/<name>.json; name is a validated policy name.
func StatePath(dir, name string) string { return filepath.Join(dir, name+".json") }

// LoadState reads and verifies <dir>/<name>.json; a missing file is a new state.
func LoadState(dir, name string) (State, error) {
	if !policy.ValidName(name) {
		return State{}, fmt.Errorf("rollout state: invalid rollout name %q", name)
	}
	b, err := os.ReadFile(StatePath(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return NewState(name), nil
	} else if err != nil {
		return State{}, fmt.Errorf("rollout state: %w", err)
	}
	var disk State
	if err := json.Unmarshal(b, &disk); err != nil {
		return State{}, fmt.Errorf("rollout state %s: %w", StatePath(dir, name), err)
	}
	if disk.Rollout != name {
		return State{}, fmt.Errorf("rollout state %s: belongs to rollout %q", StatePath(dir, name), disk.Rollout)
	}
	st := NewState(name)
	prev := ""
	for i, e := range disk.History {
		if e.Seq != i+1 || e.Prev != prev || e.Hash != e.sum() {
			return State{}, fmt.Errorf("%w: %s entry %d", ErrTampered, StatePath(dir, name), i+1)
		}
		prev = e.Hash
		st.History = append(st.History, e)
		st.apply(e)
	}
	if st.Halted != disk.Halted || st.HaltSource != disk.HaltSource || st.Step != disk.Step || !maps.Equal(st.Done, disk.Done) {
		return State{}, fmt.Errorf("%w: %s header disagrees with history", ErrTampered, StatePath(dir, name))
	}
	st.Last, st.LastAt = disk.Last, disk.LastAt // display only
	return st, nil
}

// Save writes the state atomically (0600).
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("rollout state: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("rollout state: encode: %w", err)
	}
	if err := fsutil.WriteAtomic(StatePath(dir, s.Rollout), append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("rollout state: %w", err)
	}
	return nil
}
