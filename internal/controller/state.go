package controller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/promote"
)

// Actions the controller takes at most once per experiment run.
const (
	ActionKill = "kill" // detail: "" = enforced, else why it is not known to be
	ActionPR   = "pr"
	// ActionNotify is recorded per channel as ActionNotify+":"+name (see Named);
	// a bare ActionNotify (older logs) means every channel was notified.
	ActionNotify = "notify"
	// ActionRollback marks that this run rolled back (detail: the report JSON);
	// the controller stops evaluating the experiment until it leaves "running".
	ActionRollback = "rollback"
	// ActionHold marks the once-per-run warning that an experiment is killed
	// and therefore not evaluated.
	ActionHold = "hold"
)

// VerdictKilled is the pseudo-verdict of hold records and of the Event sent
// when a running experiment is found killed (it is not evaluated).
const VerdictKilled promote.Verdict = "killed"

// stateRec is one line of controller-state.jsonl.
type stateRec struct {
	Experiment string    `json:"experiment"`
	Verdict    string    `json:"verdict,omitempty"`
	Action     string    `json:"action,omitempty"`
	Detail     string    `json:"detail,omitempty"` // e.g. the PR URL
	Reset      bool      `json:"reset,omitempty"`  // experiment left "running": start over
	At         time.Time `json:"at"`
}

// StateLog remembers which (experiment, verdict, action) the controller has
// already done, so repeated ticks never open a second PR or send a second
// notification. An experiment's entries are forgotten once it is seen not
// running (a human merged the pause/conclude), so a later restart starts clean.
// ponytail: no compaction; one line per action per experiment run.
type StateLog struct {
	mu   sync.Mutex
	f    *os.File
	done map[string]string // key -> detail
	exps map[string]bool   // experiments with entries since their last reset
}

func stateKey(exp, verdict, action string) string { return exp + "\x00" + verdict + "\x00" + action }

// OpenStateLog opens dir/controller-state.jsonl ("" = memory only).
func OpenStateLog(dir string) (*StateLog, error) {
	l := &StateLog{done: map[string]string{}, exps: map[string]bool{}}
	if dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("controller state: %w", err)
	}
	f, err := fsutil.OpenJSONL(filepath.Join(dir, "controller-state.jsonl"), func(line []byte) {
		var r stateRec
		if json.Unmarshal(line, &r) == nil && r.Experiment != "" { // torn line: skip
			l.apply(r)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("controller state: %w", err)
	}
	l.f = f
	return l, nil
}

func (l *StateLog) apply(r stateRec) {
	if r.Reset {
		for k := range l.done {
			if strings.HasPrefix(k, r.Experiment+"\x00") {
				delete(l.done, k)
			}
		}
		delete(l.exps, r.Experiment)
		return
	}
	l.done[stateKey(r.Experiment, r.Verdict, r.Action)] = r.Detail
	l.exps[r.Experiment] = true
}

func (l *StateLog) write(r stateRec) error {
	if l.f != nil {
		b, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("controller state: encode: %w", err)
		}
		if _, err := l.f.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("controller state: append: %w", err)
		}
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("controller state: sync: %w", err)
		}
	}
	l.apply(r)
	return nil
}

// Done reports whether the action was already taken, and its detail.
func (l *StateLog) Done(exp, verdict, action string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	d, ok := l.done[stateKey(exp, verdict, action)]
	return d, ok
}

// Record marks an action as taken.
func (l *StateLog) Record(exp, verdict, action, detail string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.write(stateRec{Experiment: exp, Verdict: verdict, Action: action, Detail: detail, At: at.UTC()})
}

// Reset forgets exp's actions; a no-op (nothing written) when there are none.
func (l *StateLog) Reset(exp string, at time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.exps[exp] {
		return nil
	}
	return l.write(stateRec{Experiment: exp, Reset: true, At: at.UTC()})
}

// Close closes the log file.
func (l *StateLog) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}
