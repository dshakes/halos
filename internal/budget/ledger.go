package budget

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Record is usage a gateway replica observed for one principal. At is the
// minute it happened, so usage reported late (after an outage) still lands in
// the window it belongs to.
type Record struct {
	Principal
	Spend
	At time.Time `json:"at"`
}

// batchMemory is how long a usage batch id is remembered: a replica retries
// a batch whose response it lost, and the retry must not count twice.
const batchMemory = time.Hour

// Ledger holds the authoritative counters. It lives only in halo-server, a
// single replica (ADR-0017), so a mutex is the whole concurrency story.
type Ledger struct {
	mu     sync.Mutex
	c      map[string]map[string]map[int64]Spend // budget -> key -> bucket start (unix s) -> spend
	seen   map[string]time.Time                  // batch id -> applied at
	pruned time.Time
	dirty  bool
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{c: map[string]map[string]map[int64]Spend{}, seen: map[string]time.Time{}}
}

// Apply charges every record to the counters its principal maps to under
// budgets. A batch id already applied within the last hour is ignored and
// reported as a duplicate. Records are trusted to be validated by the caller.
func (l *Ledger) Apply(budgets []policy.Budget, batch string, recs []Record, now time.Time) (duplicate bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(budgets, now)
	if batch != "" {
		if _, ok := l.seen[batch]; ok {
			return true
		}
		l.seen[batch] = now
	}
	for _, r := range recs {
		at := r.At
		if at.IsZero() || at.After(now) {
			at = now // a replica clock ahead of ours must not charge a future window
		}
		for _, c := range Charges(budgets, r.Principal) {
			byKey := l.c[c.Budget.Name]
			if byKey == nil {
				byKey = map[string]map[int64]Spend{}
				l.c[c.Budget.Name] = byKey
			}
			bk := byKey[c.Key]
			if bk == nil {
				bk = map[int64]Spend{}
				byKey[c.Key] = bk
			}
			s := bucket(c.Budget, at).Unix()
			sp := bk[s]
			sp.add(r.Spend)
			bk[s] = sp
		}
		l.dirty = true
	}
	return false
}

// prune drops buckets that left their window, counters of budgets no longer
// in policy, and remembered batch ids older than batchMemory. At most once a minute.
func (l *Ledger) prune(budgets []policy.Budget, now time.Time) {
	if now.Sub(l.pruned) < time.Minute {
		return
	}
	l.pruned = now
	for id, t := range l.seen {
		if now.Sub(t) > batchMemory {
			delete(l.seen, id)
		}
	}
	for name, byKey := range l.c {
		i := slices.IndexFunc(budgets, func(b policy.Budget) bool { return b.Name == name })
		if i < 0 {
			delete(l.c, name)
			l.dirty = true
			continue
		}
		b := &budgets[i]
		cutoff, _ := Window(b, now)
		if p := b.RollingPeriod(); p > 0 {
			cutoff = now.Add(-p - bucketSize(p))
		}
		for key, bk := range byKey {
			for s := range bk {
				if time.Unix(s, 0).Before(cutoff) {
					delete(bk, s)
					l.dirty = true
				}
			}
			if len(bk) == 0 {
				delete(byKey, key)
			}
		}
	}
}

// Status returns the state of every counter p is charged to.
func (l *Ledger) Status(budgets []policy.Budget, p Principal, now time.Time) []Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	cs := Charges(budgets, p)
	out := make([]Status, 0, len(cs))
	for _, c := range cs {
		out = append(out, l.status(c, now))
	}
	return out
}

// All returns every counter with spend in its current window, plus the
// fixed org and group counters even at zero, sorted by budget then key.
func (l *Ledger) All(budgets []policy.Budget, now time.Time) []Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Status
	for i := range budgets {
		b := &budgets[i]
		keys := map[string]bool{}
		switch b.Scope {
		case policy.ScopeOrg:
			keys["org"] = true
		case policy.ScopeGroup:
			for _, g := range b.Groups {
				keys["group:"+g] = true
			}
		case policy.ScopeRing:
			for _, r := range b.Rings {
				keys["ring:"+r] = true
			}
		}
		for k := range l.c[b.Name] {
			keys[k] = true
		}
		var sts []Status
		for k := range keys {
			st := l.status(Charge{b, k}, now)
			if st.SpentUSD > 0 || st.SpentTokens > 0 || b.Scope != policy.ScopeUser {
				sts = append(sts, st)
			}
		}
		sort.Slice(sts, func(i, j int) bool { return sts[i].Key < sts[j].Key })
		out = append(out, sts...)
	}
	return out
}

func (l *Ledger) status(c Charge, now time.Time) Status {
	st := statusFor(c)
	b := c.Budget
	bk := l.c[b.Name][c.Key]
	per := b.RollingPeriod()
	if per <= 0 {
		start, reset := Window(b, now)
		sp := bk[start.Unix()]
		st.SpentUSD, st.SpentTokens, st.ResetAt = sp.USD, sp.Tokens, reset
		return st
	}
	// Rolling: a bucket counts while any part of it is inside (now-per, now],
	// so it leaves the window at start+size+per.
	size := bucketSize(per)
	var starts []int64
	var total Spend
	for s, sp := range bk {
		if time.Unix(s, 0).Add(size + per).After(now) {
			starts = append(starts, s)
			total.add(sp)
		}
	}
	slices.Sort(starts)
	st.SpentUSD, st.SpentTokens = total.USD, total.Tokens
	st.ResetAt = now.Add(per).UTC()
	if len(starts) > 0 {
		st.ResetAt = time.Unix(starts[0], 0).Add(size + per).UTC()
	}
	if under(b, total) {
		return st
	}
	rem := total
	for _, s := range starts { // exhausted: when enough of the oldest usage expires
		rem.USD -= bk[s].USD
		rem.Tokens -= bk[s].Tokens
		if under(b, rem) {
			st.ResetAt = time.Unix(s, 0).Add(size + per).UTC()
			break
		}
	}
	return st
}

type ledgerFile struct {
	Version  int                                   `json:"version"`
	Counters map[string]map[string]map[int64]Spend `json:"counters"`
	Seen     map[string]time.Time                  `json:"seen,omitempty"`
}

const ledgerVersion = 1

// Snapshot serialises the ledger and reports whether anything changed since
// the previous snapshot (callers skip the write when not).
func (l *Ledger) Snapshot() (b []byte, changed bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, err = json.Marshal(ledgerFile{Version: ledgerVersion, Counters: l.c, Seen: l.seen}); err != nil {
		return nil, false, fmt.Errorf("budget: snapshot ledger: %w", err)
	}
	changed, l.dirty = l.dirty, false
	return b, changed, nil
}

// LoadLedger restores a Snapshot.
func LoadLedger(b []byte) (*Ledger, error) {
	var f ledgerFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("budget: load ledger: %w", err)
	}
	if f.Version != ledgerVersion {
		return nil, fmt.Errorf("budget: load ledger: version %d not supported (want %d)", f.Version, ledgerVersion)
	}
	l := NewLedger()
	if f.Counters != nil {
		l.c = f.Counters
	}
	if f.Seen != nil {
		l.seen = f.Seen
	}
	return l, nil
}
