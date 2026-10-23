package pgstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// LeaseStore grants named leases. Expiry is judged on the store's clock (for
// Postgres, the database's now()), never on a replica's.
type LeaseStore interface {
	// Acquire takes or renews lease name for holder for ttl. ok is false while
	// another holder's lease is unexpired. token is the fencing token: it is
	// unchanged across renewals and grows whenever the lease is (re)taken.
	Acquire(ctx context.Context, name, holder string, ttl time.Duration) (token int64, ok bool, err error)
	// Release expires holder's lease now so another replica can take it.
	Release(ctx context.Context, name, holder string) error
}

// Acquire implements LeaseStore on halo_leases.
func (d *DB) Acquire(ctx context.Context, name, holder string, ttl time.Duration) (int64, bool, error) {
	var token int64
	err := d.db.QueryRowContext(ctx, `INSERT INTO halo_leases (name, holder, token, expires_at)
		VALUES ($1, $2, 1, now() + $3 * interval '1 millisecond')
		ON CONFLICT (name) DO UPDATE SET
			token = CASE WHEN halo_leases.holder = EXCLUDED.holder AND halo_leases.expires_at > now()
				THEN halo_leases.token ELSE halo_leases.token + 1 END,
			holder = EXCLUDED.holder,
			expires_at = EXCLUDED.expires_at
		WHERE halo_leases.holder = EXCLUDED.holder OR halo_leases.expires_at <= now()
		RETURNING token`, name, holder, ttl.Milliseconds()).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, d.fail(fmt.Errorf("pgstore: acquire lease %s: %w", name, err))
	}
	return token, true, nil
}

// Release implements LeaseStore.
func (d *DB) Release(ctx context.Context, name, holder string) error {
	if _, err := d.db.ExecContext(ctx, `UPDATE halo_leases SET expires_at = now() WHERE name = $1 AND holder = $2 AND expires_at > now()`, name, holder); err != nil {
		return d.fail(fmt.Errorf("pgstore: release lease %s: %w", name, err))
	}
	return nil
}

// checkFence fails with ErrFenced unless f's lease is held, unexpired, at
// f.Token. It reads the lease row FOR SHARE, so a takeover (Acquire's UPDATE
// of that row) waits until this transaction ends: a fenced write either
// commits while its token still owns the lease, or the takeover commits first
// and the write sees the new token. Expiry is checked against
// clock_timestamp() (the time of the check), not now() (the transaction's start).
func checkFence(ctx context.Context, t *sql.Tx, f Fence) error {
	var one int
	err := t.QueryRowContext(ctx, `SELECT 1 FROM halo_leases WHERE name = $1 AND token = $2 AND expires_at > clock_timestamp() FOR SHARE`, f.Name, f.Token).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w (lease %s token %d)", ErrFenced, f.Name, f.Token)
	}
	if err != nil {
		return fmt.Errorf("pgstore: check lease %s: %w", f.Name, err)
	}
	return nil
}

// Elector runs a singleton loop on exactly one replica. Every replica runs
// an Elector on the same lease; the one holding it runs lead, and stops it
// (cancels its context and waits) when the lease is lost or cannot be
// renewed in time, before any other replica can take the lease over.
type Elector struct {
	Store  LeaseStore
	Name   string // lease name, e.g. "controller"
	Holder string // unique per replica (pod name + random suffix)
	// TTL is the lease length (default 15s); Renew the renewal period
	// (default TTL/3). A leader that has not renewed by TTL-Renew after its
	// last successful renewal started steps down, so it is gone before the
	// lease can expire on the database clock.
	TTL, Renew time.Duration
	Log        *slog.Logger
	Now        func() time.Time // test seam; default time.Now

	leading  bool
	token    int64
	deadline time.Time // step down at or after this (local clock)
	term     int       // bumped on every step-down: see holder

	isLeader atomic.Bool
	tok      atomic.Int64
	changes  atomic.Int64
}

func (e *Elector) defaults() {
	if e.TTL <= 0 {
		e.TTL = 15 * time.Second
	}
	if e.Renew <= 0 || e.Renew >= e.TTL {
		e.Renew = e.TTL / 3
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Log == nil {
		e.Log = slog.Default()
	}
}

// holder is the id this term campaigns under. A replica that stepped down
// comes back as a new holder, so it cannot silently resume its old lease: it
// waits for expiry like any peer and gets a new fencing token, and a renewal
// that timed out on its side but committed on the database cannot extend a
// term that has ended.
func (e *Elector) holder() string { return fmt.Sprintf("%s#%d", e.Holder, e.term) }

// Leader reports whether this replica currently leads.
func (e *Elector) Leader() bool { return e.isLeader.Load() }

// Token is the fencing token of the current leadership (0 when not leading).
func (e *Elector) Token() int64 { return e.tok.Load() }

// WriteMetrics writes halo_leader (1 when this replica leads) and leadership changes.
func (e *Elector) WriteMetrics(w io.Writer) {
	v := 0
	if e.Leader() {
		v = 1
	}
	fmt.Fprintf(w, "# HELP halo_leader 1 when this replica holds the lease.\n# TYPE halo_leader gauge\nhalo_leader{lease=%q} %d\n", e.Name, v)
	fmt.Fprintf(w, "# HELP halo_leader_changes_total Times this replica gained or lost the lease.\n# TYPE halo_leader_changes_total counter\nhalo_leader_changes_total{lease=%q} %d\n", e.Name, e.changes.Load())
}

// tick is one campaign round: step down if the renewal deadline passed, then
// try to acquire or renew. It returns whether this replica leads afterwards,
// the fencing token, and how long to wait before the next round.
func (e *Elector) tick(ctx context.Context) (bool, int64, time.Duration) {
	start := e.Now()
	if e.leading && !start.Before(e.deadline) {
		e.Log.Warn("leader lease not renewed in time; stepping down", "lease", e.Name, "holder", e.Holder)
		e.setLeading(false, 0)
	}
	actx, cancel := context.WithTimeout(ctx, e.Renew/2)
	tok, ok, err := e.Store.Acquire(actx, e.Name, e.holder(), e.TTL)
	cancel()
	switch {
	case err != nil:
		if ctx.Err() == nil {
			e.Log.Warn("leader lease renewal failed", "lease", e.Name, "holder", e.Holder, "err", err)
		}
	case ok:
		// Measured from before the call: the database's expiry is later still.
		e.deadline = start.Add(e.TTL - e.Renew)
		if !e.leading || tok != e.token {
			e.Log.Info("acquired leader lease", "lease", e.Name, "holder", e.Holder, "token", tok)
		}
		e.setLeading(true, tok)
	default:
		if e.leading {
			e.Log.Warn("leader lease taken by another replica; stepping down", "lease", e.Name, "holder", e.Holder)
		}
		e.setLeading(false, 0)
	}
	wait := e.Renew
	if e.leading {
		wait = min(wait, max(0, e.deadline.Sub(e.Now())))
	}
	return e.leading, e.token, wait
}

func (e *Elector) setLeading(on bool, tok int64) {
	if on != e.leading {
		e.changes.Add(1)
		if !on {
			e.term++
		}
	}
	e.leading, e.token = on, tok
	e.isLeader.Store(on)
	e.tok.Store(tok)
}

// Run campaigns until ctx ends. lead runs while this replica leads, with a
// context cancelled on step-down and the lease's fencing token; if it returns
// on its own it is restarted on the next round while the lease is still held.
// On exit Run stops lead and releases the lease so a peer takes over at once.
func (e *Elector) Run(ctx context.Context, lead func(ctx context.Context, token int64)) {
	e.defaults()
	var (
		cancel  context.CancelFunc
		done    chan struct{}
		running int64
	)
	stop := func() {
		if cancel != nil {
			cancel()
			<-done
			cancel, done, running = nil, nil, 0
		}
	}
	startLead := func(tok int64) {
		lctx, c := context.WithCancel(ctx)
		cancel, done, running = c, make(chan struct{}), tok
		d := done
		// c on exit releases lctx even when lead returns by itself.
		go func() { defer close(d); defer c(); lead(lctx, tok) }()
	}
	for {
		leading, tok, wait := e.tick(ctx)
		if done != nil {
			select {
			case <-done: // lead returned by itself
				cancel, done, running = nil, nil, 0
			default:
			}
		}
		switch {
		case !leading:
			stop()
		case running != tok:
			stop()
			startLead(tok)
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			stop()
			if e.leading {
				rctx, c := context.WithTimeout(context.WithoutCancel(ctx), e.Renew)
				if err := e.Store.Release(rctx, e.Name, e.holder()); err != nil {
					e.Log.Warn("release leader lease", "lease", e.Name, "err", err)
				}
				c()
				e.setLeading(false, 0)
			}
			return
		case <-t.C:
		}
	}
}

// HolderID is a replica-unique lease holder id: the host (pod) name and a
// random suffix, so two processes on one host never share a lease.
func HolderID() string {
	host, _ := os.Hostname() // best effort: the suffix makes it unique
	var b [4]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	return host + "-" + hex.EncodeToString(b[:])
}

// Leased runs fn on exactly one replica at a time: every replica calls it
// with the same name, the one holding lease name runs fn with a context that
// ends when the lease is lost, and the document writes of the view fn gets are
// fenced by that lease. Leased returns when ctx ends. ttl 0 = the default (15s).
func (d *DB) Leased(ctx context.Context, name string, ttl time.Duration, fn func(ctx context.Context, view *Fenced)) {
	e := &Elector{Store: d, Name: name, Holder: HolderID(), TTL: ttl}
	e.Run(ctx, func(lctx context.Context, token int64) { fn(lctx, d.Fenced(Fence{Name: name, Token: token})) })
}
