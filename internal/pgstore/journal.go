package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dshakes/halos/internal/storage"
)

// journalLock namespaces the per-stream append locks (two-key advisory lock).
const journalLock = 0x6a726e6c // "jrnl"

// ErrFenced means a fenced write was refused: the writer no longer holds the
// lease whose token it was opened with (another replica leads now). It is
// storage.ErrFenced, so callers outside pgstore can test for it.
var ErrFenced = storage.ErrFenced

// Fence ties a log's appends to a leader lease: an append commits only while
// lease Name is held with fencing token Token.
type Fence struct {
	Name  string
	Token int64
}

// pgLog is one stream of halo_journal, tailed by id.
type pgLog struct {
	db     *DB
	stream string
	replay func([]byte)
	cursor int64
	fence  *Fence
}

// OpenLog implements storage.Opener: it replays the stream and tails it.
func (d *DB) OpenLog(ctx context.Context, name string, replay func([]byte)) (storage.Log, error) {
	return d.openLog(ctx, name, replay, nil)
}

// OpenFencedLog is OpenLog whose appends fail with ErrFenced once f's lease
// has moved on, so a deposed leader cannot write behind the new one.
func (d *DB) OpenFencedLog(ctx context.Context, name string, replay func([]byte), f Fence) (storage.Log, error) {
	return d.openLog(ctx, name, replay, &f)
}

func (d *DB) openLog(ctx context.Context, name string, replay func([]byte), f *Fence) (*pgLog, error) {
	if !storage.ValidName(name) {
		return nil, fmt.Errorf("pgstore: invalid log name %q", name)
	}
	l := &pgLog{db: d, stream: name, replay: replay, fence: f}
	if err := l.Catchup(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

// Append implements storage.Log. The stream's advisory lock is held until
// commit, so every row with a smaller id in this stream is already committed:
// replaying (cursor, id) before returning keeps local apply order = log order.
func (l *pgLog) Append(ctx context.Context, key string, rec []byte) error {
	var id int64
	err := l.db.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, journalLock, l.stream); err != nil {
			return fmt.Errorf("pgstore: lock %s: %w", l.stream, err)
		}
		if l.fence != nil {
			if err := checkFence(ctx, t, *l.fence); err != nil {
				return err
			}
		}
		if key != "" {
			if _, err := t.ExecContext(ctx, `DELETE FROM halo_journal WHERE stream = $1 AND rkey = $2`, l.stream, key); err != nil {
				return fmt.Errorf("pgstore: compact %s: %w", l.stream, err)
			}
		}
		var rk any
		if key != "" {
			rk = key
		}
		if err := t.QueryRowContext(ctx, `INSERT INTO halo_journal (stream, rkey, body) VALUES ($1, $2, $3) RETURNING id`, l.stream, rk, rec).Scan(&id); err != nil {
			return fmt.Errorf("pgstore: append %s: %w", l.stream, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := l.read(ctx, id); err != nil {
		// The record is committed but the records before it could not be read.
		// The cursor stays before ours and the caller, seeing an error, does not
		// apply it: the next Catchup applies all of them, ours included, in order.
		return fmt.Errorf("pgstore: %s: appended but not caught up: %w", l.stream, err)
	}
	l.cursor = id
	return nil
}

// Catchup implements storage.Log.
func (l *pgLog) Catchup(ctx context.Context) error { return l.read(ctx, 0) }

// read replays rows after the cursor (and before `before` when > 0).
func (l *pgLog) read(ctx context.Context, before int64) error {
	q, args := `SELECT id, body FROM halo_journal WHERE stream = $1 AND id > $2 ORDER BY id`, []any{l.stream, l.cursor}
	if before > 0 {
		q, args = `SELECT id, body FROM halo_journal WHERE stream = $1 AND id > $2 AND id < $3 ORDER BY id`, append(args, before)
	}
	rows, err := l.db.db.QueryContext(ctx, q, args...)
	if err != nil {
		return l.db.fail(fmt.Errorf("pgstore: read %s: %w", l.stream, err))
	}
	defer func() { _ = rows.Close() }() // read-only
	for rows.Next() {
		var id int64
		var body []byte
		if err := rows.Scan(&id, &body); err != nil {
			return l.db.fail(fmt.Errorf("pgstore: read %s: %w", l.stream, err))
		}
		l.replay(body)
		l.cursor = id
	}
	return l.db.fail(rows.Err())
}

// Close implements storage.Log; the pool is the DB's to close.
func (l *pgLog) Close() error { return nil }

// ---- KV ----

// Put implements storage.KV.
func (d *DB) Put(ctx context.Context, ns, key string, val []byte, exp time.Time) error {
	if val == nil {
		val = []byte{} // nil would be SQL NULL
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO halo_kv (ns, rkey, val, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (ns, rkey) DO UPDATE SET val = EXCLUDED.val, expires_at = EXCLUDED.expires_at`, ns, key, val, exp); err != nil {
		return d.fail(fmt.Errorf("pgstore: kv put %s: %w", ns, err))
	}
	return d.reap(ctx, ns)
}

// Add implements storage.KV: the upsert only overwrites an expired row, and
// Postgres's row lock on conflict makes concurrent Adds of one key race-free.
func (d *DB) Add(ctx context.Context, ns, key string, val []byte, exp time.Time) (bool, error) {
	if val == nil {
		val = []byte{} // nil would be SQL NULL
	}
	res, err := d.db.ExecContext(ctx, `INSERT INTO halo_kv (ns, rkey, val, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (ns, rkey) DO UPDATE SET val = EXCLUDED.val, expires_at = EXCLUDED.expires_at
		WHERE halo_kv.expires_at <= now()`, ns, key, val, exp)
	if err != nil {
		return false, d.fail(fmt.Errorf("pgstore: kv add %s: %w", ns, err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, d.fail(fmt.Errorf("pgstore: kv add %s: %w", ns, err))
	}
	return n == 1, d.reap(ctx, ns)
}

// Get implements storage.KV.
func (d *DB) Get(ctx context.Context, ns, key string) ([]byte, bool, error) {
	var v []byte
	err := d.db.QueryRowContext(ctx, `SELECT val FROM halo_kv WHERE ns = $1 AND rkey = $2 AND expires_at > now()`, ns, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, d.fail(fmt.Errorf("pgstore: kv get %s: %w", ns, err))
	}
	return v, true, nil
}

// Take implements storage.KV: DELETE ... RETURNING is atomic, so of
// concurrent Takes exactly one sees the row.
func (d *DB) Take(ctx context.Context, ns, key string) ([]byte, bool, error) {
	var v []byte
	var live bool
	err := d.db.QueryRowContext(ctx, `DELETE FROM halo_kv WHERE ns = $1 AND rkey = $2 RETURNING val, expires_at > now()`, ns, key).Scan(&v, &live)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, d.fail(fmt.Errorf("pgstore: kv take %s: %w", ns, err))
	}
	if !live {
		return nil, false, nil
	}
	return v, true, nil
}

// Delete implements storage.KV.
func (d *DB) Delete(ctx context.Context, ns, key string) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_kv WHERE ns = $1 AND rkey = $2`, ns, key); err != nil {
		return d.fail(fmt.Errorf("pgstore: kv delete %s: %w", ns, err))
	}
	return nil
}

// TryLock implements storage.KV: the owner is the value, the expiry is
// computed by the database (now() + ttl), and the upsert only takes a row that
// is expired or already the owner's.
func (d *DB) TryLock(ctx context.Context, ns, key, owner string, ttl time.Duration) (bool, error) {
	res, err := d.db.ExecContext(ctx, `INSERT INTO halo_kv (ns, rkey, val, expires_at) VALUES ($1, $2, $3, now() + $4 * interval '1 millisecond')
		ON CONFLICT (ns, rkey) DO UPDATE SET val = EXCLUDED.val, expires_at = EXCLUDED.expires_at
		WHERE halo_kv.expires_at <= now() OR halo_kv.val = EXCLUDED.val`, ns, key, []byte(owner), ttl.Milliseconds())
	if err != nil {
		return false, d.fail(fmt.Errorf("pgstore: lock %s: %w", ns, err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, d.fail(fmt.Errorf("pgstore: lock %s: %w", ns, err))
	}
	return n == 1, nil
}

// Unlock implements storage.KV: it deletes only owner's row.
func (d *DB) Unlock(ctx context.Context, ns, key, owner string) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_kv WHERE ns = $1 AND rkey = $2 AND val = $3`, ns, key, []byte(owner)); err != nil {
		return d.fail(fmt.Errorf("pgstore: unlock %s: %w", ns, err))
	}
	return nil
}

// Raise implements storage.KV with one upsert: a live row keeps the greater
// of its value and at, and the later expiry.
func (d *DB) Raise(ctx context.Context, ns, key string, at int64, exp time.Time) error {
	v := []byte(strconv.FormatInt(at, 10))
	if _, err := d.db.ExecContext(ctx, `INSERT INTO halo_kv (ns, rkey, val, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (ns, rkey) DO UPDATE SET
			val = CASE WHEN halo_kv.expires_at > now() AND convert_from(halo_kv.val, 'UTF8')::bigint >= $5 THEN halo_kv.val ELSE EXCLUDED.val END,
			expires_at = CASE WHEN halo_kv.expires_at > now() THEN GREATEST(halo_kv.expires_at, EXCLUDED.expires_at) ELSE EXCLUDED.expires_at END`,
		ns, key, v, exp, at); err != nil {
		return d.fail(fmt.Errorf("pgstore: raise %s: %w", ns, err))
	}
	return nil
}

// kvAuthFail is the namespace of the shared failed-authentication counts.
const kvAuthFail = "auth-fail"

// CountAuthFailure adds one to key's failure count and returns it, in one
// upsert: a live row (younger than window on the database clock) is
// incremented, an expired or absent one restarts at 1 with a new window.
func (d *DB) CountAuthFailure(ctx context.Context, key string, window time.Duration) (int64, error) {
	var n int64
	err := d.db.QueryRowContext(ctx, `INSERT INTO halo_kv (ns, rkey, val, expires_at) VALUES ($1, $2, '\x31'::bytea, now() + $3 * interval '1 millisecond')
		ON CONFLICT (ns, rkey) DO UPDATE SET
			val = CASE WHEN halo_kv.expires_at > now() THEN convert_to((convert_from(halo_kv.val, 'UTF8')::bigint + 1)::text, 'UTF8') ELSE EXCLUDED.val END,
			expires_at = CASE WHEN halo_kv.expires_at > now() THEN halo_kv.expires_at ELSE EXCLUDED.expires_at END
		RETURNING convert_from(val, 'UTF8')::bigint`, kvAuthFail, key, window.Milliseconds()).Scan(&n)
	if err != nil {
		return 0, d.fail(fmt.Errorf("pgstore: count auth failure: %w", err))
	}
	return n, d.reap(ctx, kvAuthFail)
}

// reap drops ns's expired rows (index on expires_at keeps it cheap).
func (d *DB) reap(ctx context.Context, ns string) error {
	if _, err := d.db.ExecContext(ctx, `DELETE FROM halo_kv WHERE ns = $1 AND expires_at <= now()`, ns); err != nil {
		return d.fail(fmt.Errorf("pgstore: kv reap %s: %w", ns, err))
	}
	return nil
}
