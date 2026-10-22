// Package pgstore is the Postgres backend for running several halo-server and
// halo-shadow replicas (ADR-0021): versioned forward-only migrations, the
// shared record logs and KV behind internal/storage, the hash-chained audit
// table, fleet reports, rollout documents, leader leases with fencing tokens,
// and halo-shadow's pair table and global budget. It speaks database/sql over
// the pgx stdlib driver and stores opaque bytes: the packages that own the
// types encode them.
package pgstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is a Postgres handle shared by every store of one process.
type DB struct {
	db   *sql.DB
	errs atomic.Int64 // failed statements, for halo_db_errors_total
}

// Open connects to dsn and checks the connection.
func Open(ctx context.Context, dsn string) (*DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("pgstore: empty database URL")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		_ = db.Close() // already failing
		return nil, fmt.Errorf("pgstore: connect: %w", err)
	}
	return &DB{db: db}, nil
}

// Close closes the pool.
func (d *DB) Close() error { return d.db.Close() }

// Ping checks the database is reachable (readiness).
func (d *DB) Ping(ctx context.Context) error {
	return d.fail(d.db.PingContext(ctx))
}

// Errors is the number of failed statements since Open.
func (d *DB) Errors() int64 { return d.errs.Load() }

// WriteMetrics writes the database metrics in Prometheus text format.
func (d *DB) WriteMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP halo_db_errors_total Failed Postgres statements.\n# TYPE halo_db_errors_total counter\nhalo_db_errors_total %d\n", d.Errors())
	st := d.db.Stats()
	fmt.Fprintf(w, "# HELP halo_db_open_connections Open Postgres connections.\n# TYPE halo_db_open_connections gauge\nhalo_db_open_connections %d\n", st.OpenConnections)
}

// fail counts err (a cancelled caller is not a database error) and returns it.
func (d *DB) fail(err error) error {
	if err != nil && !errors.Is(err, context.Canceled) {
		d.errs.Add(1)
	}
	return err
}

// tx runs fn in a transaction, committing when it returns nil.
func (d *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return d.fail(err)
	}
	if err := fn(t); err != nil {
		_ = t.Rollback() // already failing; the error that matters is err
		return d.fail(err)
	}
	return d.fail(t.Commit())
}

// ---- migrations ----

type migration struct {
	version int
	name    string
	sql     string
}

func migrations() ([]migration, error) {
	ents, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range ents {
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || v < 1 {
			return nil, fmt.Errorf("pgstore: migration %s: name must start with a version number", e.Name())
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{v, e.Name(), string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i, m := range out {
		if m.version != i+1 {
			return nil, fmt.Errorf("pgstore: migration %s: versions must be 1..n without gaps", m.name)
		}
	}
	return out, nil
}

// SchemaVersion is the newest migration this binary knows.
func SchemaVersion() int {
	ms, err := migrations()
	if err != nil {
		return 0
	}
	return len(ms)
}

// migrateLock serializes migrations across replicas starting together.
const migrateLock = 0x68616c6f // "halo"

const createMigrations = `CREATE TABLE IF NOT EXISTS halo_schema_migrations (
    version    INTEGER     PRIMARY KEY,
    name       TEXT        NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// Migrate applies every pending migration in one transaction, under an
// advisory lock so concurrent replicas apply each exactly once, and returns
// the versions it applied. A database newer than this binary is an error.
func (d *DB) Migrate(ctx context.Context) (applied []int, err error) {
	ms, err := migrations()
	if err != nil {
		return nil, err
	}
	err = d.tx(ctx, func(t *sql.Tx) error {
		if _, err := t.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLock); err != nil {
			return fmt.Errorf("pgstore: migrate lock: %w", err)
		}
		if _, err := t.ExecContext(ctx, createMigrations); err != nil {
			return fmt.Errorf("pgstore: create halo_schema_migrations: %w", err)
		}
		var cur int
		if err := t.QueryRowContext(ctx, `SELECT COALESCE(max(version), 0) FROM halo_schema_migrations`).Scan(&cur); err != nil {
			return fmt.Errorf("pgstore: read schema version: %w", err)
		}
		if cur > len(ms) {
			return fmt.Errorf("pgstore: database schema v%d is newer than this binary (v%d): upgrade halo-server", cur, len(ms))
		}
		for _, m := range ms[cur:] {
			if _, err := t.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("pgstore: migration %s: %w", m.name, err)
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO halo_schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
				return fmt.Errorf("pgstore: record migration %s: %w", m.name, err)
			}
			applied = append(applied, m.version)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return applied, nil
}

// ErrSchema means the database schema does not match this binary.
var ErrSchema = errors.New("pgstore: schema mismatch")

// CheckSchema returns ErrSchema unless the database is at exactly this
// binary's schema version: behind means run `halo-server migrate` (or start
// with --auto-migrate), ahead means this binary is older than the database.
func (d *DB) CheckSchema(ctx context.Context) error {
	want := SchemaVersion()
	var cur int
	err := d.db.QueryRowContext(ctx, `SELECT COALESCE(max(version), 0) FROM halo_schema_migrations`).Scan(&cur)
	if err != nil {
		var exists bool
		if qerr := d.db.QueryRowContext(ctx, `SELECT to_regclass('halo_schema_migrations') IS NOT NULL`).Scan(&exists); qerr == nil && !exists {
			cur, err = 0, nil
		}
	}
	if err != nil {
		return d.fail(fmt.Errorf("pgstore: read schema version: %w", err))
	}
	switch {
	case cur < want:
		return fmt.Errorf("%w: database is at v%d, this binary needs v%d: run `halo-server migrate` or start with --auto-migrate", ErrSchema, cur, want)
	case cur > want:
		return fmt.Errorf("%w: database is at v%d, newer than this binary (v%d): upgrade halo-server", ErrSchema, cur, want)
	}
	return nil
}
