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
	"net"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// DB is a Postgres handle shared by every store of one process.
type DB struct {
	db   *sql.DB
	errs atomic.Int64 // failed statements, for halo_db_errors_total
}

// Options tunes Open.
type Options struct {
	// MaxConns caps the pool (default DefaultMaxConns). Every replica holds
	// up to this many connections: size it against the server's max_connections.
	MaxConns int
	// InsecureTLS accepts a connection to a non-loopback host without
	// verified TLS (sslmode below verify-full). Off by default: the database
	// holds the audit chain, device token hashes and the kill list.
	InsecureTLS bool
}

// DefaultMaxConns is the pool size when Options.MaxConns is 0.
const DefaultMaxConns = 16

// Open connects to dsn with default Options and checks the connection.
func Open(ctx context.Context, dsn string) (*DB, error) { return OpenWith(ctx, dsn, Options{}) }

// ErrInsecureTLS is CheckTLS's refusal.
var ErrInsecureTLS = errors.New("pgstore: database URL does not verify the server's certificate")

// CheckTLS refuses a URL whose connection to a non-loopback host is not
// TLS with a verified certificate and host name (sslmode=verify-full):
// sslmode disable, allow, prefer and require (no certificate check), and
// verify-ca (no host-name check) all leave the connection open to a
// man-in-the-middle on the network. Loopback hosts and Unix sockets never
// leave the machine and are accepted.
func CheckTLS(dsn string) error {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("pgstore: parse database URL: %w", errors.New(strings.ReplaceAll(err.Error(), dsn, "<url>")))
	}
	hosts := append([]*pgconn.FallbackConfig{{Host: cfg.Host, TLSConfig: cfg.TLSConfig}}, cfg.Fallbacks...)
	for _, h := range hosts {
		if localHost(h.Host) {
			continue
		}
		if h.TLSConfig == nil || h.TLSConfig.InsecureSkipVerify {
			return fmt.Errorf("%w (host %s): use sslmode=verify-full with sslrootcert, or --database-insecure-tls to accept it", ErrInsecureTLS, h.Host)
		}
	}
	return nil
}

func localHost(h string) bool {
	if strings.HasPrefix(h, "/") {
		return true // Unix socket
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// OpenWith connects to dsn and checks the connection.
func OpenWith(ctx context.Context, dsn string, o Options) (*DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("pgstore: empty database URL")
	}
	if !o.InsecureTLS {
		if err := CheckTLS(dsn); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}
	if o.MaxConns <= 0 {
		o.MaxConns = DefaultMaxConns
	}
	db.SetMaxOpenConns(o.MaxConns)
	db.SetMaxIdleConns(min(4, o.MaxConns))
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

// Every migration starts with a header naming the oldest binary schema
// version that can still run against a database with it applied:
//
//	-- min-binary-schema: 1
//
// Migrations are additive within a major (new tables, columns with defaults,
// indexes), so the value is normally 1 and an older binary keeps working
// during a rolling upgrade and after a binary rollback. A migration that
// changes or drops something an older binary uses must raise it.
const minBinaryHeader = "-- min-binary-schema:"

type migration struct {
	version   int
	minBinary int
	name      string
	sql       string
}

func migrations() ([]migration, error) {
	return parseMigrations(migrationFS, "migrations")
}

func parseMigrations(fsys fs.FS, dir string) ([]migration, error) {
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range ents {
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil || v < 1 {
			return nil, fmt.Errorf("pgstore: migration %s: name must start with a version number", e.Name())
		}
		b, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, err
		}
		first, _, _ := strings.Cut(string(b), "\n")
		mb, ok := strings.CutPrefix(strings.TrimSpace(first), minBinaryHeader)
		n, err := strconv.Atoi(strings.TrimSpace(mb))
		if !ok || err != nil || n < 1 || n > v {
			return nil, fmt.Errorf("pgstore: migration %s: first line must be %q followed by a schema version 1..%d", e.Name(), minBinaryHeader, v)
		}
		out = append(out, migration{v, n, e.Name(), string(b)})
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

// addMinBinary records each applied migration's min-binary-schema, so a
// binary older than the database can tell whether it may still run.
const addMinBinary = `ALTER TABLE halo_schema_migrations ADD COLUMN IF NOT EXISTS min_binary INTEGER`

// schemaQuerier is *sql.DB or *sql.Tx.
type schemaQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// newerCompatible reports whether a database at a schema newer than want
// still accepts a binary at want: every migration past want declares a
// min-binary-schema at or below it. Rows without one (none exist; written
// before the column) count as their own version: incompatible.
func newerCompatible(ctx context.Context, q schemaQuerier, want int) (bool, int, error) {
	var need int
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(max(COALESCE(min_binary, version)), 0) FROM halo_schema_migrations WHERE version > $1`, want).Scan(&need); err != nil {
		return false, 0, err
	}
	return need <= want, need, nil
}

// Migrate applies every pending migration in one transaction, under an
// advisory lock so concurrent replicas apply each exactly once, and returns
// the versions it applied. A database newer than this binary is fine when
// its newer migrations still accept this binary (see minBinaryHeader), and
// an error otherwise.
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
		if _, err := t.ExecContext(ctx, addMinBinary); err != nil {
			return fmt.Errorf("pgstore: upgrade halo_schema_migrations: %w", err)
		}
		var cur int
		if err := t.QueryRowContext(ctx, `SELECT COALESCE(max(version), 0) FROM halo_schema_migrations`).Scan(&cur); err != nil {
			return fmt.Errorf("pgstore: read schema version: %w", err)
		}
		if cur > len(ms) {
			ok, need, err := newerCompatible(ctx, t, len(ms))
			if err != nil {
				return fmt.Errorf("pgstore: read schema compatibility: %w", err)
			}
			if !ok {
				return fmt.Errorf("pgstore: database schema v%d needs a binary at schema v%d or newer (this one is v%d): upgrade halo-server", cur, need, len(ms))
			}
			return nil
		}
		for _, m := range ms[cur:] {
			if _, err := t.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("pgstore: migration %s: %w", m.name, err)
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO halo_schema_migrations (version, name, min_binary) VALUES ($1, $2, $3)`, m.version, m.name, m.minBinary); err != nil {
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

// CheckSchema returns ErrSchema unless this binary can run against the
// database: at exactly its schema version, or newer when every newer
// migration still accepts it (a rolling upgrade's old pods, or a binary
// rollback). Behind means run `halo-server migrate` (or --auto-migrate).
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
		ok, need, err := newerCompatible(ctx, d.db, want)
		if err != nil {
			return d.fail(fmt.Errorf("pgstore: read schema compatibility: %w", err))
		}
		if !ok {
			return fmt.Errorf("%w: database is at v%d and needs a binary at schema v%d or newer (this one is v%d): upgrade halo-server", ErrSchema, cur, need, want)
		}
	}
	return nil
}
