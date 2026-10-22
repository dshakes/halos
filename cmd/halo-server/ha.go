package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/rollout"
	"github.com/dshakes/halos/internal/server"
)

// controllerLease is the leader lease the experiment controller runs under.
const controllerLease = "controller"

// openDB connects to the URL in urlFile and checks (or, with migrate,
// brings) the schema to this binary's version.
func openDB(ctx context.Context, urlFile string, migrate bool) (*pgstore.DB, error) {
	b, err := os.ReadFile(urlFile)
	if err != nil {
		return nil, fmt.Errorf("--database-url-file: %w", err)
	}
	db, err := pgstore.Open(ctx, strings.TrimSpace(string(b)))
	if err != nil {
		return nil, err // never echo the URL: it carries the password
	}
	if migrate {
		applied, err := db.Migrate(ctx)
		if err != nil {
			_ = db.Close() // already failing
			return nil, err
		}
		if len(applied) > 0 {
			slog.Info("database migrated", "applied", applied, "version", pgstore.SchemaVersion())
		}
	}
	if err := db.CheckSchema(ctx); err != nil {
		_ = db.Close() // already failing
		return nil, err
	}
	return db, nil
}

// runMigrate is `halo-server migrate --database-url-file F`.
func runMigrate(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("halo-server migrate", flag.ContinueOnError)
	urlFile := fs.String("database-url-file", "", "file holding the Postgres URL (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *urlFile == "" || fs.NArg() > 0 {
		return errors.New("usage: halo-server migrate --database-url-file FILE")
	}
	db, err := openDB(ctx, *urlFile, true)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	fmt.Fprintf(out, "database schema at v%d\n", pgstore.SchemaVersion())
	return nil
}

// runImport is `halo-server import --from-data-dir DIR --database-url-file F`:
// copy a stopped single-replica server's data dir into Postgres and verify.
func runImport(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("halo-server import", flag.ContinueOnError)
	from := fs.String("from-data-dir", "", "the --data-dir of a STOPPED halo-server (only read)")
	urlFile := fs.String("database-url-file", "", "file holding the Postgres URL (required)")
	migrate := fs.Bool("auto-migrate", false, "apply pending migrations first")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" || *urlFile == "" || fs.NArg() > 0 {
		return errors.New("usage: halo-server import --from-data-dir DIR --database-url-file FILE [--auto-migrate]")
	}
	if st, err := os.Stat(*from); err != nil || !st.IsDir() {
		return fmt.Errorf("--from-data-dir %s: not a directory", *from)
	}
	db, err := openDB(ctx, *urlFile, *migrate)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	rep, err := server.ImportDataDir(ctx, *from, server.NewPGBackend(db))
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(rep.Copied))
	for k := range rep.Copied {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(out, "copied %-30s %d\n", k, rep.Copied[k])
	}
	for f, n := range rep.Skipped {
		fmt.Fprintf(out, "skipped %d torn or undecodable lines in %s (the server skips them on replay too)\n", n, f)
	}
	fmt.Fprintf(out, "verified: counts match; audit chain verifies, head %s\n", cmpHead(rep.Head))
	return nil
}

func cmpHead(h string) string {
	if h == "" {
		return "(empty log)"
	}
	return h
}

// newElector campaigns for the controller lease under a replica-unique holder id.
func newElector(db *pgstore.DB, ttl time.Duration) *pgstore.Elector {
	return &pgstore.Elector{Store: db, Name: controllerLease, Holder: pgstore.HolderID(), TTL: ttl}
}

// leadController runs ctrl for one leadership term: its action log and
// rollout state are opened through a view fenced by the term's token, so if
// this replica is deposed mid-tick its late writes are refused.
func leadController(ctrl *controller.Controller, db *pgstore.DB, interval time.Duration) func(context.Context, int64) {
	return func(ctx context.Context, token int64) {
		view := db.Fenced(pgstore.Fence{Name: controllerLease, Token: token})
		st, err := controller.OpenStateLogOn(ctx, view)
		if err != nil {
			slog.Error("controller: open action log; retrying next lease round", "err", err)
			return
		}
		defer func() { _ = st.Close() }()
		ctrl.State, ctrl.RolloutStates, ctrl.VerdictDocs = st, rollout.DocStore{DB: view}, view
		slog.Info("controller leading", "token", token)
		ctrl.Run(ctx, interval)
		slog.Info("controller stopped leading", "token", token)
	}
}
