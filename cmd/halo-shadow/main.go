// Command halo-shadow receives mirrored first-turn requests from halo-kong /
// halo-proxy, replays them against control and candidate, and stores the pairs
// as JSONL.
//
// Security model: halo-shadow loads the compiled policy snapshot itself and
// resolves BOTH upstreams from it (experiment + variant + model alias). A
// mirror job carries no URL or model, so the shared token only lets a caller
// spend (bounded by -budget-usd) on upstreams the policy already names.
// Credentials are per upstream (-upstream-headers) and never follow redirects.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/shadow"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Getenv)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run is halo-shadow; args are the command line without argv[0].
func run(ctx context.Context, args []string, getenv func(string) string) error {
	if len(args) > 0 && args[0] == "decrypt-pairs" {
		return decryptPairs(args[1:], os.Stdout)
	}
	if len(args) > 0 && args[0] == "export-pairs" {
		return exportPairs(ctx, args[1:], os.Stdout)
	}
	env := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	fs := flag.NewFlagSet("halo-shadow", flag.ContinueOnError)
	var (
		listen     = fs.String("listen", env("HALO_SHADOW_LISTEN", "127.0.0.1:8090"), "listen address (loopback by default)")
		metricsLn  = fs.String("metrics-listen", env("HALO_SHADOW_METRICS_LISTEN", ""), "extra address serving only GET /metrics WITHOUT the token, for Prometheus (counters only; guard with a NetworkPolicy); empty disables")
		pol        = fs.String("policy", env("HALO_SHADOW_POLICY", ""), "compiled policy snapshot (hot-reloaded); upstreams are resolved from it")
		hdrs       = fs.String("upstream-headers", env("HALO_SHADOW_UPSTREAM_HEADERS", ""), "YAML/JSON file: {upstreamName: {Header: value}}; values expand ${ENV}")
		out        = fs.String("out", env("HALO_SHADOW_OUT", "pairs.jsonl"), "JSONL pair file (mode 0600)")
		keyFile    = fs.String("pair-key-file", env("HALO_SHADOW_PAIR_KEY_FILE", ""), "base64 32-byte key: encrypt pairs at rest (AES-256-GCM)")
		retention  = fs.Duration("retention", 30*24*time.Hour, "prune pairs older than this (0 = keep forever)")
		queue      = fs.Int("queue", 64, "bounded queue length; excess is dropped")
		workers    = fs.Int("workers", 4, "replay workers")
		budget     = fs.Float64("budget-usd", shadow.DefaultBudgetUSD, "stop accepting jobs at this estimated spend (must be > 0)")
		priceIn    = fs.Float64("price-in", 3, "USD per million input tokens (spend estimate)")
		priceOut   = fs.Float64("price-out", 15, "USD per million output tokens (spend estimate)")
		dbURLFile  = fs.String("database-url-file", env("HALO_SHADOW_DATABASE_URL_FILE", ""), "file holding a Postgres URL: pairs and the budget are shared, so several replicas can run (replaces -out)")
		migrate    = fs.Bool("auto-migrate", false, "with -database-url-file: apply pending database migrations on start")
		dbInsecure = fs.Bool("database-insecure-tls", false, insecureTLSUsage)
		scope      = fs.String("budget-scope", env("HALO_SHADOW_BUDGET_SCOPE", "default"), "with -database-url-file: name of the shared budget -budget-usd caps; a new name starts a fresh budget")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	tok := getenv("HALO_SHADOW_TOKEN")
	switch {
	case tok == "":
		return errors.New("halo-shadow: HALO_SHADOW_TOKEN is required")
	case getenv("HALO_SHADOW_AUTH_HEADER") != "":
		return errors.New("halo-shadow: HALO_SHADOW_AUTH_HEADER is no longer supported (it sent one credential to every upstream); use -upstream-headers")
	case *pol == "":
		return errors.New("halo-shadow: -policy is required")
	case *budget <= 0:
		return errors.New("halo-shadow: -budget-usd must be > 0")
	}
	upHeaders, err := loadUpstreamHeaders(*hdrs)
	if err != nil {
		return err
	}
	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	opts := shadow.StoreOptions{Key: key, Retention: *retention}
	var (
		store  pairStore
		shared shadow.Budget
		ping   func(context.Context) error
	)
	if *dbURLFile != "" {
		db, err := openDB(ctx, *dbURLFile, *migrate, pgstore.Options{InsecureTLS: *dbInsecure})
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
		if store, err = shadow.NewDBStore(db, opts); err != nil {
			return err
		}
		shared, ping = shadow.SharedBudget{DB: db, Scope: *scope, Limit: *budget}, db.Ping
		*out = "postgres"
	} else if store, err = shadow.NewFileStore(*out, opts); err != nil {
		return err
	}

	snap := gateway.NewSnapshot(*pol)
	if _, err := snap.Get(); err != nil {
		log.Warn("policy snapshot not loaded yet; jobs get 503 until it is", "err", err)
	}
	srv := shadow.New(shadow.Config{Queue: *queue, Workers: *workers, Token: tok, Policy: snap.Get, UpstreamHeaders: upHeaders,
		BudgetUSD: *budget, PriceInPerMTok: *priceIn, PriceOutPerMTok: *priceOut, Log: log, Budget: shared, Ping: ping}, store)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv.Start(ctx)
	go prune(ctx, store, time.Hour, log)

	servers := []*http.Server{{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute}}
	if *metricsLn != "" {
		servers = append(servers, &http.Server{Addr: *metricsLn, Handler: srv.MetricsHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: time.Minute})
	}
	errc := make(chan error, len(servers))
	for _, hs := range servers {
		go func() {
			if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("halo-shadow: serve %s: %w", hs.Addr, err)
				return
			}
			errc <- nil
		}()
	}
	log.Info("halo-shadow listening", "addr", *listen, "metrics_addr", *metricsLn, "out", *out, "encrypted", key != nil, "budget_usd", *budget)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc: // a listener failed: shut the rest down
	}
	cancel() // stop workers after their current job (a listener may have failed)
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	for _, hs := range servers {
		_ = hs.Shutdown(sctx) // best effort; in-flight /mirror posts are tiny
	}
	srv.Wait()
	if err := store.Close(); err != nil {
		serveErr = errors.Join(serveErr, fmt.Errorf("halo-shadow: close pair store: %w", err))
	}
	return serveErr
}

// readKey loads the optional base64 pair key.
func readKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("halo-shadow: read pair key: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(b)))
	if err != nil {
		return nil, fmt.Errorf("halo-shadow: pair key %s is not base64: %w", path, err)
	}
	return key, nil
}

// decryptPairs prints each stored pair as plaintext JSONL, for offline
// analysis: `halo-shadow decrypt-pairs -pair-key-file k [-old-key-file k2] pairs.jsonl`.
// A row no key opens is an error, and so is a plaintext row when keys are
// given, unless -allow-plaintext-pairs (a store sealed part way through).
func decryptPairs(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("decrypt-pairs", flag.ContinueOnError)
	var keyFiles []string
	fs.Func("pair-key-file", "base64 32-byte key (repeatable: current and retired keys)", func(s string) error {
		keyFiles = append(keyFiles, s)
		return nil
	})
	allowPlain := fs.Bool("allow-plaintext-pairs", false, "with -pair-key-file, also print unsealed rows (written before sealing was turned on); off: they are refused")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("halo-shadow: decrypt-pairs: usage: halo-shadow decrypt-pairs [-pair-key-file FILE]... PAIRS.jsonl")
	}
	var keys [][]byte
	for _, f := range keyFiles {
		k, err := readKey(f)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	in, err := os.Open(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("halo-shadow: decrypt-pairs: %w", err)
	}
	defer func() { _ = in.Close() }() // read-only
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20) // pairs hold two full responses
	enc := json.NewEncoder(w)
	for n := 1; sc.Scan(); n++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		decode := shadow.DecodePair
		if *allowPlain {
			decode = shadow.DecodePairAllowPlaintext
		}
		p, err := decode(sc.Bytes(), keys...)
		if errors.Is(err, shadow.ErrPlaintextRow) {
			return fmt.Errorf("halo-shadow: decrypt-pairs line %d: %w: pass -allow-plaintext-pairs to read rows written before pair keys were configured (migration)", n, err)
		}
		if err != nil {
			return fmt.Errorf("halo-shadow: decrypt-pairs line %d: %w", n, err)
		}
		if err := enc.Encode(p); err != nil {
			return fmt.Errorf("halo-shadow: decrypt-pairs write: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("halo-shadow: decrypt-pairs read: %w", err)
	}
	return nil
}

// loadUpstreamHeaders reads {upstream: {header: value}}; values expand ${ENV}.
func loadUpstreamHeaders(path string) (map[string]map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("halo-shadow: read upstream headers: %w", err)
	}
	var m map[string]map[string]string
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("halo-shadow: parse upstream headers %s: %w", path, err)
	}
	for _, hs := range m {
		for k, v := range hs {
			hs[k] = os.ExpandEnv(v)
		}
	}
	return m, nil
}

// pruner is the part of FileStore the prune loop needs.
type pruner interface {
	Prune(now time.Time) (int, error)
}

// pairStore is FileStore or DBStore.
type pairStore interface {
	shadow.Store
	pruner
	Close() error
}

// openDB connects to the URL in urlFile and checks (or, with migrate, brings)
// the schema to this binary's version.
func openDB(ctx context.Context, urlFile string, migrate bool, o pgstore.Options) (*pgstore.DB, error) {
	b, err := os.ReadFile(urlFile)
	if err != nil {
		return nil, fmt.Errorf("halo-shadow: -database-url-file: %w", err)
	}
	db, err := pgstore.OpenWith(ctx, strings.TrimSpace(string(b)), o)
	if err != nil {
		return nil, fmt.Errorf("halo-shadow: %w", err) // never echo the URL: it carries the password
	}
	if migrate {
		if _, err := db.Migrate(ctx); err != nil {
			_ = db.Close() // already failing
			return nil, fmt.Errorf("halo-shadow: %w", err)
		}
	}
	if err := db.CheckSchema(ctx); err != nil {
		_ = db.Close() // already failing
		return nil, fmt.Errorf("halo-shadow: %w", err)
	}
	return db, nil
}

// exportPairs writes every stored pair row as JSONL, sealed rows as stored:
// `halo-shadow export-pairs -database-url-file F > pairs.jsonl`, then
// decrypt-pairs reads the file exactly as it reads a FileStore's.
func exportPairs(ctx context.Context, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("export-pairs", flag.ContinueOnError)
	urlFile := fs.String("database-url-file", "", "file holding the Postgres URL (required)")
	insecure := fs.Bool("database-insecure-tls", false, insecureTLSUsage)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *urlFile == "" || fs.NArg() > 0 {
		return errors.New("halo-shadow: export-pairs: usage: halo-shadow export-pairs -database-url-file FILE")
	}
	db, err := openDB(ctx, *urlFile, false, pgstore.Options{InsecureTLS: *insecure, MaxConns: 2})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return db.Pairs(ctx, func(row []byte) error {
		if _, err := w.Write(append(row, '\n')); err != nil {
			return fmt.Errorf("halo-shadow: export-pairs write: %w", err)
		}
		return nil
	})
}

func prune(ctx context.Context, s pruner, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.Prune(time.Now()); err != nil {
			log.Error("prune pairs", "err", err)
		} else if n > 0 {
			log.Info("pruned pairs", "removed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// insecureTLSUsage documents -database-insecure-tls.
const insecureTLSUsage = "accept a database URL that does not verify the server certificate and host name (sslmode below verify-full) to a non-loopback host; for test environments only"
