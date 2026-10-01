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
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/gateway"
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
	env := func(k, def string) string {
		if v := getenv(k); v != "" {
			return v
		}
		return def
	}
	fs := flag.NewFlagSet("halo-shadow", flag.ContinueOnError)
	var (
		listen    = fs.String("listen", env("HALO_SHADOW_LISTEN", "127.0.0.1:8090"), "listen address (loopback by default)")
		metricsLn = fs.String("metrics-listen", env("HALO_SHADOW_METRICS_LISTEN", ""), "extra address serving only GET /metrics WITHOUT the token, for Prometheus (counters only; guard with a NetworkPolicy); empty disables")
		pol       = fs.String("policy", env("HALO_SHADOW_POLICY", ""), "compiled policy snapshot (hot-reloaded); upstreams are resolved from it")
		hdrs      = fs.String("upstream-headers", env("HALO_SHADOW_UPSTREAM_HEADERS", ""), "YAML/JSON file: {upstreamName: {Header: value}}; values expand ${ENV}")
		out       = fs.String("out", env("HALO_SHADOW_OUT", "pairs.jsonl"), "JSONL pair file (mode 0600)")
		keyFile   = fs.String("pair-key-file", env("HALO_SHADOW_PAIR_KEY_FILE", ""), "base64 32-byte key: encrypt pairs at rest (AES-256-GCM)")
		retention = fs.Duration("retention", 30*24*time.Hour, "prune pairs older than this (0 = keep forever)")
		queue     = fs.Int("queue", 64, "bounded queue length; excess is dropped")
		workers   = fs.Int("workers", 4, "replay workers")
		budget    = fs.Float64("budget-usd", shadow.DefaultBudgetUSD, "stop accepting jobs at this estimated spend (must be > 0)")
		priceIn   = fs.Float64("price-in", 3, "USD per million input tokens (spend estimate)")
		priceOut  = fs.Float64("price-out", 15, "USD per million output tokens (spend estimate)")
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
	store, err := shadow.NewFileStore(*out, shadow.StoreOptions{Key: key, Retention: *retention})
	if err != nil {
		return err
	}

	snap := gateway.NewSnapshot(*pol)
	if _, err := snap.Get(); err != nil {
		log.Warn("policy snapshot not loaded yet; jobs get 503 until it is", "err", err)
	}
	srv := shadow.New(shadow.Config{Queue: *queue, Workers: *workers, Token: tok, Policy: snap.Get, UpstreamHeaders: upHeaders,
		BudgetUSD: *budget, PriceInPerMTok: *priceIn, PriceOutPerMTok: *priceOut, Log: log}, store)
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
// Plaintext rows pass through decoded; a row no key opens is an error.
func decryptPairs(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("decrypt-pairs", flag.ContinueOnError)
	var keyFiles []string
	fs.Func("pair-key-file", "base64 32-byte key (repeatable: current and retired keys)", func(s string) error {
		keyFiles = append(keyFiles, s)
		return nil
	})
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
		p, err := shadow.DecodePair(sc.Bytes(), keys...)
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
