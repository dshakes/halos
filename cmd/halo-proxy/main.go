// Command halo-proxy is Halos's stack-agnostic traffic plane: a reverse
// proxy that verifies the caller (OIDC JWT or trusted-proxy headers), assigns
// the rollout ring / experiment variant, rewrites the model, mirrors eligible
// first-turn requests to halo-shadow, and forwards to the decided upstream or a
// single --next-hop. See README.md for deployment modes.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	p, err := newProxy(cfg, log)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr: cfg.Listen, Handler: p,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout, ReadTimeout: cfg.ReadTimeout, IdleTimeout: cfg.IdleTimeout,
		// WriteTimeout deliberately unset: it would cut long SSE streams.
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if p.kill != nil {
		go p.kill.Run(ctx)
	}
	go p.otlp.Run(ctx, func(err error) { log.Warn("request metrics export", "err", err) }) // no-op when disabled
	errc := make(chan error, 2)
	go func() { errc <- srv.ListenAndServe() }()
	var admin *http.Server
	if cfg.AdminListen != "" {
		admin = &http.Server{Addr: cfg.AdminListen, Handler: p.AdminHandler(), ReadHeaderTimeout: cfg.ReadHeaderTimeout}
		go func() { errc <- admin.ListenAndServe() }()
	}
	log.Info("halo-proxy listening", "addr", cfg.Listen, "admin_addr", cfg.AdminListen, "policy", cfg.Policy, "next_hop", cfg.NextHop)

	select {
	case err := <-errc:
		return fmt.Errorf("halo-proxy: serve: %w", err)
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if admin != nil {
		_ = admin.Close() // stateless probes/scrapes; nothing to drain
	}
	serr := srv.Shutdown(sctx)
	if err := p.otlp.Flush(sctx); err != nil { // the drained requests' tail
		log.Warn("request metrics export", "err", err)
	}
	if serr != nil && !errors.Is(serr, http.ErrServerClosed) {
		return fmt.Errorf("halo-proxy: shutdown: %w", serr)
	}
	return nil
}
