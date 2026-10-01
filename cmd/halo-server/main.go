// Command halo-server serves the Halos API and console.
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/halos-dev/halos/internal/bundle"
	"github.com/halos-dev/halos/internal/controller"
	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/promote"
	"github.com/halos-dev/halos/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		slog.Error("halo-server", "err", err)
		os.Exit(1)
	}
}

// deprecatedFlags maps old flag names to their canonical spelling (shared
// with `halo controller run`). They still work but are hidden from -help.
var deprecatedFlags = map[string]string{"verdicts": "verdicts-file", "controller-interval": "interval"}

type options struct {
	policyDir, listen, tokenFile, dataDir, verdicts, portalCfg, devUser string
	devGroups                                                           []string
	devAdmin                                                            bool
	deviceTTL                                                           time.Duration
	trusted                                                             []netip.Prefix

	// automated experiment loop + kill switch
	controller                                                     bool
	interval                                                       time.Duration
	chURL, chDB, chUser, chPasswordFile                            string
	killKeyFile, gatewayTokenFile                                  string
	slackURLFile, webhookURLFile, webhookSecretFile                string
	policyRepoDir, policyRepoSubdir, policyRepoBase, metricsListen string
}

func parseFlags(args []string) (options, error) {
	var o options
	var devGroups, proxies string
	fs := flag.NewFlagSet("halo-server", flag.ContinueOnError)
	fs.StringVar(&o.policyDir, "policy-dir", "", "policy repo directory (required)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "listen address")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the bearer token halod uses to POST reports (required)")
	fs.StringVar(&o.dataDir, "data-dir", "", "directory for the fleet report log (empty = in-memory only)")
	fs.StringVar(&o.verdicts, "verdicts-file", "", "verdicts JSON file written by `halo exp analyze` / the controller")
	fs.StringVar(&o.verdicts, "verdicts", "", "deprecated: --verdicts-file")
	fs.StringVar(&o.portalCfg, "portal-config", "", "portal/self-service JSON config (baseURL, registry, launchers, halod checksums, ...)")
	fs.StringVar(&o.devUser, "dev-insecure-user", "", "INSECURE demo mode: disable login and act as this user")
	fs.StringVar(&devGroups, "dev-insecure-groups", "", "comma-separated groups for --dev-insecure-user")
	fs.BoolVar(&o.devAdmin, "dev-insecure-admin", false, "make the --dev-insecure-user an admin")
	fs.DurationVar(&o.deviceTTL, "device-ttl", server.DefaultDeviceTTL, "device token lifetime after enrollment; expired devices must re-enroll")
	fs.StringVar(&proxies, "trusted-proxy-cidrs", "", "comma-separated CIDRs of reverse proxies whose X-Forwarded-For is trusted for rate limiting")
	fs.BoolVar(&o.controller, "controller", false, "run the automated experiment loop (evaluate, kill switch on rollback, PRs, notifications)")
	fs.DurationVar(&o.interval, "interval", 5*time.Minute, "controller tick interval")
	fs.DurationVar(&o.interval, "controller-interval", 5*time.Minute, "deprecated: --interval")
	fs.StringVar(&o.chURL, "clickhouse-url", "", "ClickHouse HTTP URL for experiment evidence (required with --controller)")
	fs.StringVar(&o.chDB, "clickhouse-database", "", "ClickHouse database")
	fs.StringVar(&o.chUser, "clickhouse-user", "", "ClickHouse user")
	fs.StringVar(&o.chPasswordFile, "clickhouse-password-file", "", "file holding the ClickHouse password")
	fs.StringVar(&o.killKeyFile, "killswitch-key-file", "", "ed25519 PKCS#8 PEM private key signing the gateway kill list (halo keys generate --name killswitch)")
	fs.StringVar(&o.gatewayTokenFile, "gateway-token-file", "", "file holding the bearer token gateways use for GET /api/v1/gateway/killswitch")
	fs.StringVar(&o.slackURLFile, "notify-slack-url-file", "", "file holding a Slack incoming-webhook URL")
	fs.StringVar(&o.webhookURLFile, "notify-webhook-url-file", "", "file holding a generic webhook URL (JSON event, signed with X-Halo-Signature)")
	fs.StringVar(&o.webhookSecretFile, "notify-webhook-secret-file", "", "file holding the webhook HMAC-SHA256 secret")
	fs.StringVar(&o.policyRepoDir, "policy-repo-dir", "", "dedicated policy-repo clone the controller opens PRs from (hard-reset to origin before each PR; must not be --policy-dir or the portal clone)")
	fs.StringVar(&o.policyRepoSubdir, "policy-repo-subdir", "", "policy root inside --policy-repo-dir")
	fs.StringVar(&o.policyRepoBase, "policy-repo-base", "main", "PR base branch for controller PRs")
	fs.StringVar(&o.metricsListen, "metrics-listen", "", "address serving controller /metrics (unauthenticated; keep it internal; empty disables)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of halo-server:\n")
		fs.VisitAll(func(f *flag.Flag) {
			if _, old := deprecatedFlags[f.Name]; !old {
				fmt.Fprintf(fs.Output(), "  --%s\n    \t%s\n", f.Name, f.Usage)
			}
		})
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	fs.Visit(func(f *flag.Flag) {
		if to, old := deprecatedFlags[f.Name]; old {
			slog.Warn("deprecated flag; use the new name", "flag", "--"+f.Name, "use", "--"+to)
		}
	})
	o.devGroups = splitCSV(devGroups)
	for _, c := range splitCSV(proxies) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return o, fmt.Errorf("--trusted-proxy-cidrs: %w", err)
		}
		o.trusted = append(o.trusted, p.Masked())
	}
	if o.policyDir == "" || o.tokenFile == "" {
		return o, errors.New("--policy-dir and --token-file are required")
	}
	if (o.killKeyFile == "") != (o.gatewayTokenFile == "") {
		return o, errors.New("--killswitch-key-file and --gateway-token-file must be set together")
	}
	if o.killKeyFile != "" && o.dataDir == "" {
		return o, errors.New("--killswitch-key-file requires --data-dir (kills must survive a restart)")
	}
	if o.controller {
		switch {
		case o.chURL == "":
			return o, errors.New("--controller requires --clickhouse-url")
		case o.dataDir == "":
			return o, errors.New("--controller requires --data-dir (its action log prevents duplicate PRs across restarts)")
		case o.interval < time.Minute:
			return o, errors.New("--interval must be at least 1m")
		}
	}
	return o, nil
}

// policyWriter returns the PR-opening writer when the portal config names a
// writer clone; that clone must not be (or overlap) the served policy dir.
func policyWriter(portal server.Portal, policyDir string) (server.PolicyWriter, error) {
	if portal.PolicyRepoDir == "" {
		return nil, nil
	}
	if err := server.CheckSeparateClone(portal.PolicyRepoDir, policyDir); err != nil {
		return nil, fmt.Errorf("portal policyRepoDir: %w", err)
	}
	return &server.GitPolicyWriter{RepoDir: portal.PolicyRepoDir, ServedDir: policyDir, Subdir: portal.PolicySubdir, Base: portal.PolicyBase, Opener: promote.GHOpener{}}, nil
}

// run serves until ctx ends (then shuts down gracefully) or the listener fails.
func run(ctx context.Context, args []string) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	var portal server.Portal
	if o.portalCfg != "" {
		b, err := os.ReadFile(o.portalCfg)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&portal); err != nil {
			return fmt.Errorf("portal config: %w", err)
		}
	}
	readTrim := func(path string) (string, error) {
		if path == "" {
			return "", nil
		}
		b, err := os.ReadFile(path)
		return strings.TrimSpace(string(b)), err
	}
	sessionKey, err := readTrim(portal.SessionKeyFile)
	if err != nil {
		return err
	}
	clientSecret, err := readTrim(portal.OIDCClientSecretFile)
	if err != nil {
		return err
	}
	if portal.PubKeyFile != "" {
		b, err := os.ReadFile(portal.PubKeyFile)
		if err != nil {
			return err
		}
		portal.PubKeyPEM = string(b)
	}
	writer, err := policyWriter(portal, o.policyDir)
	if err != nil {
		return err
	}
	tok, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return err
	}
	store := server.NewMemStore()
	if o.dataDir != "" {
		if store, err = server.OpenLogStore(o.dataDir); err != nil {
			return err
		}
	}
	var killKey ed25519.PrivateKey
	if o.killKeyFile != "" {
		b, err := os.ReadFile(o.killKeyFile)
		if err != nil {
			return fmt.Errorf("--killswitch-key-file: %w", err)
		}
		sig, err := bundle.ParseEd25519Signer(b)
		if err != nil {
			return fmt.Errorf("--killswitch-key-file: %w", err)
		}
		killKey = sig.Key
	}
	gwToken, err := readTrim(o.gatewayTokenFile)
	if err != nil {
		return fmt.Errorf("--gateway-token-file: %w", err)
	}
	if o.gatewayTokenFile != "" && len(gwToken) < 16 {
		return errors.New("--gateway-token-file: token must be at least 16 characters")
	}
	// One kill store shared by the server (serves it) and the controller (reads it).
	kills, err := controller.OpenKillStore(o.dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = kills.Close() }()
	srv, err := server.New(server.Config{
		PolicyDir: o.policyDir, Token: strings.TrimSpace(string(tok)), VerdictsPath: o.verdicts, Store: store,
		SessionKey: []byte(sessionKey), OIDCClientSecret: clientSecret, Portal: portal, DataDir: o.dataDir, Writer: writer,
		DeviceTTL: o.deviceTTL, DevUser: o.devUser, DevGroups: o.devGroups, DevAdmin: o.devAdmin, TrustedProxies: o.trusted,
		KillStore: kills, KillKey: killKey, GatewayToken: gwToken,
	})
	if err != nil {
		return err
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-hup:
				srv.ReloadPolicy()
			case <-ctx.Done():
				return
			}
		}
	}()

	if o.controller {
		var ks *controller.KillStore
		if killKey != nil { // only a served (signed) kill list enforces anything
			ks = kills
		}
		ctrl, err := newController(o, portal, writer, srv, ks)
		if err != nil {
			return err
		}
		go ctrl.Run(ctx, o.interval)
		slog.Info("experiment controller running", "interval", o.interval, "prs", ctrl.Writer != nil, "killswitch_served", killKey != nil)
		if o.metricsListen != "" {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain; version=0.0.4")
				ctrl.WriteMetrics(w)
			})
			ms := &http.Server{Addr: o.metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("metrics listener", "err", err)
				}
			}()
			defer func() { _ = ms.Close() }() // stateless scrapes
		}
	}

	hs := &http.Server{Addr: o.listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	slog.Info("halo-server listening", "addr", o.listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// controllerWriter returns the controller's PR writer: the portal's writer
// when --policy-repo-dir names the same clone (one clone, one lock), else a
// dedicated clone that must not overlap the served dir or the portal clone.
func controllerWriter(o options, portal server.Portal, portalWriter server.PolicyWriter) (controller.Writer, error) {
	if o.policyRepoDir == "" {
		slog.Warn("--controller without --policy-repo-dir: verdicts, kills and notifications only; no PRs")
		return nil, nil
	}
	if gw, ok := portalWriter.(*server.GitPolicyWriter); ok && filepath.Clean(gw.RepoDir) == filepath.Clean(o.policyRepoDir) {
		if strings.Trim(gw.Subdir, "/") != strings.Trim(o.policyRepoSubdir, "/") || cmp.Or(gw.Base, "main") != o.policyRepoBase {
			return nil, errors.New("--policy-repo-dir is the portal policyRepoDir: --policy-repo-subdir/--policy-repo-base must match portal policySubdir/policyBase")
		}
		return gw, nil
	}
	for _, other := range []string{o.policyDir, portal.PolicyRepoDir} {
		if other == "" {
			continue
		}
		if err := server.CheckSeparateClone(o.policyRepoDir, other); err != nil {
			return nil, fmt.Errorf("--policy-repo-dir: %w", err)
		}
	}
	return &server.GitPolicyWriter{RepoDir: o.policyRepoDir, ServedDir: o.policyDir, Subdir: o.policyRepoSubdir, Base: o.policyRepoBase, Opener: promote.GHOpener{}}, nil
}

// newController wires the experiment loop into this server: the served
// policy dir, the PR writer, and the kill switch. kills is nil when no kill
// list is served (no --killswitch-key-file): then rollbacks are reported as
// NOT enforced instead of tripping a switch nobody reads.
func newController(o options, portal server.Portal, portalWriter server.PolicyWriter, srv *server.Server, kills *controller.KillStore) (*controller.Controller, error) {
	writer, err := controllerWriter(o, portal, portalWriter)
	if err != nil {
		return nil, err
	}
	pw := ""
	if o.chPasswordFile != "" {
		b, err := os.ReadFile(o.chPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("--clickhouse-password-file: %w", err)
		}
		pw = strings.TrimSpace(string(b))
	}
	notifiers, err := controller.NotifiersFromFiles(o.slackURLFile, o.webhookURLFile, o.webhookSecretFile)
	if err != nil {
		return nil, err
	}
	state, err := controller.OpenStateLog(o.dataDir)
	if err != nil {
		return nil, err
	}
	c := &controller.Controller{
		Org:          func() (*policy.Org, error) { return policy.Load(o.policyDir) },
		Metrics:      &promote.ClickHouse{URL: o.chURL, Database: o.chDB, User: o.chUser, Password: pw},
		Writer:       writer,
		Notifier:     notifiers,
		State:        state,
		VerdictsPath: o.verdicts,
	}
	if kills != nil {
		c.Kill, c.Kills = controller.KillFunc(srv.KillExperiment), kills
	} else {
		slog.Warn("--controller without --killswitch-key-file: rollbacks are NOT enforced until the pause PR merges")
	}
	return c, nil
}

func splitCSV(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
