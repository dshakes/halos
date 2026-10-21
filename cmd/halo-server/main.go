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
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/server"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	stop() // always release signal resources before potentially exiting
	if err != nil {
		slog.Error("halo-server", "err", err)
		os.Exit(1)
	}
}

// deprecatedFlags maps old flag names to their canonical spelling (shared
// with `halo controller run`). They still work but are hidden from -help.
var deprecatedFlags = map[string]string{"verdicts": "verdicts-file", "controller-interval": "interval"}

type options struct {
	policyDir, listen, tokenFile, dataDir, verdicts, portalCfg, devUser, auditCfg string
	devGroups, devRoles                                                           []string
	devAdmin                                                                      bool
	deviceTTL, postureMaxAge                                                      time.Duration
	trusted                                                                       []netip.Prefix

	// automated experiment loop + kill switch
	controller                                                     bool
	interval                                                       time.Duration
	chURL, chDB, chUser, chPasswordFile                            string
	killKeyFile, gatewayTokenFile                                  string
	gatewayCapTokenFiles                                           [4]string // killswitch, posture, budget, directory (gatewayCapFlags order)
	workloadKeyFile                                                string
	slackURLFile, webhookURLFile, webhookSecretFile                string
	policyRepoDir, policyRepoSubdir, policyRepoBase, metricsListen string

	// SCIM provisioning (ADR-0022)
	scimTokenHashFile string
	scimAuthoritative bool

	// HA: shared Postgres state instead of --data-dir files (ADR-0021)
	dbURLFile   string
	autoMigrate bool
	leaseTTL    time.Duration
}

func parseFlags(args []string) (options, error) {
	var o options
	var devGroups, devRoles, proxies string
	fs := flag.NewFlagSet("halo-server", flag.ContinueOnError)
	fs.StringVar(&o.policyDir, "policy-dir", "", "policy repo directory (required)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8080", "listen address")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the bearer token halod uses to POST reports (required)")
	fs.StringVar(&o.dataDir, "data-dir", "", "directory for the fleet report log (empty = in-memory only)")
	fs.StringVar(&o.verdicts, "verdicts-file", "", "verdicts JSON file written by `halo exp analyze` / the controller")
	fs.StringVar(&o.verdicts, "verdicts", "", "deprecated: --verdicts-file")
	fs.StringVar(&o.portalCfg, "portal-config", "", "portal/self-service JSON config (baseURL, registry, launchers, halod checksums, ...)")
	fs.StringVar(&o.auditCfg, "audit-config", "", "audit log rotation and SIEM export JSON config (ADR-0016; needs --data-dir)")
	fs.StringVar(&o.devUser, "dev-insecure-user", "", "INSECURE demo mode: disable login and act as this user")
	fs.StringVar(&devGroups, "dev-insecure-groups", "", "comma-separated groups for --dev-insecure-user")
	fs.BoolVar(&o.devAdmin, "dev-insecure-admin", false, "make the --dev-insecure-user an admin (same as --dev-insecure-roles admin)")
	fs.StringVar(&devRoles, "dev-insecure-roles", "", "comma-separated roles for --dev-insecure-user: "+strings.Join(server.Roles, ", "))
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
	fs.StringVar(&o.gatewayTokenFile, "gateway-token-file", "", "file holding the shared bearer token gateways use for /api/v1/gateway/killswitch, /posture, /budget/* and /directory (each overridable below)")
	for i, name := range gatewayCapFlags {
		fs.StringVar(&o.gatewayCapTokenFiles[i], "gateway-"+name+"-token-file", "", "file holding the only bearer token /api/v1/gateway/"+name+" accepts (recommended; overrides --gateway-token-file for it)")
	}
	fs.StringVar(&o.workloadKeyFile, "workload-key-file", "", "ed25519 PKCS#8 PEM private key signing CI/cloud workload credentials from POST /api/v1/token/exchange (halo keys generate --name workload); empty disables the endpoint")
	fs.DurationVar(&o.postureMaxAge, "posture-max-age", server.DefaultPostureMaxAge, "a device whose last halod report is older is non-compliant for the gateway posture gate")
	fs.StringVar(&o.slackURLFile, "notify-slack-url-file", "", "file holding a Slack incoming-webhook URL")
	fs.StringVar(&o.webhookURLFile, "notify-webhook-url-file", "", "file holding a generic webhook URL (JSON event, signed with X-Halo-Signature)")
	fs.StringVar(&o.webhookSecretFile, "notify-webhook-secret-file", "", "file holding the webhook HMAC-SHA256 secret")
	fs.StringVar(&o.policyRepoDir, "policy-repo-dir", "", "dedicated policy-repo clone the controller opens PRs from (hard-reset to origin before each PR; must not be --policy-dir or the portal clone)")
	fs.StringVar(&o.policyRepoSubdir, "policy-repo-subdir", "", "policy root inside --policy-repo-dir")
	fs.StringVar(&o.policyRepoBase, "policy-repo-base", "main", "PR base branch for controller PRs")
	fs.StringVar(&o.metricsListen, "metrics-listen", "", "address serving /metrics: audit export, controller with --controller, leader lease and database with --database-url-file (unauthenticated; keep it internal; empty disables)")
	fs.StringVar(&o.scimTokenHashFile, "scim-token-sha256-file", "", "file holding the hex SHA-256 of each accepted SCIM bearer token, one per line (two while rotating); enables /scim/v2")
	fs.BoolVar(&o.scimAuthoritative, "scim-authoritative", false, "the SCIM directory decides who is active and their groups (console, devices); unprovisioned users are refused")
	fs.StringVar(&o.dbURLFile, "database-url-file", "", "file holding a Postgres URL: shared state for running several replicas (replaces --data-dir state; see `halo-server migrate`)")
	fs.BoolVar(&o.autoMigrate, "auto-migrate", false, "apply pending database migrations on start (else the schema must already be current)")
	fs.DurationVar(&o.leaseTTL, "leader-lease-ttl", 15*time.Second, "with --database-url-file: controller and audit-export lease length; a failed leader is replaced within about this long")
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
	o.devGroups, o.devRoles = splitCSV(devGroups), splitCSV(devRoles)
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
	if o.killKeyFile != "" && o.gatewayTokenFile == "" && o.gatewayCapTokenFiles[0] == "" { // a gateway token alone serves the posture and budget endpoints
		return o, errors.New("--killswitch-key-file needs --gateway-token-file or --gateway-killswitch-token-file")
	}
	if o.postureMaxAge < time.Minute {
		return o, errors.New("--posture-max-age must be at least 1m")
	}
	durable := o.dataDir != "" || o.dbURLFile != ""
	if o.dbURLFile != "" && o.dataDir != "" {
		return o, errors.New("--data-dir and --database-url-file are exclusive: state lives in one place (move a data dir with `halo-server import`)")
	}
	if o.dbURLFile != "" && o.leaseTTL < 3*time.Second {
		return o, errors.New("--leader-lease-ttl must be at least 3s")
	}
	if o.auditCfg != "" && !durable {
		return o, errors.New("--audit-config requires --data-dir or --database-url-file (segments and export cursors must survive a restart)")
	}
	if o.scimAuthoritative && o.scimTokenHashFile == "" {
		return o, errors.New("--scim-authoritative requires --scim-token-sha256-file")
	}
	if o.scimTokenHashFile != "" && !durable {
		return o, errors.New("--scim-token-sha256-file requires --data-dir or --database-url-file (the provisioned directory must survive a restart)")
	}
	if o.killKeyFile != "" && !durable {
		return o, errors.New("--killswitch-key-file requires --data-dir or --database-url-file (kills must survive a restart)")
	}
	if o.controller {
		switch {
		case o.chURL == "":
			return o, errors.New("--controller requires --clickhouse-url")
		case o.dataDir == "" && o.dbURLFile == "":
			return o, errors.New("--controller requires --data-dir or --database-url-file (its action log prevents duplicate PRs across restarts)")
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

// gatewayCapFlags names the per-capability --gateway-<name>-token-file flags,
// in options.gatewayCapTokenFiles order.
var gatewayCapFlags = [4]string{"killswitch", "posture", "budget", "directory"}

// readGatewayTokens reads the shared gateway token and the per-capability
// ones. Each must be at least 16 characters, and a per-capability token must
// differ from the shared one (otherwise it separates nothing).
func readGatewayTokens(o options) (shared string, caps [4]string, err error) {
	read := func(flag, path string) (string, error) {
		if path == "" {
			return "", nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("--%s: %w", flag, err)
		}
		t := strings.TrimSpace(string(b))
		if len(t) < 16 {
			return "", fmt.Errorf("--%s: token must be at least 16 characters", flag)
		}
		return t, nil
	}
	if shared, err = read("gateway-token-file", o.gatewayTokenFile); err != nil {
		return "", caps, err
	}
	for i, name := range gatewayCapFlags {
		flag := "gateway-" + name + "-token-file"
		if caps[i], err = read(flag, o.gatewayCapTokenFiles[i]); err != nil {
			return "", caps, err
		}
		if caps[i] != "" && caps[i] == shared {
			return "", caps, fmt.Errorf("--%s: must differ from the --gateway-token-file token", flag)
		}
	}
	return shared, caps, nil
}

// readSCIMHashes reads one hex SHA-256 per line; blank lines and # comments
// are skipped. server.New validates each digest.
func readSCIMHashes(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--scim-token-sha256-file: %w", err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--scim-token-sha256-file: no token hash in the file")
	}
	return out, nil
}

// run serves until ctx ends (then shuts down gracefully) or the listener fails.
func run(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "migrate":
			return runMigrate(ctx, args[1:], os.Stdout)
		case "import":
			return runImport(ctx, args[1:], os.Stdout)
		}
	}
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
	var audit server.AuditConfig
	if o.auditCfg != "" {
		f, err := os.Open(o.auditCfg)
		if err != nil {
			return fmt.Errorf("--audit-config: %w", err)
		}
		audit, err = server.ParseAuditConfig(f)
		_ = f.Close() // read-only
		if err != nil {
			return fmt.Errorf("--audit-config %s: %w", o.auditCfg, err)
		}
	}
	writer, err := policyWriter(portal, o.policyDir)
	if err != nil {
		return err
	}
	tok, err := os.ReadFile(o.tokenFile)
	if err != nil {
		return err
	}
	var db *pgstore.DB
	if o.dbURLFile != "" {
		if db, err = openDB(ctx, o.dbURLFile, o.autoMigrate); err != nil {
			return err
		}
		defer func() { _ = db.Close() }()
	}
	store := server.NewMemStore()
	switch {
	case db != nil:
		store = server.NewPGStore(db)
	case o.dataDir != "":
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
	var workloadKey ed25519.PrivateKey
	if o.workloadKeyFile != "" {
		b, err := os.ReadFile(o.workloadKeyFile)
		if err != nil {
			return fmt.Errorf("--workload-key-file: %w", err)
		}
		sig, err := bundle.ParseEd25519Signer(b)
		if err != nil {
			return fmt.Errorf("--workload-key-file: %w", err)
		}
		workloadKey = sig.Key
	}
	gwToken, gwCaps, err := readGatewayTokens(o)
	if err != nil {
		return err
	}
	scimHashes, err := readSCIMHashes(o.scimTokenHashFile)
	if err != nil {
		return err
	}
	// One kill store shared by the server (serves it) and the controller (reads it).
	var kills *controller.KillStore
	if db != nil {
		kills, err = controller.NewKillStore(ctx, db)
	} else {
		kills, err = controller.OpenKillStore(o.dataDir)
	}
	if err != nil {
		return err
	}
	defer func() { _ = kills.Close() }()
	cfg := server.Config{
		PolicyDir: o.policyDir, Token: strings.TrimSpace(string(tok)), VerdictsPath: o.verdicts, Store: store,
		SessionKey: []byte(sessionKey), OIDCClientSecret: clientSecret, Portal: portal, DataDir: o.dataDir, Writer: writer,
		DeviceTTL: o.deviceTTL, DevUser: o.devUser, DevGroups: o.devGroups, DevRoles: o.devRoles, DevAdmin: o.devAdmin, TrustedProxies: o.trusted,
		KillStore: kills, KillKey: killKey, GatewayToken: gwToken, PostureMaxAge: o.postureMaxAge, Audit: audit,
		GatewayKillswitchToken: gwCaps[0], GatewayPostureToken: gwCaps[1], GatewayBudgetToken: gwCaps[2], GatewayDirectoryToken: gwCaps[3],
		SCIMTokenSHA256: scimHashes, SCIMAuthoritative: o.scimAuthoritative,
		WorkloadKey: workloadKey,
	}
	if db != nil {
		cfg.Backend = &server.PGBackend{DB: db, LeaseTTL: o.leaseTTL}
	}
	srv, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }() // also unlocks the data dir on Windows
	if c, ok := store.(io.Closer); ok {
		defer func() { _ = c.Close() }()
	}
	actx, stopAudit := context.WithCancel(ctx)
	auditDone := make(chan struct{})
	go func() { defer close(auditDone); srv.RunAuditExport(actx) }()
	defer func() { stopAudit(); <-auditDone }() // runs before srv.Close: forwarders read the log
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

	metrics := []func(io.Writer){srv.WriteMetrics}
	if db != nil {
		metrics = append(metrics, db.WriteMetrics)
	}
	if o.controller {
		var ks *controller.KillStore
		if killKey != nil { // only a served (signed) kill list enforces anything
			ks = kills
		}
		ctrl, err := newController(o, portal, writer, srv, ks)
		if err != nil {
			return err
		}
		cctx, stopCtrl := context.WithCancel(ctx)
		done := make(chan struct{})
		if db != nil {
			el := newElector(db, o.leaseTTL)
			metrics = append(metrics, el.WriteMetrics)
			go func() { defer close(done); el.Run(cctx, leadController(ctrl, db, o.interval)) }()
			defer func() { stopCtrl(); <-done }() // stops the loop and releases the lease
		} else {
			go func() { defer close(done); ctrl.Run(cctx, o.interval) }()
			defer func() { // stop the loop before closing the log it appends to
				stopCtrl()
				<-done
				_ = ctrl.State.Close()
			}()
		}
		metrics = append(metrics, ctrl.WriteMetrics)
		slog.Info("experiment controller running", "interval", o.interval, "prs", ctrl.Writer != nil, "killswitch_served", killKey != nil, "leader_elected", db != nil)
	}
	if o.metricsListen != "" {
		ms := &http.Server{Addr: o.metricsListen, Handler: metricsHandler(metrics...), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("metrics listener", "err", err)
			}
		}()
		defer func() { _ = ms.Close() }() // stateless scrapes
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

// metricsHandler serves GET /metrics from every writer that is set.
func metricsHandler(writers ...func(io.Writer)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		for _, write := range writers {
			if write != nil {
				write(w)
			}
		}
	})
	return mux
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
	c := &controller.Controller{
		Org:          srv.Policy, // the policy the server accepted (SecurityIssues), not a raw load
		Metrics:      &promote.ClickHouse{URL: o.chURL, Database: o.chDB, User: o.chUser, Password: pw},
		Writer:       writer,
		Notifier:     notifiers,
		VerdictsPath: o.verdicts,
		PolicyDir:    o.policyDir,
	}
	if o.dataDir != "" { // rollouts need persistent state; GET /api/v1/rollouts reads it here (HA: set per leadership term)
		c.RolloutStateDir = filepath.Join(o.dataDir, "rollouts")
	}
	if kills != nil {
		c.Kill, c.Kills = controller.KillFunc(srv.KillExperiment), kills
	} else {
		slog.Warn("--controller without --killswitch-key-file: rollbacks are NOT enforced until the pause PR merges")
	}
	if o.dataDir != "" { // HA: opened per leadership term, fenced by the lease (leadController)
		if c.State, err = controller.OpenStateLog(o.dataDir); err != nil {
			return nil, err
		}
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
