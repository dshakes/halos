package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters for the capability matrix
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
	"github.com/dshakes/halos/web"
)

// MaxReportBytes caps a POST /fleet/report body.
const MaxReportBytes = 64 << 10

// Config wires a Server.
type Config struct {
	PolicyDir    string
	Token        string // bearer token required by POST /api/v1/fleet/report; must be non-empty
	VerdictsPath string // optional JSON file written by `halo exp analyze`
	Store        Store
	Log          *slog.Logger
	Now          func() time.Time
	Web          fs.FS // nil = placeholder page (defaults to the embedded console)
	// TrustedProxies are the reverse proxies whose X-Forwarded-For is believed
	// for per-client rate limiting. Empty = use the TCP peer address only.
	TrustedProxies []netip.Prefix

	// Portal auth/self-service. SessionKey signs cookies (>=32 bytes); required unless DevUser is set.
	SessionKey       []byte
	OIDCClientSecret string
	Portal           Portal
	DataDir          string // request/device/session-revocation logs ("" = in-memory)
	// Backend, when set, replaces DataDir and in-process state with shared
	// state so several replicas can serve (ADR-0021).
	Backend   Backend
	DeviceTTL time.Duration // device token lifetime after enrollment (0 = DefaultDeviceTTL)
	Writer    PolicyWriter  // nil: approvals are recorded but need manual policy changes

	// Kill switch. KillStore nil = opened from DataDir. GET
	// /api/v1/gateway/killswitch is served only when both KillKey (signs the
	// list) and GatewayToken (gateways' bearer token) are set; GET
	// /api/v1/fleet/killswitch (device token) whenever KillKey is set.
	KillStore    *controller.KillStore
	KillKey      ed25519.PrivateKey
	GatewayToken string
	// Optional per-capability gateway tokens. When one is set it is the only
	// token that capability accepts (the shared GatewayToken no longer does);
	// empty falls back to GatewayToken. Each also enables its endpoint alone.
	GatewayKillswitchToken string
	GatewayPostureToken    string
	GatewayBudgetToken     string
	GatewayDirectoryToken  string
	GatewayDLPToken        string // POST /api/v1/gateway/dlp/events (ADR-0033)

	// PostureMaxAge: a device whose last report is older is stale (GET
	// /api/v1/gateway/posture, served whenever GatewayToken is set). 0 = DefaultPostureMaxAge.
	PostureMaxAge time.Duration

	// Audit: log rotation and SIEM export (ADR-0016). Both need DataDir.
	// Export runs only while RunAuditExport does.
	Audit AuditConfig
	// SCIM 2.0 provisioning at /scim/v2 (ADR-0022). SCIMTokenSHA256 holds the
	// hex SHA-256 of each accepted bearer token (two while rotating); empty =
	// SCIM off. SCIMAuthoritative: the directory, not the login's groups claim
	// or a device's enrollment groups, decides who is active and their groups.
	// SCIMStore nil = opened from DataDir.
	SCIMTokenSHA256   []string
	SCIMAuthoritative bool
	SCIMStore         SCIMStore
	// WorkloadKey signs workload credentials minted by POST
	// /api/v1/token/exchange (ADR-0023); nil disables the endpoint.
	WorkloadKey ed25519.PrivateKey

	// DevUser disables authentication and acts as this user. INSECURE: local demos only.
	// DevRoles are its roles (ADR-0015); DevAdmin adds RoleAdmin.
	DevUser   string
	DevGroups []string
	DevRoles  []string
	DevAdmin  bool
}

// Server is the HTTP API + console.
type Server struct {
	cfg    Config
	tokSum [32]byte
	pol    *policyHolder
	oidc   oidcState
	enroll enrollments
	reqs   *requestLog
	// approvals are rollout-step approvals (ADR-0030).
	approvals *approvalLog

	devices *deviceStore
	// Failed-auth budgets per client IP, one per endpoint class, so failures on
	// one class never lock out another: an attacker sharing a gateway's egress
	// IP who sends garbage to the public token exchange or SCIM cannot cut the
	// gateways off from their directory, posture, budget and kill endpoints.
	authFails     authLimiter // device tokens and enrollment
	loginFails    authLimiter // failed OIDC callbacks
	gwFails       authLimiter // gateway tokens; a valid token is never blocked
	exchangeFails authLimiter // POST /api/v1/token/exchange (CI workload federation)
	agentFails    authLimiter // agent delegation exchange and POST /api/v1/agents/egress
	scimFails     authLimiter // /scim/v2
	revoked       *sessionRevocations
	auditLog      *auditLog
	forwarders    []*auditForwarder
	relCache      *releaseCache
	relFetch      pointerFetch  // ring pointer reader; swapped in tests
	relChannels   channelsFetch // ring release -> experiment channels; swapped in tests
	kills         *controller.KillStore
	gwSums        map[gatewayCap][32]byte // sha256 of the token each enabled gateway capability accepts
	scim          *scimService            // nil = SCIM off
	budgets       *budgetStore
	dlpBatches    dlpBatches // recent DLP audit batch ids (ADR-0033)
	wl            workloadExchange
	kv            storage.KV    // ephemeral state: Backend, else in process
	auditFails    atomic.Uint64 // audit appends that failed (strict and best-effort)
	revs          revocationStore
	metrics       serverMetrics
}

// New validates cfg and returns a Server. It does not require the policy dir to load yet.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("server: empty report token")
	}
	if err := validRoles(cfg.DevRoles); err != nil {
		return nil, fmt.Errorf("server: dev roles: %w", err)
	}
	if cfg.DevAdmin && !slices.Contains(cfg.DevRoles, RoleAdmin) {
		cfg.DevRoles = append(slices.Clip(cfg.DevRoles), RoleAdmin)
	}
	if cfg.DevUser != "" {
		cfg.Log = orDefault(cfg.Log)
		cfg.Log.Warn("INSECURE: --dev-insecure-user set; authentication is disabled and every request acts as this user", "user", cfg.DevUser, "roles", cfg.DevRoles)
	} else if len(cfg.SessionKey) < 32 {
		return nil, errors.New("server: session key must be at least 32 bytes (or set DevUser for a demo)")
	}
	if err := cfg.Portal.Validate(cfg.DevUser != ""); err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		cfg.Store = NewMemStore()
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Web == nil {
		if d, ok := web.Dist(); ok {
			cfg.Web = d
		}
	}
	if err := cfg.Audit.Validate(); err != nil {
		return nil, err
	}
	if cfg.Audit.Rotation != (AuditRotation{}) {
		switch {
		case cfg.Backend != nil:
			return nil, errors.New("server: audit rotation is for the file backend; on Postgres the chain is one table (ADR-0021)")
		case cfg.DataDir == "":
			return nil, errors.New("server: audit rotation needs a data dir")
		}
	}
	var logs storage.Opener = storage.Dir(cfg.DataDir)
	var kv storage.KV = &storage.MemKV{Now: cfg.Now}
	auditDir := cfg.DataDir
	if cfg.Backend != nil {
		logs, kv, auditDir = cfg.Backend, cfg.Backend, ""
	}
	// On any failure below, close what was already opened: a leaked handle
	// keeps the data dir's files locked (on Windows they cannot be removed).
	var closers []func() error
	ok := false
	defer func() {
		if !ok {
			for _, c := range closers {
				_ = c() // already failing
			}
		}
	}()
	reqs, err := openRequestLog(logs)
	if err != nil {
		return nil, err
	}
	closers = append(closers, reqs.close)
	approvals, err := openApprovalLog(logs)
	if err != nil {
		return nil, err
	}
	closers = append(closers, approvals.close)
	devs, err := openDeviceStore(logs, cfg.DeviceTTL)
	if err != nil {
		return nil, err
	}
	closers = append(closers, devs.close)
	revoked, err := openSessionRevocations(logs)
	if err != nil {
		return nil, err
	}
	closers = append(closers, revoked.close)
	var revs revocationStore = cfg.Backend
	if cfg.Backend == nil {
		rl, err := openRevocationLog(logs, cfg.Now)
		if err != nil {
			return nil, err
		}
		closers = append(closers, rl.close)
		revs = rl
	}
	al, err := openAuditLog(auditDir)
	if err != nil {
		return nil, err
	}
	closers = append(closers, al.close)
	al.shared = cfg.Backend
	al.rot, al.log = cfg.Audit.Rotation, cfg.Log
	fwds, err := newAuditForwarders(cfg.Audit.Export, cfg.DataDir, al, cfg.Log)
	if err != nil {
		return nil, err
	}
	bs, err := openBudgetStore(cfg.DataDir, cfg.Backend)
	if err != nil {
		return nil, err
	}
	if cfg.gatewayToken(capBudget) != "" && cfg.DataDir == "" && cfg.Backend == nil {
		cfg.Log.Warn("no --data-dir: gateway budget counters are in memory and reset on restart")
	}
	s := &Server{cfg: cfg, tokSum: sha256.Sum256([]byte(cfg.Token)), pol: &policyHolder{dir: cfg.PolicyDir, log: cfg.Log}, reqs: reqs, approvals: approvals, devices: devs, revoked: revoked,
		auditLog: al, forwarders: fwds, relCache: &releaseCache{byKey: map[string]cachedPointer{}, chans: map[string][]string{}}, budgets: bs, kv: kv, revs: revs}
	for _, l := range []struct {
		a     *authLimiter
		class string
	}{{&s.authFails, "device"}, {&s.loginFails, "login"}, {&s.gwFails, "gateway"}, {&s.exchangeFails, "exchange"}, {&s.agentFails, "agent"}, {&s.scimFails, "scim"}} {
		l.a.class, l.a.log = l.class, cfg.Log
		if cfg.Backend != nil { // one budget across replicas (ADR-0021, amended)
			l.a.shared = cfg.Backend
		}
	}
	s.oidc.kv, s.enroll.kv = kv, kv
	s.relFetch, s.relChannels = s.registryFetch, s.registryChannels
	if s.kills = cfg.KillStore; s.kills == nil {
		if cfg.Backend != nil {
			ctx, cancel := storage.Ctx()
			s.kills, err = controller.NewKillStore(ctx, cfg.Backend)
			cancel()
		} else {
			s.kills, err = controller.OpenKillStore(cfg.DataDir)
		}
		if err != nil {
			return nil, err
		}
		if cfg.KillStore == nil {
			closers = append(closers, s.kills.Close)
		}
	}
	s.gwSums = gatewaySums(cfg)
	if s.scim, err = newSCIM(cfg); err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

// Close releases the files New opened under Config.DataDir. A Store or
// KillStore passed in via Config stays the caller's to close.
func (s *Server) Close() error {
	errs := []error{s.reqs.close(), s.approvals.close(), s.devices.close(), s.revoked.close(), s.auditLog.close(), s.scim.close(), s.budgets.save(s.cfg.Now(), true)}
	if c, ok := s.revs.(*revocationLog); ok {
		errs = append(errs, c.close())
	}
	if s.cfg.KillStore == nil && s.kills != nil {
		errs = append(errs, s.kills.Close())
	}
	return errors.Join(errs...)
}

func orDefault(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

// ReloadPolicy forces a policy reload on next read (wire to SIGHUP).
func (s *Server) ReloadPolicy() { s.pol.Invalidate() }

// Policy is the policy this server serves: the last load that passed
// policy.SecurityIssues (a refused or broken reload keeps the previous one),
// with the workload rule removals of a refused load applied
// (policy.TightenWorkloads). The in-process controller acts on it, so the
// leader never acts on a policy its own API, or any replica's, refuses.
func (s *Server) Policy() (*policy.Org, error) {
	org, _, err := s.pol.Get()
	if org == nil {
		if err == nil {
			err = errors.New("policy not loaded")
		}
		return nil, err
	}
	return org, nil
}

// Handler returns the full mux with security headers and request logging.
func (s *Server) Handler() http.Handler {
	return s.logging(secure(s.mux().ServeMux))
}

// mux registers every route. Cookie-authenticated routes go through s.route,
// which enforces routePerms; the rest authenticate with a bearer token or are public.
func (s *Server) mux() *routeMux {
	m := &routeMux{ServeMux: http.NewServeMux()}
	// /healthz: liveness — process is alive. Always 200.
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	// /readyz: readiness — policy loaded and, with a shared Backend, the
	// database reachable. 503 until the first successful policy load.
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if b := s.cfg.Backend; b != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			err := b.Ping(ctx)
			cancel()
			if err != nil {
				s.cfg.Log.Warn("readyz: database unreachable", "err", err)
				apiErr(w, http.StatusServiceUnavailable, "database unreachable")
				return
			}
		}
		if org, _, err := s.pol.Get(); org == nil {
			s.policyUnavailable(w, err) // public endpoint: the load error stays in the log
			return
		}
		_, _ = io.WriteString(w, "ok\n")
	})
	m.HandleFunc("POST /api/v1/fleet/report", s.postReport)
	m.HandleFunc("GET /api/v1/fleet/ring", s.getFleetRing)
	m.HandleFunc("GET /api/v1/fleet/killswitch", s.getFleetKillswitch)
	s.route(m, "GET /api/v1/devices", s.listDevices)
	s.route(m, "GET /api/v1/devices/{id}", s.getDevice)
	s.route(m, "GET /api/v1/audit", s.getAudit)
	s.route(m, "GET /api/v1/sessions", s.getSessions)
	s.route(m, "GET /api/v1/sessions/{id}", s.getSession)
	s.route(m, "POST /api/v1/sessions", s.postSessions)
	s.route(m, "GET /api/v1/capabilities", s.capabilities(m.ServeMux))
	s.route(m, "GET /api/v1/releases", s.getReleases)
	s.route(m, "POST /api/v1/experiments/{name}/status", s.postExperimentStatus)
	s.route(m, "POST /api/v1/experiments/{name}/kill", s.postKill(true))
	s.route(m, "POST /api/v1/experiments/{name}/unkill", s.postKill(false))
	s.route(m, "POST /api/v1/toggles/{name}/kill", s.postToggleKill(true))
	s.route(m, "POST /api/v1/toggles/{name}/unkill", s.postToggleKill(false))
	s.route(m, "GET /api/v1/toggles", s.listToggles)
	s.route(m, "GET /api/v1/toggles/{name}", s.getToggle)
	s.route(m, "POST /api/v1/toggles/{name}/propose", s.postToggleProposal)
	s.route(m, "GET /api/v1/killswitch", s.getKills)
	m.HandleFunc("GET /api/v1/gateway/killswitch", s.getGatewayKillswitch)
	m.HandleFunc("GET /api/v1/gateway/posture", s.getGatewayPosture)
	m.HandleFunc("POST /api/v1/gateway/budget/check", s.postGatewayBudgetCheck) // gateway token
	m.HandleFunc("POST /api/v1/gateway/dlp/events", s.postGatewayDLPEvents)     // gateway token (ADR-0033)
	m.HandleFunc("POST /api/v1/gateway/budget/usage", s.postGatewayBudgetUsage) // gateway token
	s.route(m, "GET /api/v1/budgets", s.getBudgets)
	s.route(m, "POST /api/v1/devices/{id}/revoke", s.revokeDevice)
	s.route(m, "POST /api/v1/users/{id}/revoke-sessions", s.revokeSessions)
	s.route(m, "POST /api/v1/revocations", s.postRevocation)
	s.route(m, "GET /api/v1/revocations", s.listRevocations)
	s.route(m, "GET /api/v1/fleet", s.getFleet)
	s.route(m, "GET /api/v1/policy", s.getPolicy)
	s.route(m, "GET /api/v1/experiments", s.listExperiments)
	s.route(m, "GET /api/v1/experiments/{name}", s.getExperiment)
	s.route(m, "GET /api/v1/rollouts", s.listRollouts)
	s.route(m, "GET /api/v1/rollouts/{name}", s.getRollout)
	s.route(m, "GET /api/v1/rollouts/{name}/approvals", s.getRolloutApprovals)
	s.route(m, "POST /api/v1/rollouts/{name}/approve", s.postRolloutApprove)
	s.route(m, "GET /api/v1/freeze", s.getFreeze)
	s.route(m, "POST /api/v1/freeze", s.postFreeze)
	s.route(m, "GET /api/v1/harnesses", s.getHarnesses)
	s.route(m, "GET /api/v1/whoami", s.whoami) // developers: self only; read permission: any user
	// developer self-service
	s.route(m, "GET /api/v1/me", s.me)
	s.route(m, "GET /api/v1/me/devices", s.myDevices)
	s.route(m, "GET /api/v1/catalog", s.catalog)
	s.route(m, "POST /api/v1/launch/{launcher}", s.launch)
	s.route(m, "POST /api/v1/requests", s.postRequest)
	s.route(m, "GET /api/v1/requests", s.listRequests)
	s.route(m, "POST /api/v1/requests/{id}/approve", s.decide(true))
	s.route(m, "POST /api/v1/requests/{id}/deny", s.decide(false))
	// laptop enrollment: scripts and key are public; the token is the credential
	m.HandleFunc("GET /enroll.sh", s.enrollSh)
	m.HandleFunc("GET /enroll.ps1", s.enrollPs1)
	m.HandleFunc("GET /enroll/release.pub", s.releasePub)
	m.HandleFunc("GET /enroll/killswitch.pub", s.killswitchPub)
	m.HandleFunc("POST /api/v1/enroll", s.postEnroll)
	// CI / cloud workloads: the federated OIDC token is the credential (ADR-0023)
	m.HandleFunc("POST /api/v1/token/exchange", s.postTokenExchange)
	// Remote (A2A) agent egress decisions: a Halos workload or agent credential is the credential (ADR-0024)
	m.HandleFunc("POST /api/v1/agents/egress", s.postAgentEgress)
	// OIDC login
	m.HandleFunc("GET /auth/login", s.login)
	m.HandleFunc("GET /auth/callback", s.callback)
	m.HandleFunc("POST /auth/logout", s.logout)
	s.scimRoutes(m) // /scim/v2 and GET /api/v1/gateway/directory
	m.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { apiErr(w, http.StatusNotFound, "not found") })
	m.HandleFunc("/", s.static)
	return m
}

// ---- middleware ----

const csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRec struct {
	http.ResponseWriter
	code int
}

func (s *statusRec) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := time.Now()
		rec := &statusRec{ResponseWriter: w, code: 200}
		id := randB64(9)
		w.Header().Set("X-Request-Id", id)
		r = r.WithContext(withReqMeta(r.Context(), reqMeta{ip: s.clientIP(r), id: id}))
		next.ServeHTTP(rec, r)
		d := time.Since(t)
		s.metrics.request(r.Pattern, rec.code, d) // the mux set Pattern on r: a bounded route label, never the raw path
		s.cfg.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.code, "dur", d, "remote", r.RemoteAddr)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // client gone: nothing useful to do
}

// decodeBody decodes one JSON value from r.Body capped at limit bytes and
// rejects anything after it: a decoder stops at the end of the first value, so
// without the trailing check an oversize body passes when its value ends early.
// An empty body returns io.EOF, as Decode does.
func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing data after JSON body")
		}
		return err
	}
	return nil
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// errPolicyUnavailable is all a client learns when no policy is loaded: the
// load error quotes policy content (paths, names, validation findings), so it
// is logged, never returned, and unauthenticated callers cannot read policy
// through it. Admins see it in the logs and in `halo validate`.
const errPolicyUnavailable = "policy not loaded"

// policyUnavailable logs err and answers a generic 503.
func (s *Server) policyUnavailable(w http.ResponseWriter, err error) {
	s.cfg.Log.Error("policy unavailable", "err", err)
	apiErr(w, http.StatusServiceUnavailable, errPolicyUnavailable)
}

// ---- fleet ----

func (s *Server) authed(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(tok)) // hash first: constant-time regardless of length
	return ok && subtle.ConstantTimeCompare(sum[:], s.tokSum[:]) == 1
}

func (r *Report) validate() error {
	switch {
	case r.Hostname == "" || len(r.Hostname) > 253:
		return errors.New("hostname required (<=253 chars)")
	case len(r.User) > 256 || len(r.Ring) > 128 || len(r.Digest) > 256 || len(r.LastError) > 4096 || len(r.ErrorCode) > 64:
		return errors.New("field too long")
	case len(r.Harnesses) > 32 || len(r.Drift) > 256:
		return errors.New("too many harnesses or drift entries")
	}
	for n, h := range r.Harnesses {
		if n == "" || len(n) > 64 || len(h.Want) > 128 || len(h.Installed) > 128 {
			return fmt.Errorf("invalid harness %q", n)
		}
	}
	return nil
}

func (s *Server) postReport(w http.ResponseWriter, r *http.Request) {
	// fleet token (MDM/devcontainer fleets) or a per-device token
	var dev *Device
	if !s.authed(r) {
		d, ok := s.deviceAuth(w, r)
		if !ok {
			return
		}
		dev = &d
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxReportBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apiErr(w, http.StatusRequestEntityTooLarge, "report exceeds 64KB")
		} else {
			apiErr(w, http.StatusBadRequest, "read body")
		}
		return
	}
	var rep Report // unknown fields tolerated: newer halod may add some
	if err := json.Unmarshal(body, &rep); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	rep.Device = "" // never from the payload: it keys the fleet row
	if dev != nil { // identity comes from the binding, never from the payload
		rep.User, rep.Device = dev.UserID, dev.ID
	}
	if err := rep.validate(); err != nil {
		apiErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if rep.Harnesses == nil {
		rep.Harnesses = map[string]HarnessStatus{}
	}
	if rep.Drift == nil {
		rep.Drift = []string{}
	}
	if err := s.cfg.Store.Put(Host{Report: rep, LastSeen: s.cfg.Now().UTC()}); err != nil {
		s.cfg.Log.Error("store report", "host", rep.Hostname, "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// FleetResponse is GET /api/v1/fleet.
type FleetResponse struct {
	Hosts []Host      `json:"hosts"`
	Rings []RingStats `json:"rings"`
	Total int         `json:"total"`
	Drift int         `json:"driftHosts"`
}

// RingStats aggregates hosts by ring x release digest x harness version.
type RingStats struct {
	Ring     string                    `json:"ring"`
	Hosts    int                       `json:"hosts"`
	Percent  float64                   `json:"percent"` // of fleet
	Drift    int                       `json:"driftHosts"`
	Digests  map[string]int            `json:"digests"`
	Versions map[string]map[string]int `json:"versions"` // harness -> installed version -> hosts
}

// Aggregate builds ring stats; rings named in order come first, others alphabetically.
func Aggregate(hosts []Host, order []string) []RingStats {
	by := map[string]*RingStats{}
	for _, h := range hosts {
		rs := by[h.Ring]
		if rs == nil {
			rs = &RingStats{Ring: h.Ring, Digests: map[string]int{}, Versions: map[string]map[string]int{}}
			by[h.Ring] = rs
		}
		rs.Hosts++
		rs.Digests[h.Digest]++
		if len(h.Drift) > 0 {
			rs.Drift++
		}
		for n, hs := range h.Harnesses {
			if rs.Versions[n] == nil {
				rs.Versions[n] = map[string]int{}
			}
			rs.Versions[n][hs.Installed]++
		}
	}
	out := make([]RingStats, 0, len(by))
	for _, n := range order {
		if rs := by[n]; rs != nil {
			out = append(out, *rs)
			delete(by, n)
		}
	}
	var rest []string
	for n := range by {
		rest = append(rest, n)
	}
	sort.Strings(rest)
	for _, n := range rest {
		out = append(out, *by[n])
	}
	for i := range out {
		out[i].Percent = 100 * float64(out[i].Hosts) / float64(len(hosts))
	}
	return out
}

func (s *Server) getFleet(w http.ResponseWriter, _ *http.Request, _ Principal) {
	hosts := s.cfg.Store.All()
	var order []string
	if org, _, _ := s.pol.Get(); org != nil {
		for _, r := range org.Rings {
			order = append(order, r.Name)
		}
	}
	resp := FleetResponse{Hosts: hosts, Rings: Aggregate(hosts, order), Total: len(hosts)}
	for _, h := range hosts {
		if len(h.Drift) > 0 {
			resp.Drift++
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- policy / experiments ----

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request, _ Principal) {
	org, view, err := s.pol.Get()
	if org == nil {
		s.cfg.Log.Error("policy unavailable", "err", err)
		s.policyUnavailable(w, err)
		return
	}
	if err != nil { // stale-but-serving: tell the console
		w.Header().Set("X-Policy-Stale", "1")
	}
	writeJSON(w, http.StatusOK, view)
}

// ExperimentDetail is an experiment plus its latest verdict, if any.
type ExperimentDetail struct {
	ExperimentView
	Verdict *Verdict `json:"verdict,omitempty"`
}

func (s *Server) experiments(w http.ResponseWriter) ([]ExperimentDetail, bool) {
	org, view, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return nil, false
	}
	vs, verr := s.verdicts()
	if verr != nil {
		s.cfg.Log.Warn("verdicts unreadable", "path", s.cfg.VerdictsPath, "err", verr)
	}
	out := make([]ExperimentDetail, 0, len(view.Experiments))
	for _, e := range view.Experiments {
		d := ExperimentDetail{ExperimentView: e}
		if v, ok := vs[e.Name]; ok {
			d.Verdict = &v
		}
		out = append(out, d)
	}
	return out, true
}

func (s *Server) listExperiments(w http.ResponseWriter, _ *http.Request, _ Principal) {
	if out, ok := s.experiments(w); ok {
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) getExperiment(w http.ResponseWriter, r *http.Request, _ Principal) {
	out, ok := s.experiments(w)
	if !ok {
		return
	}
	for _, e := range out {
		if e.Name == r.PathValue("name") {
			writeJSON(w, http.StatusOK, e)
			return
		}
	}
	apiErr(w, http.StatusNotFound, "experiment not found")
}

func (s *Server) getHarnesses(w http.ResponseWriter, _ *http.Request, _ Principal) {
	writeJSON(w, http.StatusOK, harness.Matrix())
}

// WhoAmI is GET /api/v1/whoami.
type WhoAmI struct {
	User        string          `json:"user"`
	Groups      []string        `json:"groups"`
	Ring        string          `json:"ring"`
	Profile     string          `json:"profile,omitempty"`
	Release     string          `json:"release,omitempty"`
	Assignments []AssignmentRow `json:"assignments"`
}

// AssignmentRow is one experiment's outcome for the subject; Variant is empty when not enrolled.
type AssignmentRow struct {
	Experiment string `json:"experiment"`
	Status     string `json:"status"`
	Variant    string `json:"variant,omitempty"`
	Control    bool   `json:"control,omitempty"`
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request, p Principal) {
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	if user == "" || len(user) > 256 {
		apiErr(w, http.StatusBadRequest, "user required (<=256 chars)")
		return
	}
	if !p.can(permRead) && !sameUser(user, p.ID) { // developers may only debug themselves
		s.deny(w, r, p, "GET /api/v1/whoami?user=<other>", permRead)
		return
	}
	var groups []string
	for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if !p.can(permRead) { // a developer cannot claim groups they do not hold
		groups = p.Groups
	}
	org, _, err := s.pol.Get()
	if org == nil {
		s.policyUnavailable(w, err)
		return
	}
	sub := policy.Subject{ID: user, Groups: groups}
	resp := WhoAmI{User: user, Groups: append([]string{}, groups...)}
	ring := org.ResolveRing(sub)
	if ring != nil {
		resp.Ring, resp.Profile, resp.Release = ring.Name, ring.Profile, ring.Release
	}
	resp.Assignments = assignments(org, sub, ring)
	writeJSON(w, http.StatusOK, resp)
}

// ---- static ----

const placeholder = `<!doctype html><meta charset=utf-8><title>Halos</title>
<body style="font:14px system-ui;padding:3rem"><h1>Halos API</h1>
<p>Console not embedded. Run <code>cd web &amp;&amp; npm run build</code> then <code>go build -tags webdist ./cmd/halo-server</code>.</p>
<p>API: <a href="/api/v1/fleet">/api/v1/fleet</a>, <a href="/api/v1/policy">/api/v1/policy</a></p>`

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Web == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, placeholder)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if fi, err := fs.Stat(s.cfg.Web, p); p == "" || err != nil || fi.IsDir() {
		r2 := *r // SPA fallback to index.html
		u := *r.URL
		u.Path = "/"
		r2.URL = &u
		http.FileServerFS(s.cfg.Web).ServeHTTP(w, &r2)
		return
	}
	http.FileServerFS(s.cfg.Web).ServeHTTP(w, r)
}
