package server

import (
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
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters for the capability matrix
	"github.com/dshakes/halos/internal/policy"
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
	DataDir          string        // request/device/session-revocation logs ("" = in-memory)
	DeviceTTL        time.Duration // device token lifetime after enrollment (0 = DefaultDeviceTTL)
	Writer           PolicyWriter  // nil: approvals are recorded but need manual policy changes

	// Kill switch. KillStore nil = opened from DataDir. GET
	// /api/v1/gateway/killswitch is served only when both KillKey (signs the
	// list) and GatewayToken (gateways' bearer token) are set; GET
	// /api/v1/fleet/killswitch (device token) whenever KillKey is set.
	KillStore    *controller.KillStore
	KillKey      ed25519.PrivateKey
	GatewayToken string

	// DevUser disables authentication and acts as this user. INSECURE: local demos only.
	DevUser   string
	DevGroups []string
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

	devices     *deviceStore
	authFails   authLimiter
	revoked     *sessionRevocations
	auditLog    *auditLog
	relCache    *releaseCache
	relFetch    pointerFetch  // ring pointer reader; swapped in tests
	relChannels channelsFetch // ring release -> experiment channels; swapped in tests
	kills       *controller.KillStore
	gwSum       [32]byte // sha256 of GatewayToken
}

// New validates cfg and returns a Server. It does not require the policy dir to load yet.
func New(cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("server: empty report token")
	}
	if cfg.DevUser != "" {
		cfg.Log = orDefault(cfg.Log)
		cfg.Log.Warn("INSECURE: --dev-insecure-user set; authentication is disabled and every request acts as this user", "user", cfg.DevUser, "admin", cfg.DevAdmin)
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
	reqs, err := openRequestLog(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	devs, err := openDeviceStore(cfg.DataDir, cfg.DeviceTTL)
	if err != nil {
		return nil, err
	}
	revoked, err := openSessionRevocations(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	al, err := openAuditLog(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, tokSum: sha256.Sum256([]byte(cfg.Token)), pol: &policyHolder{dir: cfg.PolicyDir, log: cfg.Log}, reqs: reqs, devices: devs, revoked: revoked,
		auditLog: al, relCache: &releaseCache{byKey: map[string]cachedPointer{}, chans: map[string][]string{}}}
	s.relFetch, s.relChannels = s.registryFetch, s.registryChannels
	if s.kills = cfg.KillStore; s.kills == nil {
		if s.kills, err = controller.OpenKillStore(cfg.DataDir); err != nil {
			return nil, err
		}
	}
	s.gwSum = sha256.Sum256([]byte(cfg.GatewayToken))
	return s, nil
}

func orDefault(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

// ReloadPolicy forces a policy reload on next read (wire to SIGHUP).
func (s *Server) ReloadPolicy() { s.pol.Invalidate() }

// Handler returns the full mux with security headers and request logging.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	m.HandleFunc("POST /api/v1/fleet/report", s.postReport)
	m.HandleFunc("GET /api/v1/fleet/ring", s.getFleetRing)
	m.HandleFunc("GET /api/v1/fleet/killswitch", s.getFleetKillswitch)
	m.HandleFunc("GET /api/v1/devices", s.admin(s.listDevices))
	m.HandleFunc("GET /api/v1/devices/{id}", s.admin(s.getDevice))
	m.HandleFunc("GET /api/v1/audit", s.admin(s.getAudit))
	m.HandleFunc("GET /api/v1/capabilities", s.user(s.capabilities(m)))
	m.HandleFunc("GET /api/v1/releases", s.admin(s.getReleases))
	m.HandleFunc("POST /api/v1/experiments/{name}/status", s.admin(s.postExperimentStatus))
	m.HandleFunc("POST /api/v1/experiments/{name}/kill", s.admin(s.postKill(true)))
	m.HandleFunc("POST /api/v1/experiments/{name}/unkill", s.admin(s.postKill(false)))
	m.HandleFunc("POST /api/v1/toggles/{name}/kill", s.admin(s.postToggleKill(true)))
	m.HandleFunc("POST /api/v1/toggles/{name}/unkill", s.admin(s.postToggleKill(false)))
	m.HandleFunc("GET /api/v1/killswitch", s.admin(s.getKills))
	m.HandleFunc("GET /api/v1/gateway/killswitch", s.getGatewayKillswitch)
	m.HandleFunc("POST /api/v1/devices/{id}/revoke", s.admin(s.revokeDevice))
	m.HandleFunc("POST /api/v1/users/{id}/revoke-sessions", s.admin(s.revokeSessions))
	// admin-only operator views
	m.HandleFunc("GET /api/v1/fleet", s.admin(s.getFleet))
	m.HandleFunc("GET /api/v1/policy", s.admin(s.getPolicy))
	m.HandleFunc("GET /api/v1/experiments", s.admin(s.listExperiments))
	m.HandleFunc("GET /api/v1/experiments/{name}", s.admin(s.getExperiment))
	m.HandleFunc("GET /api/v1/rollouts", s.admin(s.listRollouts))
	m.HandleFunc("GET /api/v1/rollouts/{name}", s.admin(s.getRollout))
	m.HandleFunc("GET /api/v1/harnesses", s.user(s.getHarnesses))
	m.HandleFunc("GET /api/v1/whoami", s.user(s.whoami)) // developers: self only; admins: any user
	// developer self-service
	m.HandleFunc("GET /api/v1/me", s.user(s.me))
	m.HandleFunc("GET /api/v1/catalog", s.user(s.catalog))
	m.HandleFunc("POST /api/v1/launch/{launcher}", s.user(s.launch))
	m.HandleFunc("POST /api/v1/requests", s.user(s.postRequest))
	m.HandleFunc("GET /api/v1/requests", s.user(s.listRequests))
	m.HandleFunc("POST /api/v1/requests/{id}/approve", s.admin(s.decide(true)))
	m.HandleFunc("POST /api/v1/requests/{id}/deny", s.admin(s.decide(false)))
	// laptop enrollment: scripts and key are public; the token is the credential
	m.HandleFunc("GET /enroll.sh", s.enrollSh)
	m.HandleFunc("GET /enroll.ps1", s.enrollPs1)
	m.HandleFunc("GET /enroll/release.pub", s.releasePub)
	m.HandleFunc("GET /enroll/killswitch.pub", s.killswitchPub)
	m.HandleFunc("POST /api/v1/enroll", s.postEnroll)
	// OIDC login
	m.HandleFunc("GET /auth/login", s.login)
	m.HandleFunc("GET /auth/callback", s.callback)
	m.HandleFunc("POST /auth/logout", s.logout)
	m.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) { apiErr(w, http.StatusNotFound, "not found") })
	m.HandleFunc("/", s.static)
	return s.logging(secure(m))
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
		s.cfg.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.code, "dur", time.Since(t), "remote", r.RemoteAddr)
	})
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // client gone: nothing useful to do
}

func apiErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
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
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
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
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
		return nil, false
	}
	vs, verr := LoadVerdicts(s.cfg.VerdictsPath)
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
	if !p.Admin && user != p.ID { // developers may only debug themselves
		apiErr(w, http.StatusForbidden, "admin role required to inspect other users")
		return
	}
	var groups []string
	for _, g := range strings.Split(r.URL.Query().Get("groups"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if !p.Admin { // a developer cannot claim groups they do not hold
		groups = p.Groups
	}
	org, _, err := s.pol.Get()
	if org == nil {
		apiErr(w, http.StatusServiceUnavailable, "policy not loaded: "+err.Error())
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
