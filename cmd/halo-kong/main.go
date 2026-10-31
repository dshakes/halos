// Command halo-kong is a Kong Go-PDK plugin (Access phase). It is a thin
// adapter: all logic lives in internal/gateway.
//
// Trust model: cohort is derived ONLY from a verified identity
// (internal/identity), never from a header a client could have set:
//   - identity_mode jwt (default when the org policy has identity.issuer, or
//     issuer is set here): the caller's bearer JWT is verified against the
//     IdP's JWKS. Works when Kong sits BEFORE the auth gateway.
//   - identity_mode trusted_header: identity_header/groups_header are honoured
//     only when the TCP peer is inside trusted_proxy_cidrs (the auth gateway).
//     Without CIDRs this mode fails closed (caller treated as anonymous).
//
// Secure defaults (opt out with allow_unverified / forward_client_credentials):
// with JWT identity a model call without a verified caller is answered 401, and
// the caller's credential headers are removed before the upstream. In
// trusted_header mode, or with allow_unverified, unverified callers get default
// routing and no experiments and the auth gateway behind Kong decides.
// All client-supplied x-halo-* and identity/groups headers are dropped.
//
// Fail closed on the model allowlist: model paths the gateway doesn't know
// (404), bodies Kong spooled to disk (413; set nginx_http_client_body_buffer_size
// to 32m), and models that are not a policy alias (400) are answered here with
// kong.response.exit and never forwarded. A trusted identity header sent twice
// is a 400.
//
// shadow_token may be a Kong env-vault reference ({vault://env/halo-shadow-token});
// go-pdk schemas can't mark fields referenceable, so the plugin resolves
// env references itself from its own environment. killswitch_token and
// killswitch_pubkey resolve the same way. With killswitch_url set, the plugin
// polls halo-server's signed kill list (every 10s) and treats killed
// experiments as not running; on fetch failure it keeps the last-known list.
// posture_url (with posture_token) applies the posture gate of rings that set
// posture warn|enforce; every ring's versionGate is applied from the policy
// alone. Enforce answers 403; warn-mode failures and unknown posture pass,
// logged at NOTICE and flagged upstream as x-halo-gate. A posture config that
// is set but invalid (an unset token env var, plain http) fails closed: enforce
// rings answer 403, warn rings pass flagged posture=unknown.
// A request that reaches the 1000-header cap of Kong's header view is a 431:
// identity and the x-halo-* clear list are never derived from a truncated view.
// With $HALO_KONG_METRICS_LISTEN set, gate, directory and admission outcomes
// are counted on GET /metrics (metrics.go).
// killswitch_url must be https unless it targets loopback or
// killswitch_allow_insecure_in_cluster is true. An invalid kill-switch config
// does not block traffic, but is logged at ERROR once a minute and flagged
// with an x-halo-killswitch: misconfigured upstream header.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/shadow"
)

const (
	version  = "0.1.0"
	priority = 900
)

// Config is the plugin's per-route/service configuration.
type Config struct {
	PolicyPath     string `json:"policy_path"`
	IdentityHeader string `json:"identity_header"` // default: policy gateway.auth.identityHeader
	GroupsHeader   string `json:"groups_header"`
	ShadowURL      string `json:"shadow_url"`     // e.g. http://halo-shadow:8090/mirror; empty disables mirroring
	ShadowToken    string `json:"shadow_token"`   // {vault://env/NAME} or literal
	MaxBodyBytes   int    `json:"max_body_bytes"` // default 1 MiB; larger bodies are not mirrored

	IdentityMode      string   `json:"identity_mode"` // jwt | trusted_header | none; default jwt if an issuer is known
	Issuer            string   `json:"issuer"`        // default: policy identity.issuer
	Audience          string   `json:"audience"`      // default: policy identity.audience / clientID
	UserClaim         string   `json:"user_claim"`
	GroupsClaimName   string   `json:"groups_claim"`
	TrustedProxyCIDRs []string `json:"trusted_proxy_cidrs"` // required for trusted_header
	// WorkloadPubkey: PEM public key(s) of halo-server --workload-key-file, or
	// {vault://env/NAME}; accepts CI / cloud workload credentials (ADR-0023).
	WorkloadPubkey string `json:"workload_pubkey"`

	// AllowUnverified opts out of the secure default. By default, when identity
	// is verified by JWT (an issuer is configured), a model call whose caller
	// cannot be verified is answered 401 (in the caller's wire format) instead
	// of being routed anonymously. Set it only when an auth gateway behind Kong
	// decides: unverified callers then get default routing and no experiments.
	AllowUnverified bool `json:"allow_unverified"`

	// ForwardClientCredentials opts out of the secure default. By default the
	// caller's Authorization, x-api-key, api-key, x-goog-api-key and
	// Proxy-Authorization are removed before the request goes upstream, so the
	// developer's IdP token never reaches a provider (the same as halo-proxy).
	// Set it only when the upstream is an auth gateway or orchestrator that
	// needs the caller's token.
	ForwardClientCredentials bool `json:"forward_client_credentials"`

	// Kill switch: halo-server's signed kill list; killed experiments get
	// control routing and no shadow. Empty URL disables.
	KillswitchURL    string `json:"killswitch_url"`    // https://halo-server/api/v1/gateway/killswitch
	KillswitchToken  string `json:"killswitch_token"`  // {vault://env/NAME} or literal
	KillswitchPubkey string `json:"killswitch_pubkey"` // ed25519 PEM public key, or {vault://env/NAME}
	// KillswitchAllowInsecure permits plain http to a non-loopback host (an
	// in-cluster Service URL on a trusted pod network). Default: https required.
	KillswitchAllowInsecure bool `json:"killswitch_allow_insecure_in_cluster"`

	// Posture: halo-server's per-subject device posture verdicts, applied on
	// rings with posture warn|enforce. Empty URL disables the posture gate.
	PostureURL   string `json:"posture_url"`   // https://halo-server/api/v1/gateway/posture
	PostureToken string `json:"posture_token"` // {vault://env/NAME} or literal (halo-server --gateway-posture-token-file, else the shared gateway token)
	// PostureAllowInsecure permits plain http to a non-loopback host.
	PostureAllowInsecure bool `json:"posture_allow_insecure_in_cluster"`

	// Directory: halo-server's SCIM directory (ADR-0022), authoritative when
	// set: a verified caller's groups are the directory's, and a verified caller
	// it does not list as active is refused (403). Empty URL disables.
	DirectoryURL   string `json:"directory_url"`   // https://halo-server/api/v1/gateway/directory
	DirectoryToken string `json:"directory_token"` // {vault://env/NAME} or literal (halo-server --gateway-directory-token-file, else the shared gateway token)
	// DirectoryAllowInsecure permits plain http to a non-loopback host.
	DirectoryAllowInsecure bool `json:"directory_allow_insecure_in_cluster"`
	// DirectoryFailMode: when the directory cannot be asked (no entry younger
	// than 5m cached), open (default) keeps the verified caller with no groups
	// (default routing, no experiments; posture gate still applies) and closed
	// answers 503. A caller is never made anonymous.
	DirectoryFailMode string `json:"directory_fail_mode"`
	// DirectoryMode: full (default) resolves callers in SCIM and checks
	// halo-server credentials against the revocation list (ADR-0026);
	// revocations checks only the revocation list, for a halo-server without SCIM.
	DirectoryMode string `json:"directory_mode"`

	// DLP audit: gateway.dlp findings are posted to halo-server's audit log
	// (ADR-0033). Empty URL: findings are counted and logged only. The scan
	// itself is policy and runs either way.
	DLPURL   string `json:"dlp_url"`   // https://halo-server/api/v1/gateway/dlp
	DLPToken string `json:"dlp_token"` // {vault://env/NAME} or literal (halo-server --gateway-dlp-token-file, else the shared gateway token)
	// DLPAllowInsecure permits plain http to a non-loopback host.
	DLPAllowInsecure bool `json:"dlp_allow_insecure_in_cluster"`
}

var (
	snapMu sync.Mutex
	snaps  = map[string]*gateway.Snapshot{}
)

func snapshot(path string) *gateway.Snapshot {
	snapMu.Lock()
	defer snapMu.Unlock()
	s, ok := snaps[path]
	if !ok {
		s = gateway.NewSnapshot(path)
		snaps[path] = s
	}
	return s
}

var (
	resMu     sync.Mutex
	resolvers = map[string]*identity.Resolver{}
)

// killEntry is the one poller for a kill-switch URL. A rotated token/pubkey
// replaces (and cancels) the previous poller, so config changes never leak
// goroutines. All routes sharing a killswitch_url must share its credentials,
// otherwise they would keep replacing each other's poller.
type killEntry struct {
	k       *gateway.KillSwitch // last good poller; nil until a valid config is seen
	cancel  context.CancelFunc
	fp      string // fingerprint of the config k was built from
	badFP   string // fingerprint of the last invalid config
	badErr  error
	lastLog time.Time
}

const killMisconfigLogEvery = time.Minute

var (
	killMu  sync.Mutex
	kills   = map[string]*killEntry{} // by killswitch_url
	killNow = time.Now
)

// killSwitch returns the process-wide poller for this config; nil when
// unconfigured or invalid. Until its first successful fetch nothing is killed.
func (c Config) killSwitch(kong kongAPI) *gateway.KillSwitch {
	k, _ := c.killPoller(kong)
	return k
}

// killPoller also reports whether this route's kill-switch config is invalid.
// Traffic keeps flowing then (an invalid kill switch must not take the gateway
// down), but the misconfiguration is loud: an ERROR log at most once a minute
// (per URL) and, from access, an x-halo-killswitch: misconfigured header for
// the auth gateway/log pipeline to alert on. A previously good poller keeps
// running so a bad rotation does not silently un-kill experiments.
func (c Config) killPoller(kong kongAPI) (k *gateway.KillSwitch, misconfigured bool) {
	if c.KillswitchURL == "" {
		return nil, false
	}
	tok, pub := secret(c.KillswitchToken), secret(c.KillswitchPubkey)
	fp := tok + "\x00" + pub + "\x00" + strconv.FormatBool(c.KillswitchAllowInsecure)
	killMu.Lock()
	defer killMu.Unlock()
	e := kills[c.KillswitchURL]
	if e == nil {
		e = &killEntry{}
		kills[c.KillswitchURL] = e
	}
	if e.k != nil && e.fp == fp {
		return e.k, false
	}
	if e.badErr == nil || e.badFP != fp {
		v, err := bundle.ParseVerifier([]byte(pub))
		var nk *gateway.KillSwitch
		if err == nil {
			nk, err = gateway.NewKillSwitch(c.KillswitchURL, tok, v, 0, nil, c.KillswitchAllowInsecure)
		}
		if err == nil {
			if e.cancel != nil {
				e.cancel() // replaced: stop the old poller
			}
			ctx, cancel := context.WithCancel(context.Background())
			e.k, e.cancel, e.fp, e.badFP, e.badErr = nk, cancel, fp, "", nil
			go nk.Run(ctx)
			return nk, false
		}
		e.badFP, e.badErr, e.lastLog = fp, err, time.Time{}
	}
	if now := killNow(); now.Sub(e.lastLog) >= killMisconfigLogEvery {
		e.lastLog = now
		_ = kong.Err("halo-kong: killswitch config invalid; kill switch not (re)configured, killed experiments may keep running: ", e.badErr.Error())
	}
	return e.k, true
}

var (
	postureMu      sync.Mutex
	postureClients = map[string]*gateway.PostureClient{} // by url, token, insecure
)

// postureClient returns the process-wide client for this config (its verdict
// cache is shared by every route); nil when unconfigured. invalid reports a
// posture_url whose config is invalid (logged): the gate then fails closed.
func (c Config) postureClient(kong kongAPI) (pc *gateway.PostureClient, invalid bool) {
	if c.PostureURL == "" {
		return nil, false
	}
	tok := secret(c.PostureToken)
	key := c.PostureURL + "\x00" + tok + "\x00" + strconv.FormatBool(c.PostureAllowInsecure)
	postureMu.Lock()
	defer postureMu.Unlock()
	if pc, ok := postureClients[key]; ok {
		return pc, false
	}
	pc, err := gateway.NewPostureClient(c.PostureURL, tok, 0, 0, nil, c.PostureAllowInsecure)
	if err != nil {
		_ = kong.Err("halo-kong: posture config invalid; enforce rings refuse every caller (403), warn rings pass with posture=unknown: ", err.Error())
		return nil, true
	}
	postureClients[key] = pc
	return pc, false
}

var (
	directoryMu      sync.Mutex
	directoryClients = map[string]*gateway.DirectoryClient{} // by url, token, insecure
)

// directoryClient returns the process-wide client for this config (its cache
// is shared by every route); nil when unconfigured. An invalid config is
// logged and handled like an unreachable directory (directoryDown).
func (c Config) directoryClient(kong kongAPI) (dc *gateway.DirectoryClient, invalid bool) {
	if c.DirectoryURL == "" {
		return nil, false
	}
	tok := secret(c.DirectoryToken)
	key := c.DirectoryURL + "\x00" + tok + "\x00" + strconv.FormatBool(c.DirectoryAllowInsecure) + "\x00" + c.DirectoryFailMode + "\x00" + c.DirectoryMode
	directoryMu.Lock()
	defer directoryMu.Unlock()
	if dc, ok := directoryClients[key]; ok {
		return dc, false
	}
	err := gateway.CheckDirectoryFailMode(c.DirectoryFailMode)
	if err == nil {
		err = gateway.CheckDirectoryMode(c.DirectoryMode)
	}
	if err == nil {
		dc, err = gateway.NewDirectoryClient(c.DirectoryURL, tok, 0, 0, nil, c.DirectoryAllowInsecure)
	}
	if err != nil {
		_ = kong.Err("halo-kong: directory config invalid; callers keep their identity with no groups (or 503 unless directory_fail_mode is open): ", err.Error())
		return nil, true
	}
	dc.FailClosed = c.DirectoryFailMode == gateway.DirectoryFailClosed
	dc.RevocationsOnly = c.DirectoryMode == gateway.DirectoryModeRevocations
	dc.Observe = kmetrics.directoryOutcome
	directoryClients[key] = dc
	return dc, false
}

// noRevocationWarned holds the workload_pubkey values already warned about.
var noRevocationWarned sync.Map

// warnNoRevocation logs gateway.NoRevocationWarning once per process for a
// config that accepts halo-server credentials without a directory_url (the
// plugin has no startup hook of its own: the first request is its startup).
func (c Config) warnNoRevocation(kong kongAPI) {
	if c.DirectoryURL != "" || c.WorkloadPubkey == "" {
		return
	}
	if _, seen := noRevocationWarned.LoadOrStore(c.WorkloadPubkey, true); !seen {
		_ = kong.Warn("halo-kong: ", gateway.NoRevocationWarning)
	}
}

// directoryDown is the answer for a verified caller when the directory config
// is invalid: the open fail mode keeps sub with no groups, never anonymous;
// any other (closed, or an invalid value) refuses.
func (c Config) directoryDown(sub *policy.Subject, path string) (*policy.Subject, *gateway.Rejection) {
	if c.DirectoryFailMode != "" && c.DirectoryFailMode != gateway.DirectoryFailOpen {
		return nil, gateway.RejectDirectoryUnavailable(path)
	}
	if sub == nil || sub.Kind == policy.SubjectWorkload { // workloads are not in SCIM: unchanged, as Resolve does
		return sub, nil
	}
	return gateway.FailOpenSubject(sub), nil // a delegated agent keeps its chain and the agent policy
}

// posture applies ring's posture gate. A configured but invalid posture
// client never turns the gate off: the posture is unknown and, under
// enforce, the request is refused.
func (c Config) posture(kong kongAPI, org *policy.Org, ring string, sub *policy.Subject) (f *gateway.Finding, unknown bool) {
	mode := gateway.RingGate(org, ring, gateway.GatePosture)
	pc, invalid := c.postureClient(kong)
	switch {
	case invalid && mode == policy.GateEnforce:
		f, unknown = &gateway.Finding{Gate: gateway.GatePosture, Mode: mode, Reason: "the gateway's posture config is invalid, so no verdict can be checked"}, true
	case invalid && mode != policy.GateOff:
		unknown = true
	default:
		f, unknown = gateway.CheckPosture(context.Background(), pc, org, ring, sub)
	}
	if mode != policy.GateOff && (pc != nil || invalid) {
		outcome := "pass"
		switch {
		case f != nil && f.Reject("") != nil:
			outcome = "deny"
		case f != nil:
			outcome = "fail"
		case unknown:
			outcome = "unknown"
		}
		kmetrics.postureOutcome(ring, outcome)
	}
	return f, unknown
}

// gate applies the ring's posture and version gates; outcomes is what failed
// or was unknown (for the x-halo-gate upstream header), rej the 403 to answer.
func (c Config) gate(kong kongAPI, org *policy.Org, ring string, sub *policy.Subject, h http.Header, proto string) (outcomes []string, rej *gateway.Rejection) {
	pf, unknown := c.posture(kong, org, ring, sub)
	if unknown {
		outcomes = append(outcomes, "posture=unknown")
	}
	for _, f := range []*gateway.Finding{pf, gateway.CheckVersion(org, ring, h.Get("User-Agent"))} {
		if f == nil {
			continue
		}
		outcomes = append(outcomes, f.Gate+"="+f.Mode)
		_ = kong.Notice("halo-kong: ", f.Gate, " check failed (", f.Mode, ", ring ", ring, "): ", f.Reason)
		if rej == nil {
			rej = f.Reject(proto)
		}
	}
	return outcomes, rej
}

var (
	dlpMu        sync.Mutex
	dlpReporters = map[string]*gateway.DLPReporter{} // by url, token, insecure; each runs for the process lifetime
)

// dlpReporter returns the process-wide reporter for this config; nil when
// unconfigured or invalid (logged).
func (c Config) dlpReporter(kong kongAPI) *gateway.DLPReporter {
	if c.DLPURL == "" {
		return nil
	}
	tok := secret(c.DLPToken)
	key := c.DLPURL + "\x00" + tok + "\x00" + strconv.FormatBool(c.DLPAllowInsecure)
	dlpMu.Lock()
	defer dlpMu.Unlock()
	if r, ok := dlpReporters[key]; ok {
		return r
	}
	r, err := gateway.NewDLPReporter(c.DLPURL, tok, 0, nil, c.DLPAllowInsecure)
	if err != nil {
		_ = kong.Err("halo-kong: dlp config invalid; findings are not audited: ", err.Error())
		dlpReporters[key] = nil // log once per config
		return nil
	}
	dlpReporters[key] = r
	go r.Run(context.Background()) // ponytail: a rotated token leaves the old reporter idle, not stopped; add cancel as killEntry does if rotations are frequent
	return r
}

// dlp records a request's DLP scan: metrics, a log line without the secret,
// and the audit events.
func (c Config) dlp(kong kongAPI, org *policy.Org, sub *policy.Subject, h http.Header, res gateway.Result) {
	if res.DLP != nil && res.DLP.Truncated {
		outcome := "forwarded"
		if res.DLP.Blocked == gateway.DLPTruncated {
			outcome = "blocked"
			_ = kong.Notice("halo-kong: dlp refused a request it could not scan in full (secret action block, ring ", res.Decision.Ring, ")")
		}
		kmetrics.dlpTruncated(outcome)
	}
	if res.DLP == nil || len(res.DLP.Findings) == 0 {
		return
	}
	units := gateway.SubjectUnits(org, sub)
	base := gateway.DLPEvent{At: time.Now().UTC(), Gateway: "halo-kong", Ring: res.Decision.Ring, Protocol: res.Protocol, Harness: gateway.HarnessFromUA(h.Get("User-Agent"))}
	if sub != nil {
		base.Subject = sub.ID
		if sub.Delegation.Depth() > 0 {
			base.Chain = sub.Delegation.Chain()
		}
	}
	if len(units) > 0 {
		base.Unit = units[0]
	}
	evs := gateway.DLPEvents(res.DLP, base)
	for _, e := range evs {
		kmetrics.dlpFinding(e.Kind, e.Detector, e.Action)
		_ = kong.Notice("halo-kong: dlp ", e.Kind, " ", e.Detector, " ", e.Action, " at ", e.Location, " #", e.Hash, " (ring ", e.Ring, ")")
	}
	c.dlpReporter(kong).Report(evs...)
}

var envVaultRef = regexp.MustCompile(`^\{vault://env/([A-Za-z0-9_-]+)\}$`)

// secret resolves a Kong env-vault reference the way Kong does
// ({vault://env/halo-shadow-token} -> $HALO_SHADOW_TOKEN); literals pass through.
func secret(v string) string {
	if m := envVaultRef.FindStringSubmatch(v); m != nil {
		return os.Getenv(strings.ToUpper(strings.ReplaceAll(m[1], "-", "_")))
	}
	return v
}

func (c Config) identityOptions(org *policy.Org) identity.Options {
	return identity.Options{
		Mode: c.IdentityMode, Issuer: c.Issuer, Audience: c.Audience,
		UserClaim: c.UserClaim, GroupsClaim: c.GroupsClaimName,
		IdentityHeader: gateway.IdentityHeaderFor(org, c.IdentityHeader), GroupsHeader: c.GroupsHeader,
		TrustedProxyCIDRs: c.TrustedProxyCIDRs, WorkloadKeys: secret(c.WorkloadPubkey),
	}
}

// rejectsUnverified reports whether an unverifiable caller is refused (401): the
// default whenever identity is verified by JWT, unless allow_unverified. In
// trusted_header mode the auth gateway that sets the identity header decides.
func (c Config) rejectsUnverified(org *policy.Org) bool {
	if c.AllowUnverified {
		return false
	}
	switch c.IdentityMode {
	case "jwt":
		return true
	case "":
		return c.Issuer != "" || (org != nil && org.Identity.Issuer != "")
	}
	return false
}

// kongAPI is the slice of the Kong PDK the Access phase uses; pdkAPI adapts
// the real *pdk.PDK and tests use a fake.
type kongAPI interface {
	Headers() (map[string][]string, error)
	Path() (string, error)
	RawBody() ([]byte, error)
	PeerIP() (string, error)
	Exit(status int, body []byte, headers map[string][]string)
	ClearHeader(name string) error
	SetHeader(name, value string) error
	SetScheme(scheme string) error
	SetTarget(host string, port int) error
	SetPath(path string) error
	SetRawBody(body string) error
	Err(args ...any) error
	Warn(args ...any) error
	Notice(args ...any) error
}

type pdkAPI struct{ k *pdk.PDK }

// maxHeaders is the most header lines Kong hands the plugin (go-pdk's cap).
// Kong truncates silently, so reaching it is answered 431 (headerCapReached).
const maxHeaders = 1000

func (a pdkAPI) Headers() (map[string][]string, error) { return a.k.Request.GetHeaders(maxHeaders) }
func (a pdkAPI) Path() (string, error)                 { return a.k.Request.GetPath() }
func (a pdkAPI) RawBody() ([]byte, error)              { return a.k.Request.GetRawBody() }
func (a pdkAPI) PeerIP() (string, error)               { return a.k.Client.GetIp() }
func (a pdkAPI) Exit(status int, body []byte, h map[string][]string) {
	a.k.Response.Exit(status, body, h)
}
func (a pdkAPI) ClearHeader(n string) error            { return a.k.ServiceRequest.ClearHeader(n) }
func (a pdkAPI) SetHeader(n, v string) error           { return a.k.ServiceRequest.SetHeader(n, v) }
func (a pdkAPI) SetScheme(s string) error              { return a.k.ServiceRequest.SetScheme(s) }
func (a pdkAPI) SetTarget(host string, port int) error { return a.k.Service.SetTarget(host, port) }
func (a pdkAPI) SetPath(p string) error                { return a.k.ServiceRequest.SetPath(p) }
func (a pdkAPI) SetRawBody(b string) error             { return a.k.ServiceRequest.SetRawBody(b) }
func (a pdkAPI) Err(args ...any) error                 { return a.k.Log.Err(args...) }
func (a pdkAPI) Warn(args ...any) error                { return a.k.Log.Warn(args...) }
func (a pdkAPI) Notice(args ...any) error              { return a.k.Log.Notice(args...) }

// verify returns the verified caller, or nil (anonymous) with a log line.
// err is non-nil only for requests that must be refused (ambiguous identity).
// enforced reports whether identity verification is configured at all: a nil
// subject is only an unverified caller when it is true (a broken identity
// config counts as enforced, so reject_unverified fails closed).
func (c Config) verify(kong kongAPI, org *policy.Org, h http.Header) (sub *policy.Subject, enforced bool, err error) {
	opts := c.identityOptions(org)
	key := fmt.Sprintf("%+v", opts)
	resMu.Lock()
	r, ok := resolvers[key]
	if !ok {
		r = &identity.Resolver{}
		resolvers[key] = r
	}
	resMu.Unlock()
	v, err := r.Get(opts, org)
	if err != nil {
		_ = kong.Err("halo-kong: identity config: ", err.Error())
		return nil, true, nil
	}
	if v == nil {
		return nil, false, nil
	}
	peer, _ := kong.PeerIP() // direct TCP peer, not X-Forwarded-For
	s, err := v.Verify(&http.Request{Header: h, RemoteAddr: peer})
	if errors.Is(err, identity.ErrAmbiguous) {
		return nil, true, err
	}
	if err != nil {
		if !errors.Is(err, identity.ErrNoCredentials) {
			_ = kong.Notice("halo-kong: unverified caller: ", err.Error())
		}
		return nil, true, nil
	}
	return &s, true, nil
}

func exit(kong kongAPI, r *gateway.Rejection) {
	kong.Exit(r.Status, r.JSON(), map[string][]string{"Content-Type": {"application/json"}})
}

func New() interface{} { return &Config{} }

func main() {
	if addr := os.Getenv(metricsListenEnv); addr != "" && !dumpOnly(os.Args[1:]) {
		serveMetrics(addr)
	}
	_ = server.StartServer(New, version, priority)
}

// dumpOnly: Kong runs the binary with -dump to read its schema and exit; that
// run must not take the metrics port from the serving process.
func dumpOnly(args []string) bool {
	return slices.ContainsFunc(args, func(a string) bool { return strings.TrimLeft(a, "-") == "dump" })
}

// headerCapReached reports a header view at Kong's cap: it may be truncated,
// so a duplicate identity header or an x-halo-* name past the cap would be
// invisible. Counted per value, as Kong counts header lines.
func headerCapReached(raw map[string][]string) bool {
	n := 0
	for _, vs := range raw {
		n += max(len(vs), 1)
	}
	return n >= maxHeaders
}

func (c Config) Access(kong *pdk.PDK) { c.access(pdkAPI{kong}) }

func (c Config) access(kong kongAPI) {
	// go-pdk runs each event in its own goroutine with no recover, so a panic
	// here would kill the plugin server and every route behind it. Refuse
	// this request instead (500, never forwarded) and log the panic.
	defer func() {
		if p := recover(); p != nil {
			_ = kong.Err("halo-kong: access phase panic (request refused): ", fmt.Sprint(p), "\n", string(debug.Stack()))
			kong.Exit(http.StatusInternalServerError, []byte(`{"error":{"type":"halos_internal_error","message":"halos: internal error in the gateway plugin"}}`),
				map[string][]string{"Content-Type": {"application/json"}})
		}
	}()
	org, err := snapshot(c.PolicyPath).Get()
	if err != nil {
		// Fail open on routing (Kong's default service), never on header hygiene.
		_ = kong.Err("halo-kong: policy: ", err.Error())
	}
	path, _ := kong.Path()
	raw, err := kong.Headers()
	if err != nil {
		// Without the header view nothing can be stripped or verified: refuse, never forward.
		_ = kong.Err("halo-kong: request refused: read headers: ", err.Error())
		exit(kong, &gateway.Rejection{Status: http.StatusInternalServerError, Protocol: gateway.ProtocolForPath(path), Message: "halos: could not read request headers"})
		return
	}
	if headerCapReached(raw) {
		kmetrics.headerCapRejected()
		_ = kong.Warn("halo-kong: request refused: header count reached the ", strconv.Itoa(maxHeaders), "-header cap")
		exit(kong, &gateway.Rejection{Status: http.StatusRequestHeaderFieldsTooLarge, Protocol: gateway.ProtocolForPath(path), Message: "too many request headers"})
		return
	}
	h := http.Header{}
	for k, vs := range raw {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	sub, enforced, err := c.verify(kong, org, h)
	if err != nil {
		exit(kong, &gateway.Rejection{Status: http.StatusBadRequest, Protocol: gateway.ProtocolForPath(path), Message: "identity header sent more than once"})
		return
	}
	if sub == nil && enforced && c.rejectsUnverified(org) && gateway.ProtocolForPath(path) != "" {
		r := &gateway.Rejection{Status: http.StatusUnauthorized, Protocol: gateway.ProtocolForPath(path), Message: "invalid or missing credentials"}
		kong.Exit(r.Status, r.JSON(), map[string][]string{"Content-Type": {"application/json"}, "WWW-Authenticate": {`Bearer realm="halos"`}})
		return
	}
	body, berr := kong.RawBody() // error if Kong spooled a large body to disk
	if berr != nil && gateway.ProtocolForPath(path) != "" {
		_ = kong.Warn("halo-kong: body unreadable (raise nginx_http_client_body_buffer_size): ", berr.Error())
		exit(kong, gateway.RejectTooLarge(path))
		return
	}

	c.warnNoRevocation(kong)
	if dc, invalid := c.directoryClient(kong); dc != nil {
		if sub, err = dc.Resolve(context.Background(), sub); err != nil { // a deprovisioned caller is refused, never anonymous
			exit(kong, gateway.DirectoryReject(path, err)) // revoked, unavailable or not provisioned
			return
		}
	} else if invalid {
		var rej *gateway.Rejection
		if sub, rej = c.directoryDown(sub, path); rej != nil {
			kmetrics.directoryOutcome("invalid_config_refused")
			exit(kong, rej)
			return
		}
		kmetrics.directoryOutcome("invalid_config_failopen")
	}
	ks, ksBad := c.killPoller(kong)
	res := gateway.PrepareVerified(ks.Apply(org), sub, h, path, body) // killed experiments: control, no shadow
	c.dlp(kong, org, sub, h, res)
	if res.Reject != nil {
		if res.RewriteErr != nil {
			_ = kong.Warn("halo-kong: rewrite failed: ", res.RewriteErr.Error())
		}
		if res.Reject.Code == gateway.CodeAgentNotPermitted {
			kmetrics.agentDenied()
			_ = kong.Notice("halo-kong: delegated agent refused: ", res.Reject.Message)
		}
		exit(kong, res.Reject)
		return
	}
	d := res.Decision
	var gates []string
	if res.Protocol != "" {
		var rej *gateway.Rejection
		if gates, rej = c.gate(kong, org, d.Ring, sub, h, res.Protocol); rej != nil {
			exit(kong, rej)
			return
		}
	}

	// res.ClearHeaders holds every owned name (x-halo-gate and
	// x-halo-killswitch included) whether or not the client sent it.
	for _, n := range append(res.ClearHeaders, c.identityOptions(org).HeaderNames(org)...) {
		_ = kong.ClearHeader(n)
	}
	if !c.ForwardClientCredentials {
		for _, n := range identity.ClientCredentialHeaders {
			_ = kong.ClearHeader(n)
		}
	}
	for k, v := range d.Headers {
		_ = kong.SetHeader(k, v)
	}
	if ksBad {
		_ = kong.SetHeader(gateway.HeaderKillswitch, "misconfigured") // alertable; client copies were cleared above
	}
	if len(gates) > 0 {
		_ = kong.SetHeader(gateway.HeaderGate, strings.Join(gates, ",")) // warn-mode and unknown outcomes, for the log pipeline
	}
	prefix := ""
	if d.Upstream != "" {
		scheme, host, port, pre, err := gateway.Target(d.Upstream)
		if err != nil {
			_ = kong.Err("halo-kong: ", err.Error())
		} else {
			prefix = pre
			_ = kong.SetScheme(scheme)
			_ = kong.SetTarget(host, port)
		}
	}
	if res.Rewritten || prefix != "" {
		_ = kong.SetPath(prefix + res.Path)
	}
	if res.Rewritten && res.Body != nil {
		_ = kong.SetRawBody(string(res.Body))
	}

	c.mirror(kong, res, h, path, body)
}

func (c Config) mirror(kong kongAPI, res gateway.Result, h http.Header, path string, body []byte) {
	if c.ShadowURL == "" {
		return
	}
	limit := c.MaxBodyBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	jobs := shadow.Jobs(res, h, path, body, limit)
	if len(jobs) == 0 {
		return
	}
	m, err := shadow.SharedMirrorer(c.ShadowURL, secret(c.ShadowToken))
	if err != nil {
		_ = kong.Err("halo-kong: shadow_url: ", err.Error())
		return
	}
	for _, j := range jobs {
		m.Submit(j)
	}
}
