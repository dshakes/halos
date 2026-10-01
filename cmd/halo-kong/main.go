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
// Unverified callers get default routing and no experiments; the request is
// not rejected here (the auth gateway behind Kong decides that), unless
// reject_unverified is set: then a model call without a verified identity is
// answered 401 (use it when Kong is the only thing in front of the upstreams).
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

	// RejectUnverified answers a model call whose caller could not be verified
	// with 401 instead of routing it anonymously (default routing, no
	// experiments). Default false: the auth gateway behind Kong decides. Set it
	// when Kong is the only thing in front of the model upstreams.
	RejectUnverified bool `json:"reject_unverified"`

	// StripClientCredentials removes the caller's Authorization, x-api-key,
	// api-key, x-goog-api-key and Proxy-Authorization before the request goes
	// upstream. Default false: Kong often sits in front of an auth gateway or
	// orchestrator that needs the caller's token. Set it when the upstreams are
	// providers and Kong (request-transformer, vault) adds their credential, so
	// the caller's IdP token never reaches a provider.
	StripClientCredentials bool `json:"strip_client_credentials"`

	// Kill switch: halo-server's signed kill list; killed experiments get
	// control routing and no shadow. Empty URL disables.
	KillswitchURL    string `json:"killswitch_url"`    // https://halo-server/api/v1/gateway/killswitch
	KillswitchToken  string `json:"killswitch_token"`  // {vault://env/NAME} or literal
	KillswitchPubkey string `json:"killswitch_pubkey"` // ed25519 PEM public key, or {vault://env/NAME}
	// KillswitchAllowInsecure permits plain http to a non-loopback host (an
	// in-cluster Service URL on a trusted pod network). Default: https required.
	KillswitchAllowInsecure bool `json:"killswitch_allow_insecure_in_cluster"`
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
		v, err := bundle.ParseEd25519Verifier([]byte(pub))
		var nk *gateway.KillSwitch
		if err == nil {
			nk, err = gateway.NewKillSwitch(c.KillswitchURL, tok, v.Key, 0, nil, c.KillswitchAllowInsecure)
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
		TrustedProxyCIDRs: c.TrustedProxyCIDRs,
	}
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

func (a pdkAPI) Headers() (map[string][]string, error) { return a.k.Request.GetHeaders(1000) }
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

func main() { _ = server.StartServer(New, version, priority) }

func (c Config) Access(kong *pdk.PDK) { c.access(pdkAPI{kong}) }

func (c Config) access(kong kongAPI) {
	org, err := snapshot(c.PolicyPath).Get()
	if err != nil {
		// Fail open on routing (Kong's default service), never on header hygiene.
		_ = kong.Err("halo-kong: policy: ", err.Error())
	}
	raw, _ := kong.Headers()
	h := http.Header{}
	for k, vs := range raw {
		for _, v := range vs {
			h.Add(k, v)
		}
	}
	path, _ := kong.Path()
	sub, enforced, err := c.verify(kong, org, h)
	if err != nil {
		exit(kong, &gateway.Rejection{Status: http.StatusBadRequest, Protocol: gateway.ProtocolForPath(path), Message: "identity header sent more than once"})
		return
	}
	if sub == nil && enforced && c.RejectUnverified && gateway.ProtocolForPath(path) != "" {
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

	ks, ksBad := c.killPoller(kong)
	res := gateway.PrepareVerified(ks.Apply(org), sub, h, path, body) // killed experiments: control, no shadow
	if res.Reject != nil {
		if res.RewriteErr != nil {
			_ = kong.Warn("halo-kong: rewrite failed: ", res.RewriteErr.Error())
		}
		exit(kong, res.Reject)
		return
	}
	d := res.Decision

	for _, n := range append(res.ClearHeaders, c.identityOptions(org).HeaderNames(org)...) {
		_ = kong.ClearHeader(n)
	}
	if c.StripClientCredentials {
		for _, n := range identity.ClientCredentialHeaders {
			_ = kong.ClearHeader(n)
		}
	}
	for k, v := range d.Headers {
		_ = kong.SetHeader(k, v)
	}
	if ksBad {
		_ = kong.SetHeader("x-halo-killswitch", "misconfigured") // alertable; client copies were cleared above
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
