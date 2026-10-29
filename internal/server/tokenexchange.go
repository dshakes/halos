package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Workload identity federation (ADR-0023): POST /api/v1/token/exchange takes a
// CI / cloud OIDC token (RFC 8693 token exchange) and, when a policy
// workloads rule matches its verified claims, answers a short-lived gateway
// credential signed with Config.WorkloadKey.

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // RFC 8693 identifier, not a credential
	tokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // RFC 8693 identifier, not a credential
	tokenTypeIDToken   = "urn:ietf:params:oauth:token-type:id_token"       //nolint:gosec // RFC 8693 identifier, not a credential
	tokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"   //nolint:gosec // RFC 8693 identifier, not a credential

	maxExchangeBody = 16 << 10
	// maxReplayEntries bounds the jti cache; when full of unexpired entries new
	// exchanges are refused (503) rather than forgetting what was seen.
	maxReplayEntries = 100_000
	// exchangeIatSkew: a subject token issued further in the future is refused.
	exchangeIatSkew = 5 * time.Minute
)

var (
	errReplayed   = errors.New("subject token already exchanged (replay)")
	errReplayFull = errors.New("replay cache full")
	errNoRule     = errors.New("no workloads rule matches the token's claims")
)

// workloadExchange is the exchange's state: one verifier (discovery + JWKS
// cache) per trusted issuer and audience, and the replay cache. Zero value ready.
// The in-process replay cache serves the single-replica file backend; with a
// shared Backend (several replicas) rememberSubjectToken uses the database.
type workloadExchange struct {
	mu        sync.Mutex
	verifiers map[string]*identity.OIDCJWT // issuer URL + "\x00" + audience
	seen      map[string]time.Time         // replay key -> subject token expiry
	denied    map[string]time.Time         // issuer + "\x00" + IP -> last workload.token.denied audit
	// deniedSuppressed counts workload.token.denied audits coalesced away
	// (halo_server_workload_denied_audit_suppressed_total).
	deniedSuppressed atomic.Uint64
}

const (
	// deniedAuditWindow: at most one workload.token.denied audit entry per
	// issuer and client IP per window; the rest are logged and counted.
	deniedAuditWindow = time.Minute
	// maxDeniedAuditKeys bounds the coalescing map; when full of keys inside
	// the window, further denials are suppressed (counted), not audited.
	maxDeniedAuditKeys = 10_000
)

// auditDenied reports whether a workload.token.denied for key (issuer+IP)
// should be audited now; false means it was coalesced and counted.
func (x *workloadExchange) auditDenied(key string, now time.Time) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if last, ok := x.denied[key]; ok && now.Sub(last) < deniedAuditWindow {
		x.deniedSuppressed.Add(1)
		return false
	}
	if x.denied == nil {
		x.denied = map[string]time.Time{}
	}
	if _, ok := x.denied[key]; !ok && len(x.denied) >= maxDeniedAuditKeys {
		for k, last := range x.denied {
			if now.Sub(last) >= deniedAuditWindow {
				delete(x.denied, k)
			}
		}
		if len(x.denied) >= maxDeniedAuditKeys {
			x.deniedSuppressed.Add(1)
			return false
		}
	}
	x.denied[key] = now
	return true
}

func (x *workloadExchange) verifier(issuer, audience string) (*identity.OIDCJWT, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	k := issuer + "\x00" + audience
	if v := x.verifiers[k]; v != nil {
		return v, nil
	}
	// The user claim is irrelevant here: Claims, not Verify, is used.
	v, err := identity.NewOIDCJWT(issuer, audience, "sub", "", nil)
	if err != nil {
		return nil, err
	}
	if x.verifiers == nil {
		x.verifiers = map[string]*identity.OIDCJWT{}
	}
	x.verifiers[k] = v
	return v, nil
}

// remember records key until exp; it fails when key is already live.
func (x *workloadExchange) remember(key string, exp, now time.Time) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.seen == nil {
		x.seen = map[string]time.Time{}
	}
	if until, ok := x.seen[key]; ok && now.Before(until) {
		return errReplayed
	}
	if len(x.seen) >= maxReplayEntries {
		for k, until := range x.seen {
			if !now.Before(until) {
				delete(x.seen, k)
			}
		}
		if len(x.seen) >= maxReplayEntries {
			return errReplayFull
		}
	}
	x.seen[key] = exp
	return nil
}

// TokenExchangeResponse is the RFC 8693 response plus the routing facts the
// `halo ci token` client exports (subject, ring, gateway URL).
type TokenExchangeResponse struct {
	AccessToken     string   `json:"access_token"`
	IssuedTokenType string   `json:"issued_token_type"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int      `json:"expires_in"`
	Subject         string   `json:"subject"`
	Groups          []string `json:"groups,omitempty"`
	Rule            string   `json:"rule,omitempty"`
	Ring            string   `json:"ring,omitempty"`
	GatewayURL      string   `json:"gateway_url,omitempty"`
	// Actors (delegated credentials, ADR-0024) is the act chain, root-side
	// first; Models the credential's model scope (absent = not narrowed).
	Actors []string `json:"actors,omitempty"`
	Models []string `json:"models,omitempty"`
}

// oauthErr is the RFC 6749 section 5.2 error shape token endpoints answer.
func oauthErr(w http.ResponseWriter, code int, kind, desc string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": desc})
}

// tooManyFailures is the 429 for a request from a client IP blocked for
// failed attempts that carried no credential signed by a trusted key.
func tooManyFailures(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	oauthErr(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts")
}

// postTokenExchange: POST /api/v1/token/exchange. A delegation exchange
// (ADR-0024) is dispatched before anything else touches a limiter: it has
// its own budget (agentFails, see delegate), so CI failures from an IP never
// block agent delegation from it. The CI exchange's budget (exchangeFails)
// counts only subject tokens that are malformed or whose signature does not
// verify: a token signed by a trusted issuer that matches no rule, is
// replayed, expired or for another audience costs nothing, because anyone on
// a shared CI runner (one egress IP for many tenants) can mint those. A
// client IP that is blocked still has its subject token verified, from
// cached keys only (identity.CacheOnly), and a signed token bypasses the
// block, so garbage from a shared IP cannot lock out the jobs behind it.
// Anything else from a blocked IP is 429.
func (s *Server) postTokenExchange(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBody)
	formErr := r.ParseForm()
	f := r.PostForm
	if formErr == nil && isMCPToken(f) && f.Get("grant_type") == grantTokenExchange {
		s.mcpToken(w, r, f, ip) // ADR-0029: before isDelegation, which a session subject_token also matches
		return
	}
	if formErr == nil && isDelegation(f) && f.Get("grant_type") == grantTokenExchange {
		s.postDelegation(w, r, f, ip)
		return
	}
	blocked := s.exchangeFails.blocked(ip)
	bad := func(code int, kind, desc string) { // a request with no verifiable credential
		if blocked {
			tooManyFailures(w)
			return
		}
		oauthErr(w, code, kind, desc)
	}
	if len(s.cfg.WorkloadKey) == 0 {
		bad(http.StatusNotFound, "unsupported_grant_type", "workload federation is not enabled on this server (--workload-key-file)")
		return
	}
	org, _, err := s.pol.Get()
	if org == nil {
		s.cfg.Log.Error("token exchange: policy unavailable", "err", err)
		bad(http.StatusServiceUnavailable, "temporarily_unavailable", errPolicyUnavailable)
		return
	}
	if formErr != nil {
		bad(http.StatusBadRequest, "invalid_request", "body must be application/x-www-form-urlencoded under 16KB")
		return
	}
	if code, kind, desc := checkExchangeForm(f); code != 0 {
		bad(code, kind, desc)
		return
	}
	if org.Workloads == nil {
		bad(http.StatusNotFound, "unsupported_grant_type", "policy declares no workloads")
		return
	}
	if t := f.Get("subject_token_type"); t != tokenTypeJWT && t != tokenTypeIDToken {
		bad(http.StatusBadRequest, "invalid_request", "subject_token_type must be "+tokenTypeJWT+" or "+tokenTypeIDToken)
		return
	}
	s.exchange(w, r, org, f.Get("subject_token"), ip, blocked)
}

// postDelegation is the delegation branch of postTokenExchange; every
// refusal before the credential is verified answers 429 when agentFails
// blocks the IP, and the credential itself is judged in delegate.
func (s *Server) postDelegation(w http.ResponseWriter, r *http.Request, f url.Values, ip string) {
	bad := func(code int, kind, desc string) {
		if s.agentFails.blocked(ip) {
			tooManyFailures(w)
			return
		}
		oauthErr(w, code, kind, desc)
	}
	if len(s.cfg.WorkloadKey) == 0 {
		bad(http.StatusNotFound, "unsupported_grant_type", "workload federation is not enabled on this server (--workload-key-file)")
		return
	}
	org, _, err := s.pol.Get()
	if org == nil {
		s.cfg.Log.Error("token exchange: policy unavailable", "err", err)
		bad(http.StatusServiceUnavailable, "temporarily_unavailable", errPolicyUnavailable)
		return
	}
	if code, kind, desc := checkExchangeForm(f); code != 0 {
		bad(code, kind, desc)
		return
	}
	s.delegate(w, r, org, f, ip)
}

// checkExchangeForm validates the RFC 8693 parameters both exchanges share;
// code 0 = valid.
func checkExchangeForm(f url.Values) (code int, kind, desc string) {
	switch {
	case f.Get("grant_type") != grantTokenExchange:
		return http.StatusBadRequest, "unsupported_grant_type", "grant_type must be " + grantTokenExchange
	case f.Get("subject_token") == "":
		return http.StatusBadRequest, "invalid_request", "subject_token is required"
	case f.Get("requested_token_type") != "" && f.Get("requested_token_type") != tokenTypeJWT && f.Get("requested_token_type") != tokenTypeAccess:
		return http.StatusBadRequest, "invalid_request", "requested_token_type must be " + tokenTypeJWT
	case f.Get("audience") != "" && f.Get("audience") != identity.WorkloadAudience:
		return http.StatusBadRequest, "invalid_target", "audience must be " + identity.WorkloadAudience
	case f.Has("actor_token"):
		return http.StatusBadRequest, "invalid_request", "actor_token is not supported: name the agent with actor_id (ADR-0024)"
	}
	return 0, "", ""
}

// signedOnly reports whether err (from verifying a subject token) still
// proves the token was signed by a trusted key: nil, or claims rejected
// after the signature verified.
func signedOnly(err error) bool { return err == nil || errors.Is(err, identity.ErrClaimsRejected) }

func (s *Server) exchange(w http.ResponseWriter, r *http.Request, org *policy.Org, raw, ip string, blocked bool) {
	now := s.cfg.Now()
	ctx := r.Context()
	if blocked {
		ctx = identity.CacheOnly(ctx) // a blocked IP never makes halo-server call the issuer
	}
	wi, claims, err := s.verifySubjectToken(ctx, org.Workloads, raw)
	switch {
	case !signedOnly(err) && blocked:
		tooManyFailures(w)
		return
	case errors.Is(err, identity.ErrDiscovery): // the issuer is down: nothing was judged, so no penalty
		s.metrics.authFailure("token_exchange", "discovery")
		s.cfg.Log.Error("workload issuer discovery failed", "issuer", wi.URL, "err", err)
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "issuer discovery failed; retry")
		return
	case !signedOnly(err): // malformed, unknown issuer or bad signature: the only failures counted
		s.metrics.authFailure("token_exchange", "unverified")
		s.exchangeFails.fail(ip)
		// Unverified input is logged, not audited: anyone can send garbage.
		s.cfg.Log.Info("workload token rejected", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	case err != nil: // signed by the issuer, claims rejected: not counted (mintable on a shared runner)
		s.metrics.authFailure("token_exchange", "claims_rejected")
		s.cfg.Log.Info("workload token claims rejected", "issuer", wi.URL, "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	}
	ciSub, _ := policy.ClaimString(claims, "sub")
	deny := func(reason error) { // a verified token: audited (coalesced per issuer+IP), never counted against the IP
		s.metrics.authFailure("token_exchange", "denied")
		if s.wl.auditDenied(wi.URL+"\x00"+ip, now) {
			s.Audit(r.Context(), wi.Name+":"+ciSub, "workload.token.denied", "", map[string]string{"issuer": wi.URL, "reason": reason.Error()})
		} else {
			s.cfg.Log.Info("workload token denied (audit coalesced)", "issuer", wi.URL, "reason", reason.Error(), "remote", ip)
		}
		oauthErr(w, http.StatusBadRequest, "invalid_grant", reason.Error())
	}
	// Match before remembering: only a token a tenant-pinned rule accepts takes
	// a replay-cache slot, so tokens anyone can mint from a shared CI issuer
	// (any repository, any audience the job picks) cannot fill the cache.
	rule, subject, ok := org.Workloads.MatchWorkload(wi.Name, claims)
	if !ok { // unpinned rules never match; policyHolder counts them per load
		deny(errNoRule)
		return
	}
	if err := s.rememberSubjectToken(replayKey(wi.URL, claims, raw), unixClaim(claims, "exp"), now); err != nil {
		if errors.Is(err, errReplayFull) {
			s.cfg.Log.Error("workload replay cache full; refusing exchanges until entries expire")
			oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again later")
			return
		}
		deny(err)
		return
	}
	// Not born revoked: a workload subject whose epoch (ADR-0026, padded by
	// revocationSkew) is not yet behind us gets no new credential until it is.
	id := randB64(16)
	if err := s.checkRevoked(r.Context(), policy.Subject{ID: subject, Kind: policy.SubjectWorkload,
		Credential: &policy.CredentialRef{IDs: []string{id}, IssuedAt: now.Unix()}}); errors.Is(err, errRevocationsUnavailable) {
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "revocations cannot be checked; retry")
		return
	} else if err != nil {
		deny(fmt.Errorf("%w; a new credential can be issued once the revocation epoch has passed", err))
		return
	}
	ttl := rule.TTL()
	exp := now.Add(ttl)
	tok, err := identity.SignWorkloadToken(s.cfg.WorkloadKey, identity.WorkloadClaims{
		Issuer: identity.WorkloadIssuer, Subject: subject, Audience: identity.WorkloadAudience, Groups: rule.Groups,
		Kind: policy.SubjectWorkload, Rule: rule.Name, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: id,
	})
	if err != nil {
		s.cfg.Log.Error("sign workload token", "rule", rule.Name, "err", err)
		oauthErr(w, http.StatusInternalServerError, "server_error", "could not mint credential")
		return
	}
	ring := ""
	if rg := org.ResolveRing(policy.Subject{ID: subject, Groups: rule.Groups, Kind: policy.SubjectWorkload}); rg != nil {
		ring = rg.Name
	}
	details := map[string]string{"issuer": wi.URL, "rule": rule.Name, "ciSubject": ciSub, "ring": ring,
		"ttl": ttl.String(), "expires": exp.UTC().Format(time.RFC3339), "groups": strings.Join(rule.Groups, ",")}
	if jti, ok := policy.ClaimString(claims, "jti"); ok {
		details["jti"] = jti
	}
	for k := range rule.Match { // the claims the decision rested on; never the token
		details["claim."+k], _ = policy.ClaimString(claims, k)
	}
	if err := s.AuditStrict(r.Context(), subject, "workload.token.exchange", rule.Name, details); err != nil {
		oauthErr(w, http.StatusInternalServerError, "server_error", errAuditFailed)
		return
	}
	resp := TokenExchangeResponse{AccessToken: tok, IssuedTokenType: tokenTypeJWT, TokenType: "Bearer", ExpiresIn: int(ttl.Seconds()),
		Subject: subject, Groups: rule.Groups, Rule: rule.Name, Ring: ring}
	if org.Gateway != nil {
		resp.GatewayURL = org.Gateway.BaseURL
	}
	writeJSON(w, http.StatusOK, resp)
}

// verifySubjectToken picks the trusted issuer by the token's (unverified) iss,
// then verifies it fully against that issuer: discovery + JWKS signature with
// the alg allowlist (no none, no HS*), iss, aud, exp, nbf; then iat. A failure
// after the signature verified wraps identity.ErrClaimsRejected. Under
// identity.CacheOnly(ctx) nothing is fetched from the issuer.
func (s *Server) verifySubjectToken(ctx context.Context, wl *policy.Workloads, raw string) (policy.WorkloadIssuer, map[string]any, error) {
	iss, err := unverifiedIssuer(raw)
	if err != nil {
		return policy.WorkloadIssuer{}, nil, err
	}
	wi, ok := wl.IssuerByURL(iss)
	if !ok {
		return policy.WorkloadIssuer{}, nil, fmt.Errorf("issuer %q is not a workloads issuer", iss)
	}
	v, err := s.wl.verifier(wi.URL, wl.AudienceFor(wi))
	if err != nil {
		return wi, nil, err
	}
	claims, err := v.Claims(ctx, raw)
	if err != nil {
		return wi, nil, err
	}
	iat := unixClaim(claims, "iat")
	if iat.IsZero() || iat.After(s.cfg.Now().Add(exchangeIatSkew)) {
		return wi, nil, fmt.Errorf("%w: iat missing or in the future", identity.ErrClaimsRejected)
	}
	return wi, claims, nil
}

func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("subject_token is not a compact JWT")
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("subject_token payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(b, &c); err != nil || c.Iss == "" {
		return "", errors.New("subject_token has no iss")
	}
	return c.Iss, nil
}

// kvWorkloadJTI is the shared replay cache's namespace (HA backend).
const kvWorkloadJTI = "workload-jti"

// rememberSubjectToken records a subject token as exchanged until it expires.
// With a shared Backend the record is one row keyed by the hashed replay key
// (insert unless a live row exists), so a token is exchanged once across every
// replica; a store error refuses the exchange (errReplayFull: 503, retry).
func (s *Server) rememberSubjectToken(key string, exp, now time.Time) error {
	if s.cfg.Backend == nil {
		return s.wl.remember(key, exp, now)
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	h := sha256.Sum256([]byte(key)) // the key holds NUL separators; the column is text
	// Kept exchangeIatSkew past exp: the row expires on the database clock, the
	// token's exp is the issuer's, and a replica's verifier accepts the token
	// until its own clock passes exp. The skew bound keeps the row alive for as
	// long as any replica could still accept the token.
	added, err := s.kv.Add(ctx, kvWorkloadJTI, hex.EncodeToString(h[:]), nil, exp.Add(exchangeIatSkew))
	switch {
	case err != nil:
		s.cfg.Log.Error("workload replay cache", "err", err)
		return errReplayFull
	case !added:
		return errReplayed
	}
	return nil
}

// replayKey is iss+jti, or the token's hash for issuers that omit jti: either
// way a token is exchanged at most once while it is valid.
func replayKey(iss string, claims map[string]any, raw string) string {
	if jti, ok := claims["jti"].(string); ok && jti != "" {
		return "jti\x00" + iss + "\x00" + jti
	}
	sum := sha256.Sum256([]byte(raw))
	return "tok\x00" + hex.EncodeToString(sum[:])
}

func unixClaim(claims map[string]any, name string) time.Time {
	switch v := claims[name].(type) {
	case float64:
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}
