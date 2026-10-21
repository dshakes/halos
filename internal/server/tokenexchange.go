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
	"strings"
	"sync"
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
	Rule            string   `json:"rule"`
	Ring            string   `json:"ring,omitempty"`
	GatewayURL      string   `json:"gateway_url,omitempty"`
}

// oauthErr is the RFC 6749 section 5.2 error shape token endpoints answer.
func oauthErr(w http.ResponseWriter, code int, kind, desc string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": desc})
}

func (s *Server) postTokenExchange(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.authFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		oauthErr(w, http.StatusTooManyRequests, "slow_down", "too many failed attempts")
		return
	}
	if len(s.cfg.WorkloadKey) == 0 {
		oauthErr(w, http.StatusNotFound, "unsupported_grant_type", "workload federation is not enabled on this server (--workload-key-file)")
		return
	}
	org, _, err := s.pol.Get()
	if org == nil {
		msg := "policy not loaded"
		if err != nil {
			msg += ": " + err.Error()
		}
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", msg)
		return
	}
	if org.Workloads == nil {
		oauthErr(w, http.StatusNotFound, "unsupported_grant_type", "policy declares no workloads")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxExchangeBody)
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request", "body must be application/x-www-form-urlencoded under 16KB")
		return
	}
	f := r.PostForm
	switch {
	case f.Get("grant_type") != grantTokenExchange:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be "+grantTokenExchange)
		return
	case f.Get("subject_token") == "":
		oauthErr(w, http.StatusBadRequest, "invalid_request", "subject_token is required")
		return
	case f.Get("subject_token_type") != tokenTypeJWT && f.Get("subject_token_type") != tokenTypeIDToken:
		oauthErr(w, http.StatusBadRequest, "invalid_request", "subject_token_type must be "+tokenTypeJWT+" or "+tokenTypeIDToken)
		return
	case f.Get("requested_token_type") != "" && f.Get("requested_token_type") != tokenTypeJWT && f.Get("requested_token_type") != tokenTypeAccess:
		oauthErr(w, http.StatusBadRequest, "invalid_request", "requested_token_type must be "+tokenTypeJWT)
		return
	case f.Get("audience") != "" && f.Get("audience") != identity.WorkloadAudience:
		oauthErr(w, http.StatusBadRequest, "invalid_target", "audience must be "+identity.WorkloadAudience)
		return
	case f.Has("actor_token"):
		oauthErr(w, http.StatusBadRequest, "invalid_request", "delegation (actor_token) is not supported")
		return
	}
	s.exchange(w, r, org, f.Get("subject_token"), ip)
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request, org *policy.Org, raw, ip string) {
	now := s.cfg.Now()
	wi, claims, err := s.verifySubjectToken(r.Context(), org.Workloads, raw)
	if errors.Is(err, identity.ErrDiscovery) { // the issuer is down: nothing was judged, so no penalty
		s.cfg.Log.Error("workload issuer discovery failed", "issuer", wi.URL, "err", err)
		oauthErr(w, http.StatusServiceUnavailable, "temporarily_unavailable", "issuer discovery failed; retry")
		return
	}
	if err != nil {
		s.authFails.fail(ip)
		// Unverified input is logged, not audited: anyone can send garbage.
		s.cfg.Log.Info("workload token rejected", "err", err.Error(), "remote", ip)
		oauthErr(w, http.StatusBadRequest, "invalid_grant", "subject_token rejected")
		return
	}
	ciSub, _ := policy.ClaimString(claims, "sub")
	deny := func(reason error) {
		s.authFails.fail(ip)
		s.Audit(r.Context(), wi.Name+":"+ciSub, "workload.token.denied", "", map[string]string{"issuer": wi.URL, "reason": reason.Error()})
		oauthErr(w, http.StatusBadRequest, "invalid_grant", reason.Error())
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
	rule, subject, ok := org.Workloads.MatchWorkload(wi.Name, claims)
	if !ok {
		deny(errNoRule)
		return
	}
	ttl := rule.TTL()
	exp := now.Add(ttl)
	tok, err := identity.SignWorkloadToken(s.cfg.WorkloadKey, identity.WorkloadClaims{
		Issuer: identity.WorkloadIssuer, Subject: subject, Audience: identity.WorkloadAudience, Groups: rule.Groups,
		Kind: policy.SubjectWorkload, Rule: rule.Name, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: exp.Unix(), ID: randB64(16),
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
// the alg allowlist (no none, no HS*), iss, aud, exp, nbf; then iat.
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
		return wi, nil, errors.New("iat missing or in the future")
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
	added, err := s.kv.Add(ctx, kvWorkloadJTI, hex.EncodeToString(h[:]), nil, exp)
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
