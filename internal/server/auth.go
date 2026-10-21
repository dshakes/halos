package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

const (
	sessionCookie = "halo_session"
	oidcCookie    = "halo_oidc"
	sessionTTL    = 12 * time.Hour
)

// Principal is the authenticated portal user. Roles are recomputed from current
// policy on every request, never trusted from the cookie.
type Principal struct {
	ID     string   `json:"id"`
	Groups []string `json:"groups"`
	Roles  []string `json:"roles"`
	Admin  bool     `json:"admin"` // holds RoleAdmin; kept for API clients that predate roles
}

func newPrincipal(id string, groups, roles []string) Principal {
	if roles == nil {
		roles = []string{}
	}
	return Principal{ID: id, Groups: groups, Roles: roles, Admin: slices.Contains(roles, RoleAdmin)}
}

func (p Principal) subject() policy.Subject { return policy.Subject{ID: p.ID, Groups: p.Groups} }

// ---- signed cookies (HMAC-SHA256, stateless) ----

type cookiePayload struct {
	Sub    string   `json:"s,omitempty"`
	Groups []string `json:"g,omitempty"`
	State  string   `json:"st,omitempty"`
	Nonce  string   `json:"n,omitempty"`
	PKCE   string   `json:"v,omitempty"`
	SID    string   `json:"i,omitempty"` // server-side session id (groups too large for a cookie)
	Iat    int64    `json:"t,omitempty"` // session issue time (unix nanos), checked against revocations
	Exp    int64    `json:"e"`
}

// maxCookie bounds a sealed session cookie; browsers drop cookies over ~4KB.
const maxCookie = 3500

func (s *Server) seal(p cookiePayload) string {
	b, _ := json.Marshal(p) // plain struct: cannot fail
	body := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.cfg.SessionKey)
	m.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) unseal(v string) (cookiePayload, error) {
	var p cookiePayload
	body, sig, ok := strings.Cut(v, ".")
	if !ok {
		return p, errors.New("malformed cookie")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return p, errors.New("malformed cookie")
	}
	m := hmac.New(sha256.New, s.cfg.SessionKey)
	m.Write([]byte(body))
	if !hmac.Equal(got, m.Sum(nil)) {
		return p, errors.New("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || json.Unmarshal(raw, &p) != nil {
		return p, errors.New("malformed cookie")
	}
	if s.cfg.Now().Unix() > p.Exp {
		return p, errors.New("expired")
	}
	return p, nil
}

func (s *Server) setCookie(w http.ResponseWriter, name, val, path string, ttl time.Duration) {
	//nolint:gosec // Secure follows the portal base URL scheme (http in local dev)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: val, Path: path, MaxAge: int(ttl.Seconds()),
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(s.cfg.Portal.BaseURL, "https://"),
	})
}

// ---- principal resolution and role gates ----

func (s *Server) roles(groups []string) []string {
	org, _, _ := s.pol.Get()
	if org == nil {
		return nil
	}
	return rolesFor(org.Identity, groups)
}

func (s *Server) principal(r *http.Request) (Principal, bool) {
	if s.cfg.DevUser != "" { // --dev-insecure-user: no authentication at all
		return newPrincipal(s.cfg.DevUser, s.cfg.DevGroups, s.cfg.DevRoles), true
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return Principal{}, false
	}
	p, err := s.unseal(c.Value)
	if err != nil || p.Sub == "" || !s.revoked.valid(p.Sub, p.Iat) {
		return Principal{}, false
	}
	if p.SID != "" {
		g, ok := s.oidc.session(p.SID)
		if !ok {
			return Principal{}, false
		}
		p.Groups = g
	}
	g, ok := s.directoryGroups(p.Sub, p.Groups) // SCIM: deactivated users are out; authoritative groups win
	if !ok {
		return Principal{}, false
	}
	// Roles are recomputed from current policy and directory groups rather than trusted from the cookie.
	return newPrincipal(p.Sub, g, s.roles(g)), true
}

type authedHandler func(http.ResponseWriter, *http.Request, Principal)

// sameOrigin rejects cross-origin state-changing requests (defence in depth on
// top of SameSite=Lax): by Fetch Metadata, which a page cannot set, then by Origin.
func sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" || sfs == "same-site" {
		return false
	}
	o := r.Header.Get("Origin")
	if o == "" {
		return true // non-browser client
	}
	u, err := url.Parse(o)
	return err == nil && u.Host == r.Host
}

func (s *Server) user(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.principal(r)
		if !ok {
			apiErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && !sameOrigin(r) {
			apiErr(w, http.StatusForbidden, "cross-origin request rejected")
			return
		}
		next(w, r, p)
	}
}

// ---- OIDC (authorization code + PKCE) ----

type oidcState struct {
	mu       sync.Mutex
	key      string
	provider *oidc.Provider

	// Consumed login states and server-side sessions. In process by default
	// (lost on restart: users log in again); shared across replicas in HA.
	kv storage.KV
}

const (
	kvLoginState = "oidc-state"
	kvSession    = "oidc-session"
)

// consume marks a login state used until exp; false if it already was (or
// the store cannot say: a login is retried, a replayed state is not let in).
func (o *oidcState) consume(state string, exp time.Time) bool {
	ctx, cancel := storage.Ctx()
	defer cancel()
	h := sha256.Sum256([]byte(state))
	ok, err := o.kv.Add(ctx, kvLoginState, hex.EncodeToString(h[:]), nil, exp)
	return err == nil && ok
}

// newSession stores groups server-side and returns the session id.
func (o *oidcState) newSession(groups []string, exp time.Time) (string, error) {
	b, err := json.Marshal(groups)
	if err != nil {
		return "", err
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	id := randB64(24)
	if err := o.kv.Put(ctx, kvSession, id, b, exp); err != nil {
		return "", err
	}
	return id, nil
}

// session returns a live session's groups; a store error is no session.
func (o *oidcState) session(id string) ([]string, bool) {
	ctx, cancel := storage.Ctx()
	defer cancel()
	b, ok, err := o.kv.Get(ctx, kvSession, id)
	var groups []string
	if err != nil || !ok || json.Unmarshal(b, &groups) != nil {
		return nil, false
	}
	return groups, true
}

// policyGroups keeps only the groups current policy refers to (role groups,
// ring membership groups and toggle rule groups: enrolled devices target
// toggles with the groups recorded here); IdPs often send hundreds, which would
// overflow the cookie. A group newly referenced by policy applies at the next login.
func policyGroups(org *policy.Org, groups []string) []string {
	if org == nil {
		return nil
	}
	var out []string
	for _, g := range groups {
		keep := slices.Contains(roleGroups(org.Identity), g) ||
			slices.ContainsFunc(org.Rings, func(r *policy.Ring) bool { return slices.Contains(r.Membership.Groups, g) }) ||
			slices.ContainsFunc(org.Toggles, func(t *policy.Toggle) bool {
				return slices.ContainsFunc(t.Rules, func(r policy.ToggleRule) bool { return slices.Contains(r.Groups, g) })
			})
		if keep && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) oidcConfig(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, policy.Identity, error) {
	org, _, err := s.pol.Get()
	if org == nil {
		return nil, nil, policy.Identity{}, fmt.Errorf("policy not loaded: %w", err)
	}
	id := org.Identity
	if id.Issuer == "" || id.ClientID == "" {
		return nil, nil, id, errors.New("identity.issuer/clientID not configured in policy")
	}
	if s.cfg.Portal.BaseURL == "" {
		return nil, nil, id, errors.New("portal baseURL not configured")
	}
	s.oidc.mu.Lock()
	defer s.oidc.mu.Unlock()
	if s.oidc.provider == nil || s.oidc.key != id.Issuer {
		p, err := oidc.NewProvider(ctx, id.Issuer)
		if err != nil {
			return nil, nil, id, fmt.Errorf("oidc discovery: %w", err)
		}
		s.oidc.provider, s.oidc.key = p, id.Issuer
	}
	oc := &oauth2.Config{
		ClientID: id.ClientID, ClientSecret: s.cfg.OIDCClientSecret, Endpoint: s.oidc.provider.Endpoint(),
		RedirectURL: strings.TrimRight(s.cfg.Portal.BaseURL, "/") + "/auth/callback",
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return oc, s.oidc.provider.Verifier(&oidc.Config{ClientID: id.ClientID}), id, nil
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	oc, _, _, err := s.oidcConfig(r.Context())
	if err != nil {
		s.cfg.Log.Error("login unavailable", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "login unavailable: "+err.Error())
		return
	}
	st, nonce, verifier := randB64(16), randB64(16), oauth2.GenerateVerifier()
	s.setCookie(w, oidcCookie, s.seal(cookiePayload{State: st, Nonce: nonce, PKCE: verifier, Exp: s.cfg.Now().Add(10 * time.Minute).Unix()}), "/auth", 10*time.Minute)
	http.Redirect(w, r, oc.AuthCodeURL(st, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), http.StatusFound)
}

// principalFromClaims extracts identity per the org's userClaim/groupsClaim
// (defaults email/groups) via identity.SubjectFromClaims, which also refuses an
// unverified email (attacker-chosen at many IdPs).
func principalFromClaims(claims map[string]any, id policy.Identity) (Principal, error) {
	sub, err := identity.SubjectFromClaims(claims, identity.Options{UserClaim: id.UserClaim, GroupsClaim: id.GroupsClaim})
	if err != nil {
		return Principal{}, err
	}
	return newPrincipal(sub.ID, sub.Groups, rolesFor(id, sub.Groups)), nil
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	// Failed callbacks are rate limited per IP on their own budget (an office
	// NAT retrying logins must not lock its devices out): each one can cost a
	// token exchange with the IdP and a consumed-state entry held until expiry.
	ip := s.clientIP(r)
	if s.loginFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed logins")
		return
	}
	fail := func(code int, msg string, err error) {
		s.loginFails.fail(ip)
		s.cfg.Log.Warn("oidc callback failed", "msg", msg, "err", err)
		apiErr(w, code, msg)
	}
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		fail(http.StatusBadRequest, "missing login state", err)
		return
	}
	st, err := s.unseal(c.Value)
	if err != nil || st.State == "" {
		fail(http.StatusBadRequest, "invalid login state", err)
		return
	}
	s.setCookie(w, oidcCookie, "", "/auth", -time.Second) // state is single-use
	if !s.oidc.consume(st.State, time.Unix(st.Exp, 0)) {
		fail(http.StatusBadRequest, "login state already used", nil)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(st.State)) != 1 {
		fail(http.StatusBadRequest, "state mismatch", nil)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail(http.StatusUnauthorized, "identity provider error: "+e, nil)
		return
	}
	oc, verifier, id, err := s.oidcConfig(r.Context())
	if err != nil {
		fail(http.StatusServiceUnavailable, "login unavailable", err)
		return
	}
	tok, err := oc.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(st.PKCE))
	if err != nil {
		fail(http.StatusUnauthorized, "code exchange failed", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(r.Context(), raw)
	if err != nil {
		fail(http.StatusUnauthorized, "id token invalid", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		fail(http.StatusUnauthorized, "nonce mismatch", nil)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail(http.StatusUnauthorized, "claims unreadable", err)
		return
	}
	p, err := principalFromClaims(claims, id)
	if err != nil {
		fail(http.StatusForbidden, err.Error(), err)
		return
	}
	g, provisioned := s.directoryGroups(p.ID, p.Groups)
	if !provisioned {
		fail(http.StatusForbidden, "user is deactivated or not provisioned", nil)
		return
	}
	// Directory groups may differ from the token's: roles follow the groups in force.
	p = newPrincipal(p.ID, g, rolesFor(id, g))
	org, _, _ := s.pol.Get()
	exp := s.cfg.Now().Add(sessionTTL)
	sess := cookiePayload{Sub: p.ID, Groups: policyGroups(org, p.Groups), Exp: exp.Unix(), Iat: s.cfg.Now().UnixNano()}
	if v := s.seal(sess); len(v) > maxCookie {
		sid, err := s.oidc.newSession(sess.Groups, exp)
		if err != nil {
			s.cfg.Log.Error("store session", "user", p.ID, "err", err)
			apiErr(w, http.StatusServiceUnavailable, "login unavailable")
			return
		}
		sess.SID, sess.Groups = sid, nil
	}
	s.setCookie(w, sessionCookie, s.seal(sess), "/", sessionTTL)
	s.cfg.Log.Info("login", "user", p.ID, "roles", p.Roles)
	s.Audit(r.Context(), p.ID, "login", "", map[string]string{"admin": strconv.FormatBool(p.Admin), "roles": strings.Join(p.Roles, ",")})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		apiErr(w, http.StatusForbidden, "cross-origin request rejected")
		return
	}
	// Logout ends every session of the user (session epoch), not just this cookie.
	if c, err := r.Cookie(sessionCookie); err == nil {
		if p, err := s.unseal(c.Value); err == nil && p.Sub != "" && s.revoked.valid(p.Sub, p.Iat) {
			if err := s.revoked.revoke(p.Sub, s.cfg.Now()); err != nil {
				s.cfg.Log.Error("persist session revocation", "user", p.Sub, "err", err)
				apiErr(w, http.StatusInternalServerError, "logout failed")
				return
			}
			s.Audit(r.Context(), p.Sub, "logout", "", nil)
			if p.SID != "" {
				ctx, cancel := storage.Ctx()
				if err := s.oidc.kv.Delete(ctx, kvSession, p.SID); err != nil {
					s.cfg.Log.Warn("delete session", "err", err) // the epoch bump already ended it
				}
				cancel()
			}
		}
	}
	s.setCookie(w, sessionCookie, "", "/", -time.Second)
	w.WriteHeader(http.StatusNoContent)
}
