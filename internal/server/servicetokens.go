package server

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Service-account API tokens (ADR-0036): long-lived bearer credentials for
// automation (CI, the MCP server, scripts) bound to one RBAC role, so nobody
// copies a human's console cookie into a pipeline.
//
// A token is ServiceTokenPrefix + a 16-hex-digit public id + 64 hex digits of
// secret (256 random bits). Only its SHA-256 is stored; the id finds the row
// and the hash is compared in constant time. Every token expires.

const (
	// ServiceTokenPrefix starts every token, so secret scanners can match it:
	// halo_sat_[0-9a-f]{80}.
	ServiceTokenPrefix = "halo_sat_"
	// DefaultServiceTokenMaxTTL is the longest lifetime, and the default, when
	// Config.ServiceTokenMaxTTL is 0.
	DefaultServiceTokenMaxTTL = 90 * 24 * time.Hour
	// MaxServiceTokenMaxTTL bounds Config.ServiceTokenMaxTTL.
	MaxServiceTokenMaxTTL = 365 * 24 * time.Hour
	minServiceTokenTTL    = time.Hour

	serviceTokenIDLen     = 16 // hex digits
	serviceTokenSecretLen = 64 // hex digits: 256 bits
	// ServiceAccountPrefix starts a service account's principal id (and audit actor).
	ServiceAccountPrefix = "service-account:"
	serviceTokenLogName  = "service-tokens"
	maxServiceTokenText  = 256
	// serviceTokenUseEvery: a token's use is audited at most this often per replica.
	serviceTokenUseEvery = time.Hour
)

// maxActiveServiceTokens caps live tokens (a var so tests can lower it).
var maxActiveServiceTokens = 1000

// Principal kinds; empty is a human console session.
const (
	KindServiceAccount = "service-account"
	KindBreakGlass     = "break-glass"
)

// serviceTokenStore is where tokens live: the Backend (shared across
// replicas), or serviceTokenLog on a single replica.
type serviceTokenStore interface {
	// PutServiceToken inserts a new token unless maxActive tokens (not
	// revoked, expiring after now) exist (pgstore.ErrServiceTokenLimit); the
	// check and the insert are atomic. An existing id is an error.
	PutServiceToken(ctx context.Context, t pgstore.ServiceToken, maxActive int, now time.Time) error
	// RevokeServiceToken marks id revoked (the first revocation's record stands).
	RevokeServiceToken(ctx context.Context, id string, record []byte) (pgstore.ServiceToken, bool, error)
	// ServiceToken is the row with id.
	ServiceToken(ctx context.Context, id string) (pgstore.ServiceToken, bool, error)
	// ServiceTokens lists every row.
	ServiceTokens(ctx context.Context) ([]pgstore.ServiceToken, error)
}

// serviceTokenLog is the single-replica serviceTokenStore: in memory, and a
// JSONL log under DataDir (none without one) replayed on start.
type serviceTokenLog struct {
	mu  sync.Mutex
	m   map[string]pgstore.ServiceToken
	log storage.Log
}

func openServiceTokenLog(o storage.Opener) (*serviceTokenLog, error) {
	l := &serviceTokenLog{m: map[string]pgstore.ServiceToken{}}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, serviceTokenLogName, func(line []byte) {
		var t pgstore.ServiceToken
		if json.Unmarshal(line, &t) == nil && t.ID != "" { // torn line: skip
			l.merge(t)
		}
	})
	if err != nil {
		return nil, err
	}
	l.log = log
	return l, nil
}

func (l *serviceTokenLog) close() error { return storage.CloseLog(&l.mu, l.log) }

// merge applies t; a revocation is never undone (caller holds mu, or replays).
func (l *serviceTokenLog) merge(t pgstore.ServiceToken) {
	if cur, ok := l.m[t.ID]; ok && cur.Revoked {
		return
	}
	l.m[t.ID] = t
}

func (l *serviceTokenLog) append(ctx context.Context, t pgstore.ServiceToken) error {
	if l.log == nil {
		return nil
	}
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("encode service token: %w", err)
	}
	return l.log.Append(ctx, "", b)
}

func (l *serviceTokenLog) PutServiceToken(ctx context.Context, t pgstore.ServiceToken, maxActive int, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, dup := l.m[t.ID]; dup {
		return fmt.Errorf("service token id %s already exists", t.ID)
	}
	n := 0
	for _, x := range l.m {
		if !x.Revoked && now.Before(x.Expires) {
			n++
		}
	}
	if n >= maxActive {
		return pgstore.ErrServiceTokenLimit
	}
	if err := l.append(ctx, t); err != nil {
		return err
	}
	l.merge(t)
	return nil
}

func (l *serviceTokenLog) RevokeServiceToken(ctx context.Context, id string, record []byte) (pgstore.ServiceToken, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.m[id]
	if !ok || t.Revoked {
		return t, ok, nil
	}
	t.Revoked, t.Record = true, record
	if err := l.append(ctx, t); err != nil {
		return pgstore.ServiceToken{}, false, err
	}
	l.m[id] = t
	return t, true, nil
}

func (l *serviceTokenLog) ServiceToken(_ context.Context, id string) (pgstore.ServiceToken, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.m[id]
	return t, ok, nil
}

func (l *serviceTokenLog) ServiceTokens(context.Context) ([]pgstore.ServiceToken, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]pgstore.ServiceToken, 0, len(l.m))
	for _, t := range l.m {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b pgstore.ServiceToken) int {
		if c := a.Expires.Compare(b.Expires); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// serviceTokenRecord is pgstore.ServiceToken.Record.
type serviceTokenRecord struct {
	Name string `json:"name"`
	// Role is a global token's role. A scoped token (ADR-0037) leaves it
	// empty and holds ScopedRole over Scope instead: a binary from before
	// ADR-0037 ignores Scope, so it must find no role it knows and refuse
	// the token rather than treat it as global (mixed-version rollout).
	Role       string           `json:"role"`
	ScopedRole string           `json:"scopedRole,omitempty"`
	Scope      policy.RoleScope `json:"scope,omitzero"`
	// CreatorScope is the scope of the creator's admin grant that allowed
	// Scope (ADR-0037). Both are names, resolved against current policy on
	// every use: a token whose scope a later policy puts outside it (a unit
	// moved to another parent) is refused. Absent = global.
	CreatorScope policy.RoleScope `json:"creatorScope,omitzero"`
	Description  string           `json:"description,omitempty"`
	Owner        string           `json:"owner,omitempty"`
	CreatedBy    string           `json:"createdBy"`
	CreatedAt    time.Time        `json:"createdAt"`
	RevokedBy    string           `json:"revokedBy,omitempty"`
	RevokedAt    *time.Time       `json:"revokedAt,omitempty"`
	RevokeReason string           `json:"revokeReason,omitempty"`
}

// CreateServiceTokenRequest is POST /api/v1/service-tokens. TTL is a Go
// duration (e.g. 720h); empty = the server's maximum. Scope (ADR-0037),
// {"rings": [...], "units": [...]}, bounds the role; absent is global. It is
// decoded strictly: a misspelt key is a 400, never a silently global token.
type CreateServiceTokenRequest struct {
	Name        string          `json:"name"`
	Role        string          `json:"role"`
	Scope       json.RawMessage `json:"scope,omitempty"`
	Description string          `json:"description,omitempty"`
	Owner       string          `json:"owner,omitempty"`
	TTL         string          `json:"ttl,omitempty"`
}

// ServiceTokenInfo is one token as the API shows it (never the secret or its hash).
type ServiceTokenInfo struct {
	ID           string           `json:"id"`
	Principal    string           `json:"principal"` // the audit actor its requests carry
	Name         string           `json:"name"`
	Role         string           `json:"role"`
	Scope        policy.RoleScope `json:"scope"` // {} = global (ADR-0037)
	Description  string           `json:"description,omitempty"`
	Owner        string           `json:"owner,omitempty"`
	CreatedBy    string           `json:"createdBy"`
	CreatedAt    time.Time        `json:"createdAt"`
	ExpiresAt    time.Time        `json:"expiresAt"`
	Expired      bool             `json:"expired"`
	Revoked      bool             `json:"revoked"`
	RevokedBy    string           `json:"revokedBy,omitempty"`
	RevokedAt    *time.Time       `json:"revokedAt,omitempty"`
	RevokeReason string           `json:"revokeReason,omitempty"`
}

// CreateServiceTokenResponse carries the token: shown once, never again.
type CreateServiceTokenResponse struct {
	Token        string           `json:"token"`
	ServiceToken ServiceTokenInfo `json:"serviceToken"`
}

// ServiceTokensResponse is GET /api/v1/service-tokens.
type ServiceTokensResponse struct {
	Tokens []ServiceTokenInfo `json:"tokens"`
}

// RevokeServiceTokenRequest is POST /api/v1/service-tokens/{id}/revoke.
type RevokeServiceTokenRequest struct {
	Reason string `json:"reason"`
}

func serviceAccountID(name, id string) string { return ServiceAccountPrefix + name + ":" + id }

// role is the record's role, and ok when the record is well formed: a known
// role, either global (Role) or scoped (ScopedRole with a non-empty Scope),
// never both. A malformed record grants nothing.
func (rec serviceTokenRecord) role() (string, bool) {
	switch {
	case rec.Role != "" && rec.ScopedRole == "" && rec.Scope.Global():
		return rec.Role, validRoles([]string{rec.Role}) == nil
	case rec.Role == "" && rec.ScopedRole != "" && !rec.Scope.Global():
		return rec.ScopedRole, validRoles([]string{rec.ScopedRole}) == nil
	}
	return "", false
}

// newTokenRecord sets role over scope the way role() reads it back.
func newTokenRecord(role string, scope policy.RoleScope) serviceTokenRecord {
	if scope.Global() {
		return serviceTokenRecord{Role: role}
	}
	return serviceTokenRecord{ScopedRole: role, Scope: scope}
}

func serviceTokenInfo(t pgstore.ServiceToken, now time.Time) ServiceTokenInfo {
	var rec serviceTokenRecord
	_ = json.Unmarshal(t.Record, &rec) // written by this package; garbage shows as empty fields
	return ServiceTokenInfo{
		ID: t.ID, Principal: serviceAccountID(rec.Name, t.ID), Name: rec.Name, Role: cmp.Or(rec.Role, rec.ScopedRole), Scope: rec.Scope, Description: rec.Description, Owner: rec.Owner,
		CreatedBy: rec.CreatedBy, CreatedAt: rec.CreatedAt.UTC(), ExpiresAt: t.Expires.UTC(), Expired: !now.Before(t.Expires), Revoked: t.Revoked,
		RevokedBy: rec.RevokedBy, RevokedAt: rec.RevokedAt, RevokeReason: rec.RevokeReason,
	}
}

// newServiceToken returns a fresh token and its public id.
func newServiceToken() (tok, id string, err error) {
	b := make([]byte, (serviceTokenIDLen+serviceTokenSecretLen)/2)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("service token: %w", err)
	}
	h := hex.EncodeToString(b)
	return ServiceTokenPrefix + h, h[:serviceTokenIDLen], nil
}

// parseServiceToken returns tok's public id, or false when tok is not
// shaped like a service token.
func parseServiceToken(tok string) (string, bool) {
	body, ok := strings.CutPrefix(tok, ServiceTokenPrefix)
	if !ok || len(body) != serviceTokenIDLen+serviceTokenSecretLen || strings.Trim(body, "0123456789abcdef") != "" {
		return "", false
	}
	return body[:serviceTokenIDLen], true
}

func hashServiceToken(tok string) []byte {
	s := sha256.Sum256([]byte(tok))
	return s[:]
}

var (
	errNoServiceToken      = errors.New("invalid service token")
	errServiceTokenExpired = errors.New("service token expired")
)

// lookupServiceToken authenticates tok: unknown, malformed, hash-mismatched
// and revoked tokens are errNoServiceToken; a store error wraps
// storage.ErrUnavailable.
func (s *Server) lookupServiceToken(ctx context.Context, tok string) (pgstore.ServiceToken, serviceTokenRecord, error) {
	id, ok := parseServiceToken(tok)
	if !ok {
		return pgstore.ServiceToken{}, serviceTokenRecord{}, errNoServiceToken
	}
	ctx, cancel := context.WithTimeout(ctx, storage.OpTimeout)
	defer cancel()
	t, found, err := s.tokens.ServiceToken(ctx, id)
	if err != nil {
		return t, serviceTokenRecord{}, fmt.Errorf("%w: %w", storage.ErrUnavailable, err)
	}
	// The id is public (it only finds the row); the secret is checked by
	// comparing whole-token hashes in constant time.
	if !found || subtle.ConstantTimeCompare(t.Hash, hashServiceToken(tok)) != 1 || t.Revoked {
		return t, serviceTokenRecord{}, errNoServiceToken
	}
	var rec serviceTokenRecord
	if json.Unmarshal(t.Record, &rec) != nil || rec.Name == "" {
		return t, rec, errNoServiceToken // unreadable record: grant nothing
	}
	if _, ok := rec.role(); !ok {
		return t, rec, errNoServiceToken
	}
	if !s.cfg.Now().Before(t.Expires) {
		return t, rec, errServiceTokenExpired
	}
	return t, rec, nil
}

// serviceTokenFrom returns the request's service token: an Authorization
// Bearer value with ServiceTokenPrefix. Any other Authorization header is
// not ours (a fronting proxy's, say) and falls through to the cookie.
func serviceTokenFrom(r *http.Request) (string, bool) {
	t := bearer(r)
	return t, strings.HasPrefix(t, ServiceTokenPrefix)
}

// serviceTokenAuth authenticates a service token, writing the 401/429/503
// itself on failure. Failed attempts are charged to the client address on
// their own budget (tokenFails); an expired token is not a guess and is not
// charged. A token's use is audited (service-token.use) at most once per
// serviceTokenUseEvery per replica; every action it takes is audited under
// its principal id like any other.
func (s *Server) serviceTokenAuth(w http.ResponseWriter, r *http.Request, tok string) (Principal, bool) {
	ip := s.clientIP(r)
	if s.tokenFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return Principal{}, false
	}
	t, rec, err := s.lookupServiceToken(r.Context(), tok)
	switch {
	case errors.Is(err, storage.ErrUnavailable): // not the client's fault: no penalty, never a pass
		s.metrics.authFailure("service_token", "unavailable")
		s.cfg.Log.Error("service token lookup", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return Principal{}, false
	case errors.Is(err, errServiceTokenExpired):
		s.metrics.authFailure("service_token", "expired")
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="token expired"`)
		apiErr(w, http.StatusUnauthorized, err.Error())
		return Principal{}, false
	case err != nil:
		s.metrics.authFailure("service_token", "invalid")
		s.tokenFails.fail(ip)
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		apiErr(w, http.StatusUnauthorized, "invalid service token")
		return Principal{}, false
	}
	role, _ := rec.role() // checked by lookupServiceToken
	if !rec.Scope.Global() {
		org, _, _ := s.pol.Get()
		if org == nil || !org.ScopeWithin(rec.Scope, rec.CreatorScope) {
			s.metrics.authFailure("service_token", "scope")
			s.Audit(r.Context(), serviceAccountID(rec.Name, t.ID), "authz.deny", r.URL.Path, map[string]string{
				"method": r.Method, "need": "token scope within its creator's grant", "scope": rec.Scope.String(),
				"creatorScope": rec.CreatorScope.String(), "onBehalfOf": rec.CreatedBy,
			})
			apiErr(w, http.StatusForbidden, "this token's scope is no longer within the grant of the admin who created it under current policy: mint a new one")
			return Principal{}, false
		}
	}
	p := grantPrincipal(serviceAccountID(rec.Name, t.ID), nil, []policy.Grant{{Role: role, Scope: rec.Scope, Source: "service-token"}})
	p.OnBehalfOf = rec.CreatedBy
	p.Kind = KindServiceAccount
	now := s.cfg.Now()
	if last, ok := s.tokenUsed.Load(t.ID); !ok || now.Sub(last.(time.Time)) >= serviceTokenUseEvery {
		s.tokenUsed.Store(t.ID, now)
		s.Audit(r.Context(), p.ID, "service-token.use", t.ID, map[string]string{"method": r.Method, "path": r.URL.Path, "role": role})
	}
	return p, true
}

// roleWithin reports whether every permission role grants, p holds
// globally: nobody mints a token stronger than themselves.
func roleWithin(role string, p Principal) bool { return grantWithin(nil, role, policy.RoleScope{}, p) }

// grantWithin extends roleWithin to scopes (ADR-0037): for every permission
// role grants, p holds it under a grant whose scope holds scope, so a token
// can do nothing, anywhere, that its creator could not.
func grantWithin(org *policy.Org, role string, scope policy.RoleScope, p Principal) bool {
	perms, ok := rolePerms[role]
	if !ok {
		return false
	}
	for _, x := range perms {
		if !slices.ContainsFunc(p.grantsFor(x), func(g policy.Grant) bool { return org.ScopeWithin(scope, g.Scope) }) {
			return false
		}
	}
	return true
}

// tokenScope decodes a create request's scope strictly (an unknown key is an
// error: a typo must not mint a global token) and checks every ring and unit
// against current policy. Absent is global; a scope that is present must name
// a ring or a unit: {}, null or empty lists are refused, never global.
func (s *Server) tokenScope(raw json.RawMessage) (policy.RoleScope, error) {
	var sc policy.RoleScope
	if len(raw) == 0 {
		return sc, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return sc, fmt.Errorf(`scope must be {"rings": [...], "units": [...]}: %w`, err)
	}
	if sc.Global() {
		return sc, errors.New("scope names no ring or unit: omit it for a global token")
	}
	org, _, _ := s.pol.Get()
	if org == nil && !sc.Global() {
		return sc, errors.New("policy not loaded: a scope cannot be checked")
	}
	seen := map[string]bool{}
	for _, rg := range sc.Rings {
		if ringByName(org, rg) == nil || seen["r:"+rg] {
			return sc, fmt.Errorf("scope.rings: %q is not a ring in policy, or is listed twice", rg)
		}
		seen["r:"+rg] = true
	}
	for _, u := range sc.Units {
		if org.Unit(u) == nil || seen["u:"+u] {
			return sc, fmt.Errorf("scope.units: %q is not a unit in policy, or is listed twice", u)
		}
		seen["u:"+u] = true
	}
	return sc, nil
}

// createTokenFields are CreateServiceTokenRequest's JSON keys, exactly.
var createTokenFields = []string{"name", "role", "scope", "description", "owner", "ttl"}

// exactKeys refuses a JSON object with a key outside allowed, a key that
// differs from one only by case (encoding/json would accept it), or a
// repeated key (encoding/json keeps the last): a proxy, an audit trail and
// this server must all read the same request. nested lists the allowed keys
// of object-valued fields.
func exactKeys(raw []byte, allowed []string, nested map[string][]string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("want a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := t.(string)
		switch {
		case !slices.Contains(allowed, k):
			return fmt.Errorf("unknown field %q (want %s)", k, strings.Join(allowed, ", "))
		case seen[k]:
			return fmt.Errorf("field %q given twice", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if sub, ok := nested[k]; ok {
			if err := exactKeys(v, sub, nil); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	}
	_, err := dec.Token()
	return err
}

// validTokenText reports whether s fits a description or owner field.
func validTokenText(s string) bool {
	return len(s) <= maxServiceTokenText && strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) }) < 0
}

// createServiceToken (admin): POST /api/v1/service-tokens. Only an
// interactive human session may mint tokens: a token cannot mint its
// successor (no self-perpetuating credentials), and break-glass is for
// recovery, not for leaving credentials behind. The token is stored before
// it is audited; if the audit append fails it is revoked again and never shown.
func (s *Server) createServiceToken(w http.ResponseWriter, r *http.Request, p Principal) {
	if p.Kind != "" {
		apiErr(w, http.StatusForbidden, "service tokens are created from an interactive admin session, not a "+p.Kind)
		return
	}
	var raw json.RawMessage
	if err := decodeBody(w, r, 4096, &raw); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	// Strict (ADR-0037 review): exact keys, once each; a misspelt or repeated
	// field never falls back to a default, least of all a global scope.
	var in CreateServiceTokenRequest
	if err := exactKeys(raw, createTokenFields, map[string][]string{"scope": {"rings", "units"}}); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	in.Description, in.Owner = strings.TrimSpace(in.Description), strings.TrimSpace(in.Owner)
	maxTTL := s.tokenMaxTTL
	ttl := maxTTL
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil {
			apiErr(w, http.StatusBadRequest, "ttl must be a duration such as 720h")
			return
		}
		ttl = d
	}
	scope, err := s.tokenScope(in.Scope)
	if err != nil {
		apiErr(w, http.StatusBadRequest, err.Error())
		return
	}
	org, _, _ := s.pol.Get()
	adminGrant, adminOver := s.adminGrantOver(p, scope)
	switch {
	case !policy.ValidName(in.Name):
		apiErr(w, http.StatusBadRequest, "name must be a lowercase name (a-z, 0-9, '.', '_', '-'; at most 63 characters)")
		return
	case !slices.Contains(Roles, in.Role):
		apiErr(w, http.StatusBadRequest, fmt.Sprintf("role must be one of %s", strings.Join(Roles, ", ")))
		return
	case !adminOver || !grantWithin(org, in.Role, scope, p):
		// The ceiling (ADR-0036, extended by ADR-0037): the token's scope is
		// within one of the creator's admin grants, and each permission of its
		// role is the creator's over that scope.
		d := map[string]string{"route": "POST /api/v1/service-tokens", "need": "role " + in.Role, "roles": strings.Join(p.Roles, ",")}
		if !scope.Global() || !p.canGlobal(permAdmin) {
			d["scope"], d["bindings"] = scope.String(), grantSummary(p.Bindings)
		}
		s.Audit(r.Context(), p.ID, "authz.deny", r.URL.Path, d)
		apiErr(w, http.StatusForbidden, "a token's role and scope may not exceed your own permissions")
		return
	case !validTokenText(in.Description) || !validTokenText(in.Owner):
		apiErr(w, http.StatusBadRequest, fmt.Sprintf("description and owner must be at most %d characters, no control characters", maxServiceTokenText))
		return
	case ttl < minServiceTokenTTL || ttl > maxTTL:
		apiErr(w, http.StatusBadRequest, fmt.Sprintf("ttl must be between %s and %s", minServiceTokenTTL, maxTTL))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	now := s.cfg.Now()
	tok, id, err := newServiceToken()
	if err != nil {
		s.cfg.Log.Error("mint service token", "err", err)
		apiErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	rec := newTokenRecord(in.Role, scope)
	rec.Name, rec.Description, rec.Owner, rec.CreatedBy, rec.CreatedAt = in.Name, in.Description, in.Owner, p.ID, now.UTC()
	rec.CreatorScope = adminGrant.Scope
	recb, _ := json.Marshal(rec) // plain struct: cannot fail
	r = withAuthz(r, p, adminGrant)
	row := pgstore.ServiceToken{ID: id, Hash: hashServiceToken(tok), Expires: now.Add(ttl).UTC().Truncate(time.Microsecond), Record: recb}
	if err := s.tokens.PutServiceToken(ctx, row, maxActiveServiceTokens, now); errors.Is(err, pgstore.ErrServiceTokenLimit) {
		apiErr(w, http.StatusConflict, fmt.Sprintf("%d service tokens are active (the limit): revoke unused ones first", maxActiveServiceTokens))
		return
	} else if err != nil {
		s.cfg.Log.Error("store service token", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	info := serviceTokenInfo(row, now)
	d := map[string]string{"name": in.Name, "role": in.Role, "expires": info.ExpiresAt.Format(time.RFC3339), "principal": info.Principal}
	if in.Owner != "" {
		d["owner"] = in.Owner
	}
	if !scope.Global() {
		d["scope"] = scope.String()
	}
	if err := s.AuditStrict(r.Context(), p.ID, "service-token.create", id, d); err != nil {
		at := now.UTC()
		rec.RevokedBy, rec.RevokedAt, rec.RevokeReason = p.ID, &at, "audit append failed at creation"
		rb, _ := json.Marshal(rec) // plain struct: cannot fail
		if _, _, rerr := s.tokens.RevokeServiceToken(ctx, id, rb); rerr != nil {
			s.cfg.Log.Error("revoke unaudited service token", "id", id, "err", rerr) // nobody holds it: never returned
		}
		apiErr(w, http.StatusInternalServerError, errAuditFailed)
		return
	}
	s.cfg.Log.Info("service token created", "id", id, "name", in.Name, "role", in.Role, "by", p.ID)
	writeJSON(w, http.StatusCreated, CreateServiceTokenResponse{Token: tok, ServiceToken: info})
}

// listServiceTokens (admin): GET /api/v1/service-tokens.
// A scoped admin (ADR-0037) sees the tokens whose scope is within one of
// their admin grants.
func (s *Server) listServiceTokens(w http.ResponseWriter, r *http.Request, p Principal) {
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	all, err := s.tokens.ServiceTokens(ctx)
	if err != nil {
		s.cfg.Log.Error("list service tokens", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	now := s.cfg.Now()
	everything := p.canGlobal(permAdmin)
	out := ServiceTokensResponse{Tokens: make([]ServiceTokenInfo, 0, len(all))}
	for _, t := range all {
		info := serviceTokenInfo(t, now)
		if _, ok := s.adminGrantOver(p, info.Scope); everything || ok {
			out.Tokens = append(out.Tokens, info)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// adminGrantOver is p's admin grant whose scope holds scope (a global one first).
func (s *Server) adminGrantOver(p Principal, scope policy.RoleScope) (policy.Grant, bool) {
	org, _, _ := s.pol.Get()
	if g, ok := p.globalGrant(permAdmin); ok {
		return g, true
	}
	if org == nil {
		return policy.Grant{}, false
	}
	for _, g := range p.grantsFor(permAdmin) {
		if org.ScopeWithin(scope, g.Scope) {
			return g, true
		}
	}
	return policy.Grant{}, false
}

// revokeServiceToken (admin): POST /api/v1/service-tokens/{id}/revoke. Any
// admin principal may revoke, a token or break-glass included: revoking only
// ever takes access away. It holds on every replica at the token's next use.
func (s *Server) revokeServiceToken(w http.ResponseWriter, r *http.Request, p Principal) {
	id := r.PathValue("id")
	if len(id) != serviceTokenIDLen || strings.Trim(id, "0123456789abcdef") != "" {
		apiErr(w, http.StatusBadRequest, "id must be a service token id (16 hex digits)")
		return
	}
	var in RevokeServiceTokenRequest
	if err := decodeBody(w, r, 4096, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if in.Reason = strings.TrimSpace(in.Reason); in.Reason == "" || len(in.Reason) > maxRevokeReason {
		apiErr(w, http.StatusBadRequest, "reason required (<=1000 chars)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), storage.OpTimeout)
	defer cancel()
	cur, ok, err := s.tokens.ServiceToken(ctx, id)
	if err == nil && !p.canGlobal(permAdmin) {
		// A scoped admin (ADR-0037) revokes tokens whose scope is within one of
		// their admin grants; an unknown id answers as out of scope.
		const route = "POST /api/v1/service-tokens/{id}/revoke"
		if !ok {
			s.denyScope(w, r, p, route, permAdmin, scopeWhyUnknown, nil)
			return
		}
		var rec serviceTokenRecord
		_ = json.Unmarshal(cur.Record, &rec) // garbage: a global scope, which no scoped grant holds
		g, within := s.adminGrantOver(p, rec.Scope)
		if !within {
			s.denyScope(w, r, p, route, permAdmin, scopeWhyOutside, nil)
			return
		}
		r = withAuthz(r, p, g)
	}
	if err == nil && !ok {
		apiErr(w, http.StatusNotFound, "service token not found")
		return
	}
	var row pgstore.ServiceToken
	if err == nil {
		var rec serviceTokenRecord
		_ = json.Unmarshal(cur.Record, &rec) // written by this package
		at := s.cfg.Now().UTC()
		rec.RevokedBy, rec.RevokedAt, rec.RevokeReason = p.ID, &at, in.Reason
		rb, _ := json.Marshal(rec) // plain struct: cannot fail
		row, _, err = s.tokens.RevokeServiceToken(ctx, id, rb)
	}
	if err != nil {
		s.cfg.Log.Error("revoke service token", "id", id, "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	info := serviceTokenInfo(row, s.cfg.Now())
	s.cfg.Log.Info("service token revoked", "id", id, "name", info.Name, "by", p.ID)
	if err := s.AuditStrict(r.Context(), p.ID, "service-token.revoke", id, map[string]string{"name": info.Name, "reason": in.Reason, "principal": info.Principal}); err != nil {
		apiErr(w, http.StatusInternalServerError, errAuditFailed) // the revocation itself is in force
		return
	}
	writeJSON(w, http.StatusOK, info)
}
