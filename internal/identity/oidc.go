package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dshakes/halos/internal/policy"
)

// AllowedAlgs is the JWT signature allowlist. "none" and HS* are never
// accepted: a shared-secret alg would let anyone holding the (public) JWKS key
// forge tokens (key confusion).
var AllowedAlgs = []string{"RS256", "ES256", "EdDSA"}

// ErrDiscovery: the issuer's discovery document could not be fetched, so no
// token was judged (an outage, not a bad credential).
var ErrDiscovery = errors.New("identity: oidc discovery")

// OIDCJWT verifies a bearer JWT issued by the org's IdP: discovery + JWKS
// (cached, refetched when no cached key verifies so key rotation works; never
// fetched under CacheOnly), then iss / aud / exp / nbf and the alg allowlist.
type OIDCJWT struct {
	Issuer, Audience       string
	UserClaim, GroupsClaim string
	// TrustUnverifiedEmail accepts an "email" user claim without
	// email_verified=true. Off by default: see SubjectFromClaims.
	TrustUnverifiedEmail bool
	client               *http.Client
	now                  func() time.Time // nil = time.Now

	// mu guards the fields below; it is never held across the network.
	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	keys     *jwksKeySet
	inflight *discovery // the one discovery running, nil when none
	failAt   time.Time  // when the last discovery failed
	failErr  error      // and why; served until failAt+discoveryRetry
}

// discovery is one in-flight discovery; done is closed when err is set.
type discovery struct {
	done chan struct{}
	err  error
}

const (
	// discoveryRetry: after a failed discovery, callers get its error without
	// asking the issuer again for this long (an IdP outage is not amplified).
	discoveryRetry = 30 * time.Second
	// discoveryTimeout bounds one discovery, whatever the client's timeout.
	discoveryTimeout = 30 * time.Second
)

// NewOIDCJWT never touches the network; discovery happens on first Verify (and
// is retried while it fails), so a proxy can start before the IdP is reachable.
// client may be nil.
func NewOIDCJWT(issuer, audience, userClaim, groupsClaim string, client *http.Client) (*OIDCJWT, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("identity: jwt mode requires issuer and audience")
	}
	if userClaim == "" {
		userClaim = "email"
	}
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &OIDCJWT{Issuer: issuer, Audience: audience, UserClaim: userClaim, GroupsClaim: groupsClaim, client: client}, nil
}

func (o *OIDCJWT) clock() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

// idVerifier returns the verifier, discovering the issuer first if needed.
// Concurrent callers share one discovery and each waits only as long as its
// own ctx allows; a failed discovery is not retried for discoveryRetry.
func (o *OIDCJWT) idVerifier(ctx context.Context) (*oidc.IDTokenVerifier, *jwksKeySet, error) {
	o.mu.Lock()
	if o.verifier != nil {
		defer o.mu.Unlock()
		return o.verifier, o.keys, nil
	}
	if cacheOnly(ctx) {
		o.mu.Unlock()
		return nil, nil, fmt.Errorf("%w for %s: not yet discovered and the request may not trigger it", ErrDiscovery, o.Issuer)
	}
	if o.failErr != nil && o.clock().Sub(o.failAt) < discoveryRetry {
		err := o.failErr
		o.mu.Unlock()
		return nil, nil, err
	}
	d := o.inflight
	if d == nil {
		d = &discovery{done: make(chan struct{})}
		o.inflight = d
		go o.discover(d)
	}
	o.mu.Unlock()
	select {
	case <-d.done:
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("%w for %s: %w", ErrDiscovery, o.Issuer, ctx.Err())
	}
	if d.err != nil {
		return nil, nil, d.err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.verifier, o.keys, nil
}

// discover runs one discovery and publishes its outcome. Its own context on
// purpose: discovery must not die with the request that started it.
func (o *OIDCJWT) discover(d *discovery) {
	ctx, cancel := context.WithTimeout(context.Background(), discoveryTimeout)
	defer cancel()
	var keys *jwksKeySet
	var v *oidc.IDTokenVerifier
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, o.client), o.Issuer)
	if err != nil {
		err = fmt.Errorf("%w for %s: %w", ErrDiscovery, o.Issuer, err)
	} else {
		var meta struct {
			JWKS string `json:"jwks_uri"`
		}
		if cerr := p.Claims(&meta); cerr != nil || meta.JWKS == "" {
			err = fmt.Errorf("%w for %s: no jwks_uri", ErrDiscovery, o.Issuer)
		} else {
			keys = &jwksKeySet{url: meta.JWKS, client: o.client}
			v = oidc.NewVerifier(o.Issuer, keys, &oidc.Config{ClientID: o.Audience, SupportedSigningAlgs: AllowedAlgs})
		}
	}
	o.mu.Lock()
	if err != nil {
		o.failAt, o.failErr = o.clock(), err
	} else {
		o.verifier, o.keys, o.failErr = v, keys, nil
	}
	o.inflight = nil
	d.err = err
	close(d.done)
	o.mu.Unlock()
}

func (o *OIDCJWT) Verify(r *http.Request) (policy.Subject, error) {
	tok := BearerToken(r.Header)
	if tok == "" {
		return policy.Subject{}, ErrNoCredentials
	}
	claims, err := o.Claims(r.Context(), tok)
	if err != nil {
		return policy.Subject{}, err
	}
	return SubjectFromClaims(claims, Options{UserClaim: o.UserClaim, GroupsClaim: o.GroupsClaim, TrustUnverifiedEmail: o.TrustUnverifiedEmail})
}

// Claims verifies tok (signature via JWKS, alg allowlist, iss, aud, exp, nbf)
// and returns its claims. A token whose signature verified but whose claims
// failed is reported with ErrClaimsRejected. Under CacheOnly(ctx) nothing is
// fetched: no discovery, no JWKS refetch.
func (o *OIDCJWT) Claims(ctx context.Context, tok string) (map[string]any, error) {
	v, _, err := o.idVerifier(ctx)
	if err != nil {
		return nil, err
	}
	// ctx bounds the JWKS fetch on unknown kid (with the client timeout);
	// verification itself is local.
	sig := &sigVerified{}
	idt, err := v.Verify(context.WithValue(ctx, sigVerifiedKey{}, sig), tok)
	if err != nil {
		if sig.ok { // go-oidc checks the signature before any claim
			err = claimsError{err}
		}
		return nil, fmt.Errorf("identity: jwt rejected: %w", err)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("identity: jwt claims: %w", err)
	}
	return claims, nil
}

// SubjectFromClaims derives the caller from verified token claims using
// cfg.UserClaim / cfg.GroupsClaim (defaults "email" / "groups"). When the
// user claim is "email" the token must also carry email_verified=true (bool
// or "true"): many IdPs let users set an unverified email, which would let
// them pick someone else's identity. cfg.TrustUnverifiedEmail opts out.
func SubjectFromClaims(claims map[string]any, cfg Options) (policy.Subject, error) {
	uc, gc := firstNonEmpty(cfg.UserClaim, "email"), firstNonEmpty(cfg.GroupsClaim, "groups")
	id, _ := claims[uc].(string)
	if id = strings.TrimSpace(id); id == "" {
		return policy.Subject{}, fmt.Errorf("identity: token has no %q claim", uc)
	}
	if err := CheckHumanID(id); err != nil {
		return policy.Subject{}, err
	}
	if uc == "email" && !cfg.TrustUnverifiedEmail {
		if v := claims["email_verified"]; v != true && v != "true" {
			return policy.Subject{}, fmt.Errorf("identity: token email %q is not verified (email_verified=%v); set userClaim to a stable IdP subject or enable trustUnverifiedEmail", id, v)
		}
	}
	return policy.Subject{ID: id, Groups: groupsOf(claims[gc])}, nil
}

// groupsOf accepts a JSON array of strings or one comma-separated string.
// Missing or malformed => no groups (the user falls through to hash/default rings).
func groupsOf(v any) []string {
	switch g := v.(type) {
	case string:
		return splitList(g)
	case []any:
		var out []string
		for _, e := range g {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
