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

	"github.com/halos-dev/halos/internal/policy"
)

// AllowedAlgs is the JWT signature allowlist. "none" and HS* are never
// accepted: a shared-secret alg would let anyone holding the (public) JWKS key
// forge tokens (key confusion).
var AllowedAlgs = []string{"RS256", "ES256", "EdDSA"}

// OIDCJWT verifies a bearer JWT issued by the org's IdP: discovery + JWKS
// (cached, refetched on unknown kid so key rotation works), then iss / aud /
// exp / nbf and the alg allowlist.
type OIDCJWT struct {
	Issuer, Audience       string
	UserClaim, GroupsClaim string
	// TrustUnverifiedEmail accepts an "email" user claim without
	// email_verified=true. Off by default: see SubjectFromClaims.
	TrustUnverifiedEmail bool
	client               *http.Client
	mu                   sync.Mutex
	verifier             *oidc.IDTokenVerifier
}

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

func (o *OIDCJWT) idVerifier() (*oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.verifier != nil {
		return o.verifier, nil
	}
	// Background ctx on purpose: the provider keeps it for later JWKS fetches,
	// so it must outlive the first request. The client carries the timeout.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), o.client), o.Issuer)
	if err != nil {
		return nil, fmt.Errorf("identity: oidc discovery for %s: %w", o.Issuer, err)
	}
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.Audience, SupportedSigningAlgs: AllowedAlgs})
	return o.verifier, nil
}

func (o *OIDCJWT) Verify(r *http.Request) (policy.Subject, error) {
	tok := BearerToken(r.Header)
	if tok == "" {
		return policy.Subject{}, ErrNoCredentials
	}
	v, err := o.idVerifier()
	if err != nil {
		return policy.Subject{}, err
	}
	// Request ctx bounds the JWKS fetch on unknown kid via the client timeout only;
	// verification itself is local.
	idt, err := v.Verify(oidc.ClientContext(r.Context(), o.client), tok)
	if err != nil {
		return policy.Subject{}, fmt.Errorf("identity: jwt rejected: %w", err)
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return policy.Subject{}, fmt.Errorf("identity: jwt claims: %w", err)
	}
	return SubjectFromClaims(claims, Options{UserClaim: o.UserClaim, GroupsClaim: o.GroupsClaim, TrustUnverifiedEmail: o.TrustUnverifiedEmail})
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
