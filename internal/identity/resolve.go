package identity

import (
	"fmt"
	"strings"
	"sync"

	"github.com/halos-dev/halos/internal/policy"
)

// Modes.
const (
	ModeJWT           = "jwt"
	ModeTrustedHeader = "trusted_header"
	ModeNone          = "none" // no verification: every caller is anonymous (default routing)
)

// Options is per-binary identity config. Empty fields fall back to the org's
// policy (Org.Identity / Org.Gateway.Auth), so most deployments set nothing.
type Options struct {
	Mode                   string
	Issuer, Audience       string
	UserClaim, GroupsClaim string
	IdentityHeader         string
	GroupsHeader           string
	TrustedProxyCIDRs      []string
	// TrustUnverifiedEmail: accept userClaim "email" without email_verified=true.
	// Default false; only for IdPs that never issue unverified emails.
	TrustUnverifiedEmail bool
}

// Effective fills gaps from the org and picks the mode: jwt when an issuer is
// known, otherwise trusted_header (which then demands CIDRs and fails closed).
func (o Options) Effective(org *policy.Org) Options {
	if org != nil {
		id := org.Identity
		o.Issuer = firstNonEmpty(o.Issuer, id.Issuer)
		o.Audience = firstNonEmpty(o.Audience, id.Audience, id.ClientID)
		o.UserClaim = firstNonEmpty(o.UserClaim, id.UserClaim)
		o.GroupsClaim = firstNonEmpty(o.GroupsClaim, id.GroupsClaim)
		if org.Gateway != nil {
			o.IdentityHeader = firstNonEmpty(o.IdentityHeader, org.Gateway.Auth.IdentityHeader)
		}
	}
	if o.Mode == "" {
		o.Mode = ModeTrustedHeader
		if o.Issuer != "" {
			o.Mode = ModeJWT
		}
	}
	return o
}

// HeaderNames are the identity/groups headers (effective for org) that must
// be cleared from every upstream request once the subject is derived.
func (o Options) HeaderNames(org *policy.Org) []string {
	e := o.Effective(org)
	var out []string
	for _, h := range []string{e.IdentityHeader, e.GroupsHeader} {
		if h != "" {
			out = append(out, strings.ToLower(h))
		}
	}
	return out
}

// New builds the Verifier for o (already Effective). ModeNone returns nil, nil.
func New(o Options) (Verifier, error) {
	switch o.Mode {
	case ModeJWT:
		v, err := NewOIDCJWT(o.Issuer, o.Audience, o.UserClaim, o.GroupsClaim, nil)
		if err != nil {
			return nil, err
		}
		v.TrustUnverifiedEmail = o.TrustUnverifiedEmail
		return v, nil
	case ModeTrustedHeader:
		return NewTrustedHeader(o.IdentityHeader, o.GroupsHeader, o.TrustedProxyCIDRs)
	case ModeNone:
		return nil, nil
	}
	return nil, fmt.Errorf("identity: unknown mode %q (want jwt|trusted_header|none)", o.Mode)
}

// Resolver caches the Verifier across policy hot-reloads: it is rebuilt only
// when the effective options change (so the JWKS cache survives reloads).
type Resolver struct {
	mu  sync.Mutex
	key string
	v   Verifier
	err error
}

// Get returns the verifier for base options + org. A nil Verifier with nil
// error means ModeNone.
func (r *Resolver) Get(base Options, org *policy.Org) (Verifier, error) {
	eff := base.Effective(org)
	key := fmt.Sprintf("%+v", eff)
	r.mu.Lock()
	defer r.mu.Unlock()
	if key != r.key {
		r.key = key
		r.v, r.err = New(eff)
	}
	return r.v, r.err
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
