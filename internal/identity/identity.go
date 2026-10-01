// Package identity verifies who a gateway request is from. Cohort assignment
// must only ever use a Subject produced here: never a header a client could
// have set itself.
package identity

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Verifier authenticates a request and returns the caller. Any error means
// the caller is unverified.
type Verifier interface {
	Verify(r *http.Request) (policy.Subject, error)
}

// ErrNoCredentials is returned when the request carries nothing to verify.
var ErrNoCredentials = errors.New("identity: no credentials")

// ErrAmbiguous is returned when a trusted identity/groups header appears more
// than once; adapters answer 400 rather than guess which value is real.
var ErrAmbiguous = errors.New("identity: identity header sent more than once")

// BearerToken returns the caller's token from "Authorization: Bearer" or,
// for Anthropic SDKs, "x-api-key".
func BearerToken(h http.Header) string {
	if a := h.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return strings.TrimSpace(h.Get("x-api-key"))
}

// TrustedHeader reads identity from headers set by an auth gateway. That is
// only safe when the request provably came from that gateway, so it refuses
// to exist without a CIDR allowlist for the peer address.
type TrustedHeader struct {
	IdentityHeader string
	GroupsHeader   string
	cidrs          []*net.IPNet
}

func NewTrustedHeader(identityHeader, groupsHeader string, trustedProxyCIDRs []string) (*TrustedHeader, error) {
	if len(trustedProxyCIDRs) == 0 {
		return nil, errors.New("identity: trusted_header mode requires trustedProxyCIDRs (headers are client-controlled otherwise)")
	}
	if identityHeader == "" {
		return nil, errors.New("identity: trusted_header mode requires an identity header")
	}
	if strings.HasPrefix(strings.ToLower(identityHeader), "x-halo-") || strings.HasPrefix(strings.ToLower(groupsHeader), "x-halo-") {
		return nil, errors.New("identity: identity headers must not be x-halo-*")
	}
	t := &TrustedHeader{IdentityHeader: identityHeader, GroupsHeader: groupsHeader}
	for _, c := range trustedProxyCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("identity: trustedProxyCIDRs %q: %w", c, err)
		}
		t.cidrs = append(t.cidrs, n)
	}
	return t, nil
}

func (t *TrustedHeader) Verify(r *http.Request) (policy.Subject, error) {
	if len(r.Header.Values(t.IdentityHeader)) > 1 || (t.GroupsHeader != "" && len(r.Header.Values(t.GroupsHeader)) > 1) {
		return policy.Subject{}, ErrAmbiguous
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	trusted := false
	for _, n := range t.cidrs {
		if ip != nil && n.Contains(ip) {
			trusted = true
			break
		}
	}
	if !trusted {
		return policy.Subject{}, fmt.Errorf("identity: peer %q is not in trustedProxyCIDRs", r.RemoteAddr)
	}
	id := strings.TrimSpace(r.Header.Get(t.IdentityHeader))
	if id == "" {
		return policy.Subject{}, ErrNoCredentials
	}
	var groups []string
	if t.GroupsHeader != "" {
		groups = splitList(r.Header.Get(t.GroupsHeader))
	}
	return policy.Subject{ID: id, Groups: groups}, nil
}

func splitList(s string) []string {
	var out []string
	for _, g := range strings.Split(s, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}
