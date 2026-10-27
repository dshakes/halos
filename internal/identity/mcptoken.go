package identity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// MCP access tokens (ADR-0029): for a registry server with auth mode halos,
// halo-server is the authorization server. It mints a short-lived token whose
// audience is the server's canonical URL (RFC 8707), so the token is good at
// that one server only: gateways refuse it (wrong typ and aud) and the server
// never receives, or passes on, the caller's own Halos credential.
const (
	// MCPTokenType is the JWT typ header of an MCP access token.
	MCPTokenType = "halo-mcp+jwt" //nolint:gosec // JWT typ value, not a credential
	// MCPTokenTTL is the lifetime cap of an MCP access token: harness header
	// helpers run on every connection, so a short token costs nothing.
	MCPTokenTTL = 5 * time.Minute
)

// MCPClaims is the payload of an MCP access token.
type MCPClaims struct {
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Audience string   `json:"aud"` // canonical server URL (policy.CanonicalResource)
	Groups   []string `json:"groups,omitempty"`
	// Kind is the subject's kind ("" human, workload); Actors the delegation
	// chain when an agent asked, root-side first. Attribution for the server.
	Kind   string   `json:"kind,omitempty"`
	Actors []string `json:"actors,omitempty"`
	// Server is the registry id the token was minted for.
	Server    string `json:"mcp_server"`
	IssuedAt  int64  `json:"iat"`
	NotBefore int64  `json:"nbf"`
	Expiry    int64  `json:"exp"`
	ID        string `json:"jti"`
}

// SignMCPToken signs c with the workload key. It refuses claims
// VerifyMCPToken would reject.
func SignMCPToken(key ed25519.PrivateKey, c MCPClaims) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("identity: mcp signing key is not an ed25519 private key")
	}
	if err := c.check(c.Audience, time.Unix(c.IssuedAt, 0)); err != nil {
		return "", fmt.Errorf("identity: refusing to sign mcp token: %w", err)
	}
	return signJWT(key, MCPTokenType, c)
}

// VerifyMCPToken is what an MCP server whose authorization server is Halos
// runs on each request: the signature against halo-server's workload public
// keys (by kid), then iss, aud (must be resource, canonicalised), exp, nbf,
// iat and the lifetime cap.
func VerifyMCPToken(keys []ed25519.PublicKey, tok, resource string, now time.Time) (MCPClaims, error) {
	var c MCPClaims
	if err := verifyJWT(keys, MCPTokenType, tok, &c); err != nil {
		return MCPClaims{}, err
	}
	if err := c.check(resource, now); err != nil {
		return MCPClaims{}, fmt.Errorf("identity: mcp token rejected: %w", claimsError{err})
	}
	return c, nil
}

func (c MCPClaims) check(resource string, now time.Time) error {
	exp, nbf, iat := time.Unix(c.Expiry, 0), time.Unix(c.NotBefore, 0), time.Unix(c.IssuedAt, 0)
	want, ok := policy.CanonicalResource(resource)
	switch {
	case !ok:
		return fmt.Errorf("resource %q is not an https URL", resource)
	case c.Issuer != WorkloadIssuer:
		return fmt.Errorf("iss %q, want %q", c.Issuer, WorkloadIssuer)
	case c.Audience != want:
		return fmt.Errorf("aud %q, want %q", c.Audience, want)
	case c.Subject == "" || c.Server == "":
		return errors.New("sub and mcp_server are required")
	case c.Expiry == 0 || c.IssuedAt == 0 || c.NotBefore == 0 || c.ID == "":
		return errors.New("exp, iat, nbf and jti are required")
	case !now.Before(exp):
		return fmt.Errorf("%w at %s", ErrTokenExpired, exp.UTC().Format(time.RFC3339))
	case nbf.After(now.Add(workloadSkew)), iat.After(now.Add(workloadSkew)):
		return errors.New("not yet valid (nbf/iat in the future)")
	case exp.Sub(iat) > MCPTokenTTL:
		return fmt.Errorf("lifetime %s exceeds %s", exp.Sub(iat), MCPTokenTTL)
	}
	return nil
}
