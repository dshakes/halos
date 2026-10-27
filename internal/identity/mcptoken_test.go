package identity

import (
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"testing"
	"time"
)

func mcpClaims(now time.Time) MCPClaims {
	return MCPClaims{Issuer: WorkloadIssuer, Subject: "alice@acme.example", Audience: "https://wiki.acme.example/mcp", Server: "wiki",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(MCPTokenTTL).Unix(), ID: "m1"}
}

func TestMCPToken(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	_, otherPriv, _ := workloadKey(t)
	keys := []ed25519.PublicKey{pub}
	now := time.Unix(1_800_000_000, 0)
	tok, err := SignMCPToken(priv, mcpClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	// The resource is compared canonically: case, default port, trailing slash.
	if c, err := VerifyMCPToken(keys, tok, "https://WIKI.acme.example:443/mcp/", now); err != nil || c.Server != "wiki" {
		t.Fatalf("verify: %+v %v", c, err)
	}
	other, _ := SignMCPToken(otherPriv, mcpClaims(now))
	wl, _ := SignWorkloadToken(priv, WorkloadClaims{Issuer: WorkloadIssuer, Subject: "workload:ci", Audience: WorkloadAudience, Kind: "workload",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(time.Minute).Unix(), ID: "w1"})
	for _, tc := range []struct {
		name, tok, resource string
		at                  time.Time
		claims              bool // rejected after the signature verified
	}{
		{"another server", tok, "https://tickets.acme.example/mcp", now, true},
		{"same host, another path", tok, "https://wiki.acme.example/mcp/admin", now, true},
		{"expired", tok, "https://wiki.acme.example/mcp", now.Add(MCPTokenTTL), true},
		{"untrusted key", other, "https://wiki.acme.example/mcp", now, false},
		{"a workload credential is not an mcp token", wl, "https://wiki.acme.example/mcp", now, false},
		{"modified audience", resign(tok, func() MCPClaims { c := mcpClaims(now); c.Audience = "https://evil.example/mcp"; return c }()), "https://evil.example/mcp", now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyMCPToken(keys, tc.tok, tc.resource, tc.at)
			if err == nil || errors.Is(err, ErrClaimsRejected) != tc.claims {
				t.Fatalf("err = %v, claims rejected = %v", err, tc.claims)
			}
		})
	}
	for _, tc := range []struct {
		name string
		mod  func(c *MCPClaims)
	}{
		{"lifetime over the cap", func(c *MCPClaims) { c.Expiry = c.IssuedAt + int64(MCPTokenTTL/time.Second) + 1 }},
		{"plain http audience", func(c *MCPClaims) { c.Audience = "http://wiki.acme.example/mcp" }},
		{"non-canonical audience", func(c *MCPClaims) { c.Audience = "https://wiki.acme.example/mcp/" }},
		{"no server", func(c *MCPClaims) { c.Server = "" }},
		{"no jti", func(c *MCPClaims) { c.ID = "" }},
	} {
		t.Run("sign refuses "+tc.name, func(t *testing.T) {
			c := mcpClaims(now)
			tc.mod(&c)
			if _, err := SignMCPToken(priv, c); err == nil {
				t.Fatal("signed")
			}
		})
	}
	// A gateway's verifier never accepts an MCP token as a caller credential:
	// it is not a workload or delegated typ, so it falls through to Next.
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := &recordingVerifier{}
	_, _ = (&WorkloadJWT{Keys: keys, Next: rec, Now: func() time.Time { return now }}).Verify(r)
	if !rec.called {
		t.Fatal("WorkloadJWT accepted an MCP token instead of handing it to the human verifier")
	}
}
