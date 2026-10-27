package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/identity"
)

const wikiURL = "https://mcp-wiki.internal.acme.example/mcp"

// mcpYAML: acme-wiki (auth mode halos) for ring0-harness-team (group
// ai-platform); github (auth mode oauth) for everyone in ring3-ga.
const mcpYAML = `mcp:
  servers:
    - id: acme-wiki
      url: ` + wikiURL + `
      rings: [ring0-harness-team]
      auth: {mode: halos}
    - id: github
      url: https://api.githubcopilot.com/mcp/
      rings: [ring3-ga]
      auth: {mode: oauth}
`

func withMCPRegistry(t *testing.T) func(*Config) {
	return func(c *Config) {
		f := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, append(b, []byte(mcpYAML)...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func mcpForm(subject, typ, resource string, kv ...string) url.Values {
	f := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {subject}, "subject_token_type": {typ}, paramResource: {resource}}
	for i := 0; i+1 < len(kv); i += 2 {
		f.Add(kv[i], kv[i+1])
	}
	return f
}

// TestMCPTokenExchange: a Halos credential becomes a token for one registry
// server, audience-bound to its URL, and the exchange is audited; every
// refusal names why and is audited too.
func TestMCPTokenExchange(t *testing.T) {
	e, _ := delegationEnv(t, false, withMCPRegistry(t))
	platform := Principal{ID: "pat@acme.example", Groups: []string{"ai-platform"}}
	w := e.exchange(mcpForm(e.session(platform), tokenTypeSession, "https://MCP-wiki.internal.acme.example/mcp/"))
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	var resp TokenExchangeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	c, err := identity.VerifyMCPToken(e.s.workloadPub(), resp.AccessToken, wikiURL, *e.now)
	if err != nil {
		t.Fatalf("minted token does not verify for its server: %v", err)
	}
	if c.Subject != platform.ID || c.Server != "acme-wiki" || c.Audience != wikiURL || resp.ExpiresIn != int(identity.MCPTokenTTL.Seconds()) ||
		resp.IssuedTokenType != tokenTypeAccess || resp.Ring != "ring0-harness-team" {
		t.Fatalf("claims %+v response %+v", c, resp)
	}
	if _, err := identity.VerifyMCPToken(e.s.workloadPub(), resp.AccessToken, "https://mcp-tickets.internal.acme.example/mcp", *e.now); err == nil {
		t.Fatal("token accepted for another server")
	}
	ents := e.auditActions(t)
	if last := ents[len(ents)-1]; last.Action != "mcp.token.exchange" || last.Actor != platform.ID || last.Details["server"] != "acme-wiki" ||
		last.Details["jti"] != c.ID || strings.Contains(last.Details["reason"]+last.Details["groups"], resp.AccessToken) {
		t.Fatalf("audit: %+v", last)
	}

	for _, tc := range []struct {
		name   string
		form   url.Values
		code   int
		kind   string
		audit  bool
		reason string
	}{
		{"server not enabled for the caller's ring", mcpForm(e.session(alice), tokenTypeSession, wikiURL), 400, "invalid_target", true, "not enabled"},
		{"not in the registry", mcpForm(e.session(platform), tokenTypeSession, "https://evil.example/mcp"), 400, "invalid_target", true, "not a remote server"},
		{"auth mode is not halos", mcpForm(e.session(platform), tokenTypeSession, "https://api.githubcopilot.com/mcp/"), 400, "invalid_target", true, "does not use auth mode halos"},
		{"two resources", mcpForm(e.session(platform), tokenTypeSession, wikiURL, paramResource, "https://evil.example/mcp"), 400, "invalid_request", false, "exactly one resource"},
		{"actor_id", mcpForm(e.session(platform), tokenTypeSession, wikiURL, paramActorID, "planner"), 400, "invalid_request", false, "no actor_id"},
		{"forged session", mcpForm("garbage", tokenTypeSession, wikiURL), 400, "invalid_grant", false, "subject_token rejected"},
		{"gateway audience requested", mcpForm(e.session(platform), tokenTypeSession, wikiURL, "audience", "other"), 400, "invalid_target", false, "audience"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(e.auditActions(t))
			w := e.exchange(tc.form)
			kind, desc := oauthErrOf(w)
			if w.Code != tc.code || kind != tc.kind || !strings.Contains(desc, tc.reason) {
				t.Fatalf("got %d %s %q", w.Code, kind, desc)
			}
			ents := e.auditActions(t)
			if audited := len(ents) > before && ents[len(ents)-1].Action == "mcp.token.denied"; audited != tc.audit {
				t.Fatalf("audited = %v, want %v", audited, tc.audit)
			}
		})
	}
}

// TestMCPTokenRevokedCredential: a revoked credential (ADR-0026) mints no MCP
// token, the refusal is audited with its jti, and an unreadable revocation
// store fails closed.
func TestMCPTokenRevokedCredential(t *testing.T) {
	e, priv := delegationEnv(t, false, withMCPRegistry(t))
	wl := e.workloadToken(t, priv, "wl-mcp")
	if w := e.exchange(mcpForm(wl, tokenTypeJWT, wikiURL)); w.Code != http.StatusOK {
		t.Fatalf("before revocation: %d %s", w.Code, w.Body)
	}
	e.revoke(t, `{"jti":"wl-mcp","reason":"token printed in a CI log"}`)
	w := e.exchange(mcpForm(wl, tokenTypeJWT, wikiURL))
	if kind, _ := oauthErrOf(w); w.Code != http.StatusBadRequest || kind != "invalid_grant" {
		t.Fatalf("revoked credential: %d %s", w.Code, w.Body)
	}
	if a := lastAuditOf(t, e, "mcp.token.denied"); !strings.Contains(a.Details["reason"], "revoked") || a.Details["parentJti"] != "wl-mcp" {
		t.Fatalf("refusal audit: %+v", a)
	}
	e.s.revs = brokenRevocations{}
	if w := e.exchange(mcpForm(e.workloadToken(t, priv, "wl-other"), tokenTypeJWT, wikiURL)); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("revocation store down: %d %s", w.Code, w.Body)
	}
}
