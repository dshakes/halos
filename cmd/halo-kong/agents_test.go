package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// TestAccessDelegatedAgent: halo-kong accepts a delegated agent credential
// (shared identity.WorkloadJWT), routes it as its root, stamps the verified
// chain and clears the client's actor headers; a tool policy denies it.
func TestAccessDelegatedAgent(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	org := &policy.Org{
		Name: "acme",
		Gateway: &policy.Gateway{
			Models:    map[string]policy.ModelRoute{"sonnet": {Upstream: "orch", Model: "us.anthropic.claude-sonnet-5-5"}},
			Upstreams: map[string]policy.Upstream{"orch": {URL: "https://orch.internal:8443", Kind: "anthropic"}},
		},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Order: 0, Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ga"}, Order: 1, Membership: policy.Membership{Default: true}},
		},
		Agents: &policy.Agents{Actors: []policy.AgentActor{{Name: "planner"}}, DeniedTools: []string{"Bash"}},
	}
	b, err := policy.Compile(org)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(pol, b, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tok, err := identity.SignDelegatedToken(priv, identity.DelegatedClaims{Issuer: identity.WorkloadIssuer, Subject: "alice", Audience: identity.WorkloadAudience,
		Groups: []string{"ai-platform"}, Kind: identity.KindAgent, Act: identity.ActFromChain([]policy.Actor{{Agent: "planner"}}),
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(5 * time.Minute).Unix(), ID: "d1"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := trustedCfg(pol)
	cfg.WorkloadPubkey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	hdrs := map[string][]string{"Authorization": {"Bearer " + tok}, "X-Halo-Actor": {"ceo"}, "x-halo-actor-depth": {"0"}}
	k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: hdrs}
	cfg.access(k)
	if k.exitStatus != 0 || k.set["x-halo-ring"] != "ring0" || k.set["x-halo-actor"] != "planner" || k.set["x-halo-actor-depth"] != "1" {
		t.Fatalf("exit %d %s, set %v", k.exitStatus, k.exitBody, k.set)
	}
	for _, n := range []string{"x-halo-actor", "x-halo-actor-depth"} {
		if !slices.Contains(k.cleared, n) {
			t.Fatalf("%s not cleared: %v", n, k.cleared)
		}
	}
	k = &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(`{"model":"sonnet","messages":[],"tools":[{"name":"Bash"}]}`), hdrs: hdrs}
	cfg.access(k)
	if k.exitStatus != 400 {
		t.Fatalf("denied tool: exit %d", k.exitStatus)
	}
}
