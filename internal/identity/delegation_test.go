package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

func delegatedClaims(now time.Time, chain ...string) DelegatedClaims {
	var actors []policy.Actor
	for _, a := range chain {
		actors = append(actors, policy.Actor{Agent: a, Harness: "claude-code"})
	}
	return DelegatedClaims{Issuer: WorkloadIssuer, Subject: "alice@acme.example", Audience: WorkloadAudience, Groups: []string{"eng"},
		Kind: KindAgent, Act: ActFromChain(actors), Models: []string{"sonnet"}, IssuedAt: now.Unix(), NotBefore: now.Unix(),
		Expiry: now.Add(10 * time.Minute).Unix(), ID: "d1"}
}

// resign replaces the payload of tok with p, keeping header and signature: a
// forged or modified claim set under a genuine signature.
func resign(tok string, p any) string {
	parts := strings.Split(tok, ".")
	b, _ := json.Marshal(p)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
}

func TestDelegatedTokenRoundTrip(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	now := time.Unix(1_800_000_000, 0)
	tok, err := SignDelegatedToken(priv, delegatedClaims(now, "planner", "reviewer"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Act.Subject != "agent:reviewer" || c.Act.Act.Subject != "agent:planner" || c.Act.Act.Act != nil {
		t.Fatalf("RFC 8693: the top-level act is the current actor: %+v", c.Act)
	}
	s := c.AsSubject()
	if s.ID != "alice@acme.example" || s.Kind != "" || s.Delegation.Depth() != 2 || s.Delegation.Current().Agent != "reviewer" ||
		s.Delegation.Chain() != "planner>reviewer" || len(s.Delegation.Models) != 1 || s.Delegation.ID != "d1" {
		t.Fatalf("subject: %+v %+v", s, s.Delegation)
	}
}

// TestDelegatedTokenRejections: every way to forge, extend or stretch a
// delegated credential fails verification (and signing refuses to mint it).
func TestDelegatedTokenRejections(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	_, otherPriv, _ := workloadKey(t)
	now := time.Unix(1_800_000_000, 0)
	good, err := SignDelegatedToken(priv, delegatedClaims(now, "planner"))
	if err != nil {
		t.Fatal(err)
	}
	byOther, _ := SignDelegatedToken(otherPriv, delegatedClaims(now, "planner"))
	mod := func(f func(*DelegatedClaims)) DelegatedClaims {
		c := delegatedClaims(now, "planner")
		f(&c)
		return c
	}
	wl, _ := SignWorkloadToken(priv, workloadClaims(now))
	cases := map[string]string{
		"act swapped":       resign(good, mod(func(c *DelegatedClaims) { c.Act = &Act{Subject: "agent:admin"} })),
		"act extended":      resign(good, mod(func(c *DelegatedClaims) { c.Act = &Act{Subject: "agent:x", Act: c.Act} })),
		"act dropped":       resign(good, mod(func(c *DelegatedClaims) { c.Act = nil })),
		"subject swapped":   resign(good, mod(func(c *DelegatedClaims) { c.Subject = "ceo@acme.example" })),
		"models widened":    resign(good, mod(func(c *DelegatedClaims) { c.Models = nil })),
		"other key":         byOther,
		"workload as agent": strings.Replace(wl, strings.Split(wl, ".")[0], strings.Split(good, ".")[0], 1),
		"not a jws":         "a.b",
		"expired":           mustSign(t, priv, mod(func(c *DelegatedClaims) {}), now.Add(-time.Hour)),
		"lifetime over 1h":  resign(good, mod(func(c *DelegatedClaims) { c.Expiry = c.IssuedAt + 7200 })),
		"cycle": resign(good, mod(func(c *DelegatedClaims) {
			c.Act = ActFromChain([]policy.Actor{{Agent: "a"}, {Agent: "b"}, {Agent: "a"}})
		})),
		"too deep":           resign(good, mod(func(c *DelegatedClaims) { c.Act = ActFromChain(chainOf(policy.MaxAgentDepth + 1)) })),
		"actor not an agent": resign(good, mod(func(c *DelegatedClaims) { c.Act = &Act{Subject: "agent:Bad Name"} })),
		"human root as workload": resign(good, mod(func(c *DelegatedClaims) {
			c.Subject = "workload:gh:acme/app"
		})),
		"workload root without prefix": resign(good, mod(func(c *DelegatedClaims) { c.RootKind = policy.SubjectWorkload })),
		"unknown claim": func() string {
			parts := strings.Split(good, ".")
			b, _ := base64.RawURLEncoding.DecodeString(parts[1])
			b = []byte(strings.Replace(string(b), `{"iss"`, `{"admin":true,"iss"`, 1))
			return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
		}(),
	}
	for name, tok := range cases {
		if _, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, tok, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, c := range map[string]DelegatedClaims{
		"too deep": mod(func(c *DelegatedClaims) { c.Act = ActFromChain(chainOf(policy.MaxAgentDepth + 1)) }),
		"cycle":    mod(func(c *DelegatedClaims) { c.Act = ActFromChain([]policy.Actor{{Agent: "a"}, {Agent: "a"}}) }),
		"no act":   mod(func(c *DelegatedClaims) { c.Act = nil }),
	} {
		if _, err := SignDelegatedToken(priv, c); err == nil {
			t.Errorf("signed %s", name)
		}
	}
}

func chainOf(n int) []policy.Actor {
	out := make([]policy.Actor, n)
	for i := range out {
		out[i] = policy.Actor{Agent: "a" + string(rune('a'+i))}
	}
	return out
}

func mustSign(t *testing.T, priv ed25519.PrivateKey, c DelegatedClaims, iat time.Time) string {
	t.Helper()
	c.IssuedAt, c.NotBefore, c.Expiry = iat.Unix(), iat.Unix(), iat.Add(10*time.Minute).Unix()
	tok, err := SignDelegatedToken(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestWorkloadJWTDelegated: the gateway verifier accepts a delegated
// credential as the root principal with the chain attached, and refuses (never
// falls through to the human verifier) a token that only claims the typ.
func TestWorkloadJWTDelegated(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	now := time.Unix(1_800_000_000, 0)
	next := &recordingVerifier{}
	v := &WorkloadJWT{Keys: []ed25519.PublicKey{pub}, Next: next, Now: func() time.Time { return now }}
	tok, _ := SignDelegatedToken(priv, delegatedClaims(now, "planner"))
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	s, err := v.Verify(r)
	if err != nil || s.ID != "alice@acme.example" || s.Delegation.Current().Agent != "planner" {
		t.Fatalf("verify: %+v %v", s, err)
	}
	r.Header.Set("Authorization", "Bearer "+resign(tok, delegatedClaims(now, "admin")))
	if _, err := v.Verify(r); err == nil || next.called {
		t.Fatalf("forged delegated token: err=%v fell through=%v", err, next.called)
	}
}

type recordingVerifier struct{ called bool }

func (r *recordingVerifier) Verify(*http.Request) (policy.Subject, error) {
	r.called = true
	return policy.Subject{}, errors.New("human verifier")
}
