package identity

import (
	"crypto/ed25519"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// TestDelegatedLineage (ADR-0026): a credential carries its parent's and its
// ancestors' jtis so revoking any of them kills it; the claim is bounded,
// needs a parent_jti, and reaches the verified subject, as a workload
// credential's jti and iat do.
func TestDelegatedLineage(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	now := time.Unix(1_800_000_000, 0)
	c := delegatedClaims(now, "planner", "reviewer")
	c.Parent, c.Ancestors = "p1", []string{"w1"}
	tok, err := SignDelegatedToken(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, tok, now)
	if err != nil {
		t.Fatal(err)
	}
	if s := got.AsSubject(); s.Credential == nil || strings.Join(s.Credential.IDs, ",") != "d1,p1,w1" || s.Credential.IssuedAt != now.Unix() {
		t.Fatalf("lineage on the subject: %+v", s.Credential)
	}
	for name, mut := range map[string]func(*DelegatedClaims){
		"ancestors without a parent": func(c *DelegatedClaims) { c.Parent = "" },
		"empty ancestor":             func(c *DelegatedClaims) { c.Ancestors = []string{""} },
		"too many ancestors":         func(c *DelegatedClaims) { c.Ancestors = strings.Split("a,b,c,d,e,f", ",") },
	} {
		bad := c
		mut(&bad)
		if _, err := SignDelegatedToken(priv, bad); err == nil {
			t.Errorf("%s: signed", name)
		}
		if _, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, resign(tok, bad), now); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	wtok, err := SignWorkloadToken(priv, WorkloadClaims{Issuer: WorkloadIssuer, Subject: "workload:gh:acme/app", Audience: WorkloadAudience,
		Kind: policy.SubjectWorkload, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(time.Minute).Unix(), ID: "w1"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+wtok)
	s, err := (&WorkloadJWT{Keys: []ed25519.PublicKey{pub}, Now: func() time.Time { return now }}).Verify(r)
	if err != nil || s.Credential == nil || s.Credential.IDs[0] != "w1" || s.Credential.IssuedAt != now.Unix() {
		t.Fatalf("workload credential on the subject: %+v %v", s.Credential, err)
	}
}
