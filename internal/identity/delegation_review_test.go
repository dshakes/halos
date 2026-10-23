package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// TestCheckChainLabels (L2): actor harness and session are labels in
// [A-Za-z0-9._:-] within a length cap; anything else could forge structure
// in the audit chain detail or reach a terminal.
func TestCheckChainLabels(t *testing.T) {
	for _, a := range []policy.Actor{
		{Agent: "p", Harness: "claude-code", Session: "0f3a:b.c_d-e"},
		{Agent: "p"},
	} {
		if err := CheckChain([]policy.Actor{a}); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
	for _, a := range []policy.Actor{
		{Agent: "p", Harness: "codex/s)>admin(x"},
		{Agent: "p", Session: "s\n"},
		{Agent: "p", Session: "\x1b[2J"},
		{Agent: "p", Harness: "claude code"},
		{Agent: "p", Session: "é"},
		{Agent: "p", Harness: strings.Repeat("a", maxActorHarness+1)},
		{Agent: "p", Session: strings.Repeat("a", maxActorSession+1)},
	} {
		if err := CheckChain([]policy.Actor{a}); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

// TestExpiredIsDistinguishable: an expired credential whose signature
// verified is ErrTokenExpired (egress does not count it as an authentication
// failure); a forged one is not; auth_time reaches the subject.
func TestExpiredIsDistinguishable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := priv.Public().(ed25519.PublicKey)
	now := time.Unix(1_800_000_000, 0)
	c := DelegatedClaims{Issuer: WorkloadIssuer, Subject: "alice@acme.example", Audience: WorkloadAudience, Kind: KindAgent,
		Act: ActFromChain([]policy.Actor{{Agent: "p"}}), AuthTime: now.Unix() - 60, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(time.Minute).Unix(), ID: "j"}
	tok, err := SignDelegatedToken(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, tok, now)
	if err != nil || got.AsSubject().Delegation.AuthTime != c.AuthTime {
		t.Fatalf("auth_time not carried: %v %+v", err, got.AsSubject().Delegation)
	}
	if _, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, tok, now.Add(2*time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	forged, _ := SignDelegatedToken(other, c)
	if _, err := VerifyDelegatedToken([]ed25519.PublicKey{pub}, forged, now.Add(2*time.Minute)); err == nil || errors.Is(err, ErrTokenExpired) {
		t.Fatalf("forged and expired must not read as merely expired: %v", err)
	}
	wl, _ := SignWorkloadToken(priv, WorkloadClaims{Issuer: WorkloadIssuer, Subject: "workload:gh:a/b", Audience: WorkloadAudience, Kind: policy.SubjectWorkload,
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(time.Minute).Unix(), ID: "w"})
	if _, err := VerifyWorkloadToken([]ed25519.PublicKey{pub}, wl, now.Add(2*time.Minute)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired workload: %v", err)
	}
}
