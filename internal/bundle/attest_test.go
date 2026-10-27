package bundle

import (
	"context"
	"strings"
	"testing"

	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/release"
)

func attested(t *testing.T, ver string) *release.Release {
	t.Helper()
	rel := mkRel(t, ver, "canary")
	a, err := release.Attest(rel, nil, release.AttestOptions{HalosVersion: "0.4.0"})
	if err != nil {
		t.Fatal(err)
	}
	rel.Attestations = a
	return rel
}

func TestPublishPullAttestations(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	rel := attested(t, "1")
	if _, err := Publish(ctx, store, rel, s, "canary"); err != nil {
		t.Fatal(err)
	}
	got, atts, err := PullAttestations(ctx, store, "v1", v)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest != rel.Digest || len(atts) != 1 || string(atts[0].BOM) != string(rel.Attestations.BOM) {
		t.Fatalf("pulled %s with %d attestations", got.Digest, len(atts))
	}
	// Republishing is idempotent: the same referrer, not a second one.
	if _, err := Publish(ctx, store, rel, s, "canary"); err != nil {
		t.Fatal(err)
	}
	if _, atts, _ := PullAttestations(ctx, store, "v1", v); len(atts) != 1 {
		t.Fatalf("%d attestations after republish", len(atts))
	}
	if _, _, err := PullAttestations(ctx, store, "v1", nil); err == nil {
		t.Fatal("pulled without a verifier")
	}
}

func TestPullAttestationsRejects(t *testing.T) {
	ctx := context.Background()
	s, v := keys(t)
	other, _ := keys(t)

	// No attestation at all.
	bare := memory.New()
	if _, err := Publish(ctx, bare, mkRel(t, "1", "canary"), s, "canary"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullAttestations(ctx, bare, "v1", v); err == nil || !strings.Contains(err.Error(), "no attestation") {
		t.Fatalf("bare release: %v", err)
	}

	// Attestations signed by a key the verifier does not trust: the release
	// itself must be signed by the trusted key, so publish it first.
	store := memory.New()
	rel := attested(t, "1")
	plain := *rel
	plain.Attestations = nil
	if _, err := Publish(ctx, store, &plain, s, "canary"); err != nil {
		t.Fatal(err)
	}
	desc, err := store.Resolve(ctx, "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := pushAttestations(ctx, store, desc, rel, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullAttestations(ctx, store, "v1", v); err == nil || !strings.Contains(err.Error(), "no attestation that verifies") {
		t.Fatalf("foreign-key attestation accepted: %v", err)
	}

	// Correctly signed attestations that describe a different release.
	forged := *rel
	forged.Attestations = attested(t, "2").Attestations
	if err := pushAttestations(ctx, store, desc, &forged, s); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullAttestations(ctx, store, "v1", v); err == nil || !strings.Contains(err.Error(), "describes a release other than") {
		t.Fatalf("mismatched attestation accepted: %v", err)
	}

	// A genuine one alongside the forgeries is found.
	if err := pushAttestations(ctx, store, desc, rel, s); err != nil {
		t.Fatal(err)
	}
	if _, atts, err := PullAttestations(ctx, store, "v1", v); err != nil || len(atts) != 1 {
		t.Fatalf("genuine attestation: %d, %v", len(atts), err)
	}
}
