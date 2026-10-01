package bundle

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/halos-dev/halos/internal/release"
)

// countingTarget records layer fetches so tests prove nothing was downloaded
// before verification.
type countingTarget struct {
	oras.Target
	layerFetches int
}

func (c *countingTarget) Fetch(ctx context.Context, d ocispec.Descriptor) (io.ReadCloser, error) {
	if d.MediaType == LayerMediaType {
		c.layerFetches++
	}
	return c.Target.Fetch(ctx, d)
}

func mkRelNoOrg(ver string) (*release.Release, error) {
	return release.Build(res{}, "p", "r", release.Options{Version: ver})
}

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

func TestPullRing(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	r1, r2 := mkRel(t, "1", "ga"), mkRel(t, "2", "ga")
	if _, err := Publish(ctx, store, r1, s, "ga"); err != nil {
		t.Fatal(err)
	}
	p1, _, err := ReadPointer(ctx, store, "ga", v)
	if err != nil || p1.Seq < uint64(time.Now().Unix()-5) || p1.Digest != r1.Digest || p1.Org != "acme" {
		t.Fatalf("first pointer %+v %v", p1, err)
	}
	if _, err := Publish(ctx, store, r2, s, "ga"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ok := RingOptions{Org: "acme", Ring: "ga", Now: now}

	rel, p2, err := PullRing(ctx, store, v, ok)
	if err != nil || rel.Digest != r2.Digest || p2.Seq <= p1.Seq {
		t.Fatalf("pull ga: %v seq=%d", err, p2.Seq)
	}
	if exp := p2.ExpiresAt.Sub(p2.IssuedAt); exp != DefaultPointerTTL {
		t.Fatalf("validity %v", exp)
	}

	// rollback = new pointer with higher seq at the old digest: accepted
	if _, err := PromoteRing(ctx, store, Source{Version: "1"}, "ga", s, nil); err != nil {
		t.Fatal(err)
	}
	withSeen := ok
	withSeen.MinSeq, withSeen.LastDigest = p2.Seq, r2.Digest
	rel, p3, err := PullRing(ctx, store, v, withSeen)
	if err != nil || rel.Digest != r1.Digest || p3.Seq <= p2.Seq {
		t.Fatalf("rollback via higher seq: %v %+v", err, p3)
	}
	// refresh keeps the digest, bumps seq
	ps, err := RefreshRing(ctx, store, "ga", s, nil)
	if err != nil {
		t.Fatal(err)
	}
	p4 := ps[0]
	if p4.Seq <= p3.Seq || p4.Digest != r1.Digest {
		t.Fatalf("refresh %+v %v", p4, err)
	}

	tests := []struct {
		name string
		mod  func(o *RingOptions)
		want string
	}{
		{"older seq (replayed pointer)", func(o *RingOptions) { o.MinSeq = p4.Seq + 1 }, "rollback/replay"},
		{"same seq different digest", func(o *RingOptions) { o.MinSeq, o.LastDigest = p4.Seq, r2.Digest }, "reused"},
		{"wrong ring", func(o *RingOptions) { o.Ring = "canary" }, "no signed pointer"},
		{"wrong org", func(o *RingOptions) { o.Org = "evil" }, "org"},
		{"expired", func(o *RingOptions) { o.Now = now.Add(DefaultPointerTTL + time.Hour) }, "expired"},
		{"oversize layer", func(o *RingOptions) { o.MaxLayerSize = 10 }, "exceeds limit"},
	}
	for _, tt := range tests {
		o := ok
		tt.mod(&o)
		ct := &countingTarget{Target: store}
		_, _, err := PullRing(ctx, ct, v, o)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v want %q", tt.name, err, tt.want)
		}
		if ct.layerFetches != 0 {
			t.Errorf("%s: layer fetched before rejection", tt.name)
		}
	}
	// same seq, same digest is fine (steady state)
	o := ok
	o.MinSeq, o.LastDigest = 4, r1.Digest
	if _, _, err := PullRing(ctx, store, v, o); err != nil {
		t.Fatalf("steady state: %v", err)
	}
}

// A pointer signed for one ring copied under another ring's tag is refused,
// as is a pointer signed by a foreign key.
func TestPointerCrossRingAndForeignKey(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	if _, err := Publish(ctx, store, mkRel(t, "1", "canary"), s, "canary"); err != nil {
		t.Fatal(err)
	}
	d, err := store.Resolve(ctx, PointerTag("canary"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, d, PointerTag("ga")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "ga", Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "signed for ring") {
		t.Fatalf("cross-ring pointer: %v", err)
	}
	_, v2 := keys(t)
	if _, _, err := PullRing(ctx, store, v2, RingOptions{Org: "acme", Ring: "canary", Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "verify pointer") {
		t.Fatalf("foreign key: %v", err)
	}
	// publisher refuses to build on a pointer it cannot verify
	s2, _ := keys(t)
	if _, err := PromoteRing(ctx, store, Source{Version: "1"}, "canary", s2, nil); err == nil {
		t.Fatal("foreign signer promoted")
	}
}

// Tampered pointer payload (e.g. seq bumped by the registry) fails signature.
func TestPointerTamperedPayload(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	if _, err := Publish(ctx, store, mkRel(t, "1", "ga"), s, "ga"); err != nil {
		t.Fatal(err)
	}
	pd, _ := store.Resolve(ctx, PointerTag("ga"))
	mb, _ := content.FetchAll(ctx, store, pd)
	var m ocispec.Manifest
	_ = json.Unmarshal(mb, &m)
	payload, _ := content.FetchAll(ctx, store, m.Config)
	var p Pointer
	_ = json.Unmarshal(payload, &p)
	p.Seq = 99
	np, _ := json.Marshal(p)
	cfg := content.NewDescriptorFromBytes(PointerConfigType, np)
	_ = store.Push(ctx, cfg, strings.NewReader(string(np)))
	nd, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, PointerArtifactType, oras.PackManifestOptions{ConfigDescriptor: &cfg, ManifestAnnotations: m.Annotations})
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Tag(ctx, nd, PointerTag("ga"))
	if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "ga", Now: time.Now()}); err == nil || !strings.Contains(err.Error(), "verify pointer") {
		t.Fatalf("tampered pointer: %v", err)
	}
}

func TestPublishSignerRules(t *testing.T) {
	ctx := context.Background()
	s, v := keys(t)
	cos := Cosign{Key: "k", Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) { return nil, nil }}
	if _, err := Publish(ctx, memory.New(), mkRel(t, "1", "r"), cos, "r"); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Fatalf("cosign-only publish: %v", err)
	}
	noOrg, err := mkRelNoOrg("1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(ctx, memory.New(), noOrg, s, "r"); err == nil || !strings.Contains(err.Error(), "org") {
		t.Fatalf("org-less ring publish: %v", err)
	}
	// ed25519 + cosign co-signature: both verifiable
	var signed []string
	cos.Runner = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		signed = append(signed, args[0])
		for i, a := range args {
			if a == "--output-signature" {
				return nil, writeFile(args[i+1], "COSIG")
			}
		}
		return nil, nil
	}
	store := memory.New()
	if _, err := Publish(ctx, store, mkRel(t, "1", "r"), MultiSigner{s, cos}, "r"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "r", Now: time.Now()}); err != nil {
		t.Fatalf("ed25519 pull of co-signed release: %v", err)
	}
	if _, err := Pull(ctx, store, "v1", cos); err != nil {
		t.Fatalf("cosign co-signature verify: %v", err)
	}
	if len(signed) == 0 || signed[0] != "sign-blob" {
		t.Fatalf("cosign not invoked: %v", signed)
	}
}
