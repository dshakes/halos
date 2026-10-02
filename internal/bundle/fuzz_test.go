package bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/release"
)

// FuzzPullRingPointer: halod's ring pointer verification. A registry that can
// serve any pointer payload, signature or signature type must never get a
// release accepted unless the payload is byte-for-byte the one the signer
// signed; and the genuine pointer must keep verifying. Nothing may panic.
func FuzzPullRingPointer(f *testing.F) {
	ctx := context.Background()
	store := memory.New()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	s, _ := ParseEd25519Signer(priv)
	v, _ := ParseEd25519Verifier(pub)
	rel, err := release.Build(res{}, "p", "ga", release.Options{Version: "1", Org: "acme"})
	if err != nil {
		f.Fatal(err)
	}
	if _, err := Publish(ctx, store, rel, s, "ga"); err != nil {
		f.Fatal(err)
	}
	pd, _ := store.Resolve(ctx, PointerTag("ga"))
	mb, _ := content.FetchAll(ctx, store, pd)
	var m ocispec.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		f.Fatal(err)
	}
	genuine, _ := content.FetchAll(ctx, store, m.Config)
	genuineSig, _ := base64.StdEncoding.DecodeString(m.Annotations[AnnSignature])
	opts := RingOptions{Org: "acme", Ring: "ga", Now: time.Now()}

	var p Pointer
	_ = json.Unmarshal(genuine, &p)
	seeds := []Pointer{p}
	q := p
	q.Seq++
	seeds = append(seeds, q)
	q = p
	q.ExpiresAt = q.ExpiresAt.Add(365 * 24 * time.Hour)
	seeds = append(seeds, q)
	q = p
	q.Org = "evil"
	seeds = append(seeds, q)
	q = p
	q.Ring = "canary"
	seeds = append(seeds, q)
	q = p
	q.Digest = "sha256:" + strings.Repeat("0", 64)
	seeds = append(seeds, q)
	for _, sp := range seeds {
		b, _ := json.Marshal(sp)
		f.Add(b, genuineSig, "ed25519")
	}
	f.Add(genuine, genuineSig, "ed25519")
	f.Add(genuine, []byte{}, "ed25519")
	f.Add(genuine, genuineSig, "cosign")
	f.Add([]byte(`{"org":"acme","ring":"ga"`), genuineSig, "ed25519")
	f.Add(bytes.Repeat([]byte("x"), maxPointerPayloadSize+1), genuineSig, "ed25519")

	f.Fuzz(func(t *testing.T, payload, sig []byte, sigType string) {
		// A fresh tag per input: the memory store is content-addressed, so a
		// repeated payload reuses its blob and only the tag moves.
		st := memory.New()
		if err := oras.CopyGraph(ctx, store, st, pd, oras.DefaultCopyGraphOptions); err != nil {
			t.Fatal(err)
		}
		// Copy the release graph too (PullRing fetches it after the pointer).
		if rd, err := store.Resolve(ctx, RingTag("ga")); err == nil {
			_ = oras.CopyGraph(ctx, store, st, rd, oras.DefaultCopyGraphOptions)
		}
		cfg := content.NewDescriptorFromBytes(PointerConfigType, payload)
		if err := st.Push(ctx, cfg, bytes.NewReader(payload)); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatal(err)
		}
		ann := map[string]string{AnnSigType: sigType, AnnSignature: base64.StdEncoding.EncodeToString(sig)}
		nd, err := oras.PackManifest(ctx, st, oras.PackManifestVersion1_1, PointerArtifactType, oras.PackManifestOptions{ConfigDescriptor: &cfg, ManifestAnnotations: ann})
		if err != nil {
			return // oras refused to pack it; nothing for halod to read
		}
		if err := st.Tag(ctx, nd, PointerTag("ga")); err != nil {
			t.Fatal(err)
		}
		got, gp, err := PullRing(ctx, st, v, opts)
		same := bytes.Equal(payload, genuine) && bytes.Equal(sig, genuineSig) && sigType == "ed25519"
		switch {
		case err == nil && !same:
			t.Fatalf("accepted a pointer that was not the signed one: %+v", gp)
		case err == nil && got.Digest != rel.Digest:
			t.Fatalf("accepted pointer resolved to release %s, want %s", got.Digest, rel.Digest)
		case err != nil && same:
			t.Fatalf("genuine pointer refused: %v", err)
		}
	})
}
