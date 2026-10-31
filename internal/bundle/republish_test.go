package bundle

import (
	"context"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
)

// M3: republishing reuses the existing manifest only when it is exactly what
// this publish would write; a co-signer added since is never silently dropped.
func TestRepublishReuseRules(t *testing.T) {
	ctx := context.Background()
	cs, _ := ecKeys(t)
	es, ev := keys(t)
	cos := Cosign{Key: "k", Runner: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		for i, a := range args {
			if a == "--output-signature" {
				return nil, writeFile(args[i+1], "COSIG")
			}
		}
		return nil, nil
	}}
	rel := mkRel(t, "1", "r")
	immutable := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "immutable") {
			t.Fatalf("want the immutability error, got %v", err)
		}
	}

	t.Run("co-signer added since: refused, not dropped", func(t *testing.T) {
		store := memory.New()
		if _, err := Publish(ctx, store, rel, cs, "r"); err != nil {
			t.Fatal(err)
		}
		_, err := Publish(ctx, store, rel, MultiSigner{cs, es}, "r")
		immutable(t, err)
		if _, _, err := PullRing(ctx, store, ev, RingOptions{Org: "acme", Ring: "r", Now: time.Now()}); err == nil {
			t.Fatal("ed25519-only halod verified a release the co-signer never signed")
		}
	})
	t.Run("cosign co-signer added since: refused", func(t *testing.T) {
		store := memory.New()
		if _, err := Publish(ctx, store, rel, cs, "r"); err != nil {
			t.Fatal(err)
		}
		_, err := Publish(ctx, store, rel, MultiSigner{cs, cos}, "r")
		immutable(t, err)
	})
	t.Run("same co-signed publish again: reused", func(t *testing.T) {
		store := memory.New()
		first, err := Publish(ctx, store, rel, MultiSigner{cs, es}, "r")
		if err != nil {
			t.Fatal(err)
		}
		again, err := Publish(ctx, store, rel, MultiSigner{cs, es}, "r")
		if err != nil || again.Digest != first.Digest {
			t.Fatalf("republish: %v", err)
		}
	})
	t.Run("co-signer dropped since: refused", func(t *testing.T) {
		store := memory.New()
		if _, err := Publish(ctx, store, rel, MultiSigner{cs, es}, "r"); err != nil {
			t.Fatal(err)
		}
		_, err := Publish(ctx, store, rel, cs, "r")
		immutable(t, err)
	})
	t.Run("co-signature by another key of the same algorithm: refused", func(t *testing.T) {
		store := memory.New()
		es2, _ := keys(t)
		if _, err := Publish(ctx, store, rel, MultiSigner{cs, es2}, "r"); err != nil {
			t.Fatal(err)
		}
		_, err := Publish(ctx, store, rel, MultiSigner{cs, es}, "r")
		immutable(t, err)
	})
	t.Run("unknown extra annotation: refused", func(t *testing.T) {
		store := memory.New()
		desc, err := Publish(ctx, store, rel, cs, "r")
		if err != nil {
			t.Fatal(err)
		}
		m := manifestAt(t, store, "v1")
		m.Annotations["org.example.injected"] = "x"
		forged, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
			ConfigDescriptor: &m.Config, Layers: m.Layers, ManifestAnnotations: m.Annotations,
		})
		if err != nil || forged.Digest == desc.Digest {
			t.Fatalf("pack: %v", err)
		}
		if err := store.Tag(ctx, forged, "v1"); err != nil {
			t.Fatal(err)
		}
		_, err = Publish(ctx, store, rel, cs, "r")
		immutable(t, err)
	})
	_ = ocispec.AnnotationCreated
}

// M3, Stage path: re-staging after a co-signer was added is refused too.
func TestStageCoSignerAddedRefused(t *testing.T) {
	ctx := context.Background()
	cs, _ := ecKeys(t)
	es, _ := keys(t)
	store := memory.New()
	rel := mkRel(t, "1", "r")
	if _, err := Stage(ctx, store, rel, cs); err != nil {
		t.Fatal(err)
	}
	if already, err := Stage(ctx, store, rel, cs); err != nil || !already {
		t.Fatalf("same restage: already=%v err=%v", already, err)
	}
	if _, err := Stage(ctx, store, rel, MultiSigner{cs, es}); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("restage with an added co-signer: %v", err)
	}
}
