package bundle

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

type ad struct{}

func (ad) Name() string                       { return "bundletest" }
func (ad) Capabilities() []harness.Capability { return nil }
func (ad) InstallCommand(v string, _ harness.OS) string {
	return "echo " + v
}
func (ad) Render(_ *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	return []harness.File{{Path: "/etc/x", Mode: 0o644, Data: []byte("ring=" + c.Ring)}}, nil, nil
}

type res struct{}

func (res) ResolveProfile(string) (*policy.Profile, error) {
	return &policy.Profile{Harnesses: map[string]policy.HarnessSpec{"bundletest": {Version: "1.0.0"}}}, nil
}

func init() { harness.Register(ad{}) }

func mkRel(t *testing.T, ver, ring string) *release.Release {
	t.Helper()
	r, err := release.Build(res{}, "p", ring, release.Options{Version: ver, Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func keys(t *testing.T) (Ed25519Signer, Ed25519Verifier) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseEd25519Signer(priv)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseEd25519Verifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func TestPublishPullRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	rel := mkRel(t, "1", "canary")
	if _, err := Publish(ctx, store, rel, s, "canary"); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"ring-canary", "v1"} {
		got, err := Pull(ctx, store, tag, v)
		if err != nil || got.Digest != rel.Digest {
			t.Fatalf("pull %s: %v", tag, err)
		}
	}
	// re-publishing identical release is idempotent
	if _, err := Publish(ctx, store, rel, s, "canary"); err != nil {
		t.Fatalf("idempotent republish: %v", err)
	}
}

// Regression: oras stamps the push time into the manifest unless told
// otherwise, so a republish in the next second got a new digest and was
// refused as an immutable-tag violation (a CI flake).
func TestRepublishAcrossSecondBoundaryIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, _ := keys(t)
	rel := mkRel(t, "1", "canary")
	d1, err := Publish(ctx, store, rel, s, "canary")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 10*time.Millisecond)))
	d2, err := Publish(ctx, store, rel, s, "canary")
	if err != nil {
		t.Fatalf("republish in the next second: %v", err)
	}
	if d1.Digest != d2.Digest {
		t.Fatalf("manifest digest changed across republish: %s != %s", d1.Digest, d2.Digest)
	}
}

func TestImmutableVersionTagAndRollback(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	r1 := mkRel(t, "1", "ga")
	if _, err := Publish(ctx, store, r1, s, "ga"); err != nil {
		t.Fatal(err)
	}
	other := mkRel(t, "1", "different") // same version, different content
	if _, err := Publish(ctx, store, other, s); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("want immutable error, got %v", err)
	}
	r2 := mkRel(t, "2", "ga")
	if _, err := Publish(ctx, store, r2, s, "ga"); err != nil {
		t.Fatal(err)
	}
	if got, _ := Pull(ctx, store, "ring-ga", v); got.Digest != r2.Digest {
		t.Fatal("ring should be at v2")
	}
	if _, err := PromoteRing(ctx, store, Source{Version: "1"}, "ga", s, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := Pull(ctx, store, "ring-ga", v); got.Digest != r1.Digest {
		t.Fatal("rollback did not repoint ring")
	}
}

func TestPullRejects(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	s, v := keys(t)
	_, v2 := keys(t)
	if _, err := Publish(ctx, store, mkRel(t, "1", "r"), s, "r"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		tag  string
		v    Verifier
		want string
	}{
		{"wrong key", "ring-r", v2, "verify"},
		{"nil verifier", "ring-r", nil, "without a verifier"},
		{"missing tag", "ring-none", v, "resolve"},
		{"wrong sig type", "ring-r", Cosign{Key: "k", Runner: nil}, "signature type"},
	}
	for _, tt := range tests {
		_, err := Pull(ctx, store, tt.tag, tt.v)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v want %q", tt.name, err, tt.want)
		}
	}
}

func TestCosignShellsOut(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if args[0] == "sign-blob" {
			for i, a := range args {
				if a == "--output-signature" {
					return nil, os.WriteFile(args[i+1], []byte("SIG"), 0o600)
				}
			}
		}
		return nil, nil
	}
	c := Cosign{Key: "cosign.key", Runner: run}
	sig, err := c.Sign(context.Background(), "sha256:abc")
	if err != nil || string(sig) != "SIG" {
		t.Fatalf("sign: %q %v", sig, err)
	}
	if err := c.Verify(context.Background(), "sha256:abc", sig); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1][1] != "verify-blob" {
		t.Fatalf("calls: %v", calls)
	}
	// L5: key-based signing never uploads to public Rekor
	if !strings.Contains(strings.Join(calls[0], " "), "--tlog-upload=false") || !strings.Contains(strings.Join(calls[1], " "), "--insecure-ignore-tlog=true") {
		t.Fatalf("tlog flags missing: %v", calls)
	}
	calls = nil
	if _, err := (Cosign{Key: "k", Keyless: true, Runner: run}).Sign(context.Background(), "sha256:abc"); err != nil || strings.Contains(strings.Join(calls[0], " "), "tlog") {
		t.Fatalf("keyless must keep tlog: %v %v", calls, err)
	}
	fail := Cosign{Key: "k", Runner: func(context.Context, string, ...string) ([]byte, error) {
		return []byte("bad"), errors.New("exit 1")
	}}
	if err := fail.Verify(context.Background(), "d", []byte("s")); err == nil {
		t.Fatal("verify failure not propagated")
	}
}

func TestParseRef(t *testing.T) {
	for in, want := range map[string][2]string{
		"localhost:5000/a/b:ring-x": {"localhost:5000/a/b", "ring-x"},
		"ghcr.io/a/b":               {"ghcr.io/a/b", ""},
		"localhost:5000/a/b":        {"localhost:5000/a/b", ""},
	} {
		if r, tg := ParseRef(in); r != want[0] || tg != want[1] {
			t.Errorf("%s: %s %s", in, r, tg)
		}
	}
}
