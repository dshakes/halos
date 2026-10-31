package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
)

// ADR-0038: publish with --key-uri (an ECDSA P-256 file key standing in for a
// KMS key), export its public key with `halo keys public`, and verify the
// ring the way halod does with that exported key only.
func TestReleaseKeyURI(t *testing.T) {
	ex := buildable(t)
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Cleanup(func() { dialRegistry = old })
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	dir := t.TempDir()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	keyPath := filepath.Join(dir, "release.key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	uri := "file://" + keyPath
	pubPath := filepath.Join(dir, "release.pub")

	code, out, errs := halo(t, "--output", "json", "keys", "public", "--key-uri", uri, "--out", pubPath)
	if code != 0 {
		t.Fatalf("keys public: %d %s", code, errs)
	}
	var pub struct{ Algorithm, KeyID, Backend, PublicKey string }
	if err := json.Unmarshal([]byte(out), &pub); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if pub.Algorithm != bundle.AlgECDSAP256 || pub.Backend != "file" || !strings.HasPrefix(pub.KeyID, "sha256:") || !strings.Contains(pub.PublicKey, "PUBLIC KEY") {
		t.Fatalf("keys public: %+v", pub)
	}
	if code, _, _ := halo(t, "keys", "public", "--key-uri", uri, "--out", pubPath); code == 0 {
		t.Fatal("keys public overwrote an existing file")
	}

	reg := "registry.test/acme/halos"
	if code, _, errs := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.0", "--registry", reg, "--key-uri", uri); code != 0 {
		t.Fatalf("publish: %d %s", code, errs)
	}
	pemb, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := bundle.ParseVerifier(pemb)
	if err != nil {
		t.Fatal(err)
	}
	rel, _, err := bundle.PullRing(context.Background(), store, bundle.Keyring{v}, bundle.RingOptions{Org: "acme-corp", Ring: "ring3-ga", Now: time.Now()})
	if err != nil || rel.Manifest.Version != "1.0.0" {
		t.Fatalf("halod-style pull with the exported key: %v", err)
	}

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"both key flags", []string{"release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.1", "--registry", reg, "--key", keyPath, "--key-uri", uri}, "only one of --key and --key-uri"},
		{"unknown scheme", []string{"release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.1", "--registry", reg, "--key-uri", "gcpkms://x"}, "unsupported key URI scheme"},
		{"keys public needs a uri", []string{"keys", "public"}, "--key-uri is required"},
	} {
		if code, _, e := halo(t, c.args...); code == 0 || !strings.Contains(e, c.want) {
			t.Errorf("%s: %d %s", c.name, code, e)
		}
	}
}

// --co-key-uri: an ECDSA (KMS-style) primary co-signed by the old ed25519 key;
// halods trusting either key verify; a same-algorithm co-key is refused.
func TestReleaseCoKeyURI(t *testing.T) {
	ex := buildable(t)
	store := memory.New()
	old := dialRegistry
	dialRegistry = func(string, bool) (oras.Target, error) { return store, nil }
	t.Cleanup(func() { dialRegistry = old })
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	if code, _, errs := halo(t, "keys", "generate", "--out", dir, "--name", "old"); code != 0 {
		t.Fatalf("keys: %s", errs)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	newKey := filepath.Join(dir, "new.key")
	if err := os.WriteFile(newKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := "registry.test/acme/halos"
	if code, _, errs := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.0",
		"--registry", reg, "--key-uri", "file://"+newKey, "--co-key-uri", "file://"+filepath.Join(dir, "old.key")); code != 0 {
		t.Fatalf("publish: %d %s", code, errs)
	}
	oldPub, err := os.ReadFile(filepath.Join(dir, "old.pub"))
	if err != nil {
		t.Fatal(err)
	}
	ov, err := bundle.ParseVerifier(oldPub)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]bundle.Verifier{"old ed25519 key": ov, "new ecdsa key": bundle.ECDSAVerifier{Key: &k.PublicKey}} {
		if _, _, err := bundle.PullRing(context.Background(), store, v, bundle.RingOptions{Org: "acme-corp", Ring: "ring3-ga", Now: time.Now()}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if code, _, e := halo(t, "release", "publish", "--no-artifacts", ex, "--ring", "ring3-ga", "--release-version", "1.0.1",
		"--registry", reg, "--key-uri", "file://"+newKey, "--co-key-uri", "file://"+newKey); code == 0 || !strings.Contains(e, "other algorithm") {
		t.Fatalf("same-algorithm co-key: %d %s", code, e)
	}
}
