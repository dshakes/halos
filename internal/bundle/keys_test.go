package bundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
)

func ecKeys(t *testing.T) (ECDSASigner, ECDSAVerifier) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ECDSASigner{Key: k}, ECDSAVerifier{Key: &k.PublicKey}
}

func pkcs8PEM(t *testing.T, k any) []byte {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b})
}

func pkixPEM(t *testing.T, k any) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b})
}

func TestParseSignerAndVerifier(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaK, _ := rsa.GenerateKey(rand.Reader, 2048)
	tests := []struct {
		name     string
		priv     []byte
		pub      []byte
		wantAlg  string
		wantFail string
	}{
		{"ed25519", pkcs8PEM(t, edPriv), pkixPEM(t, edPriv.Public()), AlgEd25519, ""},
		{"ecdsa p256", pkcs8PEM(t, p256), pkixPEM(t, &p256.PublicKey), AlgECDSAP256, ""},
		{"ecdsa p384 refused", pkcs8PEM(t, p384), pkixPEM(t, &p384.PublicKey), "", "P-256"},
		{"rsa refused", pkcs8PEM(t, rsaK), pkixPEM(t, &rsaK.PublicKey), "", "want ed25519 or ECDSA P-256"},
		{"not pem", []byte("nope"), []byte("nope"), "", "no PEM block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, serr := ParseSigner(tt.priv)
			v, verr := ParseVerifier(tt.pub)
			if tt.wantFail != "" {
				if serr == nil || !strings.Contains(serr.Error(), tt.wantFail) || verr == nil || !strings.Contains(verr.Error(), tt.wantFail) {
					t.Fatalf("want %q: signer %v, verifier %v", tt.wantFail, serr, verr)
				}
				return
			}
			if serr != nil || verr != nil {
				t.Fatal(serr, verr)
			}
			if s.Type() != tt.wantAlg || v.Type() != tt.wantAlg || s.Verifier().Type() != tt.wantAlg {
				t.Fatalf("algs %s %s %s, want %s", s.Type(), v.Type(), s.Verifier().Type(), tt.wantAlg)
			}
			sig, err := s.Sign(context.Background(), "sha256:abc")
			if err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(context.Background(), "sha256:abc", sig); err != nil {
				t.Fatalf("own signature: %v", err)
			}
			if KeyID(v) != KeyID(s.Verifier()) || !strings.HasPrefix(KeyID(v), "sha256:") {
				t.Fatalf("key ids %q %q", KeyID(v), KeyID(s.Verifier()))
			}
			pemOut, err := MarshalPublicKeyPEM(v)
			if err != nil || string(pemOut) != string(tt.pub) {
				t.Fatalf("public PEM round trip: %v\n%s", err, pemOut)
			}
		})
	}
	// a public key is not a private key, and the reverse
	if _, err := ParseSigner(pkixPEM(t, &p256.PublicKey)); err == nil {
		t.Fatal("public key parsed as signer")
	}
}

// The ed25519 KeyID is the fingerprint halod's revokedKeys always used.
func TestKeyIDEd25519Unchanged(t *testing.T) {
	_, v := keys(t)
	h := sha256Hex(v.Key)
	if KeyID(v) != "sha256:"+h {
		t.Fatalf("KeyID %s, want sha256 of the raw key %s", KeyID(v), h)
	}
}

func TestVerifyAsBindsAlgorithm(t *testing.T) {
	ctx := context.Background()
	es, ev := keys(t)
	cs, cv := ecKeys(t)
	ring := Keyring{ev, cv}
	edSig, _ := es.Sign(ctx, "m")
	ecSig, _ := cs.Sign(ctx, "m")
	tests := []struct {
		name string
		v    Verifier
		alg  string
		sig  []byte
		ok   bool
	}{
		{"ed25519 as ed25519", ring, AlgEd25519, edSig, true},
		{"ecdsa as ecdsa", ring, AlgECDSAP256, ecSig, true},
		{"ed25519 sig labelled ecdsa", ring, AlgECDSAP256, edSig, false},
		{"ecdsa sig labelled ed25519", ring, AlgEd25519, ecSig, false},
		{"unknown algorithm", ring, "rsa-pss-sha256", edSig, false},
		{"empty algorithm", ring, "", edSig, false},
		{"truncated ed25519", ring, AlgEd25519, edSig[:63], false},
		{"truncated ecdsa", ring, AlgECDSAP256, ecSig[:len(ecSig)-1], false},
		{"empty sig", ring, AlgEd25519, nil, false},
		{"single-alg verifier refuses other alg", ev, AlgECDSAP256, ecSig, false},
		// a valid signature under a wrong or unknown label is still refused
		{"valid ed25519 sig, unknown label", ev, "rsa-pss-sha256", edSig, false},
		{"valid ed25519 sig, no label", ev, "", edSig, false},
		{"valid ed25519 sig labelled ecdsa", ev, AlgECDSAP256, edSig, false},
		{"single-alg verifier", cv, AlgECDSAP256, ecSig, true},
		{"nil verifier", nil, AlgEd25519, edSig, false},
	}
	for _, tt := range tests {
		err := VerifyAs(ctx, tt.v, tt.alg, "m", tt.sig)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err %v, want ok=%v", tt.name, err, tt.ok)
		}
	}
	// a keyring of only ed25519 keys accepts no ecdsa signature
	if err := (Keyring{ev}).VerifyAlg(ctx, AlgECDSAP256, "m", ecSig); err == nil || !strings.Contains(err.Error(), "no trusted") {
		t.Fatalf("ed25519-only keyring: %v", err)
	}
	// wrong message
	if err := VerifyAs(ctx, ring, AlgECDSAP256, "m2", ecSig); err == nil {
		t.Fatal("ecdsa signature verified over another message")
	}
}

func TestECDSAReleaseRoundTrip(t *testing.T) {
	ctx := context.Background()
	cs, cv := ecKeys(t)
	_, ev := keys(t)
	_, otherEC := ecKeys(t)
	store := memory.New()
	rel := mkRel(t, "1", "r")
	desc, err := Publish(ctx, store, rel, cs, "r")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for name, v := range map[string]Verifier{"ecdsa verifier": cv, "mixed keyring": Keyring{ev, cv}} {
		if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "r", Now: now}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, v := range map[string]Verifier{"ed25519-only": ev, "other ecdsa key": otherEC, "keyring without it": Keyring{ev, otherEC}} {
		if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "r", Now: now}); err == nil {
			t.Fatalf("%s verified an ECDSA release it does not trust", name)
		}
	}
	m := manifestAt(t, store, "v1")
	if m.Annotations[AnnSigType] != AlgECDSAP256 || m.Annotations[AnnSigKeyID] != KeyID(cv) {
		t.Fatalf("annotations %v", m.Annotations)
	}
	// ECDSA is randomized: republishing the same release must reuse the
	// existing manifest, not trip tag immutability.
	again, err := Publish(ctx, store, rel, cs, "r")
	if err != nil || again.Digest != desc.Digest {
		t.Fatalf("republish: %v (digest %s vs %s)", err, again.Digest, desc.Digest)
	}
	// ...but not when the existing tag is signed by a key we do not hold
	cs2, _ := ecKeys(t)
	if _, err := Publish(ctx, store, rel, cs2, "r"); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("republish with another key: %v", err)
	}
}

// Rotating from ed25519 to ECDSA: MultiSigner{new, old} keeps halods that
// still trust only the old key working, for the release and the pointer.
func TestCoSignAcrossAlgorithms(t *testing.T) {
	ctx := context.Background()
	cs, cv := ecKeys(t)
	es, ev := keys(t)
	store := memory.New()
	if _, err := Publish(ctx, store, mkRel(t, "1", "r"), MultiSigner{cs, es}, "r"); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]Verifier{"old ed25519 key only": ev, "new ecdsa key only": cv, "both": Keyring{ev, cv}} {
		if _, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "r", Now: time.Now()}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// same-algorithm co-signing is refused (old halods read the co-signature first)
	es2, _ := keys(t)
	if _, err := Publish(ctx, memory.New(), mkRel(t, "1", "r"), MultiSigner{es, es2}, "r"); err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("same-alg co-signer: %v", err)
	}
}

// legacyPublish writes a release and pointer exactly as halo did before
// ADR-0038 (no key id annotation, ed25519 only), so old registries stay
// verifiable by new halods.
func legacyPublish(t *testing.T, store oras.Target, s Ed25519Signer, ring string) {
	t.Helper()
	ctx := context.Background()
	rel := mkRel(t, "1", ring)
	mj, _ := json.Marshal(rel.Manifest)
	cfg := content.NewDescriptorFromBytes(ConfigMediaType, mj)
	layer := content.NewDescriptorFromBytes(LayerMediaType, rel.Tar)
	for _, d := range []struct {
		d ocispec.Descriptor
		b []byte
	}{{cfg, mj}, {layer, rel.Tar}} {
		if err := pushIfMissing(ctx, store, d.d, d.b); err != nil {
			t.Fatal(err)
		}
	}
	sig := ed25519.Sign(s.Key, []byte(rel.Digest))
	desc, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, ArtifactType, oras.PackManifestOptions{
		ConfigDescriptor: &cfg, Layers: []ocispec.Descriptor{layer},
		ManifestAnnotations: map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(sig), AnnSigType: "ed25519", ocispec.AnnotationCreated: "1970-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, desc, "v1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := Pointer{Org: "acme", Ring: ring, Digest: rel.Digest, Manifest: desc.Digest.String(), ManifestSize: desc.Size,
		Seq: uint64(now.Unix()), IssuedAt: now, ExpiresAt: now.Add(DefaultPointerTTL)} //nolint:gosec // positive
	payload, _ := json.Marshal(p)
	pcfg := content.NewDescriptorFromBytes(PointerConfigType, payload)
	if err := pushIfMissing(ctx, store, pcfg, payload); err != nil {
		t.Fatal(err)
	}
	psig := ed25519.Sign(s.Key, []byte(pointerStatement(payload)))
	pd, err := oras.PackManifest(ctx, store, oras.PackManifestVersion1_1, PointerArtifactType, oras.PackManifestOptions{
		ConfigDescriptor:    &pcfg,
		ManifestAnnotations: map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(psig), AnnSigType: "ed25519"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Tag(ctx, pd, PointerTag(ring)); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyEd25519ReleasesStillVerify(t *testing.T) {
	ctx := context.Background()
	es, ev := keys(t)
	_, cv := ecKeys(t)
	store := memory.New()
	legacyPublish(t, store, es, "r")
	for name, v := range map[string]Verifier{"ed25519 verifier": ev, "keyring": Keyring{ev}, "mixed keyring": Keyring{cv, ev}} {
		rel, _, err := PullRing(ctx, store, v, RingOptions{Org: "acme", Ring: "r", Now: time.Now()})
		if err != nil || rel.Manifest.Version != "1" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, _, err := PullRing(ctx, store, cv, RingOptions{Org: "acme", Ring: "r", Now: time.Now()}); err == nil {
		t.Fatal("ecdsa-only verifier accepted an ed25519 release")
	}
	// the new publisher adopts the legacy v-tag (same release, same key) and
	// can move the ring on from the legacy pointer
	if _, err := Publish(ctx, store, mkRel(t, "1", "r"), es, "r"); err != nil {
		t.Fatalf("republish over a legacy manifest: %v", err)
	}
}

// A manifest whose recorded algorithm is unknown, or whose signature was
// swapped or truncated, never verifies.
func TestManifestSignatureTamper(t *testing.T) {
	ctx := context.Background()
	cs, cv := ecKeys(t)
	es, ev := keys(t)
	ring := Keyring{ev, cv}
	store := memory.New()
	if _, err := Publish(ctx, store, mkRel(t, "1", "r"), cs, "r"); err != nil {
		t.Fatal(err)
	}
	m := manifestAt(t, store, "v1")
	layer := m.Layers[0].Digest.String()
	edSig, _ := es.Sign(ctx, layer)
	good := m.Annotations[AnnSignature]
	raw, _ := base64.StdEncoding.DecodeString(good)
	tests := []struct {
		name string
		ann  map[string]string
	}{
		{"unknown algorithm", map[string]string{AnnSignature: good, AnnSigType: "rsa-pss-sha256"}},
		{"no algorithm", map[string]string{AnnSignature: good}},
		{"truncated", map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(raw[:len(raw)-2]), AnnSigType: AlgECDSAP256}},
		{"ed25519 sig relabelled ecdsa", map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(edSig), AnnSigType: AlgECDSAP256}},
		{"ecdsa sig relabelled ed25519", map[string]string{AnnSignature: good, AnnSigType: AlgEd25519}},
		{"not base64", map[string]string{AnnSignature: "!!", AnnSigType: AlgECDSAP256}},
		{"empty", map[string]string{AnnSignature: "", AnnSigType: AlgECDSAP256}},
	}
	for _, tt := range tests {
		mm := m
		mm.Annotations = tt.ann
		if err := verifyManifest(ctx, mm, ring, layer); err == nil {
			t.Errorf("%s: verified", tt.name)
		}
	}
	// a stranger's correctly-labelled signature is refused too
	if err := verifyManifest(ctx, ocispec.Manifest{Annotations: map[string]string{AnnSignature: base64.StdEncoding.EncodeToString(edSig), AnnSigType: AlgEd25519}}, Keyring{cv}, layer); err == nil {
		t.Fatal("ed25519 signature accepted by an ecdsa-only keyring")
	}
	// and the untampered manifest verifies
	if err := verifyManifest(ctx, m, ring, layer); err != nil {
		t.Fatal(err)
	}
}

func TestVerifierForRejectsMismatchedKeySigner(t *testing.T) {
	cs, _ := ecKeys(t)
	_, ev := keys(t)
	if _, err := verifierFor(lying{cs, ev}); err == nil {
		t.Fatal("signer whose verifier has another algorithm accepted")
	}
	if _, err := verifierFor(nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

type lying struct {
	ECDSASigner
	v Verifier
}

func (l lying) Verifier() Verifier { return l.v }

func manifestAt(t *testing.T, store oras.ReadOnlyTarget, tag string) ocispec.Manifest {
	t.Helper()
	d, err := store.Resolve(context.Background(), tag)
	if err != nil {
		t.Fatal(err)
	}
	m, err := fetchManifest(context.Background(), store, d)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
