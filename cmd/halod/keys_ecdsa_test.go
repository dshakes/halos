package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/bundle"
)

// ADR-0038: halod trusts ECDSA P-256 release keys (KMS, HSM) next to ed25519
// ones, rotates and revokes them by bundle.KeyID, and verifies each signature
// under its recorded algorithm only.
func TestKeyringECDSA(t *testing.T) {
	dir := t.TempDir()
	priv, pub, err := bundle.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	edS, _ := bundle.ParseEd25519Signer(priv)
	edP := filepath.Join(dir, "ed.pub")
	_ = os.WriteFile(edP, pub, 0o644)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	ecP := filepath.Join(dir, "kms.pub")
	_ = os.WriteFile(ecP, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	ecS := bundle.ECDSASigner{Key: k}
	ecFP := bundle.KeyID(ecS.Verifier())

	ring, fps, err := loadKeyring(Config{PubKey: edP, PubKeys: []string{ecP}})
	if err != nil || len(ring) != 2 || fps[1] != ecFP {
		t.Fatalf("ring %d fps %v err %v", len(ring), fps, err)
	}
	ctx := context.Background()
	edSig, _ := edS.Sign(ctx, "sha256:d")
	ecSig, _ := ecS.Sign(ctx, "sha256:d")
	if bundle.VerifyAs(ctx, ring, bundle.AlgEd25519, "sha256:d", edSig) != nil || bundle.VerifyAs(ctx, ring, bundle.AlgECDSAP256, "sha256:d", ecSig) != nil {
		t.Fatal("both keys must verify during the migration")
	}
	if bundle.VerifyAs(ctx, ring, bundle.AlgEd25519, "sha256:d", ecSig) == nil {
		t.Fatal("ecdsa signature accepted as ed25519")
	}
	// retire the ed25519 key; revoke the ECDSA one by its key id
	ring, _, err = loadKeyring(Config{PubKey: ecP})
	if err != nil || bundle.VerifyAs(ctx, ring, bundle.AlgEd25519, "sha256:d", edSig) == nil {
		t.Fatalf("retired key still trusted: %v", err)
	}
	if _, _, err := loadKeyring(Config{PubKey: ecP, RevokedKeys: []string{strings.ToUpper(ecFP)}}); err == nil {
		t.Fatal("revoked ECDSA key still trusted")
	}
	// a P-384 key is not a halod algorithm
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&k384.PublicKey)
	p384 := filepath.Join(dir, "p384.pub")
	_ = os.WriteFile(p384, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384}), 0o644)
	if _, _, err := loadKeyring(Config{PubKey: p384}); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("P-384 key: %v", err)
	}
}
