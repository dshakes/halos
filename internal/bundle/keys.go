package bundle

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Signature algorithms halod verifies natively (ADR-0038). The name is what a
// signature's AnnSigType annotation (and a kill envelope's alg) records; a
// verifier refuses any other name. Both are FIPS 186-5 approved and inside
// Go's FIPS 140-3 module.
const (
	// AlgEd25519 is pure Ed25519 over the message bytes (RFC 8032). The
	// original algorithm: every release signed before ADR-0038 uses it.
	AlgEd25519 = "ed25519"
	// AlgECDSAP256 is ECDSA on P-256 over SHA-256(message), ASN.1 DER
	// encoded: what AWS KMS ECC_NIST_P256 keys and most HSMs produce.
	AlgECDSAP256 = "ecdsa-p256-sha256"
)

// Algorithms lists the native signature algorithms.
var Algorithms = []string{AlgEd25519, AlgECDSAP256}

// AnnSigKeyID records the KeyID of the key that made the primary signature.
// It is informational (audit, rotation tracking): verification never trusts
// it to pick a key, it tries every trusted key of the signature's algorithm.
const AnnSigKeyID = "dev.halos.signature.keyid"

// PublicKeyVerifier is a Verifier bound to one public key.
type PublicKeyVerifier interface {
	Verifier
	PublicKey() crypto.PublicKey
}

// ---- ECDSA P-256 ----

// ECDSASigner signs with a P-256 key held in memory (a file:// key; KMS and
// HSM keys sign through internal/signer).
type ECDSASigner struct{ Key *ecdsa.PrivateKey }

// ECDSAVerifier verifies ECDSA P-256 / SHA-256 ASN.1 signatures.
type ECDSAVerifier struct{ Key *ecdsa.PublicKey }

func (ECDSASigner) Type() string   { return AlgECDSAP256 }
func (ECDSAVerifier) Type() string { return AlgECDSAP256 }

// Verifier is s's public half.
func (s ECDSASigner) Verifier() Verifier { return ECDSAVerifier{Key: &s.Key.PublicKey} }

// PublicKey returns the ECDSA public key.
func (v ECDSAVerifier) PublicKey() crypto.PublicKey { return v.Key }

func (s ECDSASigner) Sign(_ context.Context, msg string) ([]byte, error) {
	if s.Key == nil || s.Key.Curve != elliptic.P256() {
		return nil, errors.New("bundle: ecdsa signer has no P-256 private key")
	}
	h := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, h[:])
	if err != nil {
		return nil, fmt.Errorf("bundle: ecdsa sign: %w", err)
	}
	return sig, nil
}

func (v ECDSAVerifier) Verify(_ context.Context, msg string, sig []byte) error {
	if v.Key == nil || v.Key.Curve != elliptic.P256() {
		return errors.New("bundle: ecdsa verifier has no P-256 public key")
	}
	h := sha256.Sum256([]byte(msg))
	if !ecdsa.VerifyASN1(v.Key, h[:], sig) {
		return errors.New("bundle: ecdsa-p256-sha256 signature invalid")
	}
	return nil
}

// ---- parsing ----

// ParseSigner parses a PKCS#8 PEM private key: ed25519 or ECDSA P-256.
func ParseSigner(privPEM []byte) (KeySigner, error) {
	blk, _ := pem.Decode(privPEM)
	if blk == nil {
		return nil, errors.New("bundle: no PEM block in private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse private key (want PKCS#8): %w", err)
	}
	switch k := k.(type) {
	case ed25519.PrivateKey:
		return Ed25519Signer{Key: k}, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("bundle: ecdsa private key is on %s, want P-256", k.Curve.Params().Name)
		}
		return ECDSASigner{Key: k}, nil
	}
	return nil, fmt.Errorf("bundle: private key is %T, want ed25519 or ECDSA P-256", k)
}

// ParseVerifier parses a PKIX PEM public key: ed25519 or ECDSA P-256.
func ParseVerifier(pubPEM []byte) (PublicKeyVerifier, error) {
	blk, _ := pem.Decode(pubPEM)
	if blk == nil {
		return nil, errors.New("bundle: no PEM block in public key")
	}
	return ParseVerifierDER(blk.Bytes)
}

// ParseVerifierDER parses a DER SubjectPublicKeyInfo (what AWS KMS
// GetPublicKey returns).
func ParseVerifierDER(der []byte) (PublicKeyVerifier, error) {
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("bundle: parse public key: %w", err)
	}
	return VerifierFor(k)
}

// VerifierFor wraps a public key in the verifier for its algorithm.
func VerifierFor(k crypto.PublicKey) (PublicKeyVerifier, error) {
	switch k := k.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("bundle: malformed ed25519 public key")
		}
		return Ed25519Verifier{Key: k}, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("bundle: ecdsa public key is on %s, want P-256", k.Curve.Params().Name)
		}
		return ECDSAVerifier{Key: k}, nil
	}
	return nil, fmt.Errorf("bundle: public key is %T, want ed25519 or ECDSA P-256", k)
}

// MarshalPublicKeyPEM is v's key as PKIX PEM ("PUBLIC KEY").
func MarshalPublicKeyPEM(v PublicKeyVerifier) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(v.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// KeyID is "sha256:<hex>" identifying v's key: over the raw 32 bytes for
// ed25519 (unchanged from halod's revokedKeys fingerprints) and over the PKIX
// DER for ECDSA. "" for a verifier without a key.
func KeyID(v Verifier) string {
	pv, ok := v.(PublicKeyVerifier)
	if !ok {
		return ""
	}
	var b []byte
	switch k := pv.PublicKey().(type) {
	case ed25519.PublicKey:
		b = k
	default:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return ""
		}
		b = der
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ---- multi-key / multi-algorithm verification ----

// Keyring accepts a signature made by any one of its keys, each under its own
// algorithm only: a key is bound to one algorithm by its type, so an ed25519
// key never checks an ECDSA signature or the reverse.
type Keyring []PublicKeyVerifier

// Type names the algorithms the keyring accepts (for messages).
func (k Keyring) Type() string { return strings.Join(k.Algorithms(), ",") }

// Algorithms are the distinct algorithms of the keyring's keys.
func (k Keyring) Algorithms() []string {
	var out []string
	for _, v := range k {
		if !slices.Contains(out, v.Type()) {
			out = append(out, v.Type())
		}
	}
	return out
}

// Verify accepts sig if any key verifies it under its own algorithm.
func (k Keyring) Verify(ctx context.Context, msg string, sig []byte) error {
	for _, v := range k {
		if v.Verify(ctx, msg, sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("bundle: signature matches none of the %d trusted keys", len(k))
}

// VerifyAlg accepts sig only from a key of algorithm alg.
func (k Keyring) VerifyAlg(ctx context.Context, alg, msg string, sig []byte) error {
	n := 0
	for _, v := range k {
		if v.Type() != alg {
			continue
		}
		n++
		if v.Verify(ctx, msg, sig) == nil {
			return nil
		}
	}
	if n == 0 {
		return fmt.Errorf("bundle: no trusted %s key (trusted: %s)", alg, k.Type())
	}
	return fmt.Errorf("bundle: %s signature matches none of the %d trusted %s keys", alg, n, alg)
}

// algVerifier is a Verifier that accepts several algorithms (Keyring).
type algVerifier interface {
	Algorithms() []string
	VerifyAlg(ctx context.Context, alg, msg string, sig []byte) error
}

// accepted lists the algorithms v accepts.
func accepted(v Verifier) []string {
	if av, ok := v.(algVerifier); ok {
		return av.Algorithms()
	}
	return []string{v.Type()}
}

// VerifyAs checks sig over msg as a signature of algorithm alg (as recorded
// next to the signature). An algorithm v does not accept (including "") is
// refused, and only v's keys of that algorithm are tried.
func VerifyAs(ctx context.Context, v Verifier, alg, msg string, sig []byte) error {
	if v == nil {
		return errors.New("bundle: no verifier")
	}
	if alg == "" || !slices.Contains(accepted(v), alg) {
		return fmt.Errorf("bundle: signature algorithm %q is not accepted (verifier expects %q)", alg, v.Type())
	}
	if av, ok := v.(algVerifier); ok {
		return av.VerifyAlg(ctx, alg, msg, sig)
	}
	return v.Verify(ctx, msg, sig)
}
