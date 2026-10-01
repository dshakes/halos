package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Signer signs a release digest string (e.g. "sha256:ab..."). The digest is
// of the bundle tar, so it transitively covers manifest.json and every file.
type Signer interface {
	Type() string
	Sign(ctx context.Context, digest string) ([]byte, error)
}

// Verifier checks a signature made by the matching Signer type.
type Verifier interface {
	Type() string
	Verify(ctx context.Context, digest string, sig []byte) error
}

// ---- ed25519 (default; offline) ----

// Ed25519Signer signs with an ed25519 key.
type Ed25519Signer struct{ Key ed25519.PrivateKey }

// Ed25519Verifier verifies with an ed25519 public key.
type Ed25519Verifier struct{ Key ed25519.PublicKey }

func (Ed25519Signer) Type() string   { return "ed25519" }
func (Ed25519Verifier) Type() string { return "ed25519" }

func (s Ed25519Signer) Sign(_ context.Context, digest string) ([]byte, error) {
	return ed25519.Sign(s.Key, []byte(digest)), nil
}

func (v Ed25519Verifier) Verify(_ context.Context, digest string, sig []byte) error {
	if !ed25519.Verify(v.Key, []byte(digest), sig) {
		return errors.New("bundle: ed25519 signature invalid")
	}
	return nil
}

// GenerateKeyPair returns PKCS#8 private and PKIX public PEM.
func GenerateKeyPair() (privPEM, pubPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: generate key: %w", err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	pb, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pb}), nil
}

// ParseEd25519Signer parses a PKCS#8 PEM private key.
func ParseEd25519Signer(privPEM []byte) (Ed25519Signer, error) {
	blk, _ := pem.Decode(privPEM)
	if blk == nil {
		return Ed25519Signer{}, errors.New("bundle: no PEM block in private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return Ed25519Signer{}, fmt.Errorf("bundle: parse private key: %w", err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return Ed25519Signer{}, fmt.Errorf("bundle: private key is %T, want ed25519", k)
	}
	return Ed25519Signer{Key: ek}, nil
}

// ParseEd25519Verifier parses a PKIX PEM public key.
func ParseEd25519Verifier(pubPEM []byte) (Ed25519Verifier, error) {
	blk, _ := pem.Decode(pubPEM)
	if blk == nil {
		return Ed25519Verifier{}, errors.New("bundle: no PEM block in public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return Ed25519Verifier{}, fmt.Errorf("bundle: parse public key: %w", err)
	}
	ek, ok := k.(ed25519.PublicKey)
	if !ok {
		return Ed25519Verifier{}, fmt.Errorf("bundle: public key is %T, want ed25519", k)
	}
	return Ed25519Verifier{Key: ek}, nil
}

// ---- cosign (shells out) ----

// Runner executes a binary and returns combined output; injectable for tests.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner is the real Runner.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Cosign signs/verifies the digest string as a blob using `cosign sign-blob` /
// `verify-blob` with a key reference (file, KMS URI, ...).
//
// Cosign is a co-signer only: halod verifies ed25519 and never shells out to
// cosign as root, so Publish refuses a cosign-only signer (wrap it as
// MultiSigner{ed25519, Cosign}). Key-based signing does NOT upload to the
// public Rekor transparency log (release digests of a private org would
// otherwise be published) unless Keyless is set. Keyless (Fulcio + Rekor)
// verification needs certificate identity/issuer pinning and a --bundle
// transport, which is not implemented here.
type Cosign struct {
	Bin     string // default "cosign"
	Key     string // signing key ref (Sign) or public key ref (Verify)
	Keyless bool   // opt in to transparency-log upload/verification
	Runner  Runner // default ExecRunner
}

func (Cosign) Type() string { return "cosign" }

func (c Cosign) run(ctx context.Context, args ...string) ([]byte, error) {
	bin, r := c.Bin, c.Runner
	if bin == "" {
		bin = "cosign"
	}
	if r == nil {
		r = ExecRunner
	}
	return r(ctx, bin, args...)
}

func tmpFiles(digest string) (dir, payload string, err error) {
	dir, err = os.MkdirTemp("", "halod-cosign-")
	if err != nil {
		return "", "", err
	}
	payload = filepath.Join(dir, "payload")
	return dir, payload, os.WriteFile(payload, []byte(digest), 0o600)
}

func (c Cosign) Sign(ctx context.Context, digest string) ([]byte, error) {
	dir, payload, err := tmpFiles(digest)
	if err != nil {
		return nil, fmt.Errorf("bundle: cosign temp: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }() // best effort
	sigPath := filepath.Join(dir, "sig")
	args := []string{"sign-blob", "--yes", "--key", c.Key, "--output-signature", sigPath}
	if !c.Keyless {
		args = append(args, "--tlog-upload=false")
	}
	if out, err := c.run(ctx, append(args, payload)...); err != nil {
		return nil, fmt.Errorf("bundle: cosign sign-blob: %w: %s", err, out)
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, fmt.Errorf("bundle: read cosign signature: %w", err)
	}
	return sig, nil
}

func (c Cosign) Verify(ctx context.Context, digest string, sig []byte) error {
	dir, payload, err := tmpFiles(digest)
	if err != nil {
		return fmt.Errorf("bundle: cosign temp: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }() // best effort
	sigPath := filepath.Join(dir, "sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return err
	}
	args := []string{"verify-blob", "--key", c.Key, "--signature", sigPath}
	if !c.Keyless {
		args = append(args, "--insecure-ignore-tlog=true") // nothing was uploaded; the key is the trust root
	}
	if out, err := c.run(ctx, append(args, payload)...); err != nil {
		return fmt.Errorf("bundle: cosign verify-blob: %w: %s", err, out)
	}
	return nil
}
