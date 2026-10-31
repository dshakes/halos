// Package signer opens release and kill-list signing keys by URI (ADR-0038):
//
//	file://PATH or PATH   PKCS#8 PEM ed25519 or ECDSA P-256 key (the default; unchanged)
//	awskms://KEY[?region=R&endpoint=URL&fips=true]
//	                      AWS KMS asymmetric SIGN_VERIFY key (ECC_NIST_P256 or ECC_NIST_EDWARDS25519)
//	exec:///ABS/PATH[?arg=A&arg=B&key=ID&timeout=30s]
//	                      external signer speaking the halos.signer.v1 JSON protocol (exec.go; docs guides/key-management):
//	                      PKCS#11 HSMs, GCP/Azure KMS, Vault transit, ... without Halos taking their SDKs
//
// Every backend yields a bundle.KeySigner whose algorithm is one halod
// verifies natively (bundle.AlgEd25519, bundle.AlgECDSAP256). A remote
// backend's public key is fetched once at Open, and every signature it
// returns is verified against that key before Halos uses it, so a backend
// that signs with the wrong key or algorithm fails at signing time, not on
// the fleet.
package signer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/dshakes/halos/internal/bundle"
)

// DefaultTimeout bounds one remote signing operation (a KMS call or one run
// of an external signer) when the context has no earlier deadline.
const DefaultTimeout = 30 * time.Second

// Options tune remote backends; the zero value is production.
type Options struct {
	// HTTPClient is used for awskms (default: DefaultTimeout, no redirects).
	HTTPClient *http.Client
	// Credentials signs awskms requests; nil is the AWS SDK default chain
	// (env, shared config/SSO, web identity/IRSA, ECS/EC2 IMDS).
	Credentials aws.CredentialsProvider
	// Region is the awskms region when neither the URI nor the key ARN names
	// one; "" falls back to the AWS SDK default config.
	Region string
	// Now is the SigV4 clock (tests).
	Now func() time.Time
	// Log receives exec signers' stderr at debug level (nil: slog.Default).
	Log *slog.Logger
}

// Scheme reports the key URI's backend: "file", "awskms" or "exec".
func Scheme(uri string) string {
	switch {
	case strings.HasPrefix(uri, "awskms://"):
		return "awskms"
	case strings.HasPrefix(uri, "exec://"):
		return "exec"
	}
	return "file"
}

// Open returns the signer uri names. A bare path is a file:// URI.
func Open(ctx context.Context, uri string, o Options) (bundle.KeySigner, error) {
	if strings.TrimSpace(uri) == "" {
		return nil, errors.New("signer: empty key URI")
	}
	switch Scheme(uri) {
	case "awskms":
		return openAWSKMS(ctx, uri, o)
	case "exec":
		return openExec(ctx, uri, o.Log)
	}
	return openFile(uri)
}

func openFile(uri string) (bundle.KeySigner, error) {
	path := uri
	if rest, ok := strings.CutPrefix(uri, "file://"); ok {
		path = rest
	} else if i := strings.Index(uri, "://"); i >= 0 {
		return nil, fmt.Errorf("signer: unsupported key URI scheme %q (want file://, awskms:// or exec://)", uri[:i])
	}
	if path == "" {
		return nil, errors.New("signer: file:// key URI has no path")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signer: read key file: %w", err)
	}
	s, err := bundle.ParseSigner(pem)
	if err != nil {
		return nil, fmt.Errorf("signer: key file %s: %w", path, err)
	}
	return s, nil
}

// remote is a KeySigner whose private key lives elsewhere. Sign verifies
// each signature against the public key fetched at Open.
type remote struct {
	alg  string
	v    bundle.PublicKeyVerifier
	desc string // for errors: backend and key, never secrets
	sign func(ctx context.Context, msg string) ([]byte, error)
}

func (r *remote) Type() string              { return r.alg }
func (r *remote) Verifier() bundle.Verifier { return r.v }

// Remote reports that each Sign is a KMS call or a process spawn (callers
// that sign per request, like the kill-list endpoint, cache).
func (r *remote) Remote() bool { return true }

func (r *remote) Sign(ctx context.Context, msg string) ([]byte, error) {
	sig, err := r.sign(ctx, msg) // each backend bounds its own call
	if err != nil {
		return nil, fmt.Errorf("signer: %s: %w", r.desc, err)
	}
	if err := r.v.Verify(ctx, msg, sig); err != nil {
		return nil, fmt.Errorf("signer: %s returned a signature its own public key does not verify (wrong key, algorithm or encoding): %w", r.desc, err)
	}
	return sig, nil
}

// newRemote checks that pub is a native key of algorithm alg.
func newRemote(alg string, pub bundle.PublicKeyVerifier, desc string, sign func(context.Context, string) ([]byte, error)) (*remote, error) {
	if pub.Type() != alg {
		return nil, fmt.Errorf("signer: %s: public key is %s but the backend signs %s", desc, pub.Type(), alg)
	}
	return &remote{alg: alg, v: pub, desc: desc, sign: sign}, nil
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < d {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}
