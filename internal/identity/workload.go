package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
)

// Workload credentials (ADR-0023): halo-server exchanges a CI / cloud OIDC
// token for a short-lived JWT it signs with an ed25519 key; gateways verify it
// with the public half. EdDSA only: there is no alg negotiation to confuse.
const (
	// WorkloadTokenType is the JWT typ header. Gateways dispatch on it; it is
	// never trusted for verification.
	WorkloadTokenType = "halo-workload+jwt" //nolint:gosec // JWT typ value, not a credential
	WorkloadIssuer    = "halos"
	WorkloadAudience  = "halos-gateway"
	// workloadSkew tolerates halo-server / gateway clock drift on nbf and iat.
	// exp gets no leeway.
	workloadSkew = time.Minute
)

// WorkloadClaims is the payload of a workload credential.
type WorkloadClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  string   `json:"aud"`
	Groups    []string `json:"groups,omitempty"`
	Kind      string   `json:"kind"`
	Rule      string   `json:"rule"` // workloads.rules name that matched
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expiry    int64    `json:"exp"`
	ID        string   `json:"jti"`
}

type workloadHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// WorkloadKeyID is the kid for pub: lets gateways hold several keys (rotation).
func WorkloadKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

var b64 = base64.RawURLEncoding

// SignWorkloadToken signs c. It refuses claims Verify would reject, so a bug
// upstream can never mint an over-long or non-workload credential.
func SignWorkloadToken(key ed25519.PrivateKey, c WorkloadClaims) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("identity: workload signing key is not an ed25519 private key")
	}
	if err := c.check(time.Unix(c.IssuedAt, 0)); err != nil {
		return "", fmt.Errorf("identity: refusing to sign workload token: %w", err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	hb, err := json.Marshal(workloadHeader{Alg: "EdDSA", Typ: WorkloadTokenType, Kid: WorkloadKeyID(pub)})
	if err != nil {
		return "", fmt.Errorf("identity: encode workload header: %w", err)
	}
	cb, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("identity: encode workload claims: %w", err)
	}
	in := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	return in + "." + b64.EncodeToString(ed25519.Sign(key, []byte(in))), nil
}

// IsWorkloadToken reports whether tok claims (unverified) to be a workload
// credential. Used only to pick a verifier.
func IsWorkloadToken(tok string) bool {
	h, _, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	var hdr workloadHeader
	b, err := b64.DecodeString(h)
	return err == nil && json.Unmarshal(b, &hdr) == nil && hdr.Typ == WorkloadTokenType
}

// VerifyWorkloadToken checks the signature against keys (by kid), then iss,
// aud, kind, subject prefix, exp, nbf, iat and the lifetime cap.
func VerifyWorkloadToken(keys []ed25519.PublicKey, tok string, now time.Time) (WorkloadClaims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return WorkloadClaims{}, errors.New("identity: workload token is not a compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token header: %w", err)
	}
	var hdr workloadHeader
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token header: %w", err)
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != WorkloadTokenType {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token alg %q / typ %q not accepted (want EdDSA / %s)", hdr.Alg, hdr.Typ, WorkloadTokenType)
	}
	var key ed25519.PublicKey
	for _, k := range keys {
		if WorkloadKeyID(k) == hdr.Kid {
			key = k
			break
		}
	}
	if key == nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token kid %q is not a trusted halo-server key", hdr.Kid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return WorkloadClaims{}, errors.New("identity: workload token signature invalid")
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token payload: %w", err)
	}
	var c WorkloadClaims
	if err := json.Unmarshal(cb, &c); err != nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token payload: %w", err)
	}
	if err := c.check(now); err != nil {
		return WorkloadClaims{}, fmt.Errorf("identity: workload token rejected: %w", err)
	}
	return c, nil
}

func (c WorkloadClaims) check(now time.Time) error {
	exp, nbf, iat := time.Unix(c.Expiry, 0), time.Unix(c.NotBefore, 0), time.Unix(c.IssuedAt, 0)
	switch {
	case c.Issuer != WorkloadIssuer:
		return fmt.Errorf("iss %q, want %q", c.Issuer, WorkloadIssuer)
	case c.Audience != WorkloadAudience:
		return fmt.Errorf("aud %q, want %q", c.Audience, WorkloadAudience)
	case c.Kind != policy.SubjectWorkload:
		return fmt.Errorf("kind %q, want %q", c.Kind, policy.SubjectWorkload)
	case !strings.HasPrefix(c.Subject, policy.WorkloadSubjectPrefix):
		return fmt.Errorf("sub %q lacks the %q prefix", c.Subject, policy.WorkloadSubjectPrefix)
	case c.Expiry == 0 || c.IssuedAt == 0 || c.NotBefore == 0 || c.ID == "":
		return errors.New("exp, iat, nbf and jti are required")
	case !now.Before(exp):
		return fmt.Errorf("%w at %s", ErrTokenExpired, exp.UTC().Format(time.RFC3339))
	case nbf.After(now.Add(workloadSkew)), iat.After(now.Add(workloadSkew)):
		return errors.New("not yet valid (nbf/iat in the future)")
	case exp.Sub(iat) > policy.MaxWorkloadTTL:
		return fmt.Errorf("lifetime %s exceeds %s", exp.Sub(iat), policy.MaxWorkloadTTL)
	}
	return nil
}

// ParseWorkloadKeys reads one or more PEM "PUBLIC KEY" blocks (PKIX ed25519,
// as `halo keys generate` writes). Several keys allow rotation.
func ParseWorkloadKeys(pemData string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	rest := []byte(pemData)
	for {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("identity: workload key PEM block %q, want PUBLIC KEY", blk.Type)
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity: parse workload public key: %w", err)
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("identity: workload public key is %T, want ed25519", k)
		}
		keys = append(keys, pub)
	}
	if len(keys) == 0 {
		return nil, errors.New("identity: no PEM public key in workload keys")
	}
	return keys, nil
}

// WorkloadJWT accepts halo-server workload and delegated agent credentials
// and hands every other caller to Next (the human verifier). A token whose
// typ claims to be either is verified as such or refused: never a fall-through.
type WorkloadJWT struct {
	Keys []ed25519.PublicKey
	Next Verifier
	Now  func() time.Time // nil = time.Now
}

func (w *WorkloadJWT) Verify(r *http.Request) (policy.Subject, error) {
	tok := BearerToken(r.Header)
	typ := ""
	if tok != "" {
		typ = TokenType(tok)
	}
	if typ != WorkloadTokenType && typ != DelegatedTokenType {
		return w.Next.Verify(r)
	}
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	if typ == DelegatedTokenType { // an agent acting for a root principal (ADR-0024)
		c, err := VerifyDelegatedToken(w.Keys, tok, now())
		if err != nil {
			return policy.Subject{}, err
		}
		return c.AsSubject(), nil
	}
	c, err := VerifyWorkloadToken(w.Keys, tok, now())
	if err != nil {
		return policy.Subject{}, err
	}
	return policy.Subject{ID: c.Subject, Groups: c.Groups, Kind: policy.SubjectWorkload}, nil
}
