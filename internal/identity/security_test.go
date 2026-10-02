package identity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

// TestOIDCJWTAdversarial covers the JWT edge cases TestOIDCJWT does not:
// algorithms signed by the real key but outside the allowlist, kid handling,
// and audience/issuer shapes.
func TestOIDCJWTAdversarial(t *testing.T) {
	v, iss := newVerifier(t)
	other, _ := identitytest.NewIssuer("k1")
	now := time.Now()
	base := func(kv ...any) map[string]any {
		m := map[string]any{"iss": iss.URL, "aud": aud, "email": "a@x", "email_verified": true, "exp": now.Add(time.Hour).Unix()}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	rs256 := func(k *rsa.PrivateKey) func([]byte) ([]byte, error) {
		return func(in []byte) ([]byte, error) {
			d := sha256.Sum256(in)
			return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		}
	}
	sign := func(hdr, claims map[string]any, s func([]byte) ([]byte, error)) string {
		t.Helper()
		tok, err := identitytest.Sign(hdr, claims, s)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	rs512 := func(in []byte) ([]byte, error) {
		d := sha512.Sum512(in)
		return rsa.SignPKCS1v15(rand.Reader, iss.Key, crypto.SHA512, d[:])
	}
	ps256 := func(in []byte) ([]byte, error) {
		d := sha256.Sum256(in)
		return rsa.SignPSS(rand.Reader, iss.Key, crypto.SHA256, d[:], nil)
	}
	h := func(alg, kid string) map[string]any {
		m := map[string]any{"alg": alg, "typ": "JWT"}
		if kid != "" {
			m["kid"] = kid
		}
		return m
	}

	for _, tc := range []struct {
		name string
		tok  string
		ok   bool
	}{
		{"RS512 by the IdP key is outside the allowlist", sign(h("RS512", "k1"), base(), rs512), false},
		{"PS256 by the IdP key is outside the allowlist", sign(h("PS256", "k1"), base(), ps256), false},
		{"header says ES256, RS256 signature", sign(h("ES256", "k1"), base(), rs256(iss.Key)), false},
		{"lowercase alg", sign(h("rs256", "k1"), base(), rs256(iss.Key)), false},
		{"missing kid, IdP key: tried against the JWKS", sign(h("RS256", ""), base(), rs256(iss.Key)), true},
		{"missing kid, foreign key", sign(h("RS256", ""), base(), rs256(other.Key)), false},
		{"unknown kid, foreign key", sign(h("RS256", "rotated"), base(), rs256(other.Key)), false},
		{"aud array without ours", sign(h("RS256", "k1"), base("aud", []string{"a", "b"}), rs256(iss.Key)), false},
		{"empty aud array", sign(h("RS256", "k1"), base("aud", []string{}), rs256(iss.Key)), false},
		{"aud missing", sign(h("RS256", "k1"), base("aud", nil), rs256(iss.Key)), false},
		{"aud prefix of ours", sign(h("RS256", "k1"), base("aud", aud+"-x"), rs256(iss.Key)), false},
		{"iss trailing slash", sign(h("RS256", "k1"), base("iss", iss.URL+"/"), rs256(iss.Key)), false},
		{"iss missing", sign(h("RS256", "k1"), base("iss", nil), rs256(iss.Key)), false},
		{"exp missing", sign(h("RS256", "k1"), base("exp", nil), rs256(iss.Key)), false},
		{"exp just passed", sign(h("RS256", "k1"), base("exp", now.Add(-2*time.Second).Unix()), rs256(iss.Key)), false},
		{"nbf beyond skew", sign(h("RS256", "k1"), base("nbf", now.Add(10*time.Minute).Unix()), rs256(iss.Key)), false},
		{"nbf in the past", sign(h("RS256", "k1"), base("nbf", now.Add(-time.Minute).Unix()), rs256(iss.Key)), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(reqWith(tc.tok))
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestTrustedHeaderPeerOnly: only the TCP peer counts; X-Forwarded-For,
// X-Real-IP and Forwarded are client-controlled and never consulted.
func TestTrustedHeaderPeerOnly(t *testing.T) {
	v, err := NewTrustedHeader("x-user", "x-groups", []string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:4444"
	r.Header.Set("x-user", "alice")
	r.Header.Set("X-Forwarded-For", "10.1.2.3")
	r.Header.Set("X-Real-IP", "10.1.2.3")
	r.Header.Set("Forwarded", "for=10.1.2.3")
	if _, err := v.Verify(r); err == nil {
		t.Fatal("forwarding headers made an outside peer trusted")
	}
	// IPv4-mapped IPv6 peer inside the CIDR is the same address.
	r.RemoteAddr = "[::ffff:10.1.2.3]:4444"
	if sub, err := v.Verify(r); err != nil || sub.ID != "alice" {
		t.Fatalf("mapped peer: %+v %v", sub, err)
	}
}

// JWKS is cached and refetched on an unknown kid, so IdP key rotation works
// without a restart; a token whose kid is still unknown after the refetch is
// rejected.
func TestOIDCJWTRefetchesJWKSOnUnknownKid(t *testing.T) {
	old, _ := identitytest.NewIssuer("k1")
	rotated, _ := identitytest.NewIssuer("k2")
	var rotatedIn atomic.Bool
	var jwksFetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			jwksFetches.Add(1)
			keys := []any{old.JWK()}
			if rotatedIn.Load() {
				keys = append(keys, rotated.JWK())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			return
		}
		old.Handler().ServeHTTP(w, r)
	}))
	defer srv.Close()
	old.URL, rotated.URL = srv.URL, srv.URL
	v, err := NewOIDCJWT(srv.URL, aud, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(i *identitytest.Issuer) string {
		tok, err := i.Mint(map[string]any{"aud": aud, "email": "a@x"})
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if _, err := v.Verify(reqWith(mint(old))); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(reqWith(mint(old))); err != nil || jwksFetches.Load() != 1 {
		t.Fatalf("cached kid: err=%v fetches=%d, want 1", err, jwksFetches.Load())
	}
	if _, err := v.Verify(reqWith(mint(rotated))); err == nil {
		t.Fatal("kid k2 not yet published: want rejection")
	}
	rotatedIn.Store(true)
	if _, err := v.Verify(reqWith(mint(rotated))); err != nil {
		t.Fatalf("rotated key after refetch: %v", err)
	}
}
