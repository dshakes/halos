package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

const (
	fuzzModeRS256 = iota // signed with the issuer's real key
	fuzzModeHMAC         // HS256 keyed with the public key (key confusion)
	fuzzModeNone         // empty signature
	fuzzModeRaw          // hdr is the whole token
	fuzzModes
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// FuzzOIDCJWTVerify drives header and claims through every signing mode,
// including a valid signature by the IdP's own key, so the semantic checks are
// exercised, not only the signature. Property: an accepted token always has an
// allowlisted alg, our issuer, our audience, a live exp, a reached nbf, a
// valid RS256 signature by the IdP key, and yields exactly its user claim.
func FuzzOIDCJWTVerify(f *testing.F) {
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		f.Fatal(err)
	}
	srv := iss.Serve()
	f.Cleanup(srv.Close)
	v, err := NewOIDCJWT(iss.URL, aud, "", "", nil)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now()
	hdr := func(alg, kid string) []byte {
		m := map[string]any{"alg": alg, "typ": "JWT"}
		if kid != "" {
			m["kid"] = kid
		}
		b, _ := json.Marshal(m)
		return b
	}
	claims := func(kv ...any) []byte {
		m := map[string]any{"iss": iss.URL, "aud": aud, "email": "a@x", "email_verified": true, "exp": now.Add(time.Hour).Unix()}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		b, _ := json.Marshal(m)
		return b
	}
	// Seeds: the cases TestOIDCJWT covers, in every mode.
	for _, c := range [][]byte{
		claims(), claims("aud", []string{"x", aud}), claims("aud", "other"), claims("aud", []string{"other"}),
		claims("iss", "https://evil.example"), claims("exp", now.Add(-time.Hour).Unix()), claims("nbf", now.Add(time.Hour).Unix()),
		claims("email_verified", false), claims("email", ""), claims("exp", "soon"), []byte(`{}`), []byte(`not json`),
	} {
		for _, h := range [][]byte{hdr("RS256", "k1"), hdr("RS256", ""), hdr("RS256", "unknown"), hdr("HS256", "k1"), hdr("none", ""), hdr("RS512", "k1"), hdr("PS256", "k1"), hdr("ES256", "k1")} {
			for m := uint8(0); m < fuzzModes; m++ {
				f.Add(h, c, m)
			}
		}
	}
	f.Add([]byte("not.a.jwt"), []byte(nil), uint8(fuzzModeRaw))
	f.Add([]byte(""), []byte(nil), uint8(fuzzModeRaw))

	pub, _ := x509.MarshalPKIXPublicKey(&iss.Key.PublicKey)
	f.Fuzz(func(t *testing.T, h, c []byte, mode uint8) {
		in := b64u(h) + "." + b64u(c)
		var tok string
		switch mode % fuzzModes {
		case fuzzModeRS256:
			d := sha256.Sum256([]byte(in))
			sig, err := rsa.SignPKCS1v15(rand.Reader, iss.Key, crypto.SHA256, d[:])
			if err != nil {
				t.Fatal(err)
			}
			tok = in + "." + b64u(sig)
		case fuzzModeHMAC:
			m := hmac.New(sha256.New, pub)
			m.Write([]byte(in))
			tok = in + "." + b64u(m.Sum(nil))
		case fuzzModeNone:
			tok = in + "."
		case fuzzModeRaw:
			tok = string(h)
		}
		sub, err := v.Verify(reqWith(tok))
		if err != nil {
			return
		}
		checkAcceptedJWT(t, iss, tok, sub.ID, sub.Groups)
	})
}

// checkAcceptedJWT re-derives, independently of go-oidc, everything an
// accepted token must satisfy.
func checkAcceptedJWT(t *testing.T, iss *identitytest.Issuer, tok, id string, groups []string) {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 {
		t.Fatalf("accepted token without 3 parts: %q", tok)
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
		if err != nil {
			t.Fatalf("accepted token with bad base64 %q: %v", s, err)
		}
		return b
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(dec(parts[0]), &hdr); err != nil || !slices.Contains(AllowedAlgs, hdr.Alg) || hdr.Alg != "RS256" {
		t.Fatalf("accepted alg %q (err %v), allowlist %v and the IdP key is RSA", hdr.Alg, err, AllowedAlgs)
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&iss.Key.PublicKey, crypto.SHA256, d[:], dec(parts[2])); err != nil {
		t.Fatalf("accepted token not signed by the IdP key: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal(dec(parts[1]), &c); err != nil {
		t.Fatalf("accepted token with undecodable claims: %v", err)
	}
	if c["iss"] != iss.URL {
		t.Fatalf("accepted iss %v want %s", c["iss"], iss.URL)
	}
	switch a := c["aud"].(type) {
	case string:
		if a != aud {
			t.Fatalf("accepted aud %q", a)
		}
	case []any:
		if !slices.Contains(a, any(aud)) {
			t.Fatalf("accepted aud %v without %q", a, aud)
		}
	default:
		t.Fatalf("accepted aud %#v", c["aud"])
	}
	now := float64(time.Now().Unix())
	exp, ok := c["exp"].(float64)
	if !ok || exp < now-5 {
		t.Fatalf("accepted exp %#v (now %v)", c["exp"], now)
	}
	if nbf, ok := c["nbf"].(float64); ok && nbf > now+5*60+5 { // go-oidc allows 5m clock skew on nbf
		t.Fatalf("accepted nbf %v (now %v)", nbf, now)
	}
	if want, _ := c["email"].(string); strings.TrimSpace(want) != id || id == "" {
		t.Fatalf("subject %q does not match email claim %q", id, want)
	}
	if v := c["email_verified"]; v != true && v != "true" {
		t.Fatalf("accepted unverified email (email_verified=%#v)", v)
	}
	if slices.Contains(groups, "") {
		t.Fatalf("empty group in %v", groups)
	}
}
