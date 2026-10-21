package identity

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
)

func workloadKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func workloadClaims(now time.Time) WorkloadClaims {
	return WorkloadClaims{Issuer: WorkloadIssuer, Subject: "workload:gh:acme/app", Audience: WorkloadAudience, Groups: []string{"ci"},
		Kind: policy.SubjectWorkload, Rule: "r", IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Add(15 * time.Minute).Unix(), ID: "j1"}
}

func TestWorkloadTokenRoundTripAndRejections(t *testing.T) {
	pub, priv, _ := workloadKey(t)
	otherPub, otherPriv, _ := workloadKey(t)
	now := time.Unix(1_800_000_000, 0)
	sign := func(c WorkloadClaims) string {
		t.Helper()
		tok, err := SignWorkloadToken(priv, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	good := sign(workloadClaims(now))
	parts := strings.Split(good, ".")
	hdr := func(alg, typ, kid string) string {
		h, _ := identitytest.Sign(map[string]any{"alg": alg, "typ": typ, "kid": kid}, map[string]any{}, nil)
		return strings.Split(h, ".")[0]
	}
	kid := WorkloadKeyID(pub)
	// HS256 over the header+payload keyed with the public key bytes: the classic
	// alg-confusion forgery against verifiers that let the token pick the alg.
	hsIn := hdr("HS256", WorkloadTokenType, kid) + "." + parts[1]
	mac := hmac.New(sha256.New, pub)
	mac.Write([]byte(hsIn))
	hs256 := hsIn + "." + b64.EncodeToString(mac.Sum(nil))

	for _, tc := range []struct {
		name string
		tok  string
		keys []ed25519.PublicKey
		at   time.Time
		ok   bool
	}{
		{"valid", good, []ed25519.PublicKey{pub}, now, true},
		{"valid with rotated key set", good, []ed25519.PublicKey{otherPub, pub}, now, true},
		{"just before expiry", good, []ed25519.PublicKey{pub}, now.Add(15*time.Minute - time.Second), true},
		{"at expiry", good, []ed25519.PublicKey{pub}, now.Add(15 * time.Minute), false},
		{"long expired", good, []ed25519.PublicKey{pub}, now.Add(time.Hour), false},
		{"not yet valid beyond skew", good, []ed25519.PublicKey{pub}, now.Add(-2 * time.Minute), false},
		{"untrusted key", good, []ed25519.PublicKey{otherPub}, now, false},
		{"signed by other key, our kid", hdr("EdDSA", WorkloadTokenType, kid) + "." + parts[1] + "." + b64.EncodeToString(ed25519.Sign(otherPriv, []byte(hdr("EdDSA", WorkloadTokenType, kid)+"."+parts[1]))), []ed25519.PublicKey{pub}, now, false},
		{"alg none", hdr("none", WorkloadTokenType, kid) + "." + parts[1] + ".", []ed25519.PublicKey{pub}, now, false},
		{"HS256 keyed with the public key", hs256, []ed25519.PublicKey{pub}, now, false},
		{"wrong typ", hdr("EdDSA", "JWT", kid) + "." + parts[1] + "." + parts[2], []ed25519.PublicKey{pub}, now, false},
		{"payload swapped", parts[0] + "." + b64.EncodeToString([]byte(`{"iss":"halos","sub":"workload:evil"}`)) + "." + parts[2], []ed25519.PublicKey{pub}, now, false},
		{"two segments", parts[0] + "." + parts[1], []ed25519.PublicKey{pub}, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := VerifyWorkloadToken(tc.keys, tc.tok, tc.at)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v want ok=%v", err, tc.ok)
			}
			if tc.ok && (c.Subject != "workload:gh:acme/app" || c.Kind != policy.SubjectWorkload) {
				t.Fatalf("claims %+v", c)
			}
		})
	}
}

// SignWorkloadToken refuses anything Verify would reject, so a bug in the
// exchange can never mint a human subject or an over-long credential.
func TestSignWorkloadTokenRefusesBadClaims(t *testing.T) {
	_, priv, _ := workloadKey(t)
	now := time.Now()
	for name, mod := range map[string]func(*WorkloadClaims){
		"human subject": func(c *WorkloadClaims) { c.Subject = "alice@acme.com" },
		"over an hour":  func(c *WorkloadClaims) { c.Expiry = now.Add(61 * time.Minute).Unix() },
		"wrong aud":     func(c *WorkloadClaims) { c.Audience = "other" },
		"not workload":  func(c *WorkloadClaims) { c.Kind = "" },
		"no jti":        func(c *WorkloadClaims) { c.ID = "" },
	} {
		c := workloadClaims(now)
		mod(&c)
		if _, err := SignWorkloadToken(priv, c); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := SignWorkloadToken(ed25519.PrivateKey("short"), workloadClaims(now)); err == nil {
		t.Error("short key accepted")
	}
}

func TestParseWorkloadKeys(t *testing.T) {
	_, _, a := workloadKey(t)
	_, _, b := workloadKey(t)
	if keys, err := ParseWorkloadKeys(a + b); err != nil || len(keys) != 2 {
		t.Fatalf("two keys: %d %v", len(keys), err)
	}
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
	for name, in := range map[string]string{"empty": "", "garbage": "not pem", "private key block": priv} {
		if _, err := ParseWorkloadKeys(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type stubVerifier struct{ calls int }

func (s *stubVerifier) Verify(*http.Request) (policy.Subject, error) {
	s.calls++
	return policy.Subject{ID: "human@acme.com"}, nil
}

// Workload credentials go to the workload verifier; everything else goes to
// the human verifier untouched, and a bad workload token never falls through.
func TestWorkloadJWTDispatch(t *testing.T) {
	pub, priv, pemKeys := workloadKey(t)
	now := time.Now()
	tok, err := SignWorkloadToken(priv, workloadClaims(now))
	if err != nil {
		t.Fatal(err)
	}
	next := &stubVerifier{}
	v := &WorkloadJWT{Keys: []ed25519.PublicKey{pub}, Next: next}
	req := func(tok string) *http.Request {
		r := httptest.NewRequest("POST", "/v1/messages", nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		return r
	}
	sub, err := v.Verify(req(tok))
	if err != nil || sub.Kind != policy.SubjectWorkload || sub.ID != "workload:gh:acme/app" || next.calls != 0 {
		t.Fatalf("workload: %+v %v calls=%d", sub, err, next.calls)
	}
	if sub, err := v.Verify(req("idp.jwt.token")); err != nil || sub.ID != "human@acme.com" || sub.Kind != "" || next.calls != 1 {
		t.Fatalf("human: %+v %v", sub, err)
	}
	v.Now = func() time.Time { return now.Add(time.Hour) }
	if _, err := v.Verify(req(tok)); err == nil || next.calls != 1 {
		t.Fatalf("expired workload token: err=%v, fell through=%v", err, next.calls != 1)
	}

	// New wires it from Options; mode none keeps meaning "no verification".
	w, err := New(Options{Mode: ModeJWT, Issuer: "https://idp.example", Audience: "a", WorkloadKeys: pemKeys})
	if _, ok := w.(*WorkloadJWT); err != nil || !ok {
		t.Fatalf("New jwt+workload: %T %v", w, err)
	}
	if w, err := New(Options{Mode: ModeNone, WorkloadKeys: pemKeys}); err != nil || w != nil {
		t.Fatalf("mode none: %v %v", w, err)
	}
	if _, err := New(Options{Mode: ModeJWT, Issuer: "https://idp.example", Audience: "a", WorkloadKeys: "junk"}); err == nil {
		t.Fatal("bad workload keys accepted")
	}
}
