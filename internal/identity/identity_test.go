package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/identity/identitytest"
	"github.com/halos-dev/halos/internal/policy"
)

const aud = "halos-gw"

func newVerifier(t *testing.T) (*OIDCJWT, *identitytest.Issuer) {
	t.Helper()
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	srv := iss.Serve()
	t.Cleanup(srv.Close)
	v, err := NewOIDCJWT(iss.URL, aud, "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return v, iss
}

func reqWith(tok string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

func TestOIDCJWT(t *testing.T) {
	v, iss := newVerifier(t)
	now := time.Now()
	mint := func(c map[string]any) string {
		t.Helper()
		tok, err := iss.Mint(c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	other, _ := identitytest.NewIssuer("k1") // same kid, different key
	other.URL = iss.URL
	otherTok, _ := other.Mint(map[string]any{"aud": aud, "email": "eve@x"})

	// HS256 "key confusion": MAC keyed with the public key bytes the JWKS exposes.
	pub, _ := x509.MarshalPKIXPublicKey(&iss.Key.PublicKey)
	hs, _ := identitytest.Sign(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "k1"},
		map[string]any{"iss": iss.URL, "aud": aud, "email": "eve@x", "exp": now.Add(time.Hour).Unix()},
		func(in []byte) ([]byte, error) { m := hmac.New(sha256.New, pub); m.Write(in); return m.Sum(nil), nil })
	none, _ := identitytest.Sign(map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"iss": iss.URL, "aud": aud, "email": "eve@x", "exp": now.Add(time.Hour).Unix()}, nil)

	tests := []struct {
		name       string
		tok        string
		wantErr    bool
		wantID     string
		wantGroups []string
	}{
		{"valid", mint(map[string]any{"aud": aud, "email": "alice@acme.com", "groups": []string{"ai-platform", "eng"}}), false, "alice@acme.com", []string{"ai-platform", "eng"}},
		{"aud as array", mint(map[string]any{"aud": []string{"other", aud}, "email": "a@x"}), false, "a@x", nil},
		{"missing groups is not an error", mint(map[string]any{"aud": aud, "email": "bob@acme.com"}), false, "bob@acme.com", nil},
		{"expired", mint(map[string]any{"aud": aud, "email": "a@x", "exp": now.Add(-time.Hour).Unix()}), true, "", nil},
		{"not yet valid", mint(map[string]any{"aud": aud, "email": "a@x", "nbf": now.Add(time.Hour).Unix()}), true, "", nil},
		{"wrong aud", mint(map[string]any{"aud": "someone-else", "email": "a@x"}), true, "", nil},
		{"wrong iss", mint(map[string]any{"iss": "https://evil.example", "aud": aud, "email": "a@x"}), true, "", nil},
		{"missing user claim", mint(map[string]any{"aud": aud}), true, "", nil},
		{"email not verified", mint(map[string]any{"aud": aud, "email": "ceo@acme.com", "email_verified": false}), true, "", nil},
		{"email_verified missing", mint(map[string]any{"aud": aud, "email": "ceo@acme.com", "email_verified": nil}), true, "", nil},
		{"email_verified string true", mint(map[string]any{"aud": aud, "email": "a@x", "email_verified": "true"}), false, "a@x", nil},
		{"alg none", none, true, "", nil},
		{"HS256 with public key", hs, true, "", nil},
		{"signed by unknown key", otherTok, true, "", nil},
		{"garbage", "not.a.jwt", true, "", nil},
		{"no token", "", true, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := v.Verify(reqWith(tc.tok))
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && (sub.ID != tc.wantID || !slices.Equal(sub.Groups, tc.wantGroups)) {
				t.Fatalf("got %+v", sub)
			}
		})
	}
}

func TestOIDCJWTCustomClaimsAndXAPIKey(t *testing.T) {
	iss, _ := identitytest.NewIssuer("k1")
	srv := iss.Serve()
	defer srv.Close()
	v, err := NewOIDCJWT(iss.URL, aud, "preferred_username", "roles", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := iss.Mint(map[string]any{"aud": aud, "preferred_username": "carol", "roles": "a, b"})
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("x-api-key", tok)
	sub, err := v.Verify(r)
	if err != nil || sub.ID != "carol" || !slices.Equal(sub.Groups, []string{"a", "b"}) {
		t.Fatalf("got %+v err=%v", sub, err)
	}
}

func TestSubjectFromClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  map[string]any
		cfg     Options
		wantID  string
		wantErr string
	}{
		{"verified email", map[string]any{"email": " a@x ", "email_verified": true, "groups": []any{"g"}}, Options{}, "a@x", ""},
		{"verified email string", map[string]any{"email": "a@x", "email_verified": "true"}, Options{}, "a@x", ""},
		{"unverified email", map[string]any{"email": "a@x", "email_verified": false}, Options{}, "", "not verified"},
		{"email_verified missing", map[string]any{"email": "a@x"}, Options{}, "", "not verified"},
		{"email_verified wrong type", map[string]any{"email": "a@x", "email_verified": 1.0}, Options{}, "", "not verified"},
		{"explicit email claim", map[string]any{"email": "a@x", "email_verified": "false"}, Options{UserClaim: "email"}, "", "not verified"},
		{"opt-out trusts unverified", map[string]any{"email": "a@x"}, Options{TrustUnverifiedEmail: true}, "a@x", ""},
		{"other claim needs no verification", map[string]any{"sub": "00u1"}, Options{UserClaim: "sub"}, "00u1", ""},
		{"missing claim", map[string]any{"email_verified": true}, Options{}, "", `no "email" claim`},
		{"blank claim", map[string]any{"sub": "  "}, Options{UserClaim: "sub"}, "", `no "sub" claim`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := SubjectFromClaims(tc.claims, tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want ~%q", err, tc.wantErr)
				}
				return
			}
			if err != nil || sub.ID != tc.wantID {
				t.Fatalf("got %+v err=%v", sub, err)
			}
		})
	}
}

func TestNewPassesTrustUnverifiedEmail(t *testing.T) {
	v, err := New(Options{Mode: ModeJWT, Issuer: "https://idp", Audience: aud, TrustUnverifiedEmail: true})
	if err != nil || !v.(*OIDCJWT).TrustUnverifiedEmail {
		t.Fatalf("v=%+v err=%v", v, err)
	}
}

func TestOIDCJWTDiscoveryRetries(t *testing.T) {
	iss, _ := identitytest.NewIssuer("k1")
	var up atomic.Bool
	srv := httptest.NewUnstartedServer(nil)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		iss.Handler().ServeHTTP(w, r)
	})
	srv.Start()
	defer srv.Close()
	iss.URL = srv.URL
	v, _ := NewOIDCJWT(iss.URL, aud, "", "", nil)
	tok, _ := iss.Mint(map[string]any{"aud": aud, "email": "a@x"})
	if _, err := v.Verify(reqWith(tok)); err == nil {
		t.Fatal("want error while IdP down")
	}
	up.Store(true)
	if _, err := v.Verify(reqWith(tok)); err != nil {
		t.Fatalf("should recover once IdP is up: %v", err)
	}
}

func TestNewOIDCJWTRequiresAudience(t *testing.T) {
	if _, err := NewOIDCJWT("https://idp", "", "", "", nil); err == nil {
		t.Fatal("want error")
	}
}

func TestTrustedHeader(t *testing.T) {
	if _, err := NewTrustedHeader("x-user", "", nil); err == nil {
		t.Fatal("must refuse to build without CIDRs")
	}
	if _, err := NewTrustedHeader("x-halo-user", "", []string{"10.0.0.0/8"}); err == nil {
		t.Fatal("x-halo-* identity header must be refused")
	}
	if _, err := NewTrustedHeader("x-user", "", []string{"nope"}); err == nil {
		t.Fatal("bad CIDR must error")
	}
	v, err := NewTrustedHeader("x-user", "x-groups", []string{"10.0.0.0/8", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, remote, user string
		wantErr            bool
	}{
		{"in cidr", "10.1.2.3:5555", "alice", false},
		{"ipv6 in cidr", "[fd00::1]:80", "alice", false},
		{"bare ip", "10.1.2.3", "alice", false},
		{"outside cidr", "203.0.113.9:1", "alice", true},
		{"garbage remote", "nope", "alice", true},
		{"no header", "10.1.2.3:1", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.user != "" {
				r.Header.Set("x-user", tc.user)
				r.Header.Set("x-groups", "a, b")
			}
			sub, err := v.Verify(r)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
			if err == nil && (sub.ID != "alice" || !slices.Equal(sub.Groups, []string{"a", "b"})) {
				t.Fatalf("got %+v", sub)
			}
		})
	}
	for name, hdr := range map[string]string{"identity": "x-user", "groups": "x-groups"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.1.2.3:1"
		r.Header.Set("x-user", "alice")
		r.Header.Set("x-groups", "a")
		r.Header.Add(hdr, "mallory")
		if _, err := v.Verify(r); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("duplicate %s header: err=%v want ErrAmbiguous", name, err)
		}
	}
}

func TestHeaderNames(t *testing.T) {
	org := &policy.Org{Gateway: &policy.Gateway{Auth: policy.GatewayAuth{IdentityHeader: "X-Acme-User"}}}
	if got := (Options{GroupsHeader: "X-Groups"}).HeaderNames(org); !slices.Equal(got, []string{"x-acme-user", "x-groups"}) {
		t.Fatalf("got %v", got)
	}
	if got := (Options{}).HeaderNames(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestEffectiveAndResolver(t *testing.T) {
	org := &policy.Org{Identity: policy.Identity{Issuer: "https://idp", ClientID: "cid"}}
	e := Options{}.Effective(org)
	if e.Mode != ModeJWT || e.Audience != "cid" {
		t.Fatalf("%+v", e)
	}
	if got := (Options{}).Effective(&policy.Org{}).Mode; got != ModeTrustedHeader {
		t.Fatalf("mode=%s", got)
	}
	var r Resolver
	if _, err := r.Get(Options{}, &policy.Org{}); err == nil {
		t.Fatal("trusted_header without CIDRs must fail closed")
	}
	v1, err := r.Get(Options{}, org)
	if err != nil {
		t.Fatal(err)
	}
	if v2, _ := r.Get(Options{}, org); v1 != v2 {
		t.Fatal("verifier should be reused while options are unchanged")
	}
	if v, err := r.Get(Options{Mode: ModeNone}, nil); v != nil || err != nil {
		t.Fatal("none => nil verifier")
	}
	if _, err := r.Get(Options{Mode: "bogus"}, nil); err == nil {
		t.Fatal("unknown mode must error")
	}
}
