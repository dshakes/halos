package a2a

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

func TestCanonicalize(t *testing.T) {
	for in, want := range map[string]string{
		// RFC 8785 appendix B number samples
		`[1e21, 1e-7, 123456789012345680000, 0.000001, -0, 333333333.33333329, 4.50, 2e-3, 1E+30, 0.1]`: `[1e+21,1e-7,123456789012345680000,0.000001,0,333333333.3333333,4.5,0.002,1e+30,0.1]`,
		// RFC 8785 section 3.2.3: members sorted by UTF-16 code units (the emoji's surrogates sort before U+FB33)
		`{"€":1,"\r":2,"דּ":3,"1":4,"😀":5,"\u0080":6,"ö":7}`:      "{\"\\r\":2,\"1\":4,\"\u0080\":6,\"ö\":7,\"€\":1,\"😀\":5,\"דּ\":3}",
		`{ "b" : [ true , null , "a\u0007\"\\</" ] , "a" : {} }`: `{"a":{},"b":[true,null,"a\u0007\"\\</"]}`,
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", in, got, err, want)
		}
	}
	for _, bad := range []string{`{"a":1,"a":2}`, `{"a":1} x`, `{`, `[` + strings.Repeat("[", 100) + strings.Repeat("]", 101)} {
		if _, err := Canonicalize([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

const cardJSON = `{
  "name": "Billing Agent", "description": "Looks up invoices.", "version": "1.2.0",
  "supportedInterfaces": [{"url": "https://billing.example/a2a/v1", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}],
  "capabilities": {"streaming": false, "extensions": []},
  "securitySchemes": {"oidc": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://idp.example/.well-known/openid-configuration"}}},
  "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
  "skills": [{"id": "lookup-invoice", "name": "Lookup", "description": "d", "tags": ["billing"]}]
}`

// signCard adds an AgentCardSignature over card per A2A section 8.4. With
// prune, the payload drops empty members first, as section 8.4.1 asks.
func signCard(t *testing.T, card string, alg, kid string, key crypto.Signer, prune bool) string {
	t.Helper()
	v, err := decodeJSON([]byte(card))
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(map[string]any)
	delete(obj, "signatures")
	var payloadObj any = obj
	if prune {
		payloadObj = pruneDefaults(obj)
	}
	pb, _ := json.Marshal(payloadObj)
	payload, err := Canonicalize(pb)
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JOSE", "kid": kid})
	prot := b64.EncodeToString(hb)
	in := []byte(prot + "." + b64.EncodeToString(payload))
	var sig []byte
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, in)
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case *rsa.PrivateKey:
		h := sha256.Sum256(in)
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	obj["signatures"] = []any{map[string]any{"protected": prot, "signature": b64.EncodeToString(sig)}}
	out, _ := json.MarshalIndent(obj, "", "  ")
	return string(out)
}

func pemOf(t *testing.T, pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestVerifySignatures(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name  string
		card  string
		keys  []Key
		valid bool
	}{
		{"EdDSA", signCard(t, cardJSON, "EdDSA", "k1", edPriv, false), []Key{{Pub: edPub}}, true},
		{"ES256 via JWKS kid", signCard(t, cardJSON, "ES256", "ec-1", ec, false), []Key{{ID: "ec-1", Pub: &ec.PublicKey}}, true},
		{"RS256", signCard(t, cardJSON, "RS256", "r", rs, false), []Key{{Pub: &rs.PublicKey}}, true},
		{"signed after dropping defaults", signCard(t, cardJSON, "EdDSA", "k1", edPriv, true), []Key{{Pub: edPub}}, true},
		{"reformatted card still verifies", strings.ReplaceAll(signCard(t, cardJSON, "EdDSA", "k1", edPriv, false), "\n", "\n\n "), []Key{{Pub: edPub}}, true},
		{"other key", signCard(t, cardJSON, "EdDSA", "k1", otherPriv, false), []Key{{Pub: edPub}}, false},
		{"kid mismatch", signCard(t, cardJSON, "ES256", "ec-2", ec, false), []Key{{ID: "ec-1", Pub: &ec.PublicKey}}, false},
		{"alg/key confusion", signCard(t, cardJSON, "RS256", "r", rs, false), []Key{{Pub: edPub}}, false},
		{"tampered skill", strings.Replace(signCard(t, cardJSON, "EdDSA", "k1", edPriv, false), "lookup-invoice", "transfer-funds", 1), []Key{{Pub: edPub}}, false},
		{"unsigned", cardJSON, []Key{{Pub: edPub}}, false},
		{"alg none", strings.Replace(signCard(t, cardJSON, "EdDSA", "k1", edPriv, false), b64.EncodeToString(mustJSON(map[string]string{"alg": "EdDSA", "typ": "JOSE", "kid": "k1"})), b64.EncodeToString(mustJSON(map[string]string{"alg": "none", "kid": "k1"})), 1), []Key{{Pub: edPub}}, false},
	} {
		err := VerifySignatures([]byte(tc.card), tc.keys)
		if (err == nil) != tc.valid {
			t.Errorf("%s: err=%v", tc.name, err)
		}
		if err != nil && !errors.Is(err, ErrSignature) {
			t.Errorf("%s: %v is not ErrSignature", tc.name, err)
		}
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestParseJWKS(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rs, _ := rsa.GenerateKey(rand.Reader, 2048)
	// a 1024-bit modulus without generating a key: GODEBUG=fips140=only refuses
	// RSA keys under 2048 bits, and the parser must reject it either way
	small := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Rsh(rs.N, 1024), E: 65537}}
	pt, err := ec.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		t.Fatal(err)
	}
	ecx, ecy := pt[1:33], pt[33:]
	set := map[string]any{"keys": []map[string]string{
		{"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": b64.EncodeToString(edPub)},
		{"kty": "EC", "crv": "P-256", "kid": "ec", "x": b64.EncodeToString(ecx), "y": b64.EncodeToString(ecy)},
		{"kty": "EC", "crv": "P-256", "kid": "off-curve", "x": b64.EncodeToString(ecx), "y": b64.EncodeToString(ecx)},
		{"kty": "RSA", "kid": "rsa", "n": b64.EncodeToString(rs.N.Bytes()), "e": "AQAB"},
		{"kty": "RSA", "kid": "small", "n": b64.EncodeToString(small.N.Bytes()), "e": "AQAB"},
		{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
		{"kty": "OKP", "crv": "Ed25519", "kid": "enc", "use": "enc", "x": b64.EncodeToString(edPub)},
	}}
	keys, err := ParseJWKS(mustJSON(set))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	if strings.Join(ids, ",") != "ed,ec,rsa" {
		t.Fatalf("usable keys %v", ids)
	}
	if _, err := ParseJWKS([]byte(`{"keys":[{"kty":"oct","k":"x"}]}`)); err == nil {
		t.Fatal("symmetric-only JWKS accepted")
	}
}

func TestPublicAddr(t *testing.T) {
	for a, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "::1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "fe80::1": false, "fc00::1": false, "100.64.0.1": false, "0.0.0.0": false,
		"::ffff:127.0.0.1": false, "224.0.0.1": false, "198.18.0.1": false,
	} {
		if got := publicAddr(netip.MustParseAddr(a)); got != want {
			t.Errorf("%s: %v", a, got)
		}
	}
}

func tlsFetcher(srvs ...*httptest.Server) Fetcher {
	f := Fetcher{AllowPrivate: true, Timeout: 2 * time.Second}
	f.RootCAs = x509.NewCertPool()
	for _, s := range srvs {
		f.RootCAs.AddCert(s.Certificate())
	}
	return f
}

// TestFetchLimits: https only, no off-host or downgrade redirects, a size
// cap, a timeout, and no private destination unless allowed (SSRF).
func TestFetchLimits(t *testing.T) {
	ctx := context.Background()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(cardJSON)) }))
	t.Cleanup(other.Close)
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/card":
			_, _ = w.Write([]byte(cardJSON))
		case "/same-host":
			http.Redirect(w, r, "/card", http.StatusFound)
		case "/off-host":
			http.Redirect(w, r, other.URL+"/card", http.StatusFound)
		case "/downgrade":
			http.Redirect(w, r, strings.Replace(srv.URL, "https:", "http:", 1)+"/card", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat(" ", MaxCardBytes+1)))
		case "/slow":
			time.Sleep(3 * time.Second)
		}
	}))
	t.Cleanup(srv.Close)
	f := tlsFetcher(srv, other)
	if _, err := f.Get(ctx, srv.URL+"/card"); err != nil {
		t.Fatalf("direct: %v", err)
	}
	if _, err := f.Get(ctx, srv.URL+"/same-host"); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	for _, p := range []string{"/off-host", "/downgrade", "/loop", "/big", "/slow"} {
		if _, err := f.Get(ctx, srv.URL+p); err == nil {
			t.Errorf("%s fetched", p)
		}
	}
	for _, u := range []string{strings.Replace(srv.URL, "https:", "http:", 1) + "/card", "https://user:pw@example.com/card", "file:///etc/passwd"} {
		if _, err := f.Get(ctx, u); err == nil {
			t.Errorf("%s fetched", u)
		}
	}
	f.AllowPrivate = false
	if _, err := f.Get(ctx, srv.URL+"/card"); !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("loopback fetched without --allow-private: %v", err)
	}
}

// TestVerifyCard: the pinned digest and the pinned key (PEM or JWKS) both
// hold, or Verify fails; the digest ignores formatting, not content.
func TestVerifyCard(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed := signCard(t, cardJSON, "EdDSA", "k1", priv, false)
	body := signed
	jwks := mustJSON(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": b64.EncodeToString(pub)}}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			_, _ = w.Write(jwks)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	f := tlsFetcher(srv)
	ctx := context.Background()
	res, err := f.Verify(ctx, srv.URL+"/card", Expect{PublicKey: pemOf(t, pub)})
	if err != nil || !res.Verified || res.Card.Name != "Billing Agent" {
		t.Fatalf("verify: %+v %v", res, err)
	}
	pin := res.Digest
	body = strings.ReplaceAll(signed, "\n", "") // reformatted, same content
	if _, err := f.Verify(ctx, srv.URL+"/card", Expect{Digest: pin, JWKSURL: srv.URL + "/jwks"}); err != nil {
		t.Fatalf("reformatted card: %v", err)
	}
	body = strings.Replace(signed, `"1.2.0"`, `"1.2.1"`, 1) // content changed, signature now stale
	if _, err := f.Verify(ctx, srv.URL+"/card", Expect{Digest: pin}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("changed card: %v", err)
	}
	if _, err := f.Verify(ctx, srv.URL+"/card", Expect{PublicKey: pemOf(t, pub)}); !errors.Is(err, ErrSignature) {
		t.Fatalf("stale signature: %v", err)
	}
	body = cardJSON
	if _, err := f.Verify(ctx, srv.URL+"/card", Expect{JWKSURL: srv.URL + "/jwks"}); !errors.Is(err, ErrSignature) {
		t.Fatalf("unsigned card with a pinned key: %v", err)
	}
}
