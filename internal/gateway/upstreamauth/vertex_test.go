package upstreamauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetadataTokenSource(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Metadata-Flavor") != "Google" || r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/token" {
			http.Error(w, "bad", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.meta","expires_in":3600}`))
	}))
	defer srv.Close()
	clock := time.Unix(1000, 0)
	m := &MetadataTokenSource{BaseURL: srv.URL, now: func() time.Time { return clock }}
	for range 3 {
		if tok, err := m.Token(context.Background()); err != nil || tok != "ya29.meta" {
			t.Fatalf("%q %v", tok, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("token not cached: %d fetches", hits.Load())
	}
	clock = clock.Add(3600*time.Second - 30*time.Second) // inside the refresh gap
	if _, err := m.Token(context.Background()); err != nil || hits.Load() != 2 {
		t.Fatalf("expected refresh near expiry: %v, %d fetches", err, hits.Load())
	}
}

func TestMetadataTokenSourceErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret-ish body", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := (&MetadataTokenSource{BaseURL: srv.URL}).Token(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-ish") {
		t.Fatalf("want an error without the response body, got %v", err)
	}
}

func testKeyJSON(t *testing.T, tokenURI string) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	m := map[string]string{"type": "service_account", "client_email": "sa@proj.iam.gserviceaccount.com",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
	if tokenURI != "" {
		m["token_uri"] = tokenURI
	}
	b, _ := json.Marshal(m)
	return b, &key.PublicKey
}

func TestServiceAccountTokenSource(t *testing.T) {
	kj, pub := testKeyJSON(t, "")
	s, err := NewServiceAccountTokenSource(kj)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		jwt := strings.Split(r.PostForm.Get("assertion"), ".")
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || len(jwt) != 3 {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		sig, _ := base64.RawURLEncoding.DecodeString(jwt[2])
		sum := sha256.Sum256([]byte(jwt[0] + "." + jwt[1]))
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		claims, _ := base64.RawURLEncoding.DecodeString(jwt[1])
		var c map[string]any
		_ = json.Unmarshal(claims, &c)
		if c["iss"] != "sa@proj.iam.gserviceaccount.com" || c["scope"] != gcpScope || c["aud"] != s.tokenURI {
			http.Error(w, "bad claims", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"ya29.sa","expires_in":3600}`))
	}))
	defer srv.Close()
	s.tokenURI = srv.URL // production value is pinned to googleapis.com by the constructor
	if tok, err := s.Token(context.Background()); err != nil || tok != "ya29.sa" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestServiceAccountKeyValidation(t *testing.T) {
	good, _ := testKeyJSON(t, "")
	evil, _ := testKeyJSON(t, "https://attacker.example/token")
	plain, _ := testKeyJSON(t, "http://oauth2.googleapis.com/token")
	user := []byte(`{"type":"authorized_user","client_id":"x"}`)
	for name, c := range map[string]struct {
		in   []byte
		fail bool
	}{"good": {good, false}, "foreign token_uri": {evil, true}, "http token_uri": {plain, true}, "authorized_user": {user, true}, "garbage": {[]byte("{"), true}} {
		if _, err := NewServiceAccountTokenSource(c.in); (err != nil) != c.fail {
			t.Errorf("%s: err=%v, want failure=%v", name, err, c.fail)
		}
	}
}

func TestDefaultTokenSource(t *testing.T) {
	ts, err := DefaultTokenSource(func(string) string { return "" })
	if _, ok := ts.(*MetadataTokenSource); err != nil || !ok {
		t.Fatalf("no env: want metadata source, got %T %v", ts, err)
	}
	kj, _ := testKeyJSON(t, "")
	p := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(p, kj, 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err = DefaultTokenSource(func(k string) string {
		if k == "GOOGLE_APPLICATION_CREDENTIALS" {
			return p
		}
		return ""
	})
	if _, ok := ts.(*ServiceAccountTokenSource); err != nil || !ok {
		t.Fatalf("with key file: want service account source, got %T %v", ts, err)
	}
	if _, err := DefaultTokenSource(func(string) string { return filepath.Join(t.TempDir(), "missing.json") }); err == nil {
		t.Fatal("missing key file must error")
	}
}
