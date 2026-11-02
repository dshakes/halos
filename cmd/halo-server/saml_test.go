package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSAMLFlags (ADR-0039): SAML is on with IdP metadata and needs the SP key pair.
func TestSAMLFlags(t *testing.T) {
	base := []string{"--policy-dir", "p", "--token-file", "t"}
	for _, c := range []struct {
		name string
		args []string
		err  string
	}{
		{"off", nil, ""},
		{"on", []string{"--saml-idp-metadata-file", "m", "--saml-sp-key-file", "k", "--saml-sp-cert-file", "c"}, ""},
		{"needs SP key pair", []string{"--saml-idp-metadata-url", "https://idp.example/md"}, "--saml-sp-key-file"},
		{"file and URL", []string{"--saml-idp-metadata-file", "m", "--saml-idp-metadata-url", "https://x", "--saml-sp-key-file", "k", "--saml-sp-cert-file", "c"}, "only one"},
		{"stray flag", []string{"--saml-allow-idp-initiated"}, "need --saml-idp-metadata"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseFlags(append(append([]string{}, base...), c.args...))
			if (c.err == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.err)) {
				t.Fatalf("err %v, want %q", err, c.err)
			}
		})
	}
}

func TestSAMLConfigFiles(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyF := write("sp.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}))
	certF := write("sp.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	md := []byte("<EntityDescriptor/>")
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(md) }))
	defer idp.Close()
	c, err := samlOptions{metadataURL: idp.URL, keyFile: keyF, certFile: certF, groupsAttrs: "groups, memberOf"}.config(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(c.IdPMetadata) != string(md) || c.Cert == nil || c.Key == nil || strings.Join(c.GroupsAttributes, "|") != "groups|memberOf" {
		t.Fatalf("config: %+v", c)
	}
	if _, err := fetchSAMLMetadata(context.Background(), "http://idp.example/md"); err == nil {
		t.Fatal("plain http to a remote host accepted")
	}
	if _, err := (samlOptions{metadataFile: write("md.xml", md), keyFile: certF, certFile: certF}).config(context.Background()); err == nil {
		t.Fatal("certificate accepted as key")
	}
}
