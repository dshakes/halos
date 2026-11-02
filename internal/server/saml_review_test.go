package server

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
)

// Security review of ADR-0039 (2026-11-01): one test per finding.

func acrRef(v string) *saml.AuthnContextClassRef {
	if v == "" {
		return nil
	}
	return &saml.AuthnContextClassRef{Value: v}
}

// withIdentity appends lines to the test policy's identity block.
func withIdentity(t *testing.T, lines string) func(*Config) {
	return func(c *Config) {
		p := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.Replace(string(b), "  adminGroups: [platform-admins]\n", "  adminGroups: [platform-admins]\n"+lines, 1)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func lastSAMLAudit(t *testing.T, e *samlEnv) AuditEntry {
	t.Helper()
	a := e.auditActions(t)
	return a[len(a)-1]
}

// H1: identity.requireAcr / requireAmr hold for SAML logins, failing closed.
func TestSAMLAuthnContext(t *testing.T) {
	const acr = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"
	mfa := []saml.Attribute{{Name: samlAMR, Values: []saml.AttributeValue{{Value: samlMFA}}}}
	pwd := []saml.Attribute{{Name: samlAMR, Values: []saml.AttributeValue{{Value: "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/password"}}}}
	for _, tc := range []struct {
		name, policy string
		o            samlAssert
		code         int
	}{
		{"amr: multipleauthn counts as mfa", "  requireAmr: [mfa]\n", samlAssert{attrs: mfa}, 302},
		{"amr: password only", "  requireAmr: [mfa]\n", samlAssert{attrs: pwd}, 403},
		{"amr: not sent (fail closed)", "  requireAmr: [mfa]\n", samlAssert{}, 403},
		{"amr: FriendlyName does not count", "  requireAmr: [mfa]\n", samlAssert{attrs: []saml.Attribute{{Name: "x", FriendlyName: samlAMR, Values: []saml.AttributeValue{{Value: samlMFA}}}}}, 403},
		{"acr: matching class", "  requireAcr: [" + acr + "]\n", samlAssert{acr: acr}, 302},
		{"acr: weaker class", "  requireAcr: [" + acr + "]\n", samlAssert{acr: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}, 403},
		{"acr: not sent (fail closed)", "  requireAcr: [" + acr + "]\n", samlAssert{}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSAMLEnv(t, withIdentity(t, tc.policy))
			c, id := e.samlLogin(t)
			tc.o.inResponseTo, tc.o.groups = id, []string{"platform-admins"}
			w := e.acs(c, e.response(t, tc.o))
			if w.Code != tc.code {
				t.Fatalf("acs: %d %s", w.Code, w.Body)
			}
			if tc.code == 403 {
				if a := lastSAMLAudit(t, e); cookieOf(w, sessionCookie) != nil || a.Action != "login.denied" || a.Details["reason"] != "authn_context" || a.Details["method"] != "saml" {
					t.Fatalf("denial: cookie %v audit %+v", cookieOf(w, sessionCookie), a)
				}
			}
		})
	}
}

// H1: a single requireAcr is requested in the AuthnRequest; the startup log
// warns that SAML logins must carry the requirement.
func TestSAMLRequestedAuthnContextAndWarning(t *testing.T) {
	const acr = "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"
	var logs bytes.Buffer
	e := newSAMLEnv(t, withIdentity(t, "  requireAcr: ["+acr+"]\n"), func(c *Config) { c.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	if !strings.Contains(logs.String(), "SAML login with identity.requireAcr/requireAmr") {
		t.Fatalf("no startup warning: %s", logs.String())
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/saml/login", nil))
	loc, _ := url.Parse(w.Header().Get("Location"))
	z, err := base64.StdEncoding.DecodeString(loc.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(req), "RequestedAuthnContext") || !strings.Contains(string(req), acr) {
		t.Fatalf("AuthnRequest lacks RequestedAuthnContext: %s", req)
	}
}

// L1, L2, L3: the pre-parse screen.
func TestSAMLScreenResponse(t *testing.T) {
	const (
		head = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">`
		sig  = `<ds:Signature/>`
		tail = `</samlp:Response>`
	)
	enc := func(key, data string) string {
		return `<saml:EncryptedAssertion><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="` + data + `"/><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + key + `"/></xenc:EncryptedKey></xenc:EncryptedData></saml:EncryptedAssertion>`
	}
	const (
		oaep   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
		rsa15  = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
		gcm    = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
		cbc    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
		triple = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	)
	for _, tc := range []struct {
		name, doc string
		ok        bool
	}{
		{"one plain assertion", head + `<saml:Assertion/>` + tail, true},
		{"default namespace switches per element", head + `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"/></Assertion>` + tail, true},
		{"prefix rebound to another URI", head + `<saml:Assertion><x:a xmlns:saml="urn:evil"/></saml:Assertion>` + tail, false},
		{"two assertions", head + `<saml:Assertion/><saml:Assertion/>` + tail, false},
		{"assertion and encrypted assertion", head + `<saml:Assertion/>` + enc(oaep, gcm) + tail, false},
		{"nested assertion is not counted", head + `<saml:Assertion><saml:Advice><saml:Assertion/></saml:Advice></saml:Assertion>` + tail, true},
		{"OAEP + GCM unsigned", head + enc(oaep, gcm) + tail, true},
		{"rsa-1_5 key transport, even signed", head + sig + enc(rsa15, gcm) + tail, false},
		{"AES-CBC in an unsigned response", head + enc(oaep, cbc) + tail, false},
		{"AES-CBC in a signed response", head + sig + enc(oaep, cbc) + tail, true},
		{"3DES refused", head + sig + enc(oaep, triple) + tail, false},
		{"rsa-1_5 in a foreign namespace", head + `<saml:EncryptedAssertion><xenc:EncryptedData><zz:EncryptionMethod xmlns:zz="urn:not-xmlenc" Algorithm="` + cbc + `"/><xenc:EncryptedKey><zz:EncryptionMethod xmlns:zz="urn:not-xmlenc" Algorithm="` + rsa15 + `"/></xenc:EncryptedKey></xenc:EncryptedData></saml:EncryptedAssertion>` + tail, false},
		{"duplicate prefixed Algorithm", head + `<saml:EncryptedAssertion><xenc:EncryptedData><xenc:EncryptionMethod Algorithm="` + gcm + `"/><xenc:EncryptedKey><xenc:EncryptionMethod xmlns:q="urn:q" q:Algorithm="` + rsa15 + `" Algorithm="` + oaep + `"/></xenc:EncryptedKey></xenc:EncryptedData></saml:EncryptedAssertion>` + tail, false},
		{"not XML", "not xml <", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := screenResponse([]byte(tc.doc)); (err == nil) != tc.ok {
				t.Fatalf("screenResponse: %v, want ok=%v", err, tc.ok)
			}
		})
	}
	// End to end: crewjam's IdP encrypts with AES-CBC; without a Response signature it is refused.
	e := newSAMLEnv(t)
	c, id := e.samlLogin(t)
	if w := e.acs(c, e.response(t, samlAssert{inResponseTo: id, encrypt: true})); w.Code != 401 {
		t.Fatalf("CBC in unsigned response: %d %s", w.Code, w.Body)
	}
	// And a second assertion appended to a valid response is refused.
	c, id = e.samlLogin(t)
	two := e.response(t, samlAssert{inResponseTo: id, tamper: func(resp, a *etree.Element) { resp.AddChild(a.Copy()) }})
	if w := e.acs(c, two); w.Code != 401 {
		t.Fatalf("two assertions: %d %s", w.Code, w.Body)
	}
}

// L4: groups (and the user id) are matched on the attribute Name only.
func TestSAMLAttributesByNameOnly(t *testing.T) {
	e := newSAMLEnv(t)
	c, id := e.samlLogin(t)
	o := samlAssert{inResponseTo: id, attrs: []saml.Attribute{{Name: "urn:example:not-groups", FriendlyName: "groups", Values: []saml.AttributeValue{{Value: "platform-admins"}}}}}
	w := e.acs(c, e.response(t, o))
	if w.Code != 302 {
		t.Fatalf("acs: %d %s", w.Code, w.Body)
	}
	if code, m := e.me(t, cookieOf(w, sessionCookie)); code != 200 || m.Admin || slices.Contains(m.Groups, "platform-admins") {
		t.Fatalf("FriendlyName granted groups: %d %+v", code, m.Principal)
	}
}

// L5: the request cookie is __Host- prefixed (Secure, Path=/); checked in
// samlLogin and, for OIDC, in oidcEnv.login. Plain http keeps the bare name.
func TestStateCookieName(t *testing.T) {
	e := newEnv(t, nil)
	if n, p := e.s.stateCookie(samlCookie); n != "__Host-halo_saml" || p != "/" {
		t.Fatalf("https: %s %s", n, p)
	}
	e.s.cfg.Portal.BaseURL = "http://127.0.0.1:8080"
	if n, p := e.s.stateCookie(oidcCookie); n != "halo_oidc" || p != "/auth" {
		t.Fatalf("http: %s %s", n, p)
	}
}

// L7: a forged POST does not consume or clear a pending login.
func TestSAMLForgedPostKeepsPendingLogin(t *testing.T) {
	e := newSAMLEnv(t)
	c, id := e.samlLogin(t)
	forged := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="x" Version="2.0"/>`))
	w := e.acs(c, forged)
	if w.Code != 401 {
		t.Fatalf("forged: %d %s", w.Code, w.Body)
	}
	if ck := cookieOf(w, "__Host-"+samlCookie); ck != nil {
		t.Fatalf("forged post cleared the request cookie: %+v", ck)
	}
	if w := e.acs(c, e.response(t, samlAssert{inResponseTo: id, groups: []string{"platform-admins"}})); w.Code != http.StatusFound {
		t.Fatalf("genuine response after a forged one: %d %s", w.Code, w.Body)
	}
}

func TestRSA15DecrypterRefused(t *testing.T) {
	// The global registry must hold our refusing decrypter, not crewjam's PKCS#1 v1.5 one.
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<EncryptedKey><EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><CipherData><CipherValue>AAAA</CipherValue></CipherData></EncryptedKey>`); err != nil {
		t.Fatal(err)
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := xmlenc.Decrypt(k, doc.Root()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("rsa-1_5 decrypt: %v, want refused", err)
	}
}
