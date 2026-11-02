package server

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// Test keys are generated once: RSA generation is slow under -race.
var samlKeys = sync.OnceValue(func() [2]struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
} {
	var out [2]struct {
		key  *rsa.PrivateKey
		cert *x509.Certificate
	}
	for i := range out {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "saml-test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			panic(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		out[i].key, out[i].cert = k, c
	}
	return out
})

const (
	samlIdPEntity = "https://idp.saml.example/metadata"
	samlACSURL    = "https://halo.acme.example/auth/saml/acs"
	samlSPEntity  = "https://halo.acme.example/auth/saml/metadata"
)

type samlEnv struct {
	*env
	idp *saml.IdentityProvider
}

// newSAMLEnv is a server with SAML login on, trusting a crewjam test IdP.
// The clock is the wall clock: crewjam validates with it.
func newSAMLEnv(t *testing.T, mutate ...func(*Config)) *samlEnv {
	t.Helper()
	keys := samlKeys()
	idp := &saml.IdentityProvider{
		Key: keys[0].key, Certificate: keys[0].cert, SignatureMethod: sigRSASHA256,
		MetadataURL: *mustURL(samlIdPEntity), SSOURL: *mustURL("https://idp.saml.example/sso"),
	}
	md, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *Config) {
		c.Now = time.Now
		c.SAML = &SAMLConfig{IdPMetadata: md, Key: keys[1].key, Cert: keys[1].cert}
		for _, m := range mutate {
			m(c)
		}
	})
	return &samlEnv{e, idp}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// samlLogin runs GET /auth/saml/login: the tracking cookie and the request id.
func (e *samlEnv) samlLogin(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/saml/login", nil))
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	if w.Code != http.StatusFound || loc.Host != "idp.saml.example" || q.Get("SAMLRequest") == "" || q.Get("Signature") == "" || q.Get("SigAlg") != sigRSASHA256 {
		t.Fatalf("saml login: %d %s", w.Code, loc)
	}
	c := cookieOf(w, "__Host-"+samlCookie)
	if c == nil || c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteNoneMode {
		t.Fatalf("tracking cookie: %+v", c)
	}
	st, err := e.s.unseal(c.Value)
	if err != nil || st.State == "" {
		t.Fatalf("tracking cookie: %v", err)
	}
	return c, st.State
}

type samlAssert struct {
	inResponseTo, audience, nameID string
	groups                         []string
	issued, notOnOrAfter           time.Time
	unsigned, signResponse         bool
	encrypt                        bool
	acr                            string                                              // AuthnContextClassRef
	attrs                          []saml.Attribute                                    // extra attributes
	tamper                         func(resp *etree.Element, assertion *etree.Element) // after signing
}

// response is a base64 SAMLResponse from the test IdP.
func (e *samlEnv) response(t *testing.T, o samlAssert) string {
	if o.encrypt && fips140.Enforced() {
		// crewjam's test IdP encrypts with RSA-OAEP-SHA1, which FIPS 140-only mode refuses (as it should).
		t.Skip("encrypted-assertion fixture needs SHA-1 OAEP; not available in FIPS 140-only mode")
	}
	t.Helper()
	now := time.Now()
	if o.issued.IsZero() {
		o.issued = now
	}
	if o.notOnOrAfter.IsZero() {
		o.notOnOrAfter = now.Add(5 * time.Minute)
	}
	if o.audience == "" {
		o.audience = samlSPEntity
	}
	if o.nameID == "" {
		o.nameID = "boss@acme.example"
	}
	spd := &saml.SPSSODescriptor{}
	if o.encrypt {
		spd = &e.s.saml.sp.Metadata().SPSSODescriptors[0]
	}
	req := &saml.IdpAuthnRequest{
		IDP: e.idp, Now: o.issued, Request: saml.AuthnRequest{ID: o.inResponseTo}, SPSSODescriptor: spd,
		ACSEndpoint:             &saml.IndexedEndpoint{Binding: saml.HTTPPostBinding, Location: samlACSURL},
		ServiceProviderMetadata: &saml.EntityDescriptor{EntityID: samlSPEntity},
	}
	var aud []saml.AudienceRestriction
	if o.audience != "-" {
		aud = []saml.AudienceRestriction{{Audience: saml.Audience{Value: o.audience}}}
	}
	vals := make([]saml.AttributeValue, len(o.groups))
	for i, g := range o.groups {
		vals[i] = saml.AttributeValue{Type: "xs:string", Value: g}
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	req.Assertion = &saml.Assertion{
		ID: "id-" + hex.EncodeToString(id), IssueInstant: o.issued, Version: "2.0",
		Issuer: saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: samlIdPEntity},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: o.nameID},
			SubjectConfirmations: []saml.SubjectConfirmation{{Method: samlBearer, SubjectConfirmationData: &saml.SubjectConfirmationData{
				InResponseTo: o.inResponseTo, NotOnOrAfter: o.notOnOrAfter, Recipient: samlACSURL,
			}}},
		},
		Conditions:          &saml.Conditions{NotBefore: o.issued.Add(-time.Minute), NotOnOrAfter: o.notOnOrAfter, AudienceRestrictions: aud},
		AuthnStatements:     []saml.AuthnStatement{{AuthnInstant: o.issued, SessionIndex: "s1", AuthnContext: saml.AuthnContext{AuthnContextClassRef: acrRef(o.acr)}}},
		AttributeStatements: []saml.AttributeStatement{{Attributes: append([]saml.Attribute{{Name: "groups", Values: vals}}, o.attrs...)}},
	}
	if o.unsigned {
		req.AssertionEl = req.Assertion.Element()
	} else if err := req.MakeAssertionEl(); err != nil {
		t.Fatal(err)
	}
	var respEl *etree.Element
	if o.signResponse {
		if err := req.MakeResponse(); err != nil {
			t.Fatal(err)
		}
		respEl = req.ResponseEl
	} else {
		r := &saml.Response{
			ID: "id-r" + hex.EncodeToString(id), InResponseTo: o.inResponseTo, Version: "2.0", IssueInstant: o.issued, Destination: samlACSURL,
			Issuer: &saml.Issuer{Value: samlIdPEntity}, Status: saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
		}
		respEl = r.Element()
		respEl.AddChild(req.AssertionEl)
	}
	if o.tamper != nil {
		o.tamper(respEl, req.AssertionEl)
	}
	doc := etree.NewDocument()
	doc.SetRoot(respEl)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (e *samlEnv) acs(c *http.Cookie, samlResponse string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/auth/saml/acs", strings.NewReader(url.Values{"SAMLResponse": {samlResponse}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://idp.saml.example") // a cross-site form post, as from a real IdP
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *samlEnv) me(t *testing.T, c *http.Cookie) (int, Me) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/me", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 {
		return w.Code, Me{}
	}
	return w.Code, decode[Me](t, w)
}

func TestSAMLLogin(t *testing.T) {
	nameIDOf := func(el *etree.Element) *etree.Element { return el.FindElement(".//NameID") }
	tests := []struct {
		name string
		opts func(reqID string) samlAssert
		code int
		msg  string
	}{
		{name: "valid, signed assertion", code: 302, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, groups: []string{"platform-admins", "unrelated"}}
		}},
		{name: "valid, signed response, encrypted assertion", code: 302, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, groups: []string{"platform-admins"}, signResponse: true, encrypt: true}
		}},
		{name: "unsigned assertion", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, groups: []string{"platform-admins"}, unsigned: true}
		}},
		{name: "wrong audience", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, audience: "https://other-sp.example/metadata"}
		}},
		{name: "no audience restriction", code: 401, opts: func(id string) samlAssert { return samlAssert{inResponseTo: id, audience: "-"} }},
		{name: "expired", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, issued: time.Now().Add(-10 * time.Minute), notOnOrAfter: time.Now().Add(-5 * time.Minute)}
		}},
		{name: "past NotOnOrAfter beyond our 60s skew (inside crewjam's 180s)", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, notOnOrAfter: time.Now().Add(-90 * time.Second)}
		}},
		{name: "InResponseTo another request", code: 401, opts: func(string) samlAssert { return samlAssert{inResponseTo: "id-attacker"} }},
		{name: "tampered after signing", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, nameID: "dev@acme.example", tamper: func(_, a *etree.Element) {
				nameIDOf(a).SetText("boss@acme.example")
			}}
		}},
		{name: "signature wrapping: evil assertion carrying the signed one", code: 401, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, nameID: "dev@acme.example", tamper: func(resp, signed *etree.Element) {
				evil := signed.Copy() // same ID and Signature, attacker's subject
				nameIDOf(evil).SetText("boss@acme.example")
				resp.RemoveChild(signed)
				evil.FindElement("./Subject").AddChild(signed) // the genuine one, hidden where nobody reads it
				resp.AddChild(evil)
			}}
		}},
		{name: "reserved subject", code: 403, opts: func(id string) samlAssert {
			return samlAssert{inResponseTo: id, nameID: "BreakGlass:root"}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newSAMLEnv(t)
			c, id := e.samlLogin(t)
			resp := e.response(t, tc.opts(id))
			w := e.acs(c, resp)
			if w.Code != tc.code {
				t.Fatalf("acs: %d %s", w.Code, w.Body)
			}
			sc := cookieOf(w, sessionCookie)
			if tc.code != 302 {
				if sc != nil {
					t.Fatal("session cookie set on failure")
				}
				return
			}
			if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode {
				t.Fatalf("session cookie: %+v", sc)
			}
			code, m := e.me(t, sc)
			if code != 200 || m.ID != "boss@acme.example" || !m.Admin || !slices.Equal(m.Groups, []string{"platform-admins"}) {
				t.Fatalf("me: %d %+v", code, m.Principal)
			}
			if a := e.auditActions(t); a[len(a)-1].Action != "login" || a[len(a)-1].Details["method"] != "saml" {
				t.Fatalf("audit: %+v", a[len(a)-1])
			}
			// The same response with the same tracking cookie is refused.
			if w := e.acs(c, resp); w.Code != 400 || !strings.Contains(w.Body.String(), "already used") {
				t.Fatalf("replay: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestSAMLIdPInitiated(t *testing.T) {
	e := newSAMLEnv(t)
	if w := e.acs(nil, e.response(t, samlAssert{})); w.Code != 400 || !strings.Contains(w.Body.String(), "IdP-initiated login is off") {
		t.Fatalf("unsolicited response with IdP-initiated off: %d %s", w.Code, w.Body)
	}
	e = newSAMLEnv(t, func(c *Config) { c.SAML.AllowIdPInitiated = true })
	resp := e.response(t, samlAssert{groups: []string{"platform-admins"}})
	if w := e.acs(nil, resp); w.Code != 302 || cookieOf(w, sessionCookie) == nil {
		t.Fatalf("idp-initiated: %d %s", w.Code, w.Body)
	}
	// Assertion ids are single-use: a captured response cannot be posted again.
	if w := e.acs(nil, resp); w.Code != 401 || !strings.Contains(w.Body.String(), "already used") {
		t.Fatalf("replayed assertion: %d %s", w.Code, w.Body)
	}
	// A request id, when present, is still enforced.
	c, _ := e.samlLogin(t)
	if w := e.acs(c, e.response(t, samlAssert{inResponseTo: "id-other"})); w.Code != 401 {
		t.Fatalf("wrong InResponseTo with IdP-initiated on: %d %s", w.Code, w.Body)
	}
}

func TestSAMLDeactivatedSCIMUser(t *testing.T) {
	e := newSAMLEnv(t, func(c *Config) {
		c.SCIMTokenSHA256, c.SCIMAuthoritative = []string{sha256Hex(scimTok)}, true
	})
	e.createSCIMUser(t, "boss@acme.example", false)
	c, id := e.samlLogin(t)
	w := e.acs(c, e.response(t, samlAssert{inResponseTo: id, groups: []string{"platform-admins"}}))
	if w.Code != 403 || cookieOf(w, sessionCookie) != nil || !strings.Contains(w.Body.String(), "deactivated") {
		t.Fatalf("deactivated user: %d %s", w.Code, w.Body)
	}
}

func TestSAMLGroupsOverageDenied(t *testing.T) {
	e := newSAMLEnv(t)
	c, id := e.samlLogin(t)
	// Entra ID sends groups.link instead of groups past 150.
	raw := e.response(t, samlAssert{inResponseTo: id, attrs: []saml.Attribute{{Name: samlGroupsLink, Values: []saml.AttributeValue{{Value: "https://graph.windows.net/x"}}}}})
	if w := e.acs(c, raw); w.Code != 403 || !strings.Contains(w.Body.String(), "overage") {
		t.Fatalf("overage: %d %s", w.Code, w.Body)
	}
}

func TestSAMLMetadataAndMethods(t *testing.T) {
	e := newSAMLEnv(t)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/saml/metadata", nil))
	var md saml.EntityDescriptor
	if w.Code != 200 || xml.Unmarshal(w.Body.Bytes(), &md) != nil || md.EntityID != samlSPEntity || len(md.SPSSODescriptors) != 1 {
		t.Fatalf("metadata: %d %s", w.Code, w.Body)
	}
	acs := md.SPSSODescriptors[0].AssertionConsumerServices
	if len(acs) != 1 || acs[0].Binding != saml.HTTPPostBinding || acs[0].Location != samlACSURL {
		t.Fatalf("ACS endpoints: %+v", acs)
	}
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/methods", nil))
	if got := decode[AuthMethods](t, w); !got.SAML || !got.OIDC {
		t.Fatalf("methods: %+v", got)
	}
	off := newEnv(t, nil)
	for _, p := range []string{"/auth/saml/login", "/auth/saml/metadata"} {
		w := httptest.NewRecorder()
		off.h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 404 {
			t.Fatalf("%s with SAML off: %d", p, w.Code)
		}
	}
}

func TestSAMLConfigValidation(t *testing.T) {
	keys := samlKeys()
	idp := &saml.IdentityProvider{Key: keys[0].key, Certificate: keys[0].cert, MetadataURL: *mustURL(samlIdPEntity), SSOURL: *mustURL("https://idp.saml.example/sso")}
	md, _ := xml.Marshal(idp.Metadata())
	for name, c := range map[string]SAMLConfig{
		"no key":           {IdPMetadata: md, Cert: keys[1].cert},
		"key/cert differ":  {IdPMetadata: md, Key: keys[1].key, Cert: keys[0].cert},
		"no metadata":      {Key: keys[1].key, Cert: keys[1].cert},
		"garbage metadata": {IdPMetadata: []byte("<nope/>"), Key: keys[1].key, Cert: keys[1].cert},
	} {
		if _, err := newSAML(c, "https://halo.acme.example"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := newSAML(SAMLConfig{IdPMetadata: md, Key: keys[1].key, Cert: keys[1].cert}, "https://halo.acme.example"); err != nil {
		t.Fatal(err)
	}
}
