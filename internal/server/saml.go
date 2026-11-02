package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/crewjam/saml"

	"github.com/dshakes/halos/internal/storage"
)

// SAML 2.0 service provider login (ADR-0039), next to OIDC. crewjam/saml
// verifies the XML signature (or decrypts, then verifies) and checks issuer,
// destination, recipient, InResponseTo, conditions and audience; this file
// adds what it leaves open: a mandatory audience and bearer confirmation, a
// tighter clock skew, single-use request ids and assertion ids, and the same
// directory, grants, revocation and session as an OIDC login.

const (
	samlCookie = "halo_saml"
	// samlSkew is the leeway on NotBefore/NotOnOrAfter, tighter than
	// crewjam's 180s (which it still applies first).
	samlSkew = time.Minute
	// maxSAMLForm bounds the ACS POST body; real responses are a few KiB.
	maxSAMLForm     = 256 << 10
	kvSAMLAssertion = "saml-assertion"
	samlBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer" //nolint:gosec // a SAML confirmation method URI, not a credential
	// samlGroupsLink is what Entra ID sends instead of groups past 150 (groups overage).
	samlGroupsLink = "http://schemas.microsoft.com/claims/groups.link"
	// RSA-SHA256 and ECDSA-SHA256 (XML-DSig more) for signing AuthnRequests.
	sigRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sigECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
)

// DefaultSAMLGroupsAttributes are the attribute names (Name or FriendlyName)
// read as groups when SAMLConfig.GroupsAttributes is empty: Okta and generic
// (groups, Group), Ping and LDAP-backed IdPs (memberOf), Entra ID and ADFS.
var DefaultSAMLGroupsAttributes = []string{
	"groups", "Group", "memberOf",
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
	"http://schemas.xmlsoap.org/claims/Group",
}

// SAMLConfig turns on SAML login (ADR-0039); Config.SAML nil = off.
type SAMLConfig struct {
	// IdPMetadata is the IdP's SAML metadata XML (EntityDescriptor, or an
	// EntitiesDescriptor holding exactly one IdP).
	IdPMetadata []byte
	// Key and Cert are the SP key pair (RSA or ECDSA): AuthnRequests are
	// signed with it and EncryptedAssertions decrypted with it.
	Key  crypto.Signer
	Cert *x509.Certificate
	// EntityID is the SP entity id and the audience assertions must name;
	// "" = <baseURL>/auth/saml/metadata.
	EntityID string
	// UserAttribute names the attribute holding the user id; "" = the NameID.
	UserAttribute string
	// GroupsAttributes name the attributes holding groups; empty = DefaultSAMLGroupsAttributes.
	GroupsAttributes []string
	// AllowIdPInitiated accepts unsolicited responses (no AuthnRequest).
	// Off by default: they cannot be bound to the browser that logs in.
	AllowIdPInitiated bool
}

type samlState struct {
	sp  *saml.ServiceProvider
	acs url.URL
	cfg SAMLConfig
}

// newSAML validates c and builds the service provider for baseURL (already
// checked https, http only for loopback, by Portal.Validate).
func newSAML(c SAMLConfig, baseURL string) (*samlState, error) {
	if baseURL == "" {
		return nil, errors.New("server: SAML login needs the portal baseURL")
	}
	if c.Key == nil || c.Cert == nil {
		return nil, errors.New("server: SAML login needs the SP key and certificate")
	}
	pub, ok := c.Key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(c.Cert.PublicKey) {
		return nil, errors.New("server: SAML SP certificate does not match the SP key")
	}
	var sigAlg string
	switch c.Key.(type) {
	case *rsa.PrivateKey:
		sigAlg = sigRSASHA256
	case *ecdsa.PrivateKey:
		sigAlg = sigECDSASHA256
	default:
		return nil, fmt.Errorf("server: SAML SP key must be RSA or ECDSA, not %T", c.Key)
	}
	idp, err := parseIdPMetadata(c.IdPMetadata)
	if err != nil {
		return nil, err
	}
	base := strings.TrimRight(baseURL, "/")
	md, err := url.Parse(base + "/auth/saml/metadata")
	if err != nil {
		return nil, fmt.Errorf("server: SAML: %w", err)
	}
	acs, _ := url.Parse(base + "/auth/saml/acs") // same base: cannot fail now
	if c.EntityID == "" {
		c.EntityID = md.String()
	}
	if len(c.GroupsAttributes) == 0 {
		c.GroupsAttributes = DefaultSAMLGroupsAttributes
	}
	st := &samlState{acs: *acs, cfg: c}
	st.sp = &saml.ServiceProvider{
		EntityID: c.EntityID, Key: c.Key, Certificate: c.Cert,
		MetadataURL: *md, AcsURL: *acs, IDPMetadata: idp,
		SignatureMethod:   sigAlg,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat, // the IdP's configured format
		// crewjam accepts an assertion with no AudienceRestriction at all; we do not.
		ValidateAudienceRestriction: func(a *saml.Assertion) error {
			for _, ar := range a.Conditions.AudienceRestrictions {
				if ar.Audience.Value == c.EntityID {
					return nil
				}
			}
			return fmt.Errorf("assertion audience does not name %q", c.EntityID)
		},
	}
	if st.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" {
		return nil, errors.New("server: SAML IdP metadata has no HTTP-Redirect SingleSignOnService (the console CSP allows no cross-site form posts)")
	}
	return st, nil
}

// parseIdPMetadata reads an EntityDescriptor, or an EntitiesDescriptor with
// exactly one IdP, and requires a signing certificate.
func parseIdPMetadata(b []byte) (*saml.EntityDescriptor, error) {
	if len(b) == 0 {
		return nil, errors.New("server: SAML IdP metadata is empty")
	}
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil {
		var all saml.EntitiesDescriptor
		if xml.Unmarshal(b, &all) != nil {
			return nil, fmt.Errorf("server: SAML IdP metadata: %w", err)
		}
		var idps []saml.EntityDescriptor
		for _, e := range all.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				idps = append(idps, e)
			}
		}
		if len(idps) != 1 {
			return nil, fmt.Errorf("server: SAML IdP metadata: an EntitiesDescriptor must hold exactly one IdP, found %d", len(idps))
		}
		ed = idps[0]
	}
	if ed.EntityID == "" || len(ed.IDPSSODescriptors) == 0 {
		return nil, errors.New("server: SAML IdP metadata has no entityID or IDPSSODescriptor")
	}
	for _, d := range ed.IDPSSODescriptors {
		for _, k := range d.KeyDescriptors {
			if (k.Use == "" || k.Use == "signing") && len(k.KeyInfo.X509Data.X509Certificates) > 0 {
				return &ed, nil
			}
		}
	}
	return nil, errors.New("server: SAML IdP metadata has no signing certificate")
}

// samlCookieSet writes the request-tracking cookie. The IdP posts the
// response cross-site, so over https it must be SameSite=None to come back.
func (s *Server) samlCookieSet(w http.ResponseWriter, val string, ttl time.Duration) {
	secure := strings.HasPrefix(s.cfg.Portal.BaseURL, "https://")
	ss := http.SameSiteLaxMode // http (loopback dev): None needs Secure
	if secure {
		ss = http.SameSiteNoneMode
	}
	//nolint:gosec // Secure follows the portal base URL scheme (http in local dev); SameSite=None is required for the IdP's cross-site POST
	http.SetCookie(w, &http.Cookie{Name: samlCookie, Value: val, Path: "/auth/saml", MaxAge: int(ttl.Seconds()), HttpOnly: true, SameSite: ss, Secure: secure})
}

// samlLogin (GET /auth/saml/login) sends the browser to the IdP with a
// signed AuthnRequest (HTTP-Redirect binding), its id held in a sealed cookie.
func (s *Server) samlLogin(w http.ResponseWriter, r *http.Request) {
	if s.saml == nil {
		apiErr(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	sp := s.saml.sp
	req, err := sp.MakeAuthenticationRequest(sp.GetSSOBindingLocation(saml.HTTPRedirectBinding), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	var u *url.URL
	if err == nil {
		u, err = req.Redirect("", sp)
	}
	if err != nil {
		s.cfg.Log.Error("saml login unavailable", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "login unavailable")
		return
	}
	s.samlCookieSet(w, s.seal(cookiePayload{State: req.ID, Exp: s.cfg.Now().Add(10 * time.Minute).Unix()}), 10*time.Minute)
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// samlMetadata (GET /auth/saml/metadata) is the SP metadata to register at the IdP.
func (s *Server) samlMetadata(w http.ResponseWriter, _ *http.Request) {
	if s.saml == nil {
		apiErr(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	md := s.saml.sp.Metadata()
	for i := range md.SPSSODescriptors { // only HTTP-POST: artifact resolution is refused
		d := &md.SPSSODescriptors[i]
		d.AssertionConsumerServices = slices.DeleteFunc(d.AssertionConsumerServices, func(e saml.IndexedEndpoint) bool { return e.Binding != saml.HTTPPostBinding })
	}
	b, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		apiErr(w, http.StatusInternalServerError, "metadata unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(append([]byte(xml.Header), b...))
}

// parse verifies raw with crewjam/saml. A panic there (it dereferences an
// IdP-signed assertion's Subject and Conditions unchecked) is a rejection.
func (st *samlState) parse(raw []byte, ids []string) (a *saml.Assertion, err error) {
	defer func() {
		if p := recover(); p != nil {
			a, err = nil, fmt.Errorf("malformed assertion: %v", p)
		}
	}()
	sp := *st.sp
	// InResponseTo is checked whenever there is a request; only a response
	// with none (IdP-initiated, when allowed) skips it.
	sp.AllowIDPInitiated = len(ids) == 0
	return sp.ParseXMLResponse(raw, ids, st.acs)
}

// check holds a verified assertion to what crewjam leaves optional.
func (st *samlState) check(a *saml.Assertion, now time.Time) error {
	if a.Subject == nil || a.Conditions == nil {
		return errors.New("assertion has no Subject or Conditions")
	}
	if !slices.ContainsFunc(a.Subject.SubjectConfirmations, func(c saml.SubjectConfirmation) bool { return c.Method == samlBearer }) {
		return errors.New("assertion has no bearer SubjectConfirmation") // crewjam checks Recipient only on those present
	}
	if c := a.Conditions; c.NotBefore.Add(-samlSkew).After(now) || c.NotOnOrAfter.IsZero() || !c.NotOnOrAfter.Add(samlSkew).After(now) {
		return fmt.Errorf("assertion outside its validity window (%s..%s, skew %s)", c.NotBefore, c.NotOnOrAfter, samlSkew)
	}
	if a.ID == "" {
		return errors.New("assertion has no ID")
	}
	return nil
}

// subject is the user id and groups an assertion carries.
func (st *samlState) subject(a *saml.Assertion) (string, []string, bool, error) {
	var user string
	var groups []string
	overage := false
	for _, as := range a.AttributeStatements {
		for _, at := range as.Attributes {
			is := func(n string) bool { return at.Name == n || (at.FriendlyName != "" && at.FriendlyName == n) }
			if st.cfg.UserAttribute != "" && user == "" && is(st.cfg.UserAttribute) && len(at.Values) > 0 {
				user = at.Values[0].Value
			}
			if slices.ContainsFunc(st.cfg.GroupsAttributes, is) {
				for _, v := range at.Values {
					if g := strings.TrimSpace(v.Value); g != "" && !slices.Contains(groups, g) {
						groups = append(groups, g)
					}
				}
			}
			overage = overage || is(samlGroupsLink)
		}
	}
	if st.cfg.UserAttribute == "" && a.Subject.NameID != nil {
		user = a.Subject.NameID.Value
	}
	if user = strings.TrimSpace(user); user == "" {
		what := "NameID"
		if st.cfg.UserAttribute != "" {
			what = "attribute " + st.cfg.UserAttribute
		}
		return "", nil, false, fmt.Errorf("assertion has no %s", what)
	}
	return user, groups, overage && len(groups) == 0, nil
}

// consumeAssertion records a's id until it can no longer be accepted; false
// if it already was (a replay) or the store cannot say.
func (s *Server) consumeAssertion(a *saml.Assertion, now time.Time) bool {
	exp := a.IssueInstant.Add(saml.MaxIssueDelay)
	if a.Conditions.NotOnOrAfter.After(exp) {
		exp = a.Conditions.NotOnOrAfter
	}
	exp = exp.Add(saml.MaxClockSkew)
	if exp.Before(now) {
		exp = now.Add(saml.MaxClockSkew)
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	h := sha256.Sum256([]byte(a.Issuer.Value + "\x00" + a.ID))
	ok, err := s.kv.Add(ctx, kvSAMLAssertion, hex.EncodeToString(h[:]), nil, exp)
	return err == nil && ok
}

// samlACS (POST /auth/saml/acs) is the assertion consumer service (HTTP-POST
// binding only; artifact resolution is refused).
func (s *Server) samlACS(w http.ResponseWriter, r *http.Request) {
	if s.saml == nil {
		apiErr(w, http.StatusNotFound, "SAML login is not configured")
		return
	}
	ip := s.clientIP(r)
	if s.loginFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		apiErr(w, http.StatusTooManyRequests, "too many failed logins")
		return
	}
	fail := func(reason string, code int, msg string, err error) {
		s.metrics.authFailure("saml", reason)
		s.loginFails.fail(ip)
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) {
			err = ire.PrivateErr // never log ire.Response: it is the whole assertion
		}
		s.cfg.Log.Warn("saml acs failed", "msg", msg, "err", err)
		apiErr(w, code, msg)
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLForm)
	if err := r.ParseForm(); err != nil {
		fail("form", http.StatusBadRequest, "malformed SAML POST", err)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil || len(raw) == 0 {
		fail("response", http.StatusBadRequest, "missing or malformed SAMLResponse", err)
		return
	}
	var ids []string
	if c, err := r.Cookie(samlCookie); err == nil {
		st, err := s.unseal(c.Value)
		if err != nil || st.State == "" {
			fail("invalid_state", http.StatusBadRequest, "invalid login state", err)
			return
		}
		s.samlCookieSet(w, "", -time.Second) // single-use
		if !s.oidc.consume("saml\x00"+st.State, time.Unix(st.Exp, 0)) {
			fail("state_reused", http.StatusBadRequest, "login state already used", nil)
			return
		}
		ids = []string{st.State}
	} else if !s.saml.cfg.AllowIdPInitiated {
		fail("missing_state", http.StatusBadRequest, "missing login state: start at /auth/saml/login (IdP-initiated login is off)", nil)
		return
	}
	a, err := s.saml.parse(raw, ids)
	if err != nil {
		fail("assertion", http.StatusUnauthorized, "SAML response rejected", err)
		return
	}
	now := s.cfg.Now()
	if err := s.saml.check(a, now); err != nil {
		fail("assertion", http.StatusUnauthorized, "SAML response rejected", err)
		return
	}
	if !s.consumeAssertion(a, now) {
		fail("replay", http.StatusUnauthorized, "SAML assertion already used", nil)
		return
	}
	user, groups, overage, err := s.saml.subject(a)
	if err != nil {
		fail("identity", http.StatusForbidden, err.Error(), err)
		return
	}
	if reservedSubject(user) {
		fail("identity", http.StatusForbidden, "user id uses a prefix reserved for service accounts and break-glass", nil)
		return
	}
	if overage && !s.scimAuthoritative() {
		s.metrics.authFailure("saml", "groups_overage")
		s.cfg.Log.Warn("saml login denied", "user", user, "reason", "groups_overage")
		s.Audit(r.Context(), user, "login.denied", "", map[string]string{"reason": "groups_overage", "method": "saml"})
		apiErr(w, http.StatusForbidden, "your group memberships did not fit in the SAML assertion (Entra ID groups overage): an admin must emit only groups assigned to the application, or make SCIM authoritative")
		return
	}
	s.issueSession(w, r, user, groups, "saml", fail)
}

// authMethods (GET /auth/methods) tells the login page which sign-in
// methods are configured. Public: it says only whether each is on.
func (s *Server) authMethods(w http.ResponseWriter, _ *http.Request) {
	org, _, _ := s.pol.Get()
	oidcOn := org != nil && org.Identity.Issuer != "" && org.Identity.ClientID != "" && s.cfg.Portal.BaseURL != ""
	writeJSON(w, http.StatusOK, AuthMethods{OIDC: oidcOn, SAML: s.saml != nil})
}

// AuthMethods is GET /auth/methods.
type AuthMethods struct {
	OIDC bool `json:"oidc"`
	SAML bool `json:"saml"`
}
