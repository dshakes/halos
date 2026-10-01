package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/identity/identitytest"
)

type oidcEnv struct {
	*env
	iss *identitytest.Issuer
}

// newOIDCEnv points the portal policy's issuer at a live identitytest issuer;
// adminGroups is the YAML flow list to use.
func newOIDCEnv(t *testing.T, adminGroups string) *oidcEnv {
	t.Helper()
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	srv := iss.Serve()
	t.Cleanup(srv.Close)
	e := newEnv(t, func(c *Config) {
		p := filepath.Join(c.PolicyDir, "halos.yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.Replace(string(b), "https://idp.example", iss.URL, 1)
		s = strings.Replace(s, "adminGroups: [platform-admins]", "adminGroups: "+adminGroups, 1)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	return &oidcEnv{e, iss}
}

func cookieOf(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// login runs /auth/login and the issuer's /authorize; it returns the state
// cookie and the callback URL the IdP redirected to.
func (o *oidcEnv) login(t *testing.T) (*http.Cookie, *url.URL) {
	t.Helper()
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, httptest.NewRequest("GET", "/auth/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	c := cookieOf(w, oidcCookie)
	auth, _ := url.Parse(w.Header().Get("Location"))
	q := auth.Query()
	if c == nil || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("login redirect lacks state/nonce/PKCE: %s (cookie %v)", auth, c)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get(auth.String())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasSuffix(back.Path, "/auth/callback") {
		t.Fatalf("idp redirect: %d %s", resp.StatusCode, back)
	}
	return c, back
}

func (o *oidcEnv) callback(c *http.Cookie, u *url.URL) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/auth/callback?"+u.RawQuery, nil)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, r)
	return w
}

func (o *oidcEnv) me(t *testing.T, c *http.Cookie) (int, Me) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/me", nil)
	r.AddCookie(c)
	w := httptest.NewRecorder()
	o.h.ServeHTTP(w, r)
	if w.Code != 200 {
		return w.Code, Me{}
	}
	return w.Code, decode[Me](t, w)
}

func TestOIDCLogin(t *testing.T) {
	many := make([]any, 500)
	for i := range many {
		many[i] = fmt.Sprintf("idp-group-%03d-with-a-long-name", i)
	}
	tests := []struct {
		name   string
		claims map[string]any
		tamper func(c *http.Cookie, u *url.URL) (*http.Cookie, *url.URL)
		code   int
		admin  bool
		groups []string
	}{
		{name: "happy admin", claims: map[string]any{"email": "boss@acme.example", "email_verified": true, "groups": []any{"platform-admins", "unrelated"}}, code: 302, admin: true, groups: []string{"platform-admins"}},
		{name: "happy developer, 500 groups", claims: map[string]any{"email": "dev@acme.example", "email_verified": true, "groups": append(many, "ai-platform")}, code: 302, groups: []string{"ai-platform"}},
		{name: "wrong state", claims: map[string]any{"email": "a@b", "email_verified": true}, code: 400, tamper: func(c *http.Cookie, u *url.URL) (*http.Cookie, *url.URL) {
			q := u.Query()
			q.Set("state", "forged")
			u.RawQuery = q.Encode()
			return c, u
		}},
		{name: "missing state cookie", claims: map[string]any{"email": "a@b", "email_verified": true}, code: 400, tamper: func(_ *http.Cookie, u *url.URL) (*http.Cookie, *url.URL) { return nil, u }},
		{name: "nonce mismatch", claims: map[string]any{"email": "a@b", "email_verified": true, "nonce": "attacker"}, code: 401},
		{name: "idp denies", claims: nil, code: 401},
		{name: "unverified email", claims: map[string]any{"email": "boss@acme.example", "email_verified": false, "groups": []any{"platform-admins"}}, code: 403},
		{name: "email_verified absent", claims: map[string]any{"email": "boss@acme.example", "email_verified": nil}, code: 403},
		{name: "no user claim", claims: map[string]any{"groups": []any{"x"}}, code: 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := newOIDCEnv(t, "[platform-admins]")
			o.iss.SetLogin(tc.claims)
			c, u := o.login(t)
			if tc.tamper != nil {
				c, u = tc.tamper(c, u)
			}
			w := o.callback(c, u)
			if w.Code != tc.code {
				t.Fatalf("callback: %d %s", w.Code, w.Body)
			}
			if tc.code != 302 {
				if cookieOf(w, sessionCookie) != nil {
					t.Fatal("session cookie set on failure")
				}
				return
			}
			sc := cookieOf(w, sessionCookie)
			if sc == nil || len(sc.Value) > maxCookie || !sc.HttpOnly || !sc.Secure {
				t.Fatalf("session cookie: %+v", sc)
			}
			code, m := o.me(t, sc)
			if code != 200 || m.ID != tc.claims["email"] || m.Admin != tc.admin || strings.Join(m.Groups, ",") != strings.Join(tc.groups, ",") {
				t.Fatalf("me: %d %+v", code, m.Principal)
			}
			if tc.groups[0] == "ai-platform" && m.Ring != "ring0-harness-team" {
				t.Errorf("filtered groups must still resolve the ring: %q", m.Ring)
			}
			// Replaying the same state cookie + callback is refused.
			if w := o.callback(c, u); w.Code != 400 || !strings.Contains(w.Body.String(), "already used") {
				t.Fatalf("replay: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestOIDCPKCEVerified(t *testing.T) {
	o := newOIDCEnv(t, "[platform-admins]")
	o.iss.SetLogin(map[string]any{"email": "a@b", "email_verified": true})
	c, u := o.login(t)
	st, err := o.s.unseal(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	st.PKCE = "wrong-verifier-wrong-verifier-wrong-verifier-123"
	c.Value = o.s.seal(st)
	if w := o.callback(c, u); w.Code != 401 || !strings.Contains(w.Body.String(), "code exchange failed") {
		t.Fatalf("bad PKCE verifier: %d %s", w.Code, w.Body)
	}
}

// Many policy-relevant groups overflow the cookie: the session moves server-side,
// and logout both clears the cookie and kills the server-side session.
func TestOIDCServerSideSessionAndLogout(t *testing.T) {
	var admins []string
	var claims []any
	for i := range 200 {
		g := fmt.Sprintf("admins-of-some-rather-long-team-name-%03d", i)
		admins, claims = append(admins, g), append(claims, g)
	}
	o := newOIDCEnv(t, "["+strings.Join(admins, ", ")+"]")
	o.iss.SetLogin(map[string]any{"email": "boss@acme.example", "email_verified": true, "groups": claims})
	w := o.callback(o.login(t))
	sc := cookieOf(w, sessionCookie)
	if w.Code != 302 || sc == nil || len(sc.Value) > maxCookie {
		t.Fatalf("callback %d cookie %d bytes", w.Code, len(sc.String()))
	}
	if code, m := o.me(t, sc); code != 200 || !m.Admin || len(m.Groups) != 200 {
		t.Fatalf("me: %d admin=%v groups=%d", code, m.Admin, len(m.Groups))
	}
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	r.AddCookie(sc)
	lw := httptest.NewRecorder()
	o.h.ServeHTTP(lw, r)
	if c := cookieOf(lw, sessionCookie); lw.Code != 204 || c == nil || c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("logout: %d %+v", lw.Code, c)
	}
	if code, _ := o.me(t, sc); code != 401 {
		t.Fatalf("session usable after logout: %d", code)
	}
	r = httptest.NewRequest("POST", "/auth/logout", nil)
	r.Header.Set("Origin", "https://evil.example")
	lw = httptest.NewRecorder()
	o.h.ServeHTTP(lw, r)
	if lw.Code != 403 {
		t.Fatalf("cross-origin logout: %d", lw.Code)
	}
}
