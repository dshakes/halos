package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

const (
	scimTok     = "scim-token-0123456789abcdef"
	scimTokNext = "scim-token-rotated-9876543210"
)

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// scimEnv is a server with SCIM on (and the gateway token set for the directory endpoint).
func scimEnv(t testing.TB, authoritative bool, mutate func(*Config)) *env {
	t.Helper()
	return newEnv(t, func(c *Config) {
		c.SCIMTokenSHA256, c.SCIMAuthoritative, c.GatewayToken = []string{sha256Hex(scimTok)}, authoritative, gwTok
		if mutate != nil {
			mutate(c)
		}
	})
}

func (e *env) scim(method, path, body string) *httptest.ResponseRecorder {
	return e.scimAs("Bearer "+scimTok, method, path, body)
}

func (e *env) scimAs(auth, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	r.Header.Set("Content-Type", "application/scim+json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) createSCIMUser(t testing.TB, userName string, active bool) string {
	t.Helper()
	w := e.scim("POST", "/scim/v2/Users", fmt.Sprintf(`{"userName":%q,"active":%t,"externalId":"ext-%s"}`, userName, active, userName))
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", userName, w.Code, w.Body)
	}
	return decode[scimUserOut](t, w).ID
}

func (e *env) createSCIMGroup(t testing.TB, name string, members ...string) string {
	t.Helper()
	var refs []string
	for _, m := range members {
		refs = append(refs, fmt.Sprintf(`{"value":%q}`, m))
	}
	w := e.scim("POST", "/scim/v2/Groups", fmt.Sprintf(`{"displayName":%q,"members":[%s]}`, name, strings.Join(refs, ",")))
	if w.Code != http.StatusCreated {
		t.Fatalf("create group %s: %d %s", name, w.Code, w.Body)
	}
	return decode[scimGroupOut](t, w).ID
}

// sessionAt is a session cookie request for p issued at iat.
func (e *env) sessionAt(p Principal, iat time.Time, method, url string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Iat: iat.UnixNano(), Exp: e.now.Add(time.Hour).Unix()})})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func (e *env) auditActions(t testing.TB) []AuditEntry {
	t.Helper()
	all, err := e.s.auditLog.all()
	if err != nil {
		t.Fatal(err)
	}
	return all
}

type scimStep struct {
	Name   string          `json:"name"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"`
	Status int             `json:"status"`
	Save   string          `json:"save"`
}

// TestSCIMIdPFixtures replays Okta's and Entra ID's documented request
// sequences (testdata/scim) against an authoritative directory: the user lands
// in ring0-harness-team through the SCIM group alone, and the final
// deactivation revokes the session and device and drops the gateway identity.
func TestSCIMIdPFixtures(t *testing.T) {
	for _, idp := range []string{"okta", "entra"} {
		t.Run(idp, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "scim", idp+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var steps []scimStep
			if err := json.Unmarshal(raw, &steps); err != nil {
				t.Fatal(err)
			}
			e := scimEnv(t, true, nil)
			jane := Principal{ID: "jane.doe@acme.example"} // the OIDC groups claim says nothing
			ids := map[string]string{}
			subst := func(s string) string {
				for k, v := range ids {
					s = strings.ReplaceAll(s, "{{"+k+"}}", v)
				}
				return s
			}
			var dt string
			for i, st := range steps {
				if i == len(steps)-1 { // before the deactivation: provisioned state is in force
					me := decode[Me](t, e.as(jane, "GET", "/api/v1/me", ""))
					if me.Ring != "ring0-harness-team" || !slices.Equal(me.Groups, []string{"ai-platform"}) {
						t.Fatalf("provisioned user: ring %q groups %v, want ring0-harness-team via SCIM group ai-platform", me.Ring, me.Groups)
					}
					dt = enrollDevice(t, e, jane)
					if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 200 {
						t.Fatalf("device before deactivation: %d", c)
					}
				}
				w := e.scim(st.Method, subst(st.Path), subst(string(st.Body)))
				if w.Code != st.Status {
					t.Fatalf("%s: %d %s", st.Name, w.Code, w.Body)
				}
				if ct := w.Header().Get("Content-Type"); ct != "application/scim+json" {
					t.Fatalf("%s: content type %q", st.Name, ct)
				}
				if st.Save != "" {
					var out struct{ ID string }
					if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.ID == "" {
						t.Fatalf("%s: no id in %s", st.Name, w.Body)
					}
					ids[st.Save] = out.ID
				}
			}
			u, groups, ok := e.s.scim.store.Lookup(jane.ID)
			if !ok || u.Active || !slices.Equal(groups, []string{"ai-platform"}) {
				t.Fatalf("final directory state: %+v %v %v", u, groups, ok)
			}
			if idp == "entra" && (u.Emails[0].Value != "jane.d@acme.example" || u.Name.FamilyName != "Doe-Smith") {
				t.Fatalf("entra patch not applied: %+v %+v", u.Emails, u.Name)
			}
			if idp == "okta" && u.DisplayName != "Jane Doe-Smith" {
				t.Fatalf("okta PUT not applied: %+v", u)
			}
			if c := e.as(jane, "GET", "/api/v1/me", "").Code; c != 401 {
				t.Fatalf("session after deactivation: %d, want 401", c)
			}
			if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
				t.Fatalf("device after deactivation: %d, want 401", c)
			}
			gw := do(e.h, "GET", "/api/v1/gateway/directory?subject="+jane.ID, "Bearer "+gwTok, "")
			if got := decode[gateway.DirectoryEntry](t, gw); gw.Code != 200 || got.Active || len(got.Groups) != 0 {
				t.Fatalf("gateway directory after deactivation: %d %+v", gw.Code, got)
			}
			var acts []string
			for _, a := range e.auditActions(t) {
				if a.Actor == scimActor {
					acts = append(acts, a.Action)
				}
				if idp == "entra" && a.Action == "scim.user.patch" && a.Details["ignoredAttributes"] != "" &&
					!strings.Contains(a.Details["ignoredAttributes"], "employeeNumber") {
					t.Errorf("ignored attributes not audited: %v", a.Details)
				}
			}
			mutations := 0
			for _, st := range steps {
				if st.Method != "GET" {
					mutations++
				}
			}
			if len(acts) != mutations {
				t.Fatalf("%d scim audit entries for %d mutations: %v", len(acts), mutations, acts)
			}
		})
	}
}

// TestSCIMDeprovisionRevokesSessions: with SCIM on but not authoritative,
// deactivating or deleting a user kills their console sessions, device tokens
// and pending enrollment tokens at once, and audits it.
func TestSCIMDeprovisionRevokesSessions(t *testing.T) {
	for _, how := range []string{"deactivate", "delete", "put-inactive"} {
		t.Run(how, func(t *testing.T) {
			e := scimEnv(t, false, func(c *Config) { c.DataDir = t.TempDir() })
			id := e.createSCIMUser(t, dev.ID, true)
			dt := enrollDevice(t, e, dev)
			pending := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
			if c := e.as(dev, "GET", "/api/v1/me", "").Code; c != 200 {
				t.Fatalf("session before: %d", c)
			}
			var w *httptest.ResponseRecorder
			switch how {
			case "deactivate":
				w = e.scim("PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)
			case "delete":
				w = e.scim("DELETE", "/scim/v2/Users/"+id, "")
			case "put-inactive":
				w = e.scim("PUT", "/scim/v2/Users/"+id, `{"userName":"`+dev.ID+`","active":false}`)
			}
			if w.Code >= 300 {
				t.Fatalf("%s: %d %s", how, w.Code, w.Body)
			}
			if c := e.as(dev, "GET", "/api/v1/me", "").Code; c != 401 {
				t.Fatalf("session after %s: %d, want 401", how, c)
			}
			if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
				t.Fatalf("device token after %s: %d, want 401", how, c)
			}
			if c := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+pending+`"}`).Code; c != 401 {
				t.Fatalf("pending enrollment after %s: %d, want 401", how, c)
			}
			devs := e.s.devices.list()
			if len(devs) != 1 || !devs[0].Revoked {
				t.Fatalf("device not revoked on disk: %+v", devs)
			}
			last := e.auditActions(t)
			a := last[len(last)-1]
			if a.Actor != scimActor || a.Target != dev.ID || a.Details["sessionsRevoked"] != "true" || a.Details["devicesRevoked"] != "1" {
				t.Fatalf("deprovision audit: %+v", a)
			}
			// A later login (a session issued after the revocation) works only if the user is active again.
			later := e.now.Add(time.Second)
			if how != "delete" {
				if c := e.sessionAt(dev, later, "GET", "/api/v1/me").Code; c != 401 {
					t.Fatalf("new session of an inactive user: %d, want 401", c)
				}
				if c := e.scim("PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":"True"}]}`).Code; c != 200 {
					t.Fatalf("reactivate: %d", c)
				}
			}
			if c := e.sessionAt(dev, later, "GET", "/api/v1/me").Code; c != 200 {
				t.Fatalf("new session after reactivation/deletion (not authoritative): %d, want 200", c)
			}
		})
	}
}

// TestSCIMAuthoritative: unprovisioned users are refused on every
// authentication path; SCIM groups replace the session's and device's own.
func TestSCIMAuthoritative(t *testing.T) {
	e := scimEnv(t, true, nil)
	if c := e.as(admin, "GET", "/api/v1/fleet", "").Code; c != 401 {
		t.Fatalf("unprovisioned admin session: %d, want 401", c)
	}
	uid := e.createSCIMUser(t, admin.ID, true)
	// The cookie claims platform-admins; the directory has no such membership yet.
	if c := e.as(admin, "GET", "/api/v1/fleet", "").Code; c != 403 {
		t.Fatalf("provisioned, not in the admin group: %d, want 403", c)
	}
	e.createSCIMGroup(t, "platform-admins", uid)
	if c := e.as(admin, "GET", "/api/v1/fleet", "").Code; c != 200 {
		t.Fatalf("admin via the SCIM group: %d, want 200", c)
	}
	// Group membership changes apply to live sessions at once.
	gid := e.s.scim.store.Groups()[0].ID
	if c := e.scim("PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"remove","path":"members[value eq \"`+uid+`\"]"}]}`).Code; c != 200 {
		t.Fatalf("remove member: %d", c)
	}
	if c := e.as(admin, "GET", "/api/v1/fleet", "").Code; c != 403 {
		t.Fatalf("admin after removal from the SCIM group: %d, want 403", c)
	}
}

func TestNewSCIMConfig(t *testing.T) {
	for _, c := range []struct {
		name    string
		hashes  []string
		auth    bool
		wantErr bool
	}{
		{"off", nil, false, false},
		{"authoritative without token", nil, true, true},
		{"not hex", []string{"zz"}, false, true},
		{"short", []string{"abcd"}, false, true},
		{"hash of the empty token", []string{sha256Hex("")}, false, true},
		{"rotation pair", []string{sha256Hex(scimTok), " " + sha256Hex(scimTokNext) + " "}, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sc, err := newSCIM(Config{SCIMTokenSHA256: c.hashes, SCIMAuthoritative: c.auth})
			if (err != nil) != c.wantErr {
				t.Fatalf("err %v, wantErr %v", err, c.wantErr)
			}
			if err == nil && (sc == nil) != (len(c.hashes) == 0) {
				t.Fatalf("service %v for %d hashes", sc, len(c.hashes))
			}
		})
	}
}

// TestSCIMAuth: only a configured SCIM bearer token (either one of a rotation
// pair) gets in; the admin's console session, the gateway token and the fleet
// token do not. Failures are rate limited.
func TestSCIMAuth(t *testing.T) {
	e := scimEnv(t, false, func(c *Config) { c.SCIMTokenSHA256 = append(c.SCIMTokenSHA256, sha256Hex(scimTokNext)) })
	for _, c := range []struct {
		name, auth string
		want       int
	}{
		{"none", "", 401},
		{"current token", "Bearer " + scimTok, 200},
		{"rotated token", "Bearer " + scimTokNext, 200},
		{"lower-case scheme", "bearer " + scimTok, 200},
		{"wrong token", "Bearer " + scimTok + "x", 401},
		{"prefix of the token", "Bearer " + scimTok[:10], 401},
		{"empty bearer", "Bearer ", 401},
		{"basic", "Basic " + scimTok, 401},
		{"gateway token", "Bearer " + gwTok, 401},
		{"fleet token", "Bearer " + tok, 401},
	} {
		e.s.authFails = authLimiter{}
		if got := e.scimAs(c.auth, "GET", "/scim/v2/Users", "").Code; got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	// An admin session cookie is never a SCIM credential.
	e.s.authFails = authLimiter{}
	r := httptest.NewRequest("POST", "/scim/v2/Users", strings.NewReader(`{"userName":"x@acme.example"}`))
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: admin.ID, Groups: admin.Groups, Exp: e.now.Add(time.Hour).Unix()})})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 401 || len(e.s.scim.store.Users()) != 0 {
		t.Fatalf("admin session on SCIM: %d, users %d", w.Code, len(e.s.scim.store.Users()))
	}
	var se scimErr
	if json.Unmarshal(w.Body.Bytes(), &se) != nil || se.Status != "401" || se.Schemas[0] != scimErrorSchema {
		t.Fatalf("not a SCIM error: %s", w.Body)
	}
	// Brute force runs into the shared failed-auth budget.
	e.s.authFails = authLimiter{}
	last := 0
	for range authFailBurst + 1 {
		last = e.scimAs("Bearer guess", "GET", "/scim/v2/Users", "").Code
	}
	if last != 429 {
		t.Fatalf("after %d failures: %d, want 429", authFailBurst+1, last)
	}
	// SCIM off: 404 for everyone, valid-looking token or not.
	off := newEnv(t, nil)
	if c := off.scim("GET", "/scim/v2/Users", "").Code; c != 404 {
		t.Fatalf("SCIM disabled: %d, want 404", c)
	}
	if c := do(off.h, "GET", "/api/v1/gateway/directory?subject=x", "Bearer "+gwTok, "").Code; c != 404 {
		t.Fatalf("directory with SCIM disabled: %d, want 404", c)
	}
}

func TestSCIMFilterAndPagination(t *testing.T) {
	e := scimEnv(t, false, nil)
	for _, n := range []string{"a@x.example", "b@x.example", "c@x.example", "d@x.example", "E@x.example"} {
		e.createSCIMUser(t, n, true)
	}
	gid := e.createSCIMGroup(t, "Eng-Platform")
	e.createSCIMGroup(t, "eng-data")
	type listResp struct {
		TotalResults, StartIndex, ItemsPerPage int
		Resources                              []struct{ ID, UserName, DisplayName, ExternalID string }
	}
	for _, c := range []struct {
		query                   string
		status, total, n, start int
		first                   string
	}{
		{"", 200, 5, 5, 1, "E@x.example"},
		{"?count=2", 200, 5, 2, 1, "E@x.example"},
		{"?startIndex=2&count=2", 200, 5, 2, 2, "a@x.example"},
		{"?startIndex=5&count=2", 200, 5, 1, 5, "d@x.example"},
		{"?startIndex=6", 200, 5, 0, 6, ""},
		{"?startIndex=0&count=1", 200, 5, 1, 1, "E@x.example"},
		{"?startIndex=-3&count=1", 200, 5, 1, 1, "E@x.example"},
		{"?count=0", 200, 5, 0, 1, ""},
		{"?count=-1", 200, 5, 0, 1, ""},
		{"?count=100000", 200, 5, 5, 1, "E@x.example"},
		{"?filter=" + q(`userName eq "c@x.example"`), 200, 1, 1, 1, "c@x.example"},
		{"?filter=" + q(`userName eq "C@X.EXAMPLE"`), 200, 1, 1, 1, "c@x.example"}, // userName is case-insensitive
		{"?filter=" + q(`USERNAME EQ "e@x.example"`), 200, 1, 1, 1, "E@x.example"},
		{"?filter=" + q(`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a@x.example"`), 200, 1, 1, 1, "a@x.example"},
		{"?filter=" + q(`externalId eq "ext-b@x.example"`), 200, 1, 1, 1, "b@x.example"},
		{"?filter=" + q(`externalId eq "EXT-B@X.EXAMPLE"`), 200, 0, 0, 1, ""}, // externalId is caseExact
		{"?filter=" + q(`userName eq "nobody"`), 200, 0, 0, 1, ""},
		{"?filter=" + q(`userName eq "a \"quoted\" name"`), 200, 0, 0, 1, ""},
		{"?filter=" + q(`userName sw "a"`), 400, 0, 0, 0, ""},
		{"?filter=" + q(`title eq "x"`), 400, 0, 0, 0, ""},
		{"?filter=" + q(`userName eq "a@x.example" and active eq true`), 400, 0, 0, 0, ""},
		{"?filter=" + q(`userName eq a@x.example`), 400, 0, 0, 0, ""},
		{"?filter=" + q(`userName`), 400, 0, 0, 0, ""},
		{"?count=abc", 400, 0, 0, 0, ""},
		{"?startIndex=1.5", 400, 0, 0, 0, ""},
	} {
		w := e.scim("GET", "/scim/v2/Users"+c.query, "")
		if w.Code != c.status {
			t.Errorf("%s: %d %s", c.query, w.Code, w.Body)
			continue
		}
		if c.status != 200 {
			if se := decode[scimErr](t, w); se.ScimType == "" {
				t.Errorf("%s: no scimType in %s", c.query, w.Body)
			}
			continue
		}
		l := decode[listResp](t, w)
		if l.TotalResults != c.total || l.ItemsPerPage != c.n || len(l.Resources) != c.n || l.StartIndex != c.start {
			t.Errorf("%s: total %d items %d/%d start %d; want %d %d %d", c.query, l.TotalResults, l.ItemsPerPage, len(l.Resources), l.StartIndex, c.total, c.n, c.start)
			continue
		}
		if c.n > 0 && l.Resources[0].UserName != c.first {
			t.Errorf("%s: first %q, want %q", c.query, l.Resources[0].UserName, c.first)
		}
	}
	// Groups: displayName is case-insensitive; excludedAttributes=members is honoured.
	uid := e.s.scim.store.Users()[0].ID
	if c := e.scim("PATCH", "/scim/v2/Groups/"+gid, `{"Operations":[{"op":"add","path":"members","value":[{"value":"`+uid+`"}]}]}`).Code; c != 200 {
		t.Fatalf("add member: %d", c)
	}
	w := e.scim("GET", "/scim/v2/Groups?filter="+q(`displayName eq "eng-platform"`), "")
	if l := decode[struct {
		TotalResults int
		Resources    []scimGroupOut
	}](t, w); l.TotalResults != 1 || l.Resources[0].ID != gid || len(l.Resources[0].Members) != 1 {
		t.Fatalf("group filter: %s", w.Body)
	}
	w = e.scim("GET", "/scim/v2/Groups?excludedAttributes=members&filter="+q(`displayName eq "eng-platform"`), "")
	if strings.Contains(w.Body.String(), `"members"`) {
		t.Fatalf("members not excluded: %s", w.Body)
	}
	if c := e.scim("GET", "/scim/v2/Groups?filter="+q(`members eq "x"`), "").Code; c != 400 {
		t.Fatalf("unsupported group filter: %d", c)
	}
}

func q(s string) string {
	return strings.NewReplacer(" ", "%20", `"`, "%22", "&", "%26", `\`, "%5C").Replace(s)
}

// TestSCIMResourceRules: uniqueness, referential integrity, preconditions, validation.
func TestSCIMResourceRules(t *testing.T) {
	e := scimEnv(t, false, nil)
	uid := e.createSCIMUser(t, "a@x.example", true)
	gid := e.createSCIMGroup(t, "eng", uid)
	get := e.scim("GET", "/scim/v2/Users/"+uid, "")
	etag := get.Header().Get("ETag")
	u := decode[scimUserOut](t, get)
	if etag == "" || etag != u.Meta.Version || u.Meta.Location != "https://halo.acme.example/scim/v2/Users/"+uid ||
		len(u.Groups) != 1 || u.Groups[0].Value != gid || u.Groups[0].Display != "eng" {
		t.Fatalf("user resource: etag %q %+v", etag, u)
	}
	for _, c := range []struct {
		name, method, path, body, ifMatch string
		want                              int
		scimType                          string
	}{
		{"duplicate userName (case-insensitive)", "POST", "/scim/v2/Users", `{"userName":"A@X.example"}`, "", 409, "uniqueness"},
		{"missing userName", "POST", "/scim/v2/Users", `{"displayName":"x"}`, "", 400, "invalidValue"},
		{"control character", "POST", "/scim/v2/Users", `{"userName":"a\nb@x.example"}`, "", 400, "invalidValue"},
		{"workload userName", "POST", "/scim/v2/Users", `{"userName":"workload:ci/deploy"}`, "", 400, "invalidValue"},
		{"workload userName any case", "POST", "/scim/v2/Users", `{"userName":"WORKLOAD:ci/deploy"}`, "", 400, "invalidValue"},
		{"rename to a workload userName", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"replace","path":"userName","value":"workload:ci/deploy"}]}`, "", 400, "invalidValue"},
		{"over-long userName", "POST", "/scim/v2/Users", `{"userName":"` + strings.Repeat("a", 257) + `"}`, "", 400, "invalidValue"},
		{"active not boolean", "POST", "/scim/v2/Users", `{"userName":"z@x.example","active":"maybe"}`, "", 400, "invalidSyntax"},
		{"trailing data", "POST", "/scim/v2/Users", `{"userName":"z@x.example"}{}`, "", 400, "invalidSyntax"},
		{"empty body", "POST", "/scim/v2/Users", ``, "", 400, "invalidSyntax"},
		{"duplicate group name", "POST", "/scim/v2/Groups", `{"displayName":"ENG"}`, "", 409, "uniqueness"},
		{"unknown member", "POST", "/scim/v2/Groups", `{"displayName":"x","members":[{"value":"nope"}]}`, "", 400, "invalidValue"},
		{"nested group member", "PATCH", "/scim/v2/Groups/" + gid, `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + gid + `"}]}]}`, "", 400, "invalidValue"},
		{"stale If-Match", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"replace","path":"displayName","value":"x"}]}`, `W/"0000"`, 412, ""},
		{"matching If-Match", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"replace","path":"displayName","value":"x"}]}`, etag, 200, ""},
		{"unknown user", "GET", "/scim/v2/Users/nope", ``, "", 404, ""},
		{"unknown group", "DELETE", "/scim/v2/Groups/nope", ``, "", 404, ""},
		{"unknown endpoint", "GET", "/scim/v2/Bulk", ``, "", 404, ""},
		{"no operations", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[]}`, "", 400, "invalidSyntax"},
		{"bad op", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"move","path":"active","value":true}]}`, "", 400, "invalidSyntax"},
		{"replace without value", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"replace","path":"displayName"}]}`, "", 400, "invalidValue"},
		{"remove userName", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"remove","path":"userName"}]}`, "", 400, "mutability"},
		{"remove without path", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"remove"}]}`, "", 400, "noTarget"},
		{"rename onto another user", "PATCH", "/scim/v2/Users/" + uid, `{"Operations":[{"op":"replace","path":"userName","value":"b@x.example"}]}`, "", 200, ""},
	} {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		r.Header.Set("Authorization", "Bearer "+scimTok)
		if c.ifMatch != "" {
			r.Header.Set("If-Match", c.ifMatch)
		}
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: %d %s, want %d", c.name, w.Code, w.Body, c.want)
			continue
		}
		if c.want >= 400 {
			if se := decode[scimErr](t, w); se.ScimType != c.scimType || se.Status != fmt.Sprint(c.want) {
				t.Errorf("%s: %+v, want scimType %q", c.name, se, c.scimType)
			}
		}
	}
	e.createSCIMUser(t, "c@x.example", true)
	if c := e.scim("PATCH", "/scim/v2/Users/"+uid, `{"Operations":[{"op":"replace","path":"userName","value":"C@x.example"}]}`).Code; c != 409 {
		t.Fatalf("rename onto an existing userName: %d, want 409", c)
	}
	// Deleting a user drops its group memberships.
	if c := e.scim("DELETE", "/scim/v2/Users/"+uid, "").Code; c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if g, _ := e.s.scim.store.Group(gid); len(g.Members) != 0 {
		t.Fatalf("deleted user still a member: %v", g.Members)
	}
	if c := e.scim("DELETE", "/scim/v2/Groups/"+gid, "").Code; c != 204 {
		t.Fatalf("delete group: %d", c)
	}
}

// TestSCIMRenameDeprovisionsOldName: a userName change ends the old identity's sessions and devices.
func TestSCIMRenameDeprovisionsOldName(t *testing.T) {
	e := scimEnv(t, false, nil)
	id := e.createSCIMUser(t, dev.ID, true)
	dt := enrollDevice(t, e, dev)
	if c := e.scim("PATCH", "/scim/v2/Users/"+id, `{"Operations":[{"op":"Replace","path":"userName","value":"dev2@acme.example"}]}`).Code; c != 200 {
		t.Fatalf("rename: %d", c)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
		t.Fatalf("old identity's device after rename: %d", c)
	}
	if c := e.as(dev, "GET", "/api/v1/me", "").Code; c != 401 {
		t.Fatalf("old identity's session after rename: %d", c)
	}
}

func TestPatchUserOps(t *testing.T) {
	base := SCIMUser{UserName: "a@x.example", Active: true, Emails: []SCIMEmail{{Value: "a@x.example", Type: "work"}}}
	for _, c := range []struct {
		name    string
		op      scimOp
		check   func(SCIMUser) bool
		ignored string
		wantErr string
	}{
		{"entra string false", scimOp{"replace", "active", json.RawMessage(`"False"`)}, func(u SCIMUser) bool { return !u.Active }, "", ""},
		{"entra string true", scimOp{"replace", "active", json.RawMessage(`"true"`)}, func(u SCIMUser) bool { return u.Active }, "", ""},
		{"bool false", scimOp{"replace", "active", json.RawMessage(`false`)}, func(u SCIMUser) bool { return !u.Active }, "", ""},
		{"active garbage", scimOp{"replace", "active", json.RawMessage(`"nope"`)}, nil, "", "invalidValue"},
		{"active number", scimOp{"replace", "active", json.RawMessage(`0`)}, nil, "", "invalidValue"},
		{"remove active", scimOp{"remove", "active", nil}, nil, "", "mutability"},
		{"okta path-less object", scimOp{"replace", "", json.RawMessage(`{"active":false,"displayName":"A"}`)}, func(u SCIMUser) bool { return !u.Active && u.DisplayName == "A" }, "", ""},
		{"path-less remove", scimOp{"remove", "", nil}, nil, "", "noTarget"},
		{"path-less non-object", scimOp{"replace", "", json.RawMessage(`[1]`)}, nil, "", "invalidValue"},
		{"urn-qualified path", scimOp{"replace", "urn:ietf:params:scim:schemas:core:2.0:User:displayName", json.RawMessage(`"B"`)}, func(u SCIMUser) bool { return u.DisplayName == "B" }, "", ""},
		{"name sub-attribute", scimOp{"add", "name.givenName", json.RawMessage(`"Ann"`)}, func(u SCIMUser) bool { return u.Name.GivenName == "Ann" }, "", ""},
		{"name object merges", scimOp{"replace", "name", json.RawMessage(`{"familyName":"Lee"}`)}, func(u SCIMUser) bool { return u.Name.FamilyName == "Lee" }, "", ""},
		{"remove name", scimOp{"remove", "name", nil}, func(u SCIMUser) bool { return u.Name == nil }, "", ""},
		{"email by type", scimOp{"replace", `emails[type eq "work"].value`, json.RawMessage(`"n@x.example"`)}, func(u SCIMUser) bool { return len(u.Emails) == 1 && u.Emails[0].Value == "n@x.example" }, "", ""},
		{"email new type", scimOp{"add", `emails[type eq "home"].value`, json.RawMessage(`"h@x.example"`)}, func(u SCIMUser) bool { return len(u.Emails) == 2 && u.Emails[1].Type == "home" }, "", ""},
		{"remove email by type", scimOp{"remove", `emails[TYPE eq "work"]`, nil}, func(u SCIMUser) bool { return len(u.Emails) == 0 }, "", ""},
		{"add emails", scimOp{"add", "emails", json.RawMessage(`[{"value":"z@x.example","primary":"True"}]`)}, func(u SCIMUser) bool { return len(u.Emails) == 2 && u.Emails[1].Primary }, "", ""},
		{"replace emails", scimOp{"replace", "emails", json.RawMessage(`[{"value":"z@x.example"}]`)}, func(u SCIMUser) bool { return len(u.Emails) == 1 }, "", ""},
		{"userName not string", scimOp{"replace", "userName", json.RawMessage(`7`)}, nil, "", "invalidValue"},
		{"unknown attribute ignored", scimOp{"add", "title", json.RawMessage(`"x"`)}, func(u SCIMUser) bool { return u.UserName == "a@x.example" }, "title", ""},
		{"enterprise extension ignored", scimOp{"add", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager", json.RawMessage(`{"value":"m"}`)}, func(SCIMUser) bool { return true }, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := base
			u.Emails = slices.Clone(base.Emails)
			ig, err := patchUser(&u, c.op)
			if c.wantErr != "" {
				var f *scimFail
				if err == nil || !errors.As(err, &f) || f.scimType != c.wantErr {
					t.Fatalf("err %v, want scimType %s", err, c.wantErr)
				}
				return
			}
			if err != nil || !c.check(u) || strings.Join(ig, ",") != c.ignored {
				t.Fatalf("err %v ignored %v user %+v", err, ig, u)
			}
		})
	}
}

func TestPatchGroupOps(t *testing.T) {
	for _, c := range []struct {
		name    string
		op      scimOp
		want    []string
		wantErr string
	}{
		{"add", scimOp{"add", "members", json.RawMessage(`[{"value":"c"},{"value":"a"}]`)}, []string{"a", "b", "c"}, ""},
		{"add single object", scimOp{"add", "members", json.RawMessage(`{"value":"c"}`)}, []string{"a", "b", "c"}, ""},
		{"replace", scimOp{"replace", "members", json.RawMessage(`[{"value":"z"}]`)}, []string{"z"}, ""},
		{"remove list", scimOp{"remove", "members", json.RawMessage(`[{"value":"a"}]`)}, []string{"b"}, ""},
		{"remove all", scimOp{"remove", "members", nil}, nil, ""},
		{"remove by filter", scimOp{"remove", `members[value eq "b"]`, nil}, []string{"a"}, ""},
		{"remove by filter keeps id case", scimOp{"remove", `Members[Value eq "B"]`, nil}, []string{"a", "b"}, ""},
		{"replace by filter", scimOp{"replace", `members[value eq "b"]`, json.RawMessage(`"x"`)}, nil, "invalidPath"},
		{"member without value", scimOp{"add", "members", json.RawMessage(`[{"display":"x"}]`)}, nil, "invalidValue"},
		{"members not array", scimOp{"add", "members", json.RawMessage(`"a"`)}, nil, "invalidValue"},
		{"remove displayName", scimOp{"remove", "displayName", nil}, nil, "mutability"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := SCIMGroup{DisplayName: "g", Members: []string{"a", "b"}}
			_, err := patchGroup(&g, c.op)
			if c.wantErr != "" {
				var f *scimFail
				if !errors.As(err, &f) || f.scimType != c.wantErr {
					t.Fatalf("err %v, want %s", err, c.wantErr)
				}
				return
			}
			got := slices.Clone(g.Members)
			slices.Sort(got)
			if err != nil || !slices.Equal(got, c.want) {
				t.Fatalf("err %v members %v, want %v", err, got, c.want)
			}
		})
	}
}

// TestSCIMStorePersists: the directory survives a restart (JSONL replay),
// including a user delete that dropped group memberships.
func TestSCIMStorePersists(t *testing.T) {
	dir := t.TempDir()
	e := scimEnv(t, false, func(c *Config) { c.DataDir = dir })
	a := e.createSCIMUser(t, "a@x.example", true)
	b := e.createSCIMUser(t, "b@x.example", false)
	e.createSCIMGroup(t, "eng", a, b)
	if c := e.scim("DELETE", "/scim/v2/Users/"+b, "").Code; c != 204 {
		t.Fatalf("delete: %d", c)
	}
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := OpenSCIMStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	u, groups, ok := st.Lookup("A@X.EXAMPLE")
	if !ok || u.ID != a || !u.Active || !slices.Equal(groups, []string{"eng"}) {
		t.Fatalf("after reopen: %+v %v %v", u, groups, ok)
	}
	if _, _, ok := st.Lookup("b@x.example"); ok || len(st.Users()) != 1 {
		t.Fatalf("deleted user came back: %+v", st.Users())
	}
	if g := st.Groups(); len(g) != 1 || !slices.Equal(g[0].Members, []string{a}) {
		t.Fatalf("groups after reopen: %+v", g)
	}
}

func TestGatewayDirectoryEndpoint(t *testing.T) {
	e := scimEnv(t, false, nil)
	uid := e.createSCIMUser(t, "a@x.example", true)
	e.createSCIMGroup(t, "ai-platform", uid)
	e.createSCIMUser(t, "off@x.example", false)
	for _, c := range []struct {
		name, subject, auth string
		code                int
		want                gateway.DirectoryEntry
	}{
		{"active", "A@x.example", "Bearer " + gwTok, 200, gateway.DirectoryEntry{Active: true, Groups: []string{"ai-platform"}}},
		{"inactive", "off@x.example", "Bearer " + gwTok, 200, gateway.DirectoryEntry{}},
		{"unknown", "who@x.example", "Bearer " + gwTok, 200, gateway.DirectoryEntry{}},
		{"no subject", "", "Bearer " + gwTok, 400, gateway.DirectoryEntry{}},
		{"SCIM token is not the gateway token", "a@x.example", "Bearer " + scimTok, 401, gateway.DirectoryEntry{}},
		{"no token", "a@x.example", "", 401, gateway.DirectoryEntry{}},
	} {
		e.s.authFails = authLimiter{}
		w := do(e.h, "GET", "/api/v1/gateway/directory?subject="+c.subject, c.auth, "")
		if w.Code != c.code {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body)
			continue
		}
		if c.code == 200 {
			if got := decode[gateway.DirectoryEntry](t, w); got.Active != c.want.Active || !slices.Equal(got.Groups, c.want.Groups) {
				t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
			}
		}
	}
}

func TestSCIMDiscovery(t *testing.T) {
	e := scimEnv(t, false, nil)
	for _, c := range []struct {
		path, want string
	}{
		{"/scim/v2/ServiceProviderConfig", `"patch":{"supported":true}`},
		{"/scim/v2/ServiceProviderConfig", `"etag":{"supported":true}`},
		{"/scim/v2/ResourceTypes", `"totalResults":2`},
		{"/scim/v2/ResourceTypes/User", `"endpoint":"/Users"`},
		{"/scim/v2/Schemas", `"totalResults":2`},
		{"/scim/v2/Schemas/" + scimGroupSchema, `"name":"members"`},
	} {
		w := e.scim("GET", c.path, "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d, missing %s in %s", c.path, w.Code, c.want, w.Body)
		}
	}
	if c := e.scim("GET", "/scim/v2/Schemas/nope", "").Code; c != 404 {
		t.Errorf("unknown schema: %d", c)
	}
	if c := e.scimAs("", "GET", "/scim/v2/ServiceProviderConfig", "").Code; c != 401 {
		t.Errorf("discovery without the token: %d", c)
	}
}

// TestSCIMDeprovisionIgnoresCase: the IdP provisions "Dev@Acme.Example" while
// the session, device and enrollment carry "dev@acme.example". Deleting the
// user still revokes all three, and the revocation survives a restart.
func TestSCIMDeprovisionIgnoresCase(t *testing.T) {
	dir := t.TempDir()
	e := scimEnv(t, false, func(c *Config) { c.DataDir = dir })
	id := e.createSCIMUser(t, "Dev@Acme.Example", true)
	dt := enrollDevice(t, e, dev)
	pending := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	if c := e.as(dev, "GET", "/api/v1/me", "").Code; c != 200 {
		t.Fatalf("session before: %d", c)
	}
	if w := e.scim("DELETE", "/scim/v2/Users/"+id, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if c := e.as(dev, "GET", "/api/v1/me", "").Code; c != 401 {
		t.Fatalf("session after a delete under another case: %d, want 401", c)
	}
	if c := do(e.h, "GET", "/api/v1/fleet/ring", "Bearer "+dt, "").Code; c != 401 {
		t.Fatalf("device token after delete: %d, want 401", c)
	}
	if c := do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+pending+`"}`).Code; c != 401 {
		t.Fatalf("pending enrollment after delete: %d, want 401", c)
	}
	r, err := openSessionRevocations(dir) // replay
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	if r.valid(strings.ToUpper(dev.ID), e.now.UnixNano()) {
		t.Fatal("replayed revocation ignores case: session still valid")
	}
}

// TestSessionRevocationReplayCanonical: a log written before keys were
// canonical (mixed case) still revokes on replay.
func TestSessionRevocationReplayCanonical(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "session-revocations.jsonl"), []byte(`{"user":"Alice@Corp.com","at":100}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := openSessionRevocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.close() })
	if r.valid("alice@corp.com", 50) {
		t.Fatal("legacy mixed-case revocation not applied to the canonical subject")
	}
	if !r.valid("alice@corp.com", 150) {
		t.Fatal("session issued after the revocation refused")
	}
}
