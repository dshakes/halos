package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

var sha = strings.Repeat("ab", 32)

// portalPolicy copies acme-corp and enables identity + self-service + one opt-in ring.
func portalPolicy(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS("../../examples/acme-corp")); err != nil {
		t.Fatal(err)
	}
	root := "org: acme-corp\nidentity:\n  issuer: https://idp.example\n  clientID: halo\n  adminGroups: [platform-admins]\n" +
		"selfService:\n  enabled: true\n  launchers: [devcontainer, codespaces, coder, laptop]\n  requestable: [mcp-server, ring-opt-in, harness]\n  enrollmentTTLSeconds: 600\n" +
		"  catalog:\n    - name: jira\n      url: https://mcp.acme.example/jira\n"
	if err := os.WriteFile(filepath.Join(dst, "halos.yaml"), []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dst, "rings/ring1-canary.yaml")
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "  percent: 5") {
		t.Fatalf("fixture changed: %s", b)
	}
	if !strings.Contains(string(b), "optIn:") { // the example may already opt in
		_ = os.WriteFile(f, []byte(strings.Replace(string(b), "  percent: 5", "  percent: 5\n  optIn: true", 1)), 0o600)
	}
	return dst
}

type fakeWriter struct {
	mu    sync.Mutex
	calls []Request
	err   error
}

func (f *fakeWriter) Propose(_ context.Context, _ *policy.Org, r Request, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r)
	return "https://git.example/pr/1", f.err
}

type env struct {
	s   *Server
	h   http.Handler
	now *time.Time
	w   *fakeWriter
}

func newEnv(t *testing.T, mutate func(*Config)) *env {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	e := &env{now: &now, w: &fakeWriter{}}
	cfg := Config{
		PolicyDir: portalPolicy(t), Token: tok, SessionKey: []byte(strings.Repeat("k", 32)),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }, Writer: e.w,
		Portal: Portal{
			BaseURL: "https://halo.acme.example", Registry: "ghcr.io/acme/rel", PubKeyPEM: "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----\n",
			DevcontainerFeature: "ghcr.io/acme/features/halos:0", CodespacesURL: "https://github.com/codespaces/new?ref={ring}",
			CoderURL: "https://coder.acme.example/templates/ai?ring={ring}&u={user}", HalodURL: "https://dl.acme.example/halod/{os}-{arch}/halod",
			HalodSHA256: map[string]string{"linux-amd64": sha, "darwin-arm64": sha},
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() }) // an open data-dir file cannot be deleted on Windows
	e.s, e.h = s, s.Handler()
	return e
}

func (e *env) as(p Principal, method, url, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if p.ID != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: e.s.seal(cookiePayload{Sub: p.ID, Groups: p.Groups, Exp: e.now.Add(time.Hour).Unix()})})
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

var (
	dev   = Principal{ID: "dev@acme.example"}
	admin = Principal{ID: "boss@acme.example", Groups: []string{"platform-admins"}}
)

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %d %q: %v", w.Code, w.Body.String(), err)
	}
	return v
}

func TestAuthAndRoles(t *testing.T) {
	e := newEnv(t, nil)
	for _, c := range []struct {
		who          Principal
		method, path string
		want         int
	}{
		{Principal{}, "GET", "/api/v1/fleet", 401},
		{Principal{}, "GET", "/api/v1/me", 401},
		{Principal{}, "GET", "/api/v1/policy", 401},
		{dev, "GET", "/api/v1/me", 200},
		{dev, "GET", "/api/v1/fleet", 403},
		{dev, "GET", "/api/v1/policy", 403},
		{dev, "GET", "/api/v1/experiments", 403},
		{dev, "GET", "/api/v1/whoami?user=someone-else", 403},
		{dev, "GET", "/api/v1/whoami?user=" + dev.ID, 200},
		{dev, "POST", "/api/v1/requests/x/approve", 403},
		{dev, "POST", "/api/v1/requests/x/deny", 403},
		{admin, "GET", "/api/v1/fleet", 200},
		{admin, "GET", "/api/v1/policy", 200},
		{admin, "GET", "/api/v1/whoami?user=someone-else", 200},
		{admin, "POST", "/api/v1/requests/x/approve", 404},
	} {
		if got := e.as(c.who, c.method, c.path, "").Code; got != c.want {
			t.Errorf("%s %s as %q: got %d want %d", c.method, c.path, c.who.ID, got, c.want)
		}
	}
	// halod ingest keeps bearer auth, unaffected by sessions
	if c := do(e.h, "POST", "/api/v1/fleet/report", "Bearer "+tok, report("h", "r", "1.0.0", false)).Code; c != 204 {
		t.Errorf("ingest: %d", c)
	}
	// developer cannot claim admin groups via whoami
	w := e.as(dev, "GET", "/api/v1/whoami?user="+dev.ID+"&groups=platform-admins", "")
	if g := decode[WhoAmI](t, w).Groups; len(g) != 0 {
		t.Errorf("developer groups leaked: %v", g)
	}
}

func TestSessionCookieIntegrity(t *testing.T) {
	e := newEnv(t, nil)
	good := e.s.seal(cookiePayload{Sub: "x", Exp: e.now.Add(time.Hour).Unix()})
	expired := e.s.seal(cookiePayload{Sub: "x", Exp: e.now.Add(-time.Second).Unix()})
	forgedBody, _, _ := strings.Cut(e.s.seal(cookiePayload{Sub: "admin", Groups: []string{"platform-admins"}, Exp: e.now.Add(time.Hour).Unix()}), ".")
	_, goodSig, _ := strings.Cut(good, ".")
	for name, v := range map[string]string{"expired": expired, "forged": forgedBody + "." + goodSig, "garbage": "abc", "unsigned": forgedBody} {
		r := httptest.NewRequest("GET", "/api/v1/me", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: v})
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s cookie accepted: %d", name, w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/api/v1/me", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: good})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("valid cookie: %d", w.Code)
	}
	// cross-origin POST is refused even with a valid session
	r = httptest.NewRequest("POST", "/api/v1/launch/codespaces", nil)
	r.Header.Set("Origin", "https://evil.example")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: good})
	w = httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("cross-origin: %d", w.Code)
	}
}

func TestNewRequiresKeyOrDevUser(t *testing.T) {
	if _, err := New(Config{PolicyDir: "x", Token: tok}); err == nil {
		t.Error("expected error without session key or dev user")
	}
}

func TestPrincipalFromClaims(t *testing.T) {
	id := policy.Identity{AdminGroups: []string{"adm"}}
	p, err := principalFromClaims(map[string]any{"email": "a@b", "email_verified": true, "groups": []any{"x", "adm"}}, id)
	if err != nil || p.ID != "a@b" || !p.Admin || len(p.Groups) != 2 {
		t.Fatalf("%+v %v", p, err)
	}
	p, _ = principalFromClaims(map[string]any{"upn": "u", "roles": []any{"x"}}, policy.Identity{UserClaim: "upn", GroupsClaim: "roles", AdminGroups: []string{"adm"}})
	if p.ID != "u" || p.Admin {
		t.Fatalf("custom claims: %+v", p)
	}
	if _, err := principalFromClaims(map[string]any{"groups": []any{"x"}}, id); err == nil {
		t.Error("missing user claim accepted")
	}
	for _, v := range []any{nil, false, "false", "yes"} {
		if _, err := principalFromClaims(map[string]any{"email": "a@b", "email_verified": v}, id); err == nil {
			t.Errorf("email_verified=%v accepted", v)
		}
	}
	if p, err := principalFromClaims(map[string]any{"email": "a@b", "email_verified": "true"}, id); err != nil || p.ID != "a@b" {
		t.Errorf("string \"true\": %v", err)
	}
}

func TestMeAndCatalog(t *testing.T) {
	e := newEnv(t, nil)
	me := decode[Me](t, e.as(dev, "GET", "/api/v1/me", ""))
	if me.Ring == "" || me.Profile == nil || len(me.Profile.Harnesses) == 0 || !me.SelfService || len(me.Launchers) != 4 {
		t.Fatalf("me: %+v", me)
	}
	if len(me.OptInRings) != 1 || me.OptInRings[0] != "ring1-canary" {
		t.Errorf("optInRings: %v", me.OptInRings)
	}
	cat := decode[Catalog](t, e.as(dev, "GET", "/api/v1/catalog", ""))
	kinds := map[string]bool{}
	for _, it := range cat.Items {
		kinds[it.Kind+"/"+it.Item] = true
	}
	if !kinds["mcp-server/jira"] || !kinds["ring-opt-in/ring1-canary"] || len(cat.Harnesses) == 0 {
		t.Errorf("catalog: %+v", cat)
	}
}

func TestLaunchOutputs(t *testing.T) {
	e := newEnv(t, nil)
	ring := decode[Me](t, e.as(dev, "GET", "/api/v1/me", "")).Ring

	dc := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/devcontainer", ""))
	var spec struct {
		Features map[string]map[string]any `json:"features"`
	}
	if err := json.Unmarshal([]byte(dc.Snippet), &spec); err != nil {
		t.Fatalf("snippet not JSON: %v", err)
	}
	opts := spec.Features["ghcr.io/acme/features/halos:0"]
	// Everything the hardened feature requires (features/halos/install.sh).
	if opts["ring"] != ring || opts["registry"] != "ghcr.io/acme/rel" || opts["org"] != "acme-corp" || opts["halodUrl"] != "https://dl.acme.example/halod/{os}-{arch}/halod" ||
		opts["halodSha256"] != "amd64="+sha || opts["pubkeyPem"] != `-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----` || opts["pubkey"] != nil || dc.Filename != ".devcontainer/devcontainer.json" {
		t.Errorf("devcontainer opts: %v", opts)
	}
	noKey := newEnv(t, func(c *Config) { c.Portal.PubKeyPEM = "" })
	if c := noKey.as(dev, "POST", "/api/v1/launch/devcontainer", "").Code; c != 409 {
		t.Errorf("devcontainer without key must be not-configured: %d", c)
	}
	if u := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/codespaces", "")).URL; u != "https://github.com/codespaces/new?ref="+ring {
		t.Errorf("codespaces url: %s", u)
	}
	if u := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/coder", "")).URL; !strings.Contains(u, "u=dev%40acme.example") {
		t.Errorf("coder url not escaped: %s", u)
	}
	lp := decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", ""))
	wantBash := "curl -fsSL https://halo.acme.example/enroll.sh | sh -s -- " + lp.Token
	if lp.TTLSeconds != 600 || len(lp.Token) < 43 || lp.ExpiresAt == nil || lp.Bash != wantBash ||
		!strings.Contains(lp.PowerShell, "enroll.ps1") || !strings.HasSuffix(lp.PowerShell, lp.Token) {
		t.Errorf("laptop: %+v", lp)
	}
	if c := e.as(dev, "POST", "/api/v1/launch/nope", "").Code; c != 404 {
		t.Errorf("unknown launcher: %d", c)
	}
	if c := e.as(Principal{}, "POST", "/api/v1/launch/laptop", "").Code; c != 401 {
		t.Errorf("unauthenticated launch: %d", c)
	}
	bare := newEnv(t, func(c *Config) { c.Portal = Portal{} })
	if c := bare.as(dev, "POST", "/api/v1/launch/codespaces", "").Code; c != 409 {
		t.Errorf("unconfigured launcher: %d", c)
	}
}

func TestEnrollmentToken(t *testing.T) {
	e := newEnv(t, nil)
	issue := func() string { return decode[Launch](t, e.as(dev, "POST", "/api/v1/launch/laptop", "")).Token }
	enroll := func(tok string) *httptest.ResponseRecorder {
		return do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`)
	}

	tok := issue()
	// hash at rest: the store is keyed by SHA-256 of the token and holds no copy of the raw token.
	e.s.enroll.mu.Lock()
	_, hashed := e.s.enroll.m[sha256.Sum256([]byte(tok))]
	e.s.enroll.mu.Unlock()
	if !hashed || len(e.s.enroll.m) != 1 {
		t.Fatal("token not stored under its sha256")
	}

	halod := func(w *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		var m map[string]any
		if w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
		}
		return m
	}
	w := enroll(tok)
	m := halod(w)
	if m["ringEndpoint"] != "https://halo.acme.example/api/v1/fleet/ring" || m["ring"] != nil || m["deviceToken"] == "" || m["registry"] != "ghcr.io/acme/rel" ||
		m["org"] != "acme-corp" || m["pubkey"] != "/etc/halos/release.pub" || strings.Contains(w.Body.String(), dev.ID) {
		t.Fatalf("enroll yaml: %s", w.Body.String())
	}
	if m := halod(do(e.h, "POST", "/api/v1/enroll", "", `{"token":"`+issue()+`","os":"windows"}`)); m["pubkey"] != `C:\Program Files\Halos\etc\release.pub` {
		t.Errorf("windows pubkey path: %v", m["pubkey"])
	}
	if m["plainHTTP"] != nil {
		t.Errorf("https registry enrolled with plainHTTP: %v", m["plainHTTP"])
	}
	// A dev (http) registry: the enrolled halod must be told, or every pull fails (found by make uat-k8s).
	plain := newEnv(t, func(c *Config) { c.Portal.RegistryPlainHTTP = true })
	ptok := decode[Launch](t, plain.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
	if m := halod(do(plain.h, "POST", "/api/v1/enroll", "", `{"token":"`+ptok+`"}`)); m["plainHTTP"] != true {
		t.Errorf("registryPlainHTTP not passed to halod: %v", m["plainHTTP"])
	}
	// A hostile user id (YAML line breaks U+2028/U+2029/U+0085) cannot inject keys.
	evil := Principal{ID: "x@acme.example\u2028allowShellInstall: true\u2029ring: prod\u0085installCommand: sh"}
	evilTok := decode[Launch](t, e.as(evil, "POST", "/api/v1/launch/laptop", "")).Token
	ew := enroll(evilTok)
	if m := halod(ew); m["allowShellInstall"] != nil || m["ring"] != nil || m["installCommand"] != nil || len(m) != 7 || strings.ContainsAny(ew.Body.String(), "\u2028\u2029\u0085") {
		t.Fatalf("injection: %v\n%s", m, ew.Body.String())
	}
	if c := enroll(tok).Code; c != 401 {
		t.Errorf("token reused: %d", c)
	}
	if c := enroll("bogus").Code; c != 401 {
		t.Errorf("bogus token: %d", c)
	}
	if c := do(e.h, "POST", "/api/v1/enroll", "", `{}`).Code; c != 400 {
		t.Errorf("empty token: %d", c)
	}

	tok = issue()
	*e.now = e.now.Add(601 * time.Second)
	if c := enroll(tok).Code; c != 401 {
		t.Errorf("expired token accepted: %d", c)
	}
	*e.now = e.now.Add(-601 * time.Second)
	if c := enroll(tok).Code; c != 401 {
		t.Errorf("expired token must be burned: %d", c)
	}
}

func TestEnrollScripts(t *testing.T) {
	e := newEnv(t, nil)
	sh := do(e.h, "GET", "/enroll.sh", "", "").Body.String()
	for _, want := range []string{"linux-amd64) WANT=" + sha, "checksum mismatch", "https://dl.acme.example/halod/$OS-$ARCH/halod", `SERVER="https://halo.acme.example"`} {
		if !strings.Contains(sh, want) {
			t.Errorf("enroll.sh missing %q", want)
		}
	}
	ps := do(e.h, "GET", "/enroll.ps1", "", "").Body.String()
	if !strings.Contains(ps, "Get-FileHash") || !strings.Contains(ps, sha) || !strings.Contains(ps, "param(") {
		t.Errorf("enroll.ps1: %s", ps)
	}
	// H2: config (device token) under Program Files with SYSTEM/Administrators-only ACLs
	for _, want := range []string{"Join-Path $Dir 'etc'", "/inheritance:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/setowner", "os = 'windows'"} {
		if !strings.Contains(ps, want) {
			t.Errorf("enroll.ps1 missing %q", want)
		}
	}
	if strings.Contains(ps, "ProgramData") || strings.Contains(ps, "S-1-5-32-545") {
		t.Errorf("enroll.ps1 must not use ProgramData or grant Users: %s", ps)
	}
	for _, want := range []string{"BIN=/Library/Halos/bin/halod", "BIN=/usr/local/lib/halos/halod", `\"os\":\"$OS\"`, "-m 0600 -o 0 -g 0"} {
		if !strings.Contains(sh, want) {
			t.Errorf("enroll.sh missing %q", want)
		}
	}
	if c := do(e.h, "GET", "/enroll/release.pub", "", "").Code; c != 200 {
		t.Errorf("pubkey: %d", c)
	}
	bare := newEnv(t, func(c *Config) { c.Portal = Portal{} })
	if c := do(bare.h, "GET", "/enroll.sh", "", "").Code; c != 404 {
		t.Errorf("unconfigured enroll.sh: %d", c)
	}
	if err := (Portal{BaseURL: "https://x/$(id)"}).Validate(false); err == nil {
		t.Error("unsafe baseURL accepted")
	}
	if err := (Portal{HalodSHA256: map[string]string{"linux-amd64": "nothex"}}).Validate(false); err == nil {
		t.Error("bad checksum accepted")
	}
	for _, tc := range []struct {
		url string
		dev bool
		ok  bool
	}{
		{"https://halo.acme.example", false, true},
		{"http://halo.acme.example", false, false},
		{"http://halo.acme.example", true, true},
		{"http://localhost:8080", false, true},
		{"http://127.0.0.1:8080", false, true},
		{"ftp://halo.acme.example", true, false},
		{"https:/nohost", false, false},
	} {
		if err := (Portal{BaseURL: tc.url}).Validate(tc.dev); (err == nil) != tc.ok {
			t.Errorf("Validate(%s, dev=%v) = %v", tc.url, tc.dev, err)
		}
	}
}

func TestRequestsFlow(t *testing.T) {
	e := newEnv(t, nil)
	post := func(who Principal, body string) *httptest.ResponseRecorder {
		return e.as(who, "POST", "/api/v1/requests", body)
	}
	good := `{"kind":"ring-opt-in","item":"ring1-canary","justification":"want the beta"}`
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"bad kind":     {`{"kind":"model","item":"x","justification":"j"}`, 422},
		"no reason":    {`{"kind":"ring-opt-in","item":"ring1-canary"}`, 422},
		"unknown item": {`{"kind":"mcp-server","item":"nope","justification":"j"}`, 422},
		"not opt-in":   {`{"kind":"ring-opt-in","item":"ring3-ga","justification":"j"}`, 422},
		"bad json":     {`{`, 400},
	} {
		if got := post(dev, c.body).Code; got != c.want {
			t.Errorf("%s: %d want %d", name, got, c.want)
		}
	}
	w := post(dev, good)
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	id := decode[Request](t, w).ID
	if c := post(dev, good).Code; c != 409 {
		t.Errorf("duplicate: %d", c)
	}
	if n := len(decode[[]Request](t, e.as(dev, "GET", "/api/v1/requests", ""))); n != 1 {
		t.Errorf("dev list: %d", n)
	}
	other := Principal{ID: "other@acme.example"}
	if n := len(decode[[]Request](t, e.as(other, "GET", "/api/v1/requests", ""))); n != 0 {
		t.Errorf("other dev sees %d requests", n)
	}
	if n := len(decode[[]Request](t, e.as(admin, "GET", "/api/v1/requests", ""))); n != 1 {
		t.Errorf("admin list: %d", n)
	}
	approve := "/api/v1/requests/" + id + "/approve"
	if c := e.as(dev, "POST", approve, "").Code; c != 403 {
		t.Errorf("developer approve: %d", c)
	}
	selfAdmin := Principal{ID: dev.ID, Groups: []string{"platform-admins"}}
	if c := e.as(selfAdmin, "POST", approve, "").Code; c != 403 {
		t.Errorf("self approve: %d", c)
	}
	e.w.err = errors.New("gh: boom")
	if c := e.as(admin, "POST", approve, "").Code; c != 502 {
		t.Errorf("writer failure: %d", c)
	}
	if st := decode[[]Request](t, e.as(dev, "GET", "/api/v1/requests", ""))[0].Status; st != StatusPending {
		t.Errorf("failed approval must stay pending, got %s", st)
	}
	e.w.err = nil
	got := decode[Request](t, e.as(admin, "POST", approve, ""))
	if got.Status != StatusApproved || got.PRURL == "" || got.DecidedBy != admin.ID || len(e.w.calls) != 2 {
		t.Fatalf("approve: %+v calls=%d", got, len(e.w.calls))
	}
	if c := e.as(admin, "POST", approve, "").Code; c != 409 {
		t.Errorf("double approve: %d", c)
	}
	// deny path
	id2 := decode[Request](t, post(dev, `{"kind":"mcp-server","item":"jira","justification":"tickets"}`)).ID
	if d := decode[Request](t, e.as(admin, "POST", "/api/v1/requests/"+id2+"/deny", "")); d.Status != StatusDenied || d.PRURL != "" {
		t.Errorf("deny: %+v", d)
	}
}

func TestRequestLogPersists(t *testing.T) {
	dir := t.TempDir()
	l, err := openRequestLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.close() })
	r := &Request{ID: "a", Status: StatusPending}
	_ = l.save(r)
	r.Status = StatusApproved
	_ = l.save(r)
	l2, err := openRequestLog(dir)
	if err == nil {
		t.Cleanup(func() { _ = l2.close() })
	}
	if err != nil || l2.byID["a"].Status != StatusApproved {
		t.Fatalf("replay: %v %+v", err, l2.byID["a"])
	}
}

type recOpener struct{ req promote.PRRequest }

func (o *recOpener) OpenPR(_ context.Context, r promote.PRRequest) (string, error) {
	o.req = r
	return "https://git.example/pr/9", nil
}

func TestGitPolicyWriter(t *testing.T) {
	repo := portalPolicy(t)
	org, err := policy.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	var gitCalls []string
	op := &recOpener{}
	w := &GitPolicyWriter{RepoDir: repo, ServedDir: t.TempDir(), Opener: op, Git: func(_ context.Context, a ...string) (string, error) {
		gitCalls = append(gitCalls, strings.Join(a, " "))
		if a[0] == "rev-parse" {
			return repo, nil
		}
		return "", nil
	}}
	before, _ := os.ReadFile(filepath.Join(repo, "rings/ring1-canary.yaml"))

	url, err := w.Propose(context.Background(), org, Request{ID: "r1", User: "u", Kind: "ring-opt-in", Item: "ring1-canary", Justification: "j"}, "adm")
	if err != nil || url == "" {
		t.Fatal(url, err)
	}
	got := string(op.req.Files["rings/ring1-canary.yaml"])
	if !strings.Contains(got, "users:") || !strings.Contains(got, "- u") || !strings.Contains(got, "optIn: true") || op.req.Branch != "halos/request-r1" {
		t.Errorf("ring patch: %s / %s", got, op.req.Branch)
	}
	after, _ := os.ReadFile(filepath.Join(repo, "rings/ring1-canary.yaml"))
	if string(before) != string(after) {
		t.Error("writer must leave file writing to the opener; it edited in place")
	}
	want := []string{"rev-parse --show-toplevel", "fetch origin main", "checkout -f -B main origin/main", "clean -fd", "checkout -f -B main origin/main", "clean -fd"}
	if !slices.Equal(gitCalls, want) {
		t.Errorf("git calls: %v", gitCalls)
	}
	// the patched ring must still load.
	_ = os.WriteFile(filepath.Join(repo, "rings/ring1-canary.yaml"), op.req.Files["rings/ring1-canary.yaml"], 0o600)
	if o2, err := policy.Load(repo); err != nil {
		t.Errorf("patched policy fails to load: %v", err)
	} else if r := ringByName(o2, "ring1-canary"); r == nil || !slices.Contains(r.Membership.Users, "u") {
		t.Errorf("group not added: %+v", r)
	}

	ring3 := ringByName(org, "ring3-ga")
	if _, err := w.Propose(context.Background(), org, Request{ID: "r2", User: "u", Kind: "mcp-server", Item: "jira", Ring: ring3.Name}, "adm"); err != nil {
		t.Fatal(err)
	}
	var file string
	for k := range op.req.Files {
		file = k
	}
	if !strings.HasPrefix(file, "profiles/") || !strings.Contains(string(op.req.Files[file]), "https://mcp.acme.example/jira") {
		t.Errorf("mcp patch %s: %s", file, op.req.Files[file])
	}
	if _, err := w.Propose(context.Background(), org, Request{ID: "r4", User: "u", Kind: "ring-opt-in", Item: "ring0"}, "adm"); err == nil {
		t.Error("opt-in to a ring without optIn must be rejected")
	}
	if _, err := w.Propose(context.Background(), org, Request{ID: "r3", Kind: "harness", Item: "codex"}, "adm"); !errors.Is(err, ErrManual) {
		t.Errorf("harness: %v", err)
	}
}

func TestRequestableHarnessesDerivedFromMeta(t *testing.T) {
	got := requestableHarnesses()
	for _, want := range []string{"claude-code", "codex", "gemini-cli", "copilot-cli"} {
		if !slices.Contains(got, want) {
			t.Errorf("requestableHarnesses() = %v, missing %q", got, want)
		}
	}
	for _, n := range got {
		if m, ok := harness.MetaOf(n); !ok || m.Installer == "" {
			t.Errorf("%q has no verified installer", n)
		}
	}
}
