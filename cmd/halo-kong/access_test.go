package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/identity/identitytest"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/shadow"
)

// fakeKong records what the plugin asked Kong to do.
type fakeKong struct {
	hdrs    map[string][]string
	path    string
	body    []byte
	bodyErr error
	peer    string

	exitStatus int
	exitBody   []byte
	cleared    []string
	set        map[string]string
	scheme     string
	host       string
	port       int
	newPath    string
	newBody    string
	logs       []string
}

func (f *fakeKong) Headers() (map[string][]string, error) { return f.hdrs, nil }
func (f *fakeKong) Path() (string, error)                 { return f.path, nil }
func (f *fakeKong) RawBody() ([]byte, error)              { return f.body, f.bodyErr }
func (f *fakeKong) PeerIP() (string, error)               { return f.peer, nil }
func (f *fakeKong) Exit(status int, body []byte, _ map[string][]string) {
	f.exitStatus, f.exitBody = status, body
}
func (f *fakeKong) ClearHeader(n string) error {
	f.cleared = append(f.cleared, strings.ToLower(n))
	return nil
}
func (f *fakeKong) SetHeader(n, v string) error {
	if f.set == nil {
		f.set = map[string]string{}
	}
	f.set[n] = v
	return nil
}
func (f *fakeKong) SetScheme(s string) error        { f.scheme = s; return nil }
func (f *fakeKong) SetTarget(h string, p int) error { f.host, f.port = h, p; return nil }
func (f *fakeKong) SetPath(p string) error          { f.newPath = p; return nil }
func (f *fakeKong) SetRawBody(b string) error       { f.newBody = b; return nil }
func (f *fakeKong) log(args ...any) error           { f.logs = append(f.logs, fmt.Sprint(args...)); return nil }
func (f *fakeKong) Err(args ...any) error           { return f.log(args...) }
func (f *fakeKong) Warn(args ...any) error          { return f.log(args...) }
func (f *fakeKong) Notice(args ...any) error        { return f.log(args...) }

func testPolicy(t *testing.T) string {
	t.Helper()
	org := &policy.Org{
		Name: "acme",
		Gateway: &policy.Gateway{
			Models: map[string]policy.ModelRoute{"sonnet": {Upstream: "orch", Model: "us.anthropic.claude-sonnet-4-5"}},
			Upstreams: map[string]policy.Upstream{
				"orch": {URL: "https://orch.internal:8443/base", Kind: "bedrock"},
				"cand": {URL: "https://cand.internal", Kind: "anthropic"},
			},
		},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Order: 0, Release: "sha256:r0", Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ga"}, Order: 1, Membership: policy.Membership{Default: true}},
		},
		Experiments: []*policy.Experiment{{
			Meta: policy.Meta{Name: "shadow"}, Type: policy.ExperimentShadow, Status: "running", Rings: []string{"ring0"}, SampleRate: 1,
			Variants: []policy.Variant{{Name: "control", Control: true}, {Name: "cand", Routes: map[string]policy.ModelRoute{"sonnet": {Upstream: "cand", Model: "claude-next"}}}},
		}},
	}
	b, err := policy.Compile(org)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func trustedCfg(pol string) Config {
	return Config{PolicyPath: pol, IdentityMode: "trusted_header", IdentityHeader: "x-acme-user", GroupsHeader: "x-acme-groups",
		TrustedProxyCIDRs: []string{"10.0.0.0/8"}}
}

const firstTurn = `{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`

func TestAccess(t *testing.T) {
	pol := testPolicy(t)
	h := func(kv ...string) map[string][]string {
		m := map[string][]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = append(m[kv[i]], kv[i+1])
		}
		return m
	}
	for _, tc := range []struct {
		name       string
		k          *fakeKong
		wantExit   int
		wantShape  string
		wantRing   string
		wantTarget string
	}{
		{name: "verified caller routed and rewritten",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: h("x-acme-user", "alice", "x-acme-groups", "ai-platform", "X-Halo-Ring", "ga")},
			wantRing: "ring0", wantTarget: "orch.internal:8443"},
		{name: "untrusted peer is anonymous",
			k:        &fakeKong{peer: "192.0.2.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: h("x-acme-user", "alice", "x-acme-groups", "ai-platform")},
			wantRing: "unknown", wantTarget: "orch.internal:8443"},
		{name: "ambiguous identity is 400",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: h("x-acme-user", "alice", "x-acme-user", "mallory")},
			wantExit: 400, wantShape: "more than once"},
		{name: "spooled body is 413",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/messages", bodyErr: errors.New("body in file"), hdrs: h()},
			wantExit: 413, wantShape: "request_too_large"},
		{name: "unknown model is 400",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(`{"model":"opus","messages":[]}`), hdrs: h()},
			wantExit: 400, wantShape: "invalid_request_error"},
		{name: "unknown model subpath is 404",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/messages/foo", body: []byte(firstTurn), hdrs: h()},
			wantExit: 404, wantShape: "not_found_error"},
		{name: "non-model path body error ignored",
			k:        &fakeKong{peer: "10.1.2.3", path: "/v1/models", bodyErr: errors.New("x"), hdrs: h()},
			wantRing: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trustedCfg(pol).access(tc.k)
			k := tc.k
			if tc.wantExit != 0 {
				if k.exitStatus != tc.wantExit || !strings.Contains(string(k.exitBody), tc.wantShape) || !json.Valid(k.exitBody) {
					t.Fatalf("exit %d %s, want %d %q", k.exitStatus, k.exitBody, tc.wantExit, tc.wantShape)
				}
				if k.set != nil || k.newPath != "" {
					t.Fatal("rejected request was still mutated")
				}
				return
			}
			if k.exitStatus != 0 {
				t.Fatalf("unexpected exit %d %s", k.exitStatus, k.exitBody)
			}
			if k.set["x-halo-ring"] != tc.wantRing {
				t.Fatalf("ring header %q want %q (%v)", k.set["x-halo-ring"], tc.wantRing, k.set)
			}
			// Header hygiene: all owned headers and the identity headers are dropped.
			for _, n := range []string{"x-halo-ring", "x-halo-release", "x-acme-user", "x-acme-groups"} {
				if !contains(k.cleared, n) {
					t.Fatalf("%s not cleared: %v", n, k.cleared)
				}
			}
			if tc.wantTarget != "" {
				if fmt.Sprintf("%s:%d", k.host, k.port) != tc.wantTarget || k.scheme != "https" || k.newPath != "/base/v1/messages" {
					t.Fatalf("target %s://%s:%d%s", k.scheme, k.host, k.port, k.newPath)
				}
				if !strings.Contains(k.newBody, "us.anthropic.claude-sonnet-4-5") {
					t.Fatalf("body not rewritten: %s", k.newBody)
				}
			}
		})
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestAccessMirrors(t *testing.T) {
	var mu sync.Mutex
	var jobs []shadow.Job
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var j shadow.Job
		_ = json.NewDecoder(r.Body).Decode(&j)
		mu.Lock()
		jobs = append(jobs, j)
		mu.Unlock()
		w.WriteHeader(202)
	}))
	defer srv.Close()
	t.Setenv("HALO_TEST_SHADOW_TOKEN", "tok")
	c := trustedCfg(testPolicy(t))
	c.ShadowURL, c.ShadowToken = srv.URL+"/mirror", "{vault://env/halo-test-shadow-token}"
	k := &fakeKong{peer: "10.0.0.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: map[string][]string{
		"x-acme-user": {"alice"}, "x-acme-groups": {"ai-platform"}, "x-claude-code-session-id": {"sess-1"},
		"anthropic-version": {"2023-06-01"}, "authorization": {"Bearer secret"},
	}}
	c.access(k)
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(jobs)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(jobs) != 1 {
		t.Fatalf("jobs %d", len(jobs))
	}
	j := jobs[0]
	if j.Experiment != "shadow" || j.Variant != "cand" || j.SessionID != "sess-1" || j.Ring != "ring0" || j.Headers["authorization"] != "" || j.Headers["anthropic-version"] != "2023-06-01" {
		t.Fatalf("job %+v", j)
	}

	// Oversize body: not mirrored. Bad URL: logged, not panicked.
	c.MaxBodyBytes = 1
	c.access(&fakeKong{peer: "10.0.0.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: k.hdrs})
	bad := c
	bad.MaxBodyBytes, bad.ShadowURL = 0, "://nope"
	bk := &fakeKong{peer: "10.0.0.1", path: "/v1/messages", body: []byte(firstTurn), hdrs: k.hdrs}
	bad.access(bk)
	if !strings.Contains(strings.Join(bk.logs, "\n"), "shadow_url") {
		t.Fatalf("bad shadow_url not logged: %v", bk.logs)
	}
}

// Secure defaults. With JWT identity a model call without a verified caller is a
// 401 in the caller's wire format (never anonymous routing); verified callers and
// non-model paths pass. trusted_header mode leaves the decision to the auth
// gateway. allow_unverified opts out; a broken identity config fails closed.
func TestAccessRejectsUnverifiedByDefault(t *testing.T) {
	pol := testPolicy(t)
	iss, err := identitytest.NewIssuer("k1")
	if err != nil {
		t.Fatal(err)
	}
	idp := iss.Serve()
	defer idp.Close()
	jwtCfg := func() Config { return Config{PolicyPath: pol, IdentityMode: "jwt", Issuer: iss.URL, Audience: "gw"} }
	tok, _ := iss.Mint(map[string]any{"aud": "gw", "email": "alice@acme.com", "groups": []string{"ai-platform"}})
	other, _ := identitytest.NewIssuer("k1") // same kid, different key
	forged, _ := other.Mint(map[string]any{"aud": "gw", "email": "alice@acme.com"})
	wrongAud, _ := iss.Mint(map[string]any{"aud": "elsewhere", "email": "alice@acme.com"})
	bearer := func(t string) map[string][]string { return map[string][]string{"Authorization": {"Bearer " + t}} }

	allow := jwtCfg()
	allow.AllowUnverified = true
	implicit := Config{PolicyPath: pol, Issuer: iss.URL, Audience: "gw"} // mode inferred from the issuer
	for _, tc := range []struct {
		name     string
		cfg      Config
		path     string
		body     string
		hdrs     map[string][]string
		wantExit int
		wantBody string
	}{
		{"no token", jwtCfg(), "/v1/messages", firstTurn, nil, 401, "authentication_error"},
		{"forged token", jwtCfg(), "/v1/messages", firstTurn, bearer(forged), 401, "authentication_error"},
		{"wrong audience", jwtCfg(), "/v1/messages", firstTurn, bearer(wrongAud), 401, "authentication_error"},
		{"inferred jwt mode rejects too", implicit, "/v1/messages", firstTurn, nil, 401, "authentication_error"},
		{"responses wire", jwtCfg(), "/v1/responses", `{"model":"sonnet","input":"hi"}`, nil, 401, "invalid_api_key"},
		{"verified caller", jwtCfg(), "/v1/messages", firstTurn, bearer(tok), 0, ""},
		{"non-model path is not gated", jwtCfg(), "/v1/models", "", nil, 0, ""},
		{"allow_unverified routes anonymously", allow, "/v1/messages", firstTurn, nil, 0, ""},
		{"trusted_header mode: the auth gateway decides", trustedCfg(pol), "/v1/messages", firstTurn, nil, 0, ""},
		{"broken identity config fails closed", Config{PolicyPath: pol, IdentityMode: "jwt"}, "/v1/messages", firstTurn, bearer(tok), 401, "authentication_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKong{peer: "10.1.2.3", path: tc.path, body: []byte(tc.body), hdrs: tc.hdrs}
			tc.cfg.access(k)
			if k.exitStatus != tc.wantExit || (tc.wantBody != "" && !strings.Contains(string(k.exitBody), tc.wantBody)) {
				t.Fatalf("exit %d %s, want %d %q", k.exitStatus, k.exitBody, tc.wantExit, tc.wantBody)
			}
			if tc.wantExit != 0 && (k.set != nil || k.newPath != "") {
				t.Fatal("rejected request was still mutated")
			}
		})
	}
}

func TestAccessStripsClientCredentialsByDefault(t *testing.T) {
	pol := testPolicy(t)
	run := func(forward bool) *fakeKong {
		c := trustedCfg(pol)
		c.ForwardClientCredentials = forward
		k := &fakeKong{peer: "10.1.2.3", path: "/v1/messages", body: []byte(firstTurn), hdrs: map[string][]string{
			"x-acme-user": {"alice"}, "Authorization": {"Bearer idp"}, "x-api-key": {"k"}, "Api-Key": {"k"}, "x-goog-api-key": {"k"}, "Proxy-Authorization": {"p"}}}
		c.access(k)
		return k
	}
	creds := []string{"authorization", "x-api-key", "api-key", "x-goog-api-key", "proxy-authorization"}
	k := run(false)
	for _, n := range creds {
		if !contains(k.cleared, n) {
			t.Errorf("default: %s not cleared: %v", n, k.cleared)
		}
	}
	k = run(true)
	for _, n := range creds {
		if contains(k.cleared, n) {
			t.Errorf("forward_client_credentials: %s was cleared", n)
		}
	}
}
