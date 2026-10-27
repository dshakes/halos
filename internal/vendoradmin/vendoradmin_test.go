package vendoradmin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/harness/hutil/hutiltest"
	"github.com/dshakes/halos/internal/policy"
)

func exampleOrg(t *testing.T) *policy.Org {
	t.Helper()
	org, err := policy.Load("../../examples/acme-corp")
	if err != nil {
		t.Fatal(err)
	}
	org.VendorAdmin = &policy.VendorAdmin{
		Claude: &policy.VendorTarget{}, Codex: &policy.VendorTarget{}, Cursor: &policy.VendorTarget{},
		Gemini:  &policy.VendorTarget{Project: "acme-dev", ReleaseChannel: "stable"},
		Copilot: &policy.VendorTarget{Org: "acme"},
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		t.Fatal(issues)
	}
	return org
}

func setting(p *Plan, key string) (Setting, bool) {
	i := slices.IndexFunc(p.Desired, func(s Setting) bool { return s.Key == key })
	if i < 0 {
		return Setting{}, false
	}
	return p.Desired[i], true
}

func TestRender(t *testing.T) {
	rep, err := Render(exampleOrg(t))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ring != "ring3-ga" || len(rep.Vendors) != 5 {
		t.Fatalf("ring %s, %d vendors", rep.Ring, len(rep.Vendors))
	}
	if !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.Contains(w, "org-wide") }) {
		t.Errorf("no org-wide ring warning: %v", rep.Warnings)
	}
	by := map[string]*Plan{}
	for _, p := range rep.Vendors {
		by[p.Vendor] = p
	}
	tests := []struct {
		vendor, key string
		want        any
		access      Access
	}{
		{"gemini", "loggingSettings/halos.logMetadata", true, AccessWrite},
		{"gemini", "loggingSettings/halos.logPromptsAndResponses", false, AccessWrite},
		{"gemini", "loggingSettings/halos.binding", "projects/acme-dev", AccessWrite},
		{"gemini", "releaseChannelSettings/halos.releaseChannel", "STABLE", AccessWrite},
		{"copilot", "content_exclusion.*", []string{"/.env", "/.env.*", "/secrets/**"}, AccessWrite},
		{"copilot", "billing.cli", "disabled", AccessRead}, // the GA profile does not enable copilot-cli
	}
	for _, tc := range tests {
		t.Run(tc.vendor+"/"+tc.key, func(t *testing.T) {
			s, ok := setting(by[tc.vendor], tc.key)
			if !ok {
				t.Fatalf("missing; have %+v", by[tc.vendor].Desired)
			}
			if !reflect.DeepEqual(s.Value, tc.want) || s.Access != tc.access {
				t.Fatalf("got %#v (%s), want %#v (%s)", s.Value, s.Access, tc.want, tc.access)
			}
		})
	}
	artifacts := map[string][]string{"claude": {"claude-managed-settings.json"}, "codex": {"codex-config.toml", "codex-requirements.toml"}, "cursor": {"cursor-models.md"}}
	for v, names := range artifacts {
		p := by[v]
		var got []string
		for _, a := range p.Artifacts {
			if a.Content != "" {
				got = append(got, a.Name)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, names) || len(p.Manual) == 0 || p.HasAPI() {
			t.Errorf("%s: want manual vendor with artifacts %v, got %v", v, names, got)
		}
	}
	var cs map[string]any
	if err := json.Unmarshal([]byte(by["claude"].Artifacts[0].Content), &cs); err != nil {
		t.Fatalf("claude artifact is not JSON: %v", err)
	}
	if i := slices.IndexFunc(by["codex"].Artifacts, func(a Artifact) bool { return a.Name == "codex-requirements.toml" }); i < 0 || !strings.Contains(by["codex"].Artifacts[i].Content, "allowed_sandbox_modes") {
		t.Errorf("codex requirements artifact lacks allowed_sandbox_modes: %+v", by["codex"].Artifacts)
	}
}

// The release-channel setting is absent unless policy pins it, and Copilot
// CLI is disabled when the profile does not enable copilot-cli.
func TestRenderUnmanaged(t *testing.T) {
	org := exampleOrg(t)
	p, _ := hutiltest.Fixture()
	delete(p.Harnesses, copilotHarness)
	g, err := RenderProfile("gemini", org, p, policy.VendorTarget{Project: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := setting(g, "releaseChannelSettings/halos.releaseChannel"); ok {
		t.Error("release channel rendered without vendorAdmin.gemini.releaseChannel")
	}
	c, err := RenderProfile("copilot", org, p, policy.VendorTarget{Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := setting(c, "billing.cli"); s.Value != "disabled" {
		t.Errorf("billing.cli = %v, want disabled", s.Value)
	}
}

func TestReadDenyGlob(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"Read(./.env)", "/.env", true},
		{"Read(**/*.pem)", "**/*.pem", true},
		{"Read(//etc/shadow)", "/etc/shadow", true},
		{"Read(~/.ssh/**)", "", true},
		{"Bash(rm -rf:*)", "", false},
		{"Read(unclosed", "", false},
	} {
		got, ok := readDenyGlob(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestDiff(t *testing.T) {
	p := &Plan{Desired: []Setting{
		{Key: "a", Value: true, Access: AccessWrite, Strict: true},
		{Key: "b", Value: "STABLE", Access: AccessWrite, Strict: "STABLE"},
		{Key: "c", Value: []string{"/x"}, Access: AccessWrite},
		{Key: "d", Value: "enabled", Access: AccessRead},
		{Key: "e", Value: "x", Access: AccessManual},
	}}
	p.Diff(map[string]any{"a": true, "b": "EXPERIMENTAL", "c": []any{"/x", "/y"}})
	got := map[string]Change{}
	for _, c := range p.Changes {
		got[c.Key] = c
	}
	if len(got) != 3 {
		t.Fatalf("changes %+v, want b, c, d", p.Changes)
	}
	if got["b"].Loosens || !got["c"].Loosens || got["d"].Current != nil || got["d"].Access != AccessRead {
		t.Fatalf("changes %+v", p.Changes)
	}
	if _, ok := got["e"]; ok {
		t.Fatal("manual setting diffed")
	}
	if !(&Report{Vendors: []*Plan{p}}).Drift() {
		t.Fatal("drift not reported")
	}
}

type recorded struct{ method, path, body, auth, version, ifMatch string }

// reply is a fake's answer: status, body and optional response headers.
type reply struct {
	code int
	body string
	hdr  map[string]string
}

func ok(body string) reply { return reply{code: 200, body: body} }

// fakeFn records every request and answers with fn(method, request URI, call
// number of that METHOD+URI); unknown routes get 404.
func fakeFn(t *testing.T, fn func(method, uri string, n int) (reply, bool)) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.RequestURI(), string(b), r.Header.Get("Authorization"), r.Header.Get("X-GitHub-Api-Version"), r.Header.Get("If-Match")})
		k := r.Method + " " + r.URL.RequestURI()
		calls[k]++
		n := calls[k]
		mu.Unlock()
		rp, found := fn(r.Method, r.URL.RequestURI(), n)
		if !found {
			rp = reply{404, `{"error":{"code":404,"status":"NOT_FOUND"}}`, nil}
		}
		for k, v := range rp.hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(rp.code)
		_, _ = io.WriteString(w, rp.body)
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// fake answers from a fixed route table ("METHOD uri").
func fake(t *testing.T, routes map[string]reply) (*httptest.Server, *[]recorded) {
	return fakeFn(t, func(m, u string, _ int) (reply, bool) { r, ok := routes[m+" "+u]; return r, ok })
}

func vendorPlan(t *testing.T, vendor string) *Plan {
	t.Helper()
	rep, err := Render(exampleOrg(t))
	if err != nil {
		t.Fatal(err)
	}
	return rep.Vendors[slices.IndexFunc(rep.Vendors, func(p *Plan) bool { return p.Vendor == vendor })]
}

// readDiff is plan: read the live console and diff it into p.
func readDiff(t *testing.T, c *Client, p *Plan) {
	t.Helper()
	cur, err := c.Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	p.Diff(cur)
}

const gParent = "/v1/projects/acme-dev/locations/global"

// geminiRoutes: logging exists (logMetadata false omitted, proto3 JSON) and
// is bound; release channel does not exist.
func geminiRoutes() map[string]reply {
	return map[string]reply{
		"GET " + gParent + "/loggingSettings":                                                        ok(`{"loggingSettings":[{"name":"projects/acme-dev/locations/global/loggingSettings/halos"}]}`),
		"GET " + gParent + "/loggingSettings/halos":                                                  ok(`{"name":"projects/acme-dev/locations/global/loggingSettings/halos"}`),
		"GET " + gParent + "/loggingSettings/halos/settingBindings/halos":                            ok(`{"name":"x","target":"projects/acme-dev","product":"GEMINI_CODE_ASSIST"}`),
		"GET " + gParent + "/releaseChannelSettings":                                                 ok(`{}`),
		"PATCH " + gParent + "/loggingSettings/halos?updateMask=logMetadata":                         ok(`{}`),
		"POST " + gParent + "/releaseChannelSettings?release_channel_setting_id=halos":               ok(`{}`),
		"POST " + gParent + "/releaseChannelSettings/halos/settingBindings?setting_binding_id=halos": ok(`{"name":"operations/1"}`),
	}
}

var geminiReads = []recorded{
	{method: "GET", path: gParent + "/loggingSettings"},
	{method: "GET", path: gParent + "/loggingSettings/halos"},
	{method: "GET", path: gParent + "/loggingSettings/halos/settingBindings/halos"},
	{method: "GET", path: gParent + "/releaseChannelSettings"},
	{method: "GET", path: gParent + "/releaseChannelSettings/halos"}, // 404: no binding to read
}

func TestApplyGemini(t *testing.T) {
	srv, got := fake(t, geminiRoutes())
	p := vendorPlan(t, "gemini")
	c := NewClient("gemini", srv.URL, "ya29.secret", policy.VendorTarget{Project: "acme-dev"})
	readDiff(t, c, p)
	res, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 || slices.ContainsFunc(res, func(r Result) bool { return !r.OK }) {
		t.Fatalf("results %+v", res)
	}
	want := slices.Concat(geminiReads, geminiReads, []recorded{ // plan's read, apply's re-read, the writes
		{method: "PATCH", path: gParent + "/loggingSettings/halos?updateMask=logMetadata", body: `{"logMetadata":true}`},
		{method: "POST", path: gParent + "/releaseChannelSettings?release_channel_setting_id=halos", body: `{"releaseChannel":"STABLE"}`},
		{method: "POST", path: gParent + "/releaseChannelSettings/halos/settingBindings?setting_binding_id=halos", body: `{"product":"GEMINI_CODE_ASSIST","target":"projects/acme-dev"}`},
	})
	assertRequests(t, *got, want, "Bearer ya29.secret", "")
}

func copilotRoutes(all string) map[string]reply {
	return map[string]reply{
		"GET /orgs/acme/copilot/content_exclusion": ok(`{"octo-repo":["/src/kernel.rs"],"*":` + all + `}`),
		"GET /orgs/acme/copilot/billing":           ok(`{"seat_breakdown":{"total":3},"seat_management_setting":"assign_selected","ide_chat":"enabled","platform_chat":"enabled","cli":"enabled","public_code_suggestions":"block","plan_type":"business"}`),
		"PUT /orgs/acme/copilot/content_exclusion": ok(`{"message":"Content exclusion rules updated successfully."}`),
	}
}

var copilotReads = []recorded{
	{method: "GET", path: "/orgs/acme/copilot/content_exclusion"},
	{method: "GET", path: "/orgs/acme/copilot/billing"},
}

func TestApplyCopilot(t *testing.T) {
	srv, got := fake(t, copilotRoutes(`["/.env"]`))
	p := vendorPlan(t, "copilot")
	c := NewClient("copilot", srv.URL, "ghp_secret", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	if len(p.Changes) != 2 {
		t.Fatalf("changes %+v, want content exclusion and cli", p.Changes)
	}
	res, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Change.Key != exclusionKey || !res[0].OK {
		t.Fatalf("results %+v: only content exclusion is writable", res)
	}
	want := slices.Concat(copilotReads, copilotReads, []recorded{
		{method: "GET", path: "/orgs/acme/copilot/content_exclusion"},
		{method: "PUT", path: "/orgs/acme/copilot/content_exclusion", body: `{"*":["/.env","/.env.*","/secrets/**"],"octo-repo":["/src/kernel.rs"]}`},
	})
	assertRequests(t, *got, want, "Bearer ghp_secret", githubVersion)
	if (*got)[len(*got)-1].ifMatch != "" {
		t.Fatal("If-Match sent without an ETag from GitHub")
	}
}

func assertRequests(t *testing.T, got, want []recorded, auth, version string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d requests %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.method != w.method || g.path != w.path || g.body != w.body {
			t.Errorf("request %d: got %s %s %s, want %s %s %s", i, g.method, g.path, g.body, w.method, w.path, w.body)
		}
		if g.auth != auth || g.version != version {
			t.Errorf("request %d: auth %q version %q", i, g.auth, g.version)
		}
	}
}

func TestNoLoosening(t *testing.T) {
	// The console excludes more than policy; policy does not.
	srv, got := fake(t, copilotRoutes(`["/.env","/.env.*","/secrets/**","/extra"]`))
	p := vendorPlan(t, "copilot")
	c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	n := len(*got)
	if _, err := c.Apply(context.Background(), p); err == nil || !strings.Contains(err.Error(), "refusing to loosen content_exclusion.*") {
		t.Fatalf("want loosening refusal, got %v", err)
	}
	if len(*got) != n {
		t.Fatalf("apply sent %d requests after refusing", len(*got)-n)
	}

	g := &Plan{Vendor: "gemini", Desired: []Setting{{Key: geminiKey("loggingSettings", "logPromptsAndResponses"), Value: false, Access: AccessWrite, Strict: true}}}
	g.Diff(map[string]any{geminiKey("loggingSettings", "logPromptsAndResponses"): true})
	if _, err := NewClient("gemini", "http://127.0.0.1:1", "t", policy.VendorTarget{Project: "p"}).Apply(context.Background(), g); err == nil {
		t.Fatal("turning logging off must be refused")
	}
}

func TestForbiddenValuesRefused(t *testing.T) {
	p := &Plan{Vendor: "claude", Artifacts: []Artifact{{Name: "x", Content: `{"permissions":{"defaultMode":"bypassPermissions"}}`}}}
	if err := p.CheckForbidden(); err == nil {
		t.Fatal("bypassPermissions artifact accepted")
	}
	p = &Plan{Vendor: "codex", Desired: []Setting{{Key: "k", Value: "danger-full-access", Access: AccessWrite}}}
	if _, err := NewClient("gemini", "http://unused.invalid", "t", policy.VendorTarget{Project: "p"}).Apply(context.Background(), p); err == nil {
		t.Fatal("danger-full-access accepted")
	}
	// the same shared check as validate and the release build: any case, CLI flags too
	for _, tc := range []struct {
		plan *Plan
		want string
	}{
		{&Plan{Vendor: "claude", Artifacts: []Artifact{{Name: "managed-settings.json", Content: `{"hooks":{"Stop":[{"hooks":[{"command":"claude --permission-mode BYPASSPERMISSIONS"}]}]}}`}}},
			`artifact managed-settings.json contains permission-bypass token "BYPASSPERMISSIONS"`},
		{&Plan{Vendor: "codex", Desired: []Setting{{Key: "notify", Value: []string{"codex", "--dangerously-bypass-approvals-and-sandbox"}}}},
			`notify would set permission-bypass token "dangerously-bypass-approvals-and-sandbox"`},
		{&Plan{Vendor: "gemini", Desired: []Setting{{Key: "k", Value: "gemini --yolo"}}}, `"--yolo"`},
		{&Plan{Vendor: "claude", Desired: []Setting{{Key: "disableBypassPermissionsMode", Value: "disable"}}}, ""},
	} {
		err := tc.plan.CheckForbidden()
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err = %v, want ~%q", tc.plan.Vendor, err, tc.want)
		}
	}
}

func TestCredentialRedaction(t *testing.T) {
	const token = "ghp_TOPSECRET123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"message":"Bad credentials: `+r.Header.Get("Authorization")+`"}`)
	}))
	defer srv.Close()
	c := NewClient("copilot", srv.URL, token, policy.VendorTarget{Org: "acme"})
	_, err := c.Read(context.Background(), &Plan{})
	if err == nil {
		t.Fatal("want 401 error")
	}
	if strings.Contains(err.Error(), token) || !strings.Contains(err.Error(), "[REDACTED]") || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("token not redacted: %v", err)
	}
	// transport errors carry the URL, never the header; redaction covers them too
	c = NewClient("copilot", "http://127.0.0.1:1/"+token, token, policy.VendorTarget{Org: "acme"})
	if _, err := c.Read(context.Background(), &Plan{}); err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("transport error leaks token: %v", err)
	}
	if _, err := NewClient("copilot", "", "", policy.VendorTarget{Org: "acme"}).Read(context.Background(), &Plan{}); err == nil {
		t.Fatal("read without a credential must fail")
	}
}

// Invariant 2 across the console renderers: removing any populated profile
// field changes the desired settings, the artifacts or the warnings.
func TestNoSilentDrop(t *testing.T) {
	org := exampleOrg(t)
	base, gw := hutiltest.Fixture()
	org.Gateway = gw
	full := clone(t, base)
	full.Egress.AllowedDomains = append(full.Egress.AllowedDomains, "nodrop.example.com")
	full.Env = map[string]string{"NODROP": "1"}
	full.Instructions = "nodrop instructions"
	full.Login = policy.LoginAPI
	full.Telemetry.LogPrompts = true
	full.Permissions.Deny = append(full.Permissions.Deny, "Read(./.nodrop)")
	full.Models.Enforce = true
	targets := map[string]policy.VendorTarget{"claude": {}, "codex": {}, "cursor": {}, "gemini": {Project: "p"}, "copilot": {Org: "o"}}
	// implied: the field cannot change this vendor's output because another
	// field already decides it. Reviewed reasons, not a way to pass.
	implied := map[string]string{
		"claude/mcp.managedOnly":          "listing mcp.servers already renders allowManagedMcpServersOnly",
		"codex/permissions.disableBypass": "permissions.sandbox already excludes danger-full-access",
	}
	render := func(v string, p *policy.Profile) string {
		pl, err := RenderProfile(v, org, p, targets[v])
		if err != nil {
			return "error: " + err.Error()
		}
		b, _ := json.Marshal([]any{pl.Desired, pl.Artifacts, pl.Warnings})
		return string(b)
	}
	for _, v := range Vendors() {
		ref := render(v, full)
		if strings.HasPrefix(ref, "error") {
			t.Fatalf("%s: %s", v, ref)
		}
		for _, f := range hutil.Populated(full) {
			if _, ok := implied[v+"/"+f]; ok {
				continue
			}
			p := clone(t, full)
			zeroField(t, p, f)
			if render(v, p) == ref {
				t.Errorf("%s: profile field %q is silently dropped", v, f)
			}
		}
	}
}

func clone(t *testing.T, p *policy.Profile) *policy.Profile {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out policy.Profile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

func zeroField(t *testing.T, p *policy.Profile, path string) {
	t.Helper()
	v := reflect.ValueOf(p).Elem()
	for _, part := range strings.Split(path, ".") {
		found := false
		for i := 0; i < v.NumField(); i++ {
			if strings.Split(v.Type().Field(i).Tag.Get("json"), ",")[0] == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			t.Fatalf("cannot resolve %q", path)
		}
	}
	v.Set(reflect.Zero(v.Type()))
}
