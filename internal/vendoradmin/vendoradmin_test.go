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
	p.Diff(map[string]any{"a": true, "b": "EXPERIMENTAL", "c": []string{"/x", "/y"}})
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

type recorded struct{ method, path, body, auth, version string }

// fake records every request and answers from routes ("METHOD path" -> status, body).
func fake(t *testing.T, routes map[string][2]string) (*httptest.Server, *[]recorded) {
	t.Helper()
	var mu sync.Mutex
	var got []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, recorded{r.Method, r.URL.RequestURI(), string(b), r.Header.Get("Authorization"), r.Header.Get("X-GitHub-Api-Version")})
		mu.Unlock()
		rt, ok := routes[r.Method+" "+r.URL.RequestURI()]
		if !ok {
			rt = [2]string{"404", `{"error":{"code":404,"status":"NOT_FOUND"}}`}
		}
		code := map[string]int{"200": 200, "404": 404, "401": 401}[rt[0]]
		w.WriteHeader(code)
		_, _ = io.WriteString(w, rt[1])
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestApplyGemini(t *testing.T) {
	const parent = "/v1/projects/acme-dev/locations/global"
	srv, got := fake(t, map[string][2]string{
		// logging exists (logMetadata false omitted, proto3 JSON) and is bound; release channel does not exist
		"GET " + parent + "/loggingSettings/halos":                                                  {"200", `{"name":"projects/acme-dev/locations/global/loggingSettings/halos"}`},
		"GET " + parent + "/loggingSettings/halos/settingBindings/halos":                            {"200", `{"name":"x","target":"projects/acme-dev","product":"GEMINI_CODE_ASSIST"}`},
		"PATCH " + parent + "/loggingSettings/halos?updateMask=logMetadata":                         {"200", `{}`},
		"POST " + parent + "/releaseChannelSettings?release_channel_setting_id=halos":               {"200", `{}`},
		"POST " + parent + "/releaseChannelSettings/halos/settingBindings?setting_binding_id=halos": {"200", `{"name":"operations/1"}`},
	})
	rep, err := Render(exampleOrg(t))
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Vendors[slices.IndexFunc(rep.Vendors, func(p *Plan) bool { return p.Vendor == "gemini" })]
	c := NewClient("gemini", srv.URL, "ya29.secret", policy.VendorTarget{Project: "acme-dev"})
	cur, err := c.Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	p.Diff(cur)
	applied, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 3 {
		t.Fatalf("applied %+v", applied)
	}
	want := []recorded{
		{"GET", parent + "/loggingSettings/halos", "", "", ""},
		{"GET", parent + "/loggingSettings/halos/settingBindings/halos", "", "", ""},
		{"GET", parent + "/releaseChannelSettings/halos", "", "", ""}, // 404: no binding to read
		{"PATCH", parent + "/loggingSettings/halos?updateMask=logMetadata", `{"logMetadata":true}`, "", ""},
		{"POST", parent + "/releaseChannelSettings?release_channel_setting_id=halos", `{"releaseChannel":"STABLE"}`, "", ""},
		{"POST", parent + "/releaseChannelSettings/halos/settingBindings?setting_binding_id=halos", `{"product":"GEMINI_CODE_ASSIST","target":"projects/acme-dev"}`, "", ""},
	}
	assertRequests(t, *got, want, "Bearer ya29.secret", "")
}

func TestApplyCopilot(t *testing.T) {
	srv, got := fake(t, map[string][2]string{
		"GET /orgs/acme/copilot/content_exclusion": {"200", `{"octo-repo":["/src/kernel.rs"],"*":["/.env"]}`},
		"GET /orgs/acme/copilot/billing":           {"200", `{"seat_breakdown":{"total":3},"seat_management_setting":"assign_selected","ide_chat":"enabled","platform_chat":"enabled","cli":"enabled","public_code_suggestions":"block","plan_type":"business"}`},
		"PUT /orgs/acme/copilot/content_exclusion": {"200", `{"message":"Content exclusion rules updated successfully."}`},
	})
	rep, err := Render(exampleOrg(t))
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Vendors[slices.IndexFunc(rep.Vendors, func(p *Plan) bool { return p.Vendor == "copilot" })]
	c := NewClient("copilot", srv.URL, "ghp_secret", policy.VendorTarget{Org: "acme"})
	cur, err := c.Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	p.Diff(cur)
	if len(p.Changes) != 2 {
		t.Fatalf("changes %+v, want content exclusion and cli", p.Changes)
	}
	applied, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Key != "content_exclusion.*" {
		t.Fatalf("applied %+v: only content exclusion is writable", applied)
	}
	want := []recorded{
		{"GET", "/orgs/acme/copilot/content_exclusion", "", "", ""},
		{"GET", "/orgs/acme/copilot/billing", "", "", ""},
		{"GET", "/orgs/acme/copilot/content_exclusion", "", "", ""},
		{"PUT", "/orgs/acme/copilot/content_exclusion", `{"*":["/.env","/.env.*","/secrets/**"],"octo-repo":["/src/kernel.rs"]}`, "", ""},
	}
	assertRequests(t, *got, want, "Bearer ghp_secret", githubVersion)
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
	// The console excludes more than policy and logs prompts; policy does neither.
	srv, got := fake(t, map[string][2]string{
		"GET /orgs/acme/copilot/content_exclusion": {"200", `{"*":["/.env","/.env.*","/secrets/**","/extra"]}`},
		"GET /orgs/acme/copilot/billing":           {"200", `{"cli":"enabled"}`},
	})
	rep, err := Render(exampleOrg(t))
	if err != nil {
		t.Fatal(err)
	}
	p := rep.Vendors[slices.IndexFunc(rep.Vendors, func(p *Plan) bool { return p.Vendor == "copilot" })]
	c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	cur, err := c.Read(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	p.Diff(cur)
	n := len(*got)
	if _, err := c.Apply(context.Background(), p); err == nil || !strings.Contains(err.Error(), "refusing to loosen content_exclusion.*") {
		t.Fatalf("want loosening refusal, got %v", err)
	}
	if len(*got) != n {
		t.Fatalf("apply sent %d requests after refusing", len(*got)-n)
	}

	g := &Plan{Vendor: "gemini", Desired: []Setting{{Key: geminiKey("loggingSettings", "logPromptsAndResponses"), Value: false, Access: AccessWrite, Strict: true}}}
	g.Diff(map[string]any{geminiKey("loggingSettings", "logPromptsAndResponses"): true})
	if _, err := NewClient("gemini", "http://unused.invalid", "t", policy.VendorTarget{Project: "p"}).Apply(context.Background(), g); err == nil {
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
