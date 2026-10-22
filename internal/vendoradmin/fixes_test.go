package vendoradmin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// Regression tests for the vendor admin sync security review (ADR-0025,
// Amended). Each names the finding it pins.

// H1: object entries in "*" ({"if-any-match": [...]}) are read, kept on PUT,
// never make a plan look in sync when strings differ, and never loosen.
func TestCopilotObjectEntriesPreserved(t *testing.T) {
	const obj = `{"if-any-match":["*.key"]}`
	// strings match policy, plus an object: in sync, nothing to write
	srv, _ := fake(t, copilotRoutes(`["/.env","/.env.*","/secrets/**",`+obj+`]`))
	p := vendorPlan(t, "copilot")
	c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	if slices.ContainsFunc(p.Changes, func(ch Change) bool { return ch.Key == exclusionKey }) {
		t.Fatalf("object entry made the exclusion drift: %+v", p.Changes)
	}

	// strings drift: the PUT keeps the object entry and the other repository
	srv, got := fake(t, copilotRoutes(`["/.env",`+obj+`]`))
	p = vendorPlan(t, "copilot")
	c = NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	if len(p.Loosenings()) != 0 {
		t.Fatalf("adding strings next to an object is not a loosening: %+v", p.Changes)
	}
	if _, err := c.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	put := (*got)[len(*got)-1]
	if put.method != "PUT" || put.body != `{"*":["/.env","/.env.*","/secrets/**",`+obj+`],"octo-repo":["/src/kernel.rs"]}` {
		t.Fatalf("PUT dropped the object entry: %s %s", put.method, put.body)
	}

	// a live string missing from policy, next to an object, still loosens
	srv, _ = fake(t, copilotRoutes(`["/.env","/.env.*","/secrets/**","/extra",`+obj+`]`))
	p = vendorPlan(t, "copilot")
	readDiff(t, NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"}), p)
	if len(p.Loosenings()) != 1 {
		t.Fatalf("dropping /extra must loosen: %+v", p.Changes)
	}
}

// H2: an admin edits "*" between the confirmed plan and the write. Apply
// re-reads and aborts with ErrStale; no PUT is sent. Covers both windows:
// before Apply's re-read and between it and the PUT.
func TestCopilotStalePlanAborts(t *testing.T) {
	for _, changedAt := range []int{2, 3} { // GET #1 is plan, #2 apply's re-read, #3 just before PUT
		srv, got := fakeFn(t, func(m, u string, n int) (reply, bool) {
			if m == "GET" && u == "/orgs/acme/copilot/content_exclusion" && n >= changedAt {
				return ok(`{"*":["/.env","/secret/**"]}`), true
			}
			r, found := copilotRoutes(`["/.env"]`)[m+" "+u]
			return r, found
		})
		p := vendorPlan(t, "copilot")
		c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
		readDiff(t, c, p)
		res, err := c.Apply(context.Background(), p)
		stale := errors.Is(err, ErrStale) || slices.ContainsFunc(res, func(r Result) bool { return !r.OK && strings.Contains(r.Error, "changed since the plan") })
		if !stale {
			t.Fatalf("change at GET #%d: want ErrStale, got %v %+v", changedAt, err, res)
		}
		if slices.ContainsFunc(*got, func(r recorded) bool { return r.method == "PUT" }) {
			t.Fatalf("change at GET #%d: PUT sent over a concurrent edit", changedAt)
		}
	}
}

// H2: an ETag from GitHub makes the PUT conditional; 412 is ErrStale.
func TestCopilotETagIfMatch(t *testing.T) {
	routes := copilotRoutes(`["/.env"]`)
	g := routes["GET /orgs/acme/copilot/content_exclusion"]
	g.hdr = map[string]string{"ETag": `W/"v42"`}
	routes["GET /orgs/acme/copilot/content_exclusion"] = g
	routes["PUT /orgs/acme/copilot/content_exclusion"] = reply{code: 412, body: `{"message":"Precondition Failed"}`}
	srv, got := fake(t, routes)
	p := vendorPlan(t, "copilot")
	c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	res, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	put := (*got)[len(*got)-1]
	if put.method != "PUT" || put.ifMatch != `W/"v42"` {
		t.Fatalf("PUT without If-Match: %+v", put)
	}
	if len(res) != 1 || res[0].OK || !strings.Contains(res[0].Error, "changed since the plan") {
		t.Fatalf("412 not reported as stale: %+v", res)
	}
}

// M1: a concurrent Gemini edit between plan and apply aborts before any write.
func TestGeminiStalePlanAborts(t *testing.T) {
	srv, got := fakeFn(t, func(m, u string, n int) (reply, bool) {
		if m == "GET" && u == gParent+"/loggingSettings/halos" && n >= 2 { // someone turned prompt logging on
			return ok(`{"name":"projects/acme-dev/locations/global/loggingSettings/halos","logPromptsAndResponses":true}`), true
		}
		r, found := geminiRoutes()[m+" "+u]
		return r, found
	})
	p := vendorPlan(t, "gemini")
	c := NewClient("gemini", srv.URL, "t", policy.VendorTarget{Project: "acme-dev"})
	readDiff(t, c, p)
	if _, err := c.Apply(context.Background(), p); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}
	if slices.ContainsFunc(*got, func(r recorded) bool { return r.method != "GET" }) {
		t.Fatalf("write sent over a concurrent edit: %+v", *got)
	}
}

// M2: the Claude console artifact carries no machine config.
func TestClaudeConsoleArtifactHasNoMachineConfig(t *testing.T) {
	p := vendorPlan(t, "claude")
	art := p.Artifacts[0].Content
	var m map[string]any
	if err := json.Unmarshal([]byte(art), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range claudeMachineKeys {
		if _, ok := m[k]; ok {
			t.Errorf("console artifact has machine key %s", k)
		}
	}
	env, _ := m["env"].(map[string]any)
	for k := range env {
		if claudeMachineEnv(k) {
			t.Errorf("console artifact has env.%s", k)
		}
	}
	for _, bad := range []string{"apiKeyHelper", "ANTHROPIC_", "x-halo-", "/usr/local/bin", "halo.ring", "ai.acme.example\"\n"} {
		if strings.Contains(art, bad) {
			t.Errorf("console artifact contains %q:\n%s", bad, art)
		}
	}
	if _, ok := m["permissions"]; !ok {
		t.Error("policy keys were stripped too")
	}
	for _, want := range []string{"the Halos gateway is machine config", "hooks is machine config"} {
		if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("no warning for %q: %v", want, p.Warnings)
		}
	}
	for _, v := range []string{"claude", "codex"} {
		steps := strings.Join(vendorPlan(t, v).Manual, "\n")
		if !strings.Contains(steps, "keep any") || strings.Contains(steps, "unchanged") || strings.Contains(steps, "Replace the JSON") {
			t.Errorf("%s steps must reconcile, not replace: %s", v, steps)
		}
	}
}

// M2: the strip pass itself, on the machine file the gateway context renders.
func TestConsoleSettingsStripsMachineKeys(t *testing.T) {
	in := `{"apiKeyHelper":"/usr/local/bin/acme-token","hooks":{"PreToolUse":[]},"modelOverrides":{"a":"b"},` +
		`"env":{"ANTHROPIC_BASE_URL":"https://ai.acme.example","ANTHROPIC_CUSTOM_HEADERS":"x-halo-ring: ga","CLAUDE_CODE_API_KEY_HELPER_TTL_MS":"1",` +
		`"DISABLE_AUTOUPDATER":"1","OTEL_RESOURCE_ATTRIBUTES":"halo.harness=claude-code,halo.ring=ga,halo.release=1,org=acme"},` +
		`"permissions":{"deny":["Read(./.env)"]}}`
	out, warns, err := consoleSettings(in)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"env":         map[string]any{"DISABLE_AUTOUPDATER": "1", "OTEL_RESOURCE_ATTRIBUTES": "halo.harness=claude-code,org=acme"},
		"permissions": map[string]any{"deny": []any{"Read(./.env)"}},
	}
	if a, b := mustJSON(t, m), mustJSON(t, want); a != b {
		t.Fatalf("console settings\n got %s\nwant %s", a, b)
	}
	for _, k := range []string{"apiKeyHelper", "hooks", "modelOverrides", "env.ANTHROPIC_BASE_URL", "env.ANTHROPIC_CUSTOM_HEADERS", "env.CLAUDE_CODE_API_KEY_HELPER_TTL_MS", "halo.ring, halo.release"} {
		if !slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, k) }) {
			t.Errorf("no warning for %s: %v", k, warns)
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// L2: control and format characters never reach a terminal or STEPS.md.
func TestSanitize(t *testing.T) {
	in := "a\x1b[31mred\x1b[0m\r\nb\u202ec\u200bd\x07"
	if got := Sanitize(in); got != "a[31mred[0mbcd" {
		t.Fatalf("Sanitize = %q", got)
	}
}

// L3: credentials only go over https, or http to loopback.
func TestCheckBaseURL(t *testing.T) {
	for u, good := range map[string]bool{
		"":                              true,
		"https://api.github.com":        true,
		"https://ghes.example/api/v3":   true,
		"http://127.0.0.1:8080":         true,
		"http://localhost:9":            true,
		"http://[::1]:9":                true,
		"http://api.github.com":         false,
		"http://127.0.0.1.evil.example": false,
		"ftp://x":                       false,
		"https://user:pw@x.example":     false,
		"https://x.example/?q=1":        false,
		"api.github.com":                false,
	} {
		if err := CheckBaseURL(u); (err == nil) != good {
			t.Errorf("%q: err %v, want ok=%v", u, err, good)
		}
	}
	rep := &Report{Vendors: []*Plan{{Vendor: "copilot", Desired: []Setting{{Key: exclusionKey, Access: AccessWrite}}}}}
	if _, err := rep.Clients(map[string]policy.VendorTarget{"copilot": {Org: "acme"}}, map[string]Cred{"copilot": {Token: "t", BaseURL: "http://evil.example"}}); err == nil {
		t.Fatal("plain-http base URL accepted")
	}
}

// L4: a failed write leaves a truthful result for every writable change.
func TestApplyPartialFailureResults(t *testing.T) {
	routes := geminiRoutes()
	routes["POST "+gParent+"/releaseChannelSettings?release_channel_setting_id=halos"] = reply{code: 500, body: `{"error":"boom"}`}
	srv, got := fake(t, routes)
	p := vendorPlan(t, "gemini")
	c := NewClient("gemini", srv.URL, "t", policy.VendorTarget{Project: "acme-dev"})
	readDiff(t, c, p)
	res, err := c.Apply(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]bool{}
	for _, r := range res {
		status[r.Change.Key] = r.OK
	}
	want := map[string]bool{
		geminiKey("loggingSettings", "logMetadata"):           true,
		geminiKey("releaseChannelSettings", "releaseChannel"): false,
		geminiKey("releaseChannelSettings", "binding"):        false,
	}
	if len(res) != 3 || !maps(status, want) {
		t.Fatalf("results %+v", res)
	}
	if slices.ContainsFunc(*got, func(r recorded) bool { return strings.Contains(r.path, "settingBindings?setting_binding_id") }) {
		t.Fatal("binding written after its setting failed")
	}
}

func maps(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// L5: an unspecified channel is stable, a rebind is a loosening, and another
// setting bound to the project is a conflict apply refuses.
func TestGeminiLooseningClassification(t *testing.T) {
	ch := Setting{Key: geminiKey("releaseChannelSettings", "releaseChannel"), Value: "EXPERIMENTAL", Access: AccessWrite, Strict: "STABLE", StrictAlso: []any{"CHANNEL_TYPE_UNSPECIFIED"}}
	bind := Setting{Key: geminiKey("loggingSettings", "binding"), Value: "projects/new", Access: AccessWrite, Sticky: true}
	p := &Plan{Vendor: "gemini", Desired: []Setting{ch, bind}}
	p.Diff(map[string]any{ch.Key: "CHANNEL_TYPE_UNSPECIFIED", bind.Key: "projects/old"})
	if len(p.Loosenings()) != 2 {
		t.Fatalf("want both loosenings, got %+v", p.Changes)
	}
	p.Diff(map[string]any{}) // nothing exists yet: creating is not loosening
	if len(p.Loosenings()) != 0 {
		t.Fatalf("creating loosens nothing: %+v", p.Changes)
	}

	routes := geminiRoutes()
	routes["GET "+gParent+"/loggingSettings"] = ok(`{"loggingSettings":[{"name":"projects/acme-dev/locations/global/loggingSettings/halos"},{"name":"projects/acme-dev/locations/global/loggingSettings/console-made"}],"nextPageToken":"p2"}`)
	routes["GET "+gParent+"/loggingSettings?pageToken=p2"] = ok(`{"loggingSettings":[]}`)
	routes["GET "+gParent+"/loggingSettings/console-made/settingBindings"] = ok(`{"settingBindings":[{"name":"b","target":"projects/acme-dev","product":"GEMINI_CODE_ASSIST"}]}`)
	srv, got := fake(t, routes)
	gp := vendorPlan(t, "gemini")
	c := NewClient("gemini", srv.URL, "t", policy.VendorTarget{Project: "acme-dev"})
	readDiff(t, c, gp)
	if len(gp.Conflicts) != 1 || !strings.HasSuffix(gp.Conflicts[0], "/loggingSettings/console-made") {
		t.Fatalf("conflicts %v", gp.Conflicts)
	}
	n := len(*got)
	if _, err := c.Apply(context.Background(), gp); err == nil || !strings.Contains(err.Error(), "console-made") {
		t.Fatalf("want conflict refusal, got %v", err)
	}
	if len(*got) != n {
		t.Fatal("requests sent after a conflict refusal")
	}
}

// L6: a loosening Halos would not write (read-only) is shown but does not
// block apply; one it would write does.
func TestReadOnlyLooseningDoesNotBlock(t *testing.T) {
	routes := copilotRoutes(`["/.env"]`)
	routes["GET /orgs/acme/copilot/billing"] = ok(`{"cli":"disabled"}`)
	srv, got := fake(t, routes)
	p := vendorPlan(t, "copilot")
	for i := range p.Desired {
		if p.Desired[i].Key == "billing.cli" {
			p.Desired[i].Value = "enabled" // policy enables Copilot CLI; the console has it off
		}
	}
	c := NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "acme"})
	readDiff(t, c, p)
	if !slices.ContainsFunc(p.Changes, func(ch Change) bool { return ch.Key == "billing.cli" && ch.Loosens }) {
		t.Fatalf("read-only loosening not shown: %+v", p.Changes)
	}
	if len(p.Loosenings()) != 0 {
		t.Fatalf("read-only loosening counted as blocking: %+v", p.Loosenings())
	}
	if _, err := c.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(*got, func(r recorded) bool { return r.method == "PUT" }) {
		t.Fatal("writable change not applied")
	}
}

// L1: a path-traversal org never reaches an API path (validation is the
// gate; the client also escapes).
func TestOrgPathEscaped(t *testing.T) {
	srv, got := fake(t, nil)
	_, _ = NewClient("copilot", srv.URL, "t", policy.VendorTarget{Org: "../../user"}).Read(context.Background(), &Plan{})
	for _, r := range *got {
		if strings.Contains(r.path, "/../") || strings.HasPrefix(r.path, "/user") {
			t.Fatalf("traversal reached the server: %s", r.path)
		}
	}
}

// A redirect is never followed: net/http would resend the Authorization
// header to the same host over http (or to a subdomain). A 3xx is an error
// naming the redirect, and the credential never reaches the target.
func TestClientDoesNotFollowRedirects(t *testing.T) {
	const token = "ghp_secret-admin-token"
	var leaked atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/landing/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Add(1)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/landing"+r.URL.Path, http.StatusFound)
	})
	for name, c := range map[string]*Client{
		"NewClient":            NewClient("copilot", srv.URL, token, policy.VendorTarget{Org: "acme"}),
		"caller-supplied HTTP": {Vendor: "copilot", BaseURL: srv.URL, Token: token, Target: policy.VendorTarget{Org: "acme"}, HTTP: srv.Client()},
	} {
		_, err := c.Read(context.Background(), &Plan{})
		if err == nil || !strings.Contains(err.Error(), "redirect") || !hasStatus(err, http.StatusFound) {
			t.Fatalf("%s: err %v, want a 302 redirect error", name, err)
		}
		if strings.Contains(err.Error(), token) {
			t.Fatalf("%s: error leaks the token: %v", name, err)
		}
	}
	if n := leaked.Load(); n != 0 {
		t.Fatalf("Authorization followed a redirect %d time(s)", n)
	}
}
