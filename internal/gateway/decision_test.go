package gateway

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/halos-dev/halos/internal/policy"
)

func testOrg() *policy.Org {
	rt := func(up, m string) policy.ModelRoute { return policy.ModelRoute{Upstream: up, Model: m} }
	return &policy.Org{
		Name: "acme",
		Gateway: &policy.Gateway{
			Auth: policy.GatewayAuth{IdentityHeader: "x-acme-user"},
			Models: map[string]policy.ModelRoute{
				"sonnet": rt("orch", "us.anthropic.claude-sonnet-4-5"),
			},
			Upstreams: map[string]policy.Upstream{
				"orch":      {URL: "https://orch.internal:8443", Kind: "orchestrator"},
				"anthropic": {URL: "https://api.anthropic.com", Kind: "anthropic"},
			},
		},
		Rings: []*policy.Ring{
			{Meta: policy.Meta{Name: "ring0"}, Order: 0, Release: "sha256:r0", Membership: policy.Membership{Groups: []string{"ai-platform"}}},
			{Meta: policy.Meta{Name: "ring1"}, Order: 1, Release: "sha256:r1", Membership: policy.Membership{Percent: 5}},
			{Meta: policy.Meta{Name: "ga"}, Order: 2, Release: "sha256:ga", Membership: policy.Membership{Default: true}},
		},
		Experiments: []*policy.Experiment{
			{
				Meta: policy.Meta{Name: "sonnet-canary"}, Type: policy.ExperimentCanary, Axis: policy.AxisTraffic,
				Status: "running", Rings: []string{"ring1", "ga"},
				Variants: []policy.Variant{
					{Name: "control", Weight: 90, Control: true},
					{Name: "direct", Weight: 10, Routes: map[string]policy.ModelRoute{"sonnet": rt("anthropic", "claude-sonnet-4-5-20250929")}},
				},
			},
			{
				Meta: policy.Meta{Name: "sonnet-shadow"}, Type: policy.ExperimentShadow, Axis: policy.AxisTraffic,
				Status: "running", Rings: []string{"ring0", "ring1", "ga"}, SampleRate: 0.25,
				Variants: []policy.Variant{
					{Name: "control", Weight: 50, Control: true},
					{Name: "cand", Weight: 50, Routes: map[string]policy.ModelRoute{"sonnet": rt("anthropic", "claude-sonnet-next")}},
				},
			},
		},
	}
}

func TestDecideRingRouting(t *testing.T) {
	org := testOrg()
	tests := []struct {
		name      string
		req       RequestInfo
		ring      string
		release   string
		wantUp    string
		wantModel string
	}{
		{"group ring0", RequestInfo{UserID: "alice", Groups: []string{"ai-platform"}, ModelAlias: "sonnet"}, "ring0", "sha256:r0", "https://orch.internal:8443", "us.anthropic.claude-sonnet-4-5"},
		{"unknown alias passes through", RequestInfo{UserID: "alice", Groups: []string{"ai-platform"}, ModelAlias: "mystery"}, "ring0", "sha256:r0", "", ""},
		{"missing identity", RequestInfo{ModelAlias: "sonnet", Groups: []string{"ai-platform"}}, "unknown", "", "https://orch.internal:8443", "us.anthropic.claude-sonnet-4-5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(org, tc.req)
			if d.Ring != tc.ring || d.Release != tc.release || d.Upstream != tc.wantUp || d.UpstreamModel != tc.wantModel {
				t.Fatalf("got %+v", d)
			}
			if d.Headers[HeaderRing] != tc.ring {
				t.Fatalf("x-halo-ring=%q want %q", d.Headers[HeaderRing], tc.ring)
			}
		})
	}
}

func TestDecideMissingIdentityNoExperiment(t *testing.T) {
	d := Decide(testOrg(), RequestInfo{ModelAlias: "sonnet", SessionID: "s", FirstTurn: true})
	if d.Experiment != "" || d.Variant != "" || len(d.Shadow) != 0 {
		t.Fatalf("anonymous request enrolled: %+v", d)
	}
	if _, ok := d.Headers[HeaderExperiment]; ok {
		t.Fatal("experiment header set for anonymous request")
	}
	if d.Headers[HeaderRing] != "unknown" {
		t.Fatalf("ring header = %q", d.Headers[HeaderRing])
	}
}

func TestCanarySplitAndSticky(t *testing.T) {
	org := testOrg()
	const n = 20000
	var direct, enrolled int
	for i := 0; i < n; i++ {
		req := RequestInfo{UserID: fmt.Sprintf("user-%d", i), ModelAlias: "sonnet"}
		d := Decide(org, req)
		if d.Experiment == "" {
			continue
		}
		enrolled++
		if d.Variant == "direct" {
			direct++
			if d.Upstream != "https://api.anthropic.com" || d.UpstreamModel != "claude-sonnet-4-5-20250929" {
				t.Fatalf("canary variant did not override route: %+v", d)
			}
		} else if d.UpstreamModel != "us.anthropic.claude-sonnet-4-5" {
			t.Fatalf("control routed wrongly: %+v", d)
		}
		// sticky, independent of session/model-turn state
		req.SessionID = "other"
		if d2 := Decide(org, req); d2.Variant != d.Variant {
			t.Fatalf("variant not sticky for %s", req.UserID)
		}
	}
	if enrolled < n*9/10 { // ring0 members excluded by group; none here, ring1+ga enrolled
		t.Fatalf("enrolled only %d", enrolled)
	}
	got := float64(direct) / float64(enrolled)
	if math.Abs(got-0.10) > 0.02 {
		t.Fatalf("canary share %.4f, want 0.10±0.02", got)
	}
}

func TestShadowSampling(t *testing.T) {
	org := testOrg()
	base := RequestInfo{UserID: "alice", ModelAlias: "sonnet", FirstTurn: true}
	const n = 20000
	hit := 0
	for i := 0; i < n; i++ {
		r := base
		r.SessionID = fmt.Sprintf("sess-%d", i)
		d := Decide(org, r)
		if len(d.Shadow) > 0 {
			hit++
			st := d.Shadow[0]
			if st.Variant != "cand" || st.Model != "claude-sonnet-next" || st.Upstream != "https://api.anthropic.com" || st.Experiment != "sonnet-shadow" {
				t.Fatalf("bad target %+v", st)
			}
		}
		// whole session is consistent whatever the user
		r.UserID = "bob"
		if (len(Decide(org, r).Shadow) > 0) != (len(d.Shadow) > 0) {
			t.Fatal("shadow sampling not session-keyed")
		}
	}
	if got := float64(hit) / n; math.Abs(got-0.25) > 0.02 {
		t.Fatalf("shadow rate %.4f want 0.25±0.02", got)
	}
}

func TestShadowEligibility(t *testing.T) {
	org := testOrg()
	org.Experiments[1].SampleRate = 1
	tests := []struct {
		name string
		mut  func(*RequestInfo)
		want bool
	}{
		{"eligible", func(*RequestInfo) {}, true},
		{"not first turn", func(r *RequestInfo) { r.FirstTurn = false }, false},
		{"no session", func(r *RequestInfo) { r.SessionID = "" }, false},
		{"no identity", func(r *RequestInfo) { r.UserID = "" }, false},
		{"no candidate route for alias", func(r *RequestInfo) { r.ModelAlias = "haiku" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := RequestInfo{UserID: "alice", ModelAlias: "sonnet", SessionID: "s1", FirstTurn: true}
			tc.mut(&r)
			if got := len(Decide(org, r).Shadow) > 0; got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	org.Experiments[1].Status = "paused"
	if len(Decide(org, RequestInfo{UserID: "alice", ModelAlias: "sonnet", SessionID: "s1", FirstTurn: true}).Shadow) != 0 {
		t.Fatal("paused experiment mirrored")
	}
}

func TestInspect(t *testing.T) {
	tests := []struct {
		name, proto, path, body string
		model                   string
		first                   bool
	}{
		{"anthropic first", ProtoAnthropic, "/v1/messages", `{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`, "sonnet", true},
		{"anthropic with system+one user", ProtoAnthropic, "/v1/messages", `{"model":"sonnet","system":"x","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`, "sonnet", true},
		{"anthropic second turn", ProtoAnthropic, "/v1/messages", `{"model":"sonnet","messages":[{"role":"user","content":"a"},{"role":"assistant","content":"b"},{"role":"user","content":"c"}]}`, "sonnet", false},
		{"anthropic two users", ProtoAnthropic, "/v1/messages", `{"model":"sonnet","messages":[{"role":"user","content":"a"},{"role":"user","content":"b"}]}`, "sonnet", false},
		{"anthropic bad json", ProtoAnthropic, "/v1/messages", `{`, "", false},
		{"bedrock alias from path", ProtoBedrock, "/model/sonnet/invoke-with-response-stream", `{"anthropic_version":"bedrock-2023-05-31","messages":[{"role":"user","content":"hi"}]}`, "sonnet", true},
		{"bedrock encoded", ProtoBedrock, "/model/us.anthropic.x%3Av1/invoke", `{"messages":[{"role":"user","content":"hi"}]}`, "us.anthropic.x:v1", true},
		{"responses string input", ProtoResponses, "/v1/responses", `{"model":"gpt","input":"hi"}`, "gpt", true},
		{"responses items", ProtoResponses, "/v1/responses", `{"model":"gpt","input":[{"role":"developer","content":"x"},{"role":"user","content":"hi"}]}`, "gpt", true},
		{"responses tool output", ProtoResponses, "/v1/responses", `{"model":"gpt","input":[{"role":"user","content":"hi"},{"type":"function_call","name":"f"},{"type":"function_call_output","output":"o"}]}`, "gpt", false},
		{"responses previous id", ProtoResponses, "/v1/responses", `{"model":"gpt","previous_response_id":"r1","input":"more"}`, "gpt", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, f := Inspect(tc.proto, tc.path, []byte(tc.body))
			if m != tc.model || f != tc.first {
				t.Fatalf("got (%q,%v) want (%q,%v)", m, f, tc.model, tc.first)
			}
		})
	}
}

func TestHarnessFromUA(t *testing.T) {
	for ua, want := range map[string]string{
		"claude-cli/2.1.0 (external, cli)": "claude-code",
		"codex_cli_rs/0.40":                "codex",
		"GeminiCLI/0.5 (darwin)":           "gemini-cli",
		"curl/8":                           "",
	} {
		if got := HarnessFromUA(ua); got != want {
			t.Errorf("%q => %q want %q", ua, got, want)
		}
	}
}

// Spoofing: client-supplied x-halo-* headers must never change cohort, and are
// always cleared / overwritten.
func TestSpoofingImpossible(t *testing.T) {
	org := testOrg()
	carol := &policy.Subject{ID: "carol"}
	body := []byte(`{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`)

	spoof := func(h http.Header) {
		h.Set("X-Halo-Ring", "ring0")
		h.Set("x-halo-release", "sha256:evil")
		h.Set("X-Halo-Experiment", "sonnet-canary")
		h.Set("x-halo-variant", "direct")
		h.Set("x-halo-anything", "1")
	}

	t.Run("identical decision with and without spoofed headers", func(t *testing.T) {
		clean := PrepareVerified(org, carol, http.Header{}, "/v1/messages", body)
		h := http.Header{}
		spoof(h)
		dirty := PrepareVerified(org, carol, h, "/v1/messages", body)
		if fmt.Sprint(clean.Decision) != fmt.Sprint(dirty.Decision) {
			t.Fatalf("spoofed headers changed decision:\n%+v\n%+v", clean.Decision, dirty.Decision)
		}
	})

	t.Run("all spoofed headers cleared", func(t *testing.T) {
		h := http.Header{}
		spoof(h)
		res := PrepareVerified(org, carol, h, "/v1/messages", body)
		if len(res.ClearHeaders) != 5 {
			t.Fatalf("ClearHeaders=%v", res.ClearHeaders)
		}
		for _, n := range res.ClearHeaders {
			if !strings.HasPrefix(n, HaloPrefix) || n != strings.ToLower(n) {
				t.Fatalf("bad clear name %q", n)
			}
		}
		for n := range h {
			if !slices.Contains(res.ClearHeaders, strings.ToLower(n)) {
				t.Fatalf("spoofed %s not cleared: %v", n, res.ClearHeaders)
			}
		}
		if res.Decision.Headers[HeaderRing] == "ring0" && res.Decision.Ring != "ring0" {
			t.Fatal("spoofed ring value leaked")
		}
	})

	t.Run("no identity: spoofed ring0/experiment ignored", func(t *testing.T) {
		h := http.Header{}
		spoof(h)
		res := PrepareVerified(org, nil, h, "/v1/messages", body)
		d := res.Decision
		if d.Headers[HeaderRing] != "unknown" || d.Experiment != "" || d.Headers[HeaderExperiment] != "" || d.Headers[HeaderVariant] != "" || d.Headers[HeaderRelease] != "" {
			t.Fatalf("spoof succeeded: %+v", d.Headers)
		}
		if d.UpstreamModel != "us.anthropic.claude-sonnet-4-5" {
			t.Fatalf("anonymous request not on default route: %+v", d)
		}
	})
}

func TestPrepareRewrites(t *testing.T) {
	org := testOrg()
	ic := &policy.Subject{ID: "alice"}
	h := http.Header{}
	h.Set("x-acme-user", "alice")
	res := PrepareVerified(org, ic, h, "/v1/messages", []byte(`{"model":"sonnet","max_tokens":5,"stream":true}`))
	if !res.Rewritten || !strings.Contains(string(res.Body), `"model":"`) || strings.Contains(string(res.Body), `"model":"sonnet"`) {
		t.Fatalf("not rewritten: %s (err=%v variant=%s)", res.Body, res.RewriteErr, res.Decision.Variant)
	}
	res = PrepareVerified(org, ic, h, "/model/sonnet/invoke", []byte(`{}`))
	if !res.Rewritten || strings.Contains(res.Path, "sonnet/") {
		t.Fatalf("path not rewritten: %s", res.Path)
	}
	// Unparseable body: no alias can be read, so it is refused, never forwarded as-is.
	res = PrepareVerified(org, ic, h, "/v1/messages", []byte(`not json`))
	if res.Rewritten || res.Reject == nil || res.Reject.Status != http.StatusForbidden {
		t.Fatalf("bad body: %+v", res)
	}
	res = PrepareVerified(org, ic, h, PathCountTokens, []byte(`{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`))
	if res.Reject != nil || !res.Rewritten || strings.Contains(string(res.Body), `"sonnet"`) {
		t.Fatalf("count_tokens not rewritten: %+v", res)
	}
}

func TestPrepareRejects(t *testing.T) {
	org := testOrg()
	org.Experiments[1].SampleRate = 1
	h := http.Header{}
	h.Set("x-claude-code-session-id", "s1")
	sub := &policy.Subject{ID: "alice"}
	first := func(model string) []byte {
		return []byte(`{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`)
	}
	tests := []struct {
		name, path string
		org        *policy.Org
		body       []byte
		status     int
		shape      string // substring of the error body
	}{
		{"configured alias", "/v1/messages", org, first("sonnet"), 0, ""},
		{"unknown model", "/v1/messages", org, first("claude-opus-4"), 403, `"permission_error"`},
		{"upstream id is not an alias", "/v1/messages", org, first("us.anthropic.claude-sonnet-4-5"), 403, "allowed models: sonnet"},
		{"no model", "/v1/messages", org, []byte(`{"messages":[]}`), 403, `"type":"error"`},
		{"nil body", "/v1/messages", org, nil, 403, ""},
		{"count_tokens unknown model", PathCountTokens, org, first("opus"), 403, ""},
		{"responses unknown model", "/v1/responses", org, []byte(`{"model":"gpt-5","input":"hi"}`), 403, `"code":"model_not_allowed"`},
		{"bedrock unknown model", "/model/claude-opus/invoke", org, []byte(`{}`), 403, `{"message":`},
		{"batches", "/v1/messages/batches", org, first("sonnet"), 403, "batches"},
		{"batch results", "/v1/messages/batches/b1/results", org, nil, 403, ""},
		{"unknown messages subpath", "/v1/messages/foo", org, first("sonnet"), 404, `"not_found_error"`},
		{"trailing slash", "/v1/messages/", org, first("sonnet"), 404, ""},
		{"double slash", "/v1//messages", org, first("sonnet"), 404, ""},
		{"escaped", "/v1/%6Dessages", org, first("sonnet"), 404, ""},
		{"case", "/V1/Messages", org, first("sonnet"), 404, ""},
		{"responses subpath", "/v1/responses/compact", org, []byte(`{"model":"sonnet"}`), 404, `"code":"unknown_url"`},
		{"bedrock unknown op", "/model/sonnet/foo", org, []byte(`{}`), 404, `{"message":`},
		{"non-model path passes", "/v1/models", org, nil, 0, ""},
		{"model detail passes", "/v1/models/claude-sonnet-4-5", org, nil, 0, ""},
		{"chat completions refused", "/v1/chat/completions", org, []byte(`{"model":"gpt-5"}`), 404, `"not_found_error"`},
		{"legacy complete refused", "/v1/complete", org, nil, 404, ""},
		{"gemini refused", "/v1beta/models/gemini-2.5-pro:generateContent", org, nil, 404, ""},
		{"models traversal refused", "/v1/models/..", org, nil, 404, ""},
		{"models escaped refused", "/v1/models/%2e%2e", org, nil, 404, ""},
		{"models subpath refused", "/v1/models/x/y", org, nil, 404, ""},
		{"root refused", "/", org, nil, 404, ""},
		{"no policy", "/v1/messages", nil, first("sonnet"), 503, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := PrepareVerified(tc.org, sub, h, tc.path, tc.body)
			if tc.status == 0 {
				if res.Reject != nil {
					t.Fatalf("unexpected reject %v", res.Reject)
				}
				return
			}
			if res.Reject == nil || res.Reject.Status != tc.status {
				t.Fatalf("reject=%v want %d", res.Reject, tc.status)
			}
			if b := string(res.Reject.JSON()); !strings.Contains(b, tc.shape) || !json.Valid(res.Reject.JSON()) {
				t.Fatalf("body %s want %q", b, tc.shape)
			}
		})
	}
	// count_tokens is never a shadow candidate even when it looks like a first turn.
	if res := PrepareVerified(org, sub, h, PathCountTokens, first("sonnet")); len(res.Decision.Shadow) != 0 {
		t.Fatalf("count_tokens mirrored: %+v", res.Decision.Shadow)
	}
	if res := PrepareVerified(org, sub, h, PathMessages, first("sonnet")); len(res.Decision.Shadow) == 0 {
		t.Fatal("messages first turn should be mirrored at sample rate 1")
	}
	if r := RejectTooLarge("/v1/responses"); r.Status != 413 || !strings.Contains(string(r.JSON()), "request_too_large") {
		t.Fatalf("413: %v %s", r, r.JSON())
	}
}

func TestPrepareVerifiedIgnoresHeaders(t *testing.T) {
	org := testOrg()
	h := http.Header{}
	h.Set("x-acme-user", "mallory") // client-forged; must not matter
	h.Set("x-halo-ring", "ring0")
	body := []byte(`{"model":"sonnet","messages":[{"role":"user","content":"hi"}]}`)
	res := PrepareVerified(org, &policy.Subject{ID: "alice", Groups: []string{"ai-platform"}}, h, "/v1/messages", body)
	if res.Decision.Ring != "ring0" || !res.Rewritten {
		t.Fatalf("got %+v", res.Decision)
	}
	if !strings.Contains(string(res.Body), "us.anthropic.claude-sonnet-4-5") {
		t.Fatalf("body not rewritten: %s", res.Body)
	}
	if anon := PrepareVerified(org, nil, h, "/v1/messages", body); anon.Decision.Ring != RingUnknown {
		t.Fatalf("anonymous got ring %q", anon.Decision.Ring)
	}
}

// A client-axis experiment is attributed (headers + Decision fields feed
// gwmetrics) with the same ResolveVariant halod uses, never changes the route,
// and never displaces a traffic-axis experiment listed after it.
func TestDecideClientAxisAttribution(t *testing.T) {
	base := testOrg()
	cli := &policy.Experiment{
		Meta: policy.Meta{Name: "cli-upgrade"}, Type: policy.ExperimentAB, Axis: policy.AxisClient,
		Status: "running", Rings: []string{"ga", "ring0"},
		Variants: []policy.Variant{{Name: "control", Weight: 1, Control: true, Profile: "base"}, {Name: "treatment", Weight: 1, Profile: "next"}},
	}
	withCli := testOrg()
	withCli.Experiments = append([]*policy.Experiment{cli}, withCli.Experiments...) // listed FIRST
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		req := RequestInfo{UserID: fmt.Sprintf("u%d@acme.com", i), ModelAlias: "sonnet"}
		if i%2 == 1 { // ring0: no traffic ab/canary there, so the client experiment is attributed
			req.Groups = []string{"ai-platform"}
		}
		before, after := Decide(base, req), Decide(withCli, req)
		if before.Upstream != after.Upstream || before.UpstreamModel != after.UpstreamModel {
			t.Fatalf("%s: client-axis experiment changed routing: %+v -> %+v", req.UserID, before, after)
		}
		if before.Experiment != "" { // in the traffic canary: it keeps the attribution
			if after.Experiment != before.Experiment || after.Variant != before.Variant {
				t.Fatalf("%s: traffic experiment displaced: %+v -> %+v", req.UserID, before, after)
			}
			continue
		}
		want := cli.ResolveVariant(policy.Subject{ID: req.UserID}, after.Ring)
		if want == nil {
			if after.Experiment != "" {
				t.Fatalf("%s (ring %s): unexpected attribution %s", req.UserID, after.Ring, after.Experiment)
			}
			continue
		}
		if after.Experiment != "cli-upgrade" || after.Variant != want.Name ||
			after.Headers[HeaderExperiment] != "cli-upgrade" || after.Headers[HeaderVariant] != want.Name {
			t.Fatalf("%s: got %+v, want cli-upgrade/%s", req.UserID, after, want.Name)
		}
		seen[want.Name] = true
	}
	if !seen["control"] || !seen["treatment"] {
		t.Fatalf("both variants should be attributed across 2000 users: %v", seen)
	}
	cli.Status = "paused"
	if d := Decide(withCli, RequestInfo{UserID: "u1@acme.com", Groups: []string{"ai-platform"}, ModelAlias: "sonnet"}); d.Experiment != "" {
		t.Fatal("paused client-axis experiment still attributed")
	}
}
