package policy

import (
	"strings"
	"testing"
)

func gatewayIssues(g *Gateway) []Issue {
	v := &validator{org: &Org{Gateway: g}, issues: []Issue{}}
	v.gateway()
	return v.issues
}

func baseGateway() *Gateway {
	return &Gateway{
		BaseURL: "https://ai.example.com",
		Upstreams: map[string]Upstream{
			"anthropic": {URL: "https://api.anthropic.com", Kind: "anthropic"},
			"bedrock":   {URL: "https://bedrock-runtime.us-east-1.amazonaws.com", Kind: "bedrock", Region: "us-east-1"},
		},
		Models: map[string]ModelRoute{},
	}
}

func TestGatewayRouteValidation(t *testing.T) {
	two := []RouteTarget{{Upstream: "bedrock", Model: "m1"}, {Upstream: "anthropic", Model: "m2", Priority: 1}}
	for _, tc := range []struct {
		name   string
		mod    func(*Gateway)
		want   string // substring of the one expected issue; "" = none
		sev    Severity
		errors bool
	}{
		{"valid targets", func(g *Gateway) { g.Models["opus"] = ModelRoute{Targets: two} }, "", "", false},
		{"valid single", func(g *Gateway) { g.Models["opus"] = ModelRoute{Upstream: "anthropic", Model: "m"} }, "", "", false},
		{"both forms", func(g *Gateway) { g.Models["opus"] = ModelRoute{Upstream: "anthropic", Model: "m", Targets: two} }, "not both", SeverityError, true},
		{"unknown target upstream", func(g *Gateway) {
			g.Models["opus"] = ModelRoute{Targets: []RouteTarget{{Upstream: "nope", Model: "m"}}}
		}, `upstream "nope" not defined`, SeverityError, true},
		{"target without model", func(g *Gateway) {
			g.Models["opus"] = ModelRoute{Targets: []RouteTarget{{Upstream: "anthropic"}}}
		}, "model is required", SeverityError, true},
		{"negative weight", func(g *Gateway) {
			g.Models["opus"] = ModelRoute{Targets: []RouteTarget{{Upstream: "anthropic", Model: "m", Weight: -1}}}
		}, "must be >= 0", SeverityError, true},
		{"kong warns on multi-target", func(g *Gateway) { g.Engine = "kong"; g.Models["opus"] = ModelRoute{Targets: two} }, "only in halo-proxy", SeverityWarning, false},
		{"kong single target is fine", func(g *Gateway) {
			g.Engine = "kong"
			g.Models["opus"] = ModelRoute{Targets: two[:1]}
		}, "", "", false},
		{"bad engine", func(g *Gateway) { g.Engine = "envoy" }, "halo-proxy or kong", SeverityError, true},
		{"unreachable kind warns", func(g *Gateway) {
			g.Protocols = map[string]string{"codex": "openai-responses"}
			g.Models["opus"] = ModelRoute{Targets: two[:1]} // bedrock cannot serve a Responses client
		}, "never be used", SeverityWarning, false},
		{"vertex ok", func(g *Gateway) {
			g.Upstreams["v"] = Upstream{Kind: "vertex", Project: "p", Region: "us-east5"}
			g.Models["opus"] = ModelRoute{Targets: []RouteTarget{{Upstream: "v", Model: "claude-opus-4-1@20250805"}}}
		}, "", "", false},
		{"vertex needs project", func(g *Gateway) { g.Upstreams["v"] = Upstream{Kind: "vertex", Region: "global"} }, "project is required", SeverityError, true},
		{"vertex needs region", func(g *Gateway) { g.Upstreams["v"] = Upstream{Kind: "vertex", Project: "p"} }, "region is required", SeverityError, true},
		{"vertex bad region", func(g *Gateway) { g.Upstreams["v"] = Upstream{Kind: "vertex", Project: "p", Region: "mars"} }, "us-east5 or global", SeverityError, true},
		{"azure needs credential", func(g *Gateway) {
			g.Upstreams["az"] = Upstream{URL: "https://a.openai.azure.com", Kind: "azure-openai"}
		}, "needs credential", SeverityError, true},
		{"azure ok", func(g *Gateway) {
			g.Upstreams["az"] = Upstream{URL: "https://a.openai.azure.com", Kind: "azure-openai", Credential: &Credential{Env: "AZURE_OPENAI_KEY"}}
		}, "", "", false},
		{"credential env xor file", func(g *Gateway) {
			g.Upstreams["oai"] = Upstream{URL: "https://api.openai.com", Kind: "openai", Credential: &Credential{Env: "A", File: "/f"}}
		}, "exactly one", SeverityError, true},
		{"credential bad scheme", func(g *Gateway) {
			g.Upstreams["oai"] = Upstream{URL: "https://api.openai.com", Kind: "openai", Credential: &Credential{Env: "A", Scheme: "basic"}}
		}, "api-key or bearer", SeverityError, true},
		{"credential on anthropic", func(g *Gateway) {
			g.Upstreams["x"] = Upstream{URL: "https://x", Kind: "anthropic", Credential: &Credential{Env: "A"}}
		}, "only valid on kinds openai", SeverityError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := baseGateway()
			tc.mod(g)
			issues := gatewayIssues(g)
			if tc.want == "" {
				if len(issues) != 0 {
					t.Fatalf("unexpected issues: %v", issues)
				}
				return
			}
			var found bool
			for _, i := range issues {
				if strings.Contains(i.Message, tc.want) {
					found = true
					if i.Severity != tc.sev {
						t.Errorf("%v: severity %s, want %s", i, i.Severity, tc.sev)
					}
				}
			}
			if !found {
				t.Fatalf("no issue containing %q in %v", tc.want, issues)
			}
			if HasErrors(issues) != tc.errors {
				t.Errorf("HasErrors=%v, want %v: %v", HasErrors(issues), tc.errors, issues)
			}
		})
	}
}

func TestModelRoutePrimaryAndCandidates(t *testing.T) {
	r := ModelRoute{Targets: []RouteTarget{{Upstream: "b", Model: "mb", Priority: 1}, {Upstream: "a", Model: "ma"}}}
	if p := r.Primary(); p.Upstream != "a" || p.Model != "ma" {
		t.Fatalf("primary %+v", p)
	}
	if got := (ModelRoute{Upstream: "u", Model: "m"}).Candidates(); len(got) != 1 || got[0].Upstream != "u" {
		t.Fatalf("single %+v", got)
	}
	if (ModelRoute{}).Candidates() != nil || (ModelRoute{}).Primary().Upstream != "" {
		t.Fatal("zero route must have no candidates")
	}
}

func TestVertexEndpoint(t *testing.T) {
	for _, tt := range []struct { // a slice: Upstream is not comparable (Serves)
		in   Upstream
		want string
	}{
		{Upstream{Kind: "vertex", Region: "us-east5"}, "https://us-east5-aiplatform.googleapis.com"},
		{Upstream{Kind: "vertex", Region: "global"}, "https://aiplatform.googleapis.com"},
		{Upstream{Kind: "vertex", Region: "global", URL: "https://pe.corp"}, "https://pe.corp"},
		{Upstream{Kind: "anthropic", URL: "https://api.anthropic.com"}, "https://api.anthropic.com"},
	} {
		if got := tt.in.Endpoint(); got != tt.want {
			t.Errorf("%+v: %q, want %q", tt.in, got, tt.want)
		}
	}
}
