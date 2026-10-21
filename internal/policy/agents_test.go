package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func agentsFixture() *Agents {
	return &Agents{
		MaxDepth: 4, AllowedModels: []string{"sonnet", "haiku"},
		Actors: []AgentActor{{Name: "planner", Harnesses: []string{"claude-code"}}, {Name: "reviewer", Models: []string{"haiku"}}},
		Remote: []RemoteAgent{
			{Name: "billing", CardURL: "https://agents.billing.example/.well-known/agent-card.json", Digest: digestA, Skills: []string{"lookup"}, Rings: []string{"ring3-ga"}, JWKSURL: "https://agents.billing.example/jwks.json"},
			{Name: "payments-bot", CardURL: "https://pay.example/.well-known/agent-card.json", Digest: digestB, Skills: []string{"refund"}, Units: []string{"payments"}, JWKSURL: "https://pay.example/jwks.json"},
		},
	}
}

func agentErrors(o *Org) []string {
	var out []string
	for _, i := range o.Validate() {
		if i.Severity == SeverityError {
			out = append(out, i.Path)
		}
	}
	return out
}

func TestValidateAgents(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	for _, tc := range []struct {
		name string
		mod  func(o *Org)
		want []string
	}{
		{"valid", func(o *Org) { o.Agents.Remote[0].PublicKey = pemKey }, nil},
		{"depth over the ceiling", func(o *Org) { o.Agents.MaxDepth = MaxAgentDepth + 1 }, []string{"agents.maxDepth"}},
		{"ttl over 1h", func(o *Org) { o.Agents.MaxTTLSeconds = 7200 }, []string{"agents.maxTTLSeconds"}},
		{"unknown model", func(o *Org) { o.Agents.AllowedModels = []string{"gpt-9"} }, []string{"agents.allowedModels[0]", "agents.actors[1].models[0]"}},
		{"actor model outside allowedModels", func(o *Org) { o.Agents.Actors[1].Models = []string{"opus"} }, []string{"agents.actors[1].models[0]"}},
		{"duplicate actor, bad harness", func(o *Org) {
			o.Agents.Actors = append(o.Agents.Actors, AgentActor{Name: "planner", Harnesses: []string{"vim"}})
		}, []string{"agents.actors[2].name", "agents.actors[2].harnesses"}},
		{"plain http card", func(o *Org) { o.Agents.Remote[0].CardURL = "http://agents.billing.example/card.json" }, []string{"agents.remote[0].cardURL"}},
		{"card URL with credentials", func(o *Org) { o.Agents.Remote[0].CardURL = "https://u:p@agents.billing.example/card.json" }, []string{"agents.remote[0].cardURL"}},
		{"bad digest", func(o *Org) { o.Agents.Remote[0].Digest = "sha256:abc" }, []string{"agents.remote[0].digest"}},
		{"bad key", func(o *Org) { o.Agents.Remote[0].PublicKey = "not a key" }, []string{"agents.remote[0].publicKey"}},
		{"http jwks", func(o *Org) { o.Agents.Remote[0].JWKSURL = "http://x.example/jwks" }, []string{"agents.remote[0].jwksURL"}},
		{"unknown ring and unit", func(o *Org) { o.Agents.Remote[0].Rings, o.Agents.Remote[0].Units = []string{"nope"}, []string{"nope"} },
			[]string{"agents.remote[0].rings", "agents.remote[0].units"}},
		{"profile depth above the org's", func(o *Org) { o.Profiles["engineering"].Agents.MaxDepth = 5 }, []string{"profiles[engineering].agents.maxDepth"}},
		{"profile names an unknown remote agent", func(o *Org) { o.Profiles["engineering"].Agents.Remote = []string{"nope"} }, []string{"profiles[engineering].agents.remote"}},
		{"profile agents without org agents", func(o *Org) { o.Agents = nil; o.Profiles["engineering"].Agents.MaxDepth = 1 }, []string{"profiles[engineering].agents"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := mustLoad(t)
			o.Agents = agentsFixture()
			tc.mod(o)
			if got := agentErrors(o); !slices.Equal(got, tc.want) {
				t.Fatalf("errors %v, want %v", got, tc.want)
			}
		})
	}
}

// TestUnitAgentLoosenings: a unit may lower maxDepth and narrow the remote
// allowlist, never raise or widen them (ADR-0024).
func TestUnitAgentLoosenings(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile AgentLimits
		units   []*Unit
		want    []string
	}{
		{"lower depth, narrow remote", AgentLimits{}, []*Unit{testUnit("u", "", Overlay{Agents: AgentLimits{MaxDepth: 1, Remote: []string{"billing"}}})}, nil},
		{"raise depth over the parent unit", AgentLimits{}, []*Unit{
			testUnit("bu", "", Overlay{Agents: AgentLimits{MaxDepth: 2}}),
			testUnit("team", "bu", Overlay{Agents: AgentLimits{MaxDepth: 3}}),
		}, []string{"units[team].overlay.agents.maxDepth"}},
		{"raise depth over the profile", AgentLimits{MaxDepth: 1}, []*Unit{testUnit("u", "", Overlay{Agents: AgentLimits{MaxDepth: 3}})}, []string{"units[u].overlay.agents.maxDepth"}},
		{"add a remote agent", AgentLimits{Remote: []string{"billing"}}, []*Unit{testUnit("u", "", Overlay{Agents: AgentLimits{Remote: []string{"billing", "payments-bot"}}})},
			[]string{"units[u].overlay.agents.remote"}},
		{"nested unit adds a remote agent", AgentLimits{}, []*Unit{
			testUnit("bu", "", Overlay{Agents: AgentLimits{Remote: []string{"billing"}}}),
			testUnit("team", "bu", Overlay{Agents: AgentLimits{Remote: []string{"payments-bot"}}}),
		}, []string{"units[team].overlay.agents.remote"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := mustLoad(t)
			o.Agents = agentsFixture()
			for _, p := range o.Profiles {
				p.Agents = tc.profile
			}
			o.Units = append(o.Units, tc.units...)
			var got []string
			for _, p := range agentErrors(o) {
				if strings.HasPrefix(p, "units[") {
					got = append(got, p)
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("errors %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecideRemote(t *testing.T) {
	o := mustLoad(t)
	o.Agents = agentsFixture()
	ga := Subject{ID: "alice@acme.example"}
	pay := Subject{ID: "pat@acme.example", Groups: []string{"payments-eng"}}
	deep := &DelegationChain{Actors: []Actor{{Agent: "planner"}, {Agent: "reviewer"}, {Agent: "planner"}, {Agent: "reviewer"}, {Agent: "planner"}}}
	for _, tc := range []struct {
		name              string
		s                 Subject
		d                 *DelegationChain
		agent, url, skill string
		allow             bool
	}{
		{"ring member", ga, nil, "billing", "", "lookup", true},
		{"by origin", ga, nil, "", "https://agents.billing.example/a2a/v1", "", true},
		{"other origin", ga, nil, "", "https://agents.billing.example.evil.example/a2a", "", false},
		{"skill not allowed", ga, nil, "billing", "", "refund", false},
		{"unit-only agent, outsider", ga, nil, "payments-bot", "", "", false},
		{"unit-only agent, member", pay, nil, "payments-bot", "", "refund", true},
		{"unknown", ga, nil, "elsewhere", "", "", false},
		{"actor no longer allowed", ga, &DelegationChain{Actors: []Actor{{Agent: "rogue"}}}, "billing", "", "", false},
		{"chain deeper than policy", ga, deep, "billing", "", "", false},
	} {
		if got := o.DecideRemote(tc.s, tc.d, tc.agent, tc.url, tc.skill); got.Allow != tc.allow {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	o.Profiles["engineering"].Agents.Remote = []string{"payments-bot"} // the profile narrows billing away
	if got := o.DecideRemote(ga, nil, "billing", "", ""); got.Allow {
		t.Fatalf("profile narrowing ignored: %+v", got)
	}
	o.Agents = nil
	if got := o.DecideRemote(ga, nil, "billing", "", ""); got.Allow {
		t.Fatal("allowed without agents policy")
	}
}

func TestIntersectScope(t *testing.T) {
	if got := IntersectScope(nil, nil); got != nil {
		t.Fatalf("nil,nil = %v", got)
	}
	if got := IntersectScope([]string{"a"}, []string{"b"}); got == nil || len(got) != 0 {
		t.Fatalf("disjoint scopes must be empty, never unrestricted: %#v", got)
	}
	if got := IntersectScope(nil, []string{"b"}); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("nil narrows to the other: %v", got)
	}
	if got := (&Agents{AllowedModels: []string{"a", "b"}}).ModelLimit(&AgentActor{Models: []string{"c"}}); got == nil || len(got) != 0 {
		t.Fatalf("disjoint actor models: %#v", got)
	}
}

func TestSchemaAgents(t *testing.T) {
	s := compileSchemas(t)["halos.schema.json"]
	good := "kind: Halos\norg: acme\nagents:\n  maxDepth: 2\n  allowedModels: [sonnet]\n  deniedTools: [Bash]\n  actors:\n    - {name: planner, harnesses: [claude-code]}\n" +
		"  remote:\n    - name: billing\n      cardURL: https://a.example/.well-known/agent-card.json\n      digest: " + digestA + "\n      skills: [lookup]\n      rings: [ga]\n"
	if err := s.Validate(yamlDocs(t, []byte(good))[0]); err != nil {
		t.Fatalf("valid agents rejected: %v", err)
	}
	for name, bad := range map[string]string{
		"unknown field": strings.Replace(good, "deniedTools: [Bash]", "bogus: 1", 1),
		"depth 6":       strings.Replace(good, "maxDepth: 2", "maxDepth: 6", 1),
		"http card":     strings.Replace(good, "cardURL: https://", "cardURL: http://", 1),
		"short digest":  strings.Replace(good, digestA, "sha256:abc", 1),
		"no digest":     strings.Replace(good, "      digest: "+digestA+"\n", "", 1),
	} {
		if err := s.Validate(yamlDocs(t, []byte(bad))[0]); err == nil {
			t.Errorf("%s: schema accepted it", name)
		}
	}
	unit := compileSchemas(t)["unit.schema.json"]
	u := "apiVersion: halos.dev/v1\nkind: Unit\nname: u\nowners: [\"@acme/u\"]\nmembers: {groups: [u]}\noverlay:\n  agents: {maxDepth: 1, remote: [billing]}\n"
	if err := unit.Validate(yamlDocs(t, []byte(u))[0]); err != nil {
		t.Fatalf("unit overlay agents rejected: %v", err)
	}
}
