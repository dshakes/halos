package policy

import (
	"slices"
	"testing"
)

// TestDeniesTool: function tools match exactly (ignoring case); hosted tools
// match as a prefix ignoring case and underscores, so a versioned or
// vendor-spelled identifier cannot slip past a deny.
func TestDeniesTool(t *testing.T) {
	a := &Agents{DeniedTools: []string{"Bash", "web_search", "code_execution", "mcp", "computer"}}
	for _, tc := range []struct {
		name   string
		hosted bool
		want   bool
	}{
		{"bash", false, true},
		{"BASH", false, true},
		{"Bash2", false, false},
		{"web_search", false, true},
		{"web_search_20250305", true, true},
		{"web_search_preview_2025_03_11", true, true},
		{"webSearch", true, true},
		{"web_search_20250305", false, false}, // a client function of that name is matched exactly
		{"codeExecution", true, true},
		{"code_interpreter", true, false},
		{"mcp:github", true, true},
		{"mcp_toolset", true, true},
		{"computer_20250124", true, true},
		{"computerUse", true, true},
		{"googleSearch", true, false},
		{"text_editor_20250124", true, false},
	} {
		if got := a.DeniesTool(tc.name, tc.hosted); got != tc.want {
			t.Errorf("DeniesTool(%q, hosted=%v) = %v", tc.name, tc.hosted, got)
		}
	}
	if (*Agents)(nil).DeniesTool("Bash", false) || (&Agents{DeniedTools: []string{"_"}}).DeniesTool("x", true) {
		t.Fatal("an empty or nil deny list denied a tool")
	}
}

// TestChainRecheck (L3): the chain is re-checked against today's policy,
// every actor of it, not only the current one.
func TestChainRecheck(t *testing.T) {
	a := agentsFixture()
	a.Actors = append(a.Actors, AgentActor{Name: "admin-only", Groups: []string{"platform-admins"}})
	chain := func(names ...string) *DelegationChain {
		d := &DelegationChain{}
		for _, n := range names {
			d.Actors = append(d.Actors, Actor{Agent: n})
		}
		return d
	}
	if err := a.AdmitChain(nil, chain("planner", "reviewer")); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]*DelegationChain{
		"parent removed":           chain("gone", "reviewer"),
		"parent's groups not held": chain("admin-only", "reviewer"),
		"too deep":                 chain("planner", "reviewer", "a", "b", "c"),
	} {
		if err := a.AdmitChain([]string{"eng"}, d); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
	if err := a.AdmitChain([]string{"platform-admins"}, chain("admin-only")); err != nil {
		t.Fatalf("root holds the group: %v", err)
	}
	// reviewer narrows to haiku, so a chain through it may not call sonnet,
	// even when the current actor (planner) could.
	if got := a.ChainModelLimit(chain("reviewer", "planner")); !slices.Equal(got, []string{"haiku"}) {
		t.Fatalf("model limit along the chain: %v", got)
	}
	d := chain("planner")
	d.Models = []string{"sonnet"}
	if got := a.ChainModelLimit(d); !slices.Equal(got, []string{"sonnet"}) {
		t.Fatalf("credential scope: %v", got)
	}
	if got := (*Agents)(nil).ChainModelLimit(nil); got != nil {
		t.Fatalf("nil: %v", got)
	}
}

// TestDecideRemoteRechecksChain (L3): the egress decision re-checks every
// actor's groups against the root and applies the root's profile maxDepth.
func TestDecideRemoteRechecksChain(t *testing.T) {
	o := mustLoad(t)
	o.Agents = agentsFixture()
	ga := Subject{ID: "alice@acme.example"}
	two := &DelegationChain{Actors: []Actor{{Agent: "planner"}, {Agent: "reviewer"}}}
	if got := o.DecideRemote(ga, two, "billing", "", ""); !got.Allow {
		t.Fatalf("baseline: %+v", got)
	}
	o.Agents.Actors[0].Groups = []string{"platform-admins"} // the parent actor now needs a group alice lacks
	if got := o.DecideRemote(ga, two, "billing", "", ""); got.Allow {
		t.Fatalf("parent actor's groups ignored: %+v", got)
	}
	o.Agents = agentsFixture()
	for _, p := range o.Profiles {
		p.Agents.MaxDepth = 1
	}
	if got := o.DecideRemote(ga, two, "billing", "", ""); got.Allow {
		t.Fatalf("profile maxDepth ignored: %+v", got)
	}
}
