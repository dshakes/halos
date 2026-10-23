package release

import (
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/policy"
)

// TestBuildPinsRemoteAgents: the ring release pins the remote agents its
// members may call with their card digests (signed with the release, so a
// changed card needs a policy change), and every harness warns that it has no
// A2A allowlist setting rather than dropping it silently (invariant 2).
func TestBuildPinsRemoteAgents(t *testing.T) {
	o := unitOrg(0, 0)
	o.Agents = &policy.Agents{Remote: []policy.RemoteAgent{
		{Name: "billing", CardURL: "https://b.example/.well-known/agent-card.json", Digest: "sha256:" + strings.Repeat("a", 64), Skills: []string{"lookup"}, Rings: []string{"ga"}},
		{Name: "pay", CardURL: "https://p.example/.well-known/agent-card.json", Digest: "sha256:" + strings.Repeat("b", 64), Units: []string{"payments"}},
		{Name: "canary-only", CardURL: "https://c.example/.well-known/agent-card.json", Digest: "sha256:" + strings.Repeat("c", 64), Rings: []string{"canary"}},
	}}
	r, err := Build(o, "base", "ga", Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := r.Manifest.RemoteAgents
	if len(got) != 2 || got[0].Name != "billing" || got[0].Digest != o.Agents.Remote[0].Digest || got[0].Units != nil ||
		got[1].Name != "pay" || !slices.Equal(got[1].Units, []string{"payments"}) {
		t.Fatalf("pinned: %+v", got)
	}
	if !slices.ContainsFunc(r.Manifest.Warnings, func(w string) bool {
		return strings.HasPrefix(w, "unitfake: agents.remote is not rendered") && strings.Contains(w, "/api/v1/agents/egress")
	}) {
		t.Fatalf("no per-harness warning: %v", r.Manifest.Warnings)
	}
	o.Profiles["base"].Agents.Remote = []string{"pay"} // the profile narrows billing away
	r, _ = Build(o, "base", "ga", Options{})
	if len(r.Manifest.RemoteAgents) != 1 || r.Manifest.RemoteAgents[0].Name != "pay" {
		t.Fatalf("profile narrowing: %+v", r.Manifest.RemoteAgents)
	}
	o.Agents = nil
	r, _ = Build(o, "base", "ga", Options{})
	if r.Manifest.RemoteAgents != nil || slices.ContainsFunc(r.Manifest.Warnings, func(w string) bool { return strings.Contains(w, "agents.remote") }) {
		t.Fatalf("no agents, yet: %+v %v", r.Manifest.RemoteAgents, r.Manifest.Warnings)
	}
	if w := remoteAgentsWarning("gemini-cli"); !strings.Contains(w, "kind: remote") || !strings.Contains(w, "experimental.enableAgents") {
		t.Fatalf("gemini warning: %s", w)
	}
}
