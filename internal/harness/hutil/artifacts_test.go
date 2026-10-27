package hutil

import (
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/supplychain"
)

func TestRenderArtifacts(t *testing.T) {
	p := &policy.Profile{}
	p.Extensions.Artifacts = []string{"sk", "ag", "multi", "pl", "remote", "ghost", "cmd"}
	p.Resolved = []policy.ResolvedArtifact{
		{Name: "sk", Kind: policy.ArtifactSkill, Files: supplychain.Tree{"SKILL.md": []byte("s"), "ref/a.md": []byte("a")}},
		{Name: "ag", Kind: policy.ArtifactAgent, Files: supplychain.Tree{"reviewer.md": []byte("r")}},
		{Name: "multi", Kind: policy.ArtifactAgent, Files: supplychain.Tree{"a.md": nil, "b.md": nil}},
		{Name: "pl", Kind: policy.ArtifactPlugin, Files: supplychain.Tree{"plugin.json": []byte("{}")}},
		{Name: "remote", Kind: policy.ArtifactSkill, Source: "oci://x"},
		{Name: "cmd", Kind: policy.ArtifactCommand, Files: supplychain.Tree{"c.md": []byte("c")}},
	}
	ad := ArtifactDirs{
		Dirs:   map[string]string{policy.ArtifactSkill: "/m/skills"},
		Single: map[string]string{policy.ArtifactAgent: "/m/agents"},
		Why:    map[string]string{policy.ArtifactPlugin: "use marketplaces"},
	}
	files, warns := RenderArtifacts("x", harness.Linux, p, ad)
	got := map[string]harness.File{}
	for _, f := range files {
		got[f.Path] = f
	}
	if len(files) != 3 {
		t.Fatalf("files = %v", files)
	}
	if f := got["/m/skills/sk/ref/a.md"]; f.Artifact != "sk" || f.ArtifactPath != "ref/a.md" || string(f.Data) != "a" || f.Mode != 0o644 {
		t.Errorf("skill file = %+v", f)
	}
	if f := got["/m/agents/ag.md"]; f.Artifact != "ag" || f.ArtifactPath != "reviewer.md" {
		t.Errorf("agent file = %+v", f)
	}
	all := strings.Join(warns, "\n")
	for _, w := range []string{
		`"multi" (agent) was not rendered: a agent is one Markdown file, it has 2`,
		`"pl" (plugin) was not rendered: use marketplaces`,
		`"remote" (skill) was not rendered: its content is not resolved here`,
		`"ghost" was not rendered: the profile was not resolved`,
		`"cmd" (command) was not rendered: the CLI has no documented managed location`,
	} {
		if !strings.Contains(all, w) {
			t.Errorf("missing warning %q in:\n%s", w, all)
		}
	}
	if len(warns) != 5 {
		t.Errorf("%d warnings, want 5 (one per unplaced artifact)", len(warns))
	}
	wf, _ := RenderArtifacts("x", harness.Windows, p, ArtifactDirs{Dirs: map[string]string{policy.ArtifactSkill: `C:\m\skills`}})
	if len(wf) != 2 || !strings.Contains(wf[0].Path, `C:\m\skills\sk\`) {
		t.Errorf("windows paths = %v", wf)
	}
}
