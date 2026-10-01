package toggle_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/toggle"
)

func loadExample(t *testing.T) *policy.Org {
	t.Helper()
	org, err := policy.Load("../../examples/acme-corp")
	if err != nil {
		t.Fatal(err)
	}
	if issues := org.Validate(); policy.HasErrors(issues) {
		t.Fatalf("example has validation errors: %v", issues)
	}
	return org
}

func TestBuildCarriesToggleFragments(t *testing.T) {
	org := loadExample(t)
	rel, _, err := release.BuildRing(org, "ring1-canary", release.Options{Version: "1.0.0", OSes: []harness.OS{harness.Linux}})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range rel.Manifest.Toggles {
		names = append(names, e.Name)
	}
	if want := []string{"format-hook", "github-mcp"}; !slices.Equal(names, want) {
		t.Fatalf("manifest toggles = %v, want %v (traffic toggles never ship in a release)", names, want)
	}
	// Survives the signed-bundle round trip (Open re-verifies every fragment blob).
	reopened, err := release.Open(rel.Tar)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reopened.Manifest.Toggles, rel.Manifest.Toggles) {
		t.Fatal("toggles changed across Open")
	}
	// The codex hook fragment is unsupported by that adapter: it must warn, not vanish.
	var warned bool
	for _, w := range rel.Manifest.Warnings {
		warned = warned || strings.Contains(w, "toggle format-hook") && strings.Contains(w, "codex")
	}
	if !warned {
		t.Fatalf("expected a toggle format-hook codex warning, got %v", rel.Manifest.Warnings)
	}
}

// Merging a toggle's fragment into the toggle-off file must give exactly what
// the adapter renders with the toggle on.
func TestFragmentMergeEqualsOnRender(t *testing.T) {
	org := loadExample(t)
	ring := org.Rings[1]
	prof, err := org.ResolveProfile(ring.Profile)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := release.Build(org, ring.Profile, ring.Name, release.Options{Version: "1.0.0", OSes: []harness.OS{harness.Linux}})
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := harness.Get("claude-code")
	for _, tg := range org.Toggles {
		if tg.Client == nil || tg.Client.Harnesses["claude-code"].Hooks == nil && tg.Client.Harnesses["claude-code"].MCPServers == nil {
			continue
		}
		on := tg.Client.Harnesses["claude-code"].Apply(prof, "claude-code")
		wantFiles, _, err := ad.Render(on, harness.Context{Gateway: org.Gateway, Ring: ring.Name, Release: "1.0.0", OS: harness.Linux})
		if err != nil {
			t.Fatal(err)
		}
		var entry release.ToggleEntry
		for _, e := range rel.Manifest.Toggles {
			if e.Name == tg.Name {
				entry = e
			}
		}
		base := map[string][]byte{}
		for _, f := range rel.Manifest.Harnesses["claude-code"].Files["linux"] {
			base[f.Path], _ = rel.Content(f)
		}
		got := map[string][]byte{}
		for p, b := range base {
			got[p] = b
		}
		for _, ff := range entry.Fragments["claude-code"]["linux"] {
			d, _ := rel.Content(ff)
			if got[ff.Path], err = toggle.Merge(ff.Path, base[ff.Path], d); err != nil {
				t.Fatal(err)
			}
		}
		for _, wf := range wantFiles {
			if !strings.HasSuffix(wf.Path, ".json") {
				continue // CLAUDE.md: a toggle cannot change it
			}
			var a, b any
			if err := json.Unmarshal(got[wf.Path], &a); err != nil {
				t.Fatalf("%s: %v", wf.Path, err)
			}
			_ = json.Unmarshal(wf.Data, &b)
			if !reflect.DeepEqual(a, b) {
				t.Errorf("toggle %s: merged %s differs from the on-render:\n got %s\nwant %s", tg.Name, wf.Path, got[wf.Path], wf.Data)
			}
		}
	}
}

// A fragment can only ever come from a validated toggle, but the build
// re-checks it: a forbidden value reaching the adapter output fails the build.
func TestBuildRejectsForbiddenFragment(t *testing.T) {
	org := loadExample(t)
	for _, tg := range org.Toggles {
		if tg.Name == "github-mcp" {
			p := tg.Client.Harnesses["claude-code"]
			p.Overrides = map[string]any{"permissions": map[string]any{"defaultMode": "bypassPermissions"}}
			tg.Client.Harnesses["claude-code"] = p
		}
	}
	if _, _, err := release.BuildRing(org, "ring1-canary", release.Options{Version: "1.0.0"}); err == nil || !strings.Contains(err.Error(), "bypassPermissions") {
		t.Fatalf("want a bypassPermissions build failure, got %v", err)
	}
}
