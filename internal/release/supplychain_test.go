package release

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/supplychain"
)

// scAdapter places skill artifacts under /etc/sc/skills, like claude-code.
type scAdapter struct{}

func (scAdapter) Name() string                             { return "scfake" }
func (scAdapter) Capabilities() []harness.Capability       { return nil }
func (scAdapter) InstallCommand(string, harness.OS) string { return "" }
func (scAdapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	fs, ws := hutil.RenderArtifacts("scfake", c.OS, p, hutil.ArtifactDirs{Dirs: map[string]string{policy.ArtifactSkill: "/etc/sc/skills"}})
	return append(fs, harness.File{Path: "/etc/sc/settings.json", Mode: 0o644, Data: []byte("{}\n")}), ws, nil
}

func init() { harness.Register(scAdapter{}) }

var skillTree = supplychain.Tree{"SKILL.md": []byte("# s\n"), "ref/notes.md": []byte("n\n")}

func scProfile(pin string) *policy.Profile {
	p := prof("1.0.0", "scfake")
	p.Name = "p"
	p.Extensions.Artifacts = []string{"s"}
	p.Resolved = []policy.ResolvedArtifact{{Name: "s", Kind: policy.ArtifactSkill, Source: "path:art/s", Digest: pin, Files: skillTree}}
	return p
}

func scBuild(t *testing.T) *Release {
	t.Helper()
	rel, err := Build(resolver{p: scProfile(skillTree.Digest())}, "p", "ga", Options{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	return rel
}

func TestBuildPinsArtifacts(t *testing.T) {
	rel := scBuild(t)
	e, ok := rel.Manifest.Artifact("s")
	if !ok || e.Digest != skillTree.Digest() || len(e.Files) != 2 || e.Source != "path:art/s" {
		t.Fatalf("supply-chain entry = %+v", rel.Manifest.SupplyChain)
	}
	var tagged int
	for _, f := range rel.Manifest.Harnesses["scfake"].Files["linux"] {
		if f.Artifact == "s" {
			tagged++
			if e.Files[f.ArtifactPath] != f.SHA256 || !strings.HasPrefix(f.Path, "/etc/sc/skills/s/") {
				t.Errorf("file %+v does not match the pin", f)
			}
		}
	}
	if tagged != 2 {
		t.Fatalf("%d artifact files rendered, want 2", tagged)
	}
	if err := rel.Manifest.CheckArtifactFiles(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(rel.Tar)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Manifest.CheckArtifactFiles(); err != nil || len(reopened.Manifest.SupplyChain) != 1 {
		t.Fatalf("pins lost in the tar: %v", err)
	}
}

func TestBuildRefusesDigestMismatch(t *testing.T) {
	other := "sha256:" + strings.Repeat("0", 64)
	_, err := Build(resolver{p: scProfile(other)}, "p", "ga", Options{Version: "1"})
	if err == nil || !strings.Contains(err.Error(), "does not match the pinned "+other) {
		t.Fatalf("err = %v", err)
	}
	p := scProfile("")
	p.Resolved[0].Files = supplychain.Tree{"../escape": []byte("x")}
	if _, err := Build(resolver{p: p}, "p", "ga", Options{Version: "1"}); err == nil {
		t.Fatal("artifact with an escaping path built")
	}
}

func TestCheckArtifactFileTamper(t *testing.T) {
	rel := scBuild(t)
	var f FileEntry
	for _, fe := range rel.Manifest.Harnesses["scfake"].Files["linux"] {
		if fe.Artifact == "s" && fe.ArtifactPath == "SKILL.md" {
			f = fe
		}
	}
	data := rel.Blobs[f.SHA256]
	if err := rel.Manifest.CheckArtifactFile(f, data); err != nil {
		t.Fatalf("untampered: %v", err)
	}
	plain := FileEntry{Path: "/etc/sc/settings.json", SHA256: "x"}
	if err := rel.Manifest.CheckArtifactFile(plain, []byte("anything")); err != nil {
		t.Fatalf("non-artifact file: %v", err)
	}
	clone := func() Manifest {
		var m Manifest
		b, _ := json.Marshal(rel.Manifest)
		_ = json.Unmarshal(b, &m)
		return m
	}
	for _, tc := range []struct {
		name string
		m    func() Manifest
		f    func(FileEntry) FileEntry
		data []byte
		want string
	}{
		{"content changed", clone, func(f FileEntry) FileEntry { return f }, []byte("# evil\n"), "does not hash to"},
		{"file hash swapped", clone, func(f FileEntry) FileEntry { f.SHA256 = strings.Repeat("a", 64); return f }, nil, "is not artifact s's"},
		{"wrong path in artifact", clone, func(f FileEntry) FileEntry { f.ArtifactPath = "ref/notes.md"; return f }, nil, "is not artifact s's"},
		{"unpinned artifact", clone, func(f FileEntry) FileEntry { f.Artifact = "ghost"; return f }, nil, "does not pin"},
		{"listing edited", func() Manifest {
			m := clone()
			m.SupplyChain[0].Files["SKILL.md"] = strings.Repeat("b", 64)
			return m
		}, func(f FileEntry) FileEntry { return f }, nil, "not its pinned digest"},
		{"listing extended", func() Manifest {
			m := clone()
			m.SupplyChain[0].Files["extra.md"] = strings.Repeat("b", 64)
			return m
		}, func(f FileEntry) FileEntry { return f }, nil, "not its pinned digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m().CheckArtifactFile(tc.f(f), tc.data)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func scAttest(t *testing.T, rel *Release) *Attestations {
	t.Helper()
	a, err := Attest(rel, nil, AttestOptions{HalosVersion: "0.4.0", PolicyCommit: strings.Repeat("c", 40), PolicyRepo: "https://git.example/policy"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAttest(t *testing.T) {
	rel := scBuild(t)
	a := scAttest(t, rel)
	if b := scAttest(t, rel); string(b.BOM) != string(a.BOM) || string(b.Provenance) != string(a.Provenance) {
		t.Fatal("attestations not deterministic")
	}
	var bom cdxBOM
	if err := json.Unmarshal(a.BOM, &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Fatalf("bom header = %+v", bom)
	}
	var art *cdxComponent
	for i, c := range bom.Components {
		if c.BOMRef == "artifact:s" {
			art = &bom.Components[i]
		}
	}
	if art == nil || len(art.Components) != 2 || art.Hashes[0].Content != strings.TrimPrefix(skillTree.Digest(), "sha256:") {
		t.Fatalf("artifact component = %+v", art)
	}
	if !strings.Contains(string(a.BOM), `"halos:policy-commit"`) {
		t.Fatal("bom lacks the policy commit")
	}
	var st statement
	if err := json.Unmarshal(a.Provenance, &st); err != nil {
		t.Fatal(err)
	}
	if st.Type != StatementType || st.PredicateType != SLSAProvenanceType || st.Predicate.RunDetails.Builder.ID != "https://github.com/dshakes/halos/cmd/halo@0.4.0" {
		t.Fatalf("statement = %+v", st)
	}
	if err := VerifyAttestations(rel, a.BOM, a.Provenance); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAttestationsTamper(t *testing.T) {
	rel := scBuild(t)
	a := scAttest(t, rel)
	other, err := Build(resolver{p: prof("2.0.0", "scfake")}, "p", "ga", Options{Version: "2"})
	if err != nil {
		t.Fatal(err)
	}
	edit := func(doc []byte, f func(map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(doc, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	comps := func(m map[string]any) []any { return m["components"].([]any) }
	for _, tc := range []struct {
		name      string
		rel       *Release
		bom, prov []byte
		want      string
	}{
		{"other release", other, a.BOM, a.Provenance, "describes a release other than"},
		{"not cyclonedx", rel, edit(a.BOM, func(m map[string]any) { m["specVersion"] = "1.4" }), a.Provenance, "want CycloneDX 1.6"},
		{"artifact hash changed", rel, edit(a.BOM, func(m map[string]any) {
			for _, c := range comps(m) {
				if c.(map[string]any)["bom-ref"] == "artifact:s" {
					c.(map[string]any)["hashes"] = []any{map[string]any{"alg": "SHA-256", "content": strings.Repeat("0", 64)}}
				}
			}
		}), a.Provenance, "artifact:s has sha256"},
		{"component dropped", rel, edit(a.BOM, func(m map[string]any) {
			var keep []any
			for _, c := range comps(m) {
				if c.(map[string]any)["bom-ref"] != "artifact:s" {
					keep = append(keep, c)
				}
			}
			m["components"] = keep
		}), a.Provenance, "artifact:s has sha256"},
		{"component added", rel, edit(a.BOM, func(m map[string]any) {
			m["components"] = append(comps(m), map[string]any{"type": "file", "bom-ref": "artifact:ghost", "name": "ghost",
				"hashes": []any{map[string]any{"alg": "SHA-256", "content": strings.Repeat("1", 64)}}})
		}), a.Provenance, "does not contain"},
		{"bom byproduct mismatch", rel, edit(a.BOM, func(m map[string]any) { m["version"] = 2 }), a.Provenance, "byproduct digest"},
		{"provenance subject", rel, a.BOM, edit(a.Provenance, func(m map[string]any) {
			m["subject"].([]any)[0].(map[string]any)["digest"] = map[string]any{"sha256": strings.Repeat("0", 64)}
		}), "subject is not release"},
		{"provenance artifact pin", rel, a.BOM, edit(a.Provenance, func(m map[string]any) {
			bd := m["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
			for _, d := range bd["resolvedDependencies"].([]any) {
				if d.(map[string]any)["name"] == "artifact:s" {
					d.(map[string]any)["digest"] = map[string]any{"sha256": strings.Repeat("0", 64)}
				}
			}
		}), "is not pinned to"},
		{"wrong predicate", rel, a.BOM, edit(a.Provenance, func(m map[string]any) { m["predicateType"] = "https://slsa.dev/provenance/v0.2" }), "SLSA provenance v1"},
		{"garbage", rel, []byte("{"), a.Provenance, "bom:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyAttestations(tc.rel, tc.bom, tc.prov)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPinnedPackage(t *testing.T) {
	for _, tc := range []struct {
		cmd       []string
		ver, purl string
	}{
		{[]string{"npx", "-y", "@acme/mcp@1.2.3"}, "1.2.3", "pkg:npm/%40acme/mcp@1.2.3"},
		{[]string{"npx", "-y", "@acme/mcp@latest"}, "", ""},
		{[]string{"npx", "@acme/mcp"}, "", ""},
		{[]string{"/usr/bin/uvx", "mcp-server-git==0.6.2"}, "0.6.2", "pkg:pypi/mcp-server-git@0.6.2"},
		{[]string{"uv", "run", "srv==1.0.0"}, "1.0.0", "pkg:pypi/srv@1.0.0"},
		{[]string{"pnpm", "dlx", "srv@2.0.0"}, "2.0.0", "pkg:npm/srv@2.0.0"},
		{[]string{"docker", "run", "-i", "ghcr.io/acme/mcp@sha256:" + strings.Repeat("a", 64)}, "sha256:" + strings.Repeat("a", 64),
			"pkg:oci/mcp@sha256%3A" + strings.Repeat("a", 64) + "?repository_url=ghcr.io/acme/mcp"},
		{[]string{"docker", "run", "ghcr.io/acme/mcp:latest"}, "", ""},
		{[]string{"./server"}, "", ""},
		{nil, "", ""},
	} {
		if v, p := pinnedPackage(tc.cmd); v != tc.ver || p != tc.purl {
			t.Errorf("%v: got %q %q, want %q %q", tc.cmd, v, p, tc.ver, tc.purl)
		}
	}
}
