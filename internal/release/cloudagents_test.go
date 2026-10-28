package release

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/cloudagents"
	"github.com/dshakes/halos/internal/policy"
)

// Cloud agent workflows ride in the release as signed blobs, listed apart
// from the harness files halod writes; Open refuses a listing without its blob.
func TestBuildCarriesCloudAgentFiles(t *testing.T) {
	org := &policy.Org{Name: "acme", Profiles: map[string]*policy.Profile{"p": prof("1.0.0", "fake")},
		CloudAgents: &policy.CloudAgents{Claude: &policy.CloudAgent{Enabled: true, Repos: []string{"acme/app"}}, Cursor: &policy.CloudAgent{Enabled: true}}}
	rel, err := Build(org, "p", "ga", Options{Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	ca := rel.Manifest.CloudAgents
	if len(ca) != 1 || ca[0].Vendor != "claude" || ca[0].Path != cloudagents.ClaudeWorkflow || ca[0].Repos[0] != "acme/app" {
		t.Fatalf("cloudAgents %+v", ca)
	}
	if b, ok := rel.Blobs[ca[0].SHA256]; !ok || !strings.Contains(string(b), "anthropics/claude-code-action@") {
		t.Fatal("workflow blob missing")
	}
	if !strings.Contains(strings.Join(rel.Manifest.Warnings, "\n"), "cloudAgents.cursor: configured in the vendor console") {
		t.Fatalf("console vendor not warned: %v", rel.Manifest.Warnings)
	}
	for _, he := range rel.Manifest.Harnesses {
		for _, fs := range he.Files {
			for _, f := range fs {
				if f.SHA256 == ca[0].SHA256 {
					t.Fatal("a cloud agent file is listed as a machine file")
				}
			}
		}
	}
	if _, err := Open(rel.Tar); err != nil {
		t.Fatal(err)
	}
	// Drop the workflow blob: Open must refuse the bundle.
	var buf bytes.Buffer
	tw, tr := tar.NewWriter(&buf), tar.NewReader(bytes.NewReader(rel.Tar))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		if h.Name == "blobs/"+ca[0].SHA256 {
			continue
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "cloud agent") {
		t.Fatalf("Open without the blob: %v", err)
	}
}
