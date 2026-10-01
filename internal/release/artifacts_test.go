package release

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	sha = "51f09bd1e021d9fa8a1864c179799bd37cb39962a937935c5cf6823398e86db4"
	sri = "sha512-SE13C3nZCYoVL569BdegoOl6vwjb7o2sXOo7ivwVzaVoY0cswwi0/6pIE0TyO/C0vIkQh3jslExitET7PBTfIg=="
)

func vendorServer(t *testing.T, claudeVer, npmBody string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/claude/2.0.0/manifest.json":
			fmt.Fprintf(w, `{"version":%q,"platforms":{"darwin-arm64":{"binary":"claude","checksum":%q,"size":10},"win32-x64":{"binary":"claude.exe","checksum":%q,"size":11}}}`, claudeVer, sha, sha)
		case "/npm/@openai/codex/0.5.0":
			fmt.Fprint(w, strings.ReplaceAll(npmBody, "HOST", srv.URL))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func relWith(t *testing.T, h map[string]HarnessEntry) *Release {
	t.Helper()
	r, err := pack(Manifest{SchemaVersion: 1, Org: "acme", Harnesses: h}, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveArtifacts(t *testing.T) {
	goodNPM := `{"name":"@openai/codex","version":"0.5.0","bin":{"codex":"bin/codex.js"},"dist":{"tarball":"HOST/npm/@openai/codex/-/codex-0.5.0.tgz","integrity":"` + sri + `"}}`
	srv := vendorServer(t, "2.0.0", goodNPM)
	r := ArtifactResolver{HTTP: srv.Client(), ClaudeBase: srv.URL + "/claude", NPMRegistry: srv.URL + "/npm"}
	rel := relWith(t, map[string]HarnessEntry{
		"claude-code": {Version: "2.0.0"}, "codex": {Version: "0.5.0"},
		"gemini-cli": {Version: "latest"}, "mystery": {Version: "1.0.0"},
	})
	out, err := r.Resolve(context.Background(), rel)
	if err != nil {
		t.Fatal(err)
	}
	if out.Digest == rel.Digest {
		t.Fatal("digest must change when artifacts are added")
	}
	re, err := Open(out.Tar) // round-trips through the signed tar
	if err != nil {
		t.Fatal(err)
	}
	c := re.Manifest.Harnesses["claude-code"]
	a, ok := c.ArtifactFor("darwin", "arm64")
	if !ok || a.Kind != KindBinary || a.SHA256 != sha || a.URL != srv.URL+"/claude/2.0.0/darwin-arm64/claude" || a.Size != 10 {
		t.Fatalf("claude darwin: %+v", a)
	}
	if w, _ := c.ArtifactFor("windows", "amd64"); w.BinPath != "claude.exe" {
		t.Fatalf("claude windows: %+v", w)
	}
	if _, ok := c.ArtifactFor("linux", "amd64"); ok {
		t.Fatal("platform absent from vendor manifest must not resolve")
	}
	n, ok := re.Manifest.Harnesses["codex"].ArtifactFor("linux", "arm64")
	if !ok || n.Kind != KindNPMTgz || n.Integrity != sri || n.Package != "@openai/codex" || n.BinPath != "codex" {
		t.Fatalf("codex: %+v", n)
	}
	if w := strings.Join(re.Manifest.Warnings, "\n"); !strings.Contains(w, "gemini-cli: version \"latest\"") || !strings.Contains(w, "mystery: no verified installer") {
		t.Fatalf("warnings: %s", w)
	}
}

func TestResolveArtifactsRejects(t *testing.T) {
	tests := []struct{ name, claudeVer, npm, harness, want string }{
		{"claude manifest for other version", "9.9.9", "", "claude-code", "want \"2.0.0\""},
		{"npm tarball off-registry", "2.0.0", `{"name":"@openai/codex","version":"0.5.0","bin":{"codex":"x"},"dist":{"tarball":"https://evil.example/c.tgz","integrity":"` + sri + `"}}`, "codex", "not on registry host"},
		{"npm sha1 integrity", "2.0.0", `{"name":"@openai/codex","version":"0.5.0","bin":{"codex":"x"},"dist":{"tarball":"HOST/npm/c.tgz","integrity":"sha1-abc"}}`, "codex", "integrity"},
		{"npm wrong package", "2.0.0", `{"name":"@evil/codex","version":"0.5.0"}`, "codex", "want @openai/codex"},
		{"npm missing bin", "2.0.0", `{"name":"@openai/codex","version":"0.5.0","bin":{"other":"x"},"dist":{"tarball":"HOST/npm/c.tgz","integrity":"` + sri + `"}}`, "codex", "bin"},
	}
	for _, tt := range tests {
		srv := vendorServer(t, tt.claudeVer, tt.npm)
		r := ArtifactResolver{HTTP: srv.Client(), ClaudeBase: srv.URL + "/claude", NPMRegistry: srv.URL + "/npm"}
		ver := map[string]string{"claude-code": "2.0.0", "codex": "0.5.0"}[tt.harness]
		_, err := r.Resolve(context.Background(), relWith(t, map[string]HarnessEntry{tt.harness: {Version: ver}}))
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v want %q", tt.name, err, tt.want)
		}
	}
}

func TestArtifactValidate(t *testing.T) {
	ok := Artifact{URL: "https://x/y", SHA256: sha, Kind: KindBinary, BinPath: "claude"}
	tests := []struct {
		name string
		mod  func(*Artifact)
		want string
	}{
		{"ok", func(*Artifact) {}, ""},
		{"http", func(a *Artifact) { a.URL = "http://x/y" }, "https"},
		{"no hash", func(a *Artifact) { a.SHA256 = "" }, "no sha256"},
		{"bin traversal", func(a *Artifact) { a.BinPath = "../../etc/passwd" }, "binPath"},
		{"bad kind", func(a *Artifact) { a.Kind = "sh" }, "kind"},
		{"npm bad pkg", func(a *Artifact) { a.Kind, a.Package = KindNPMTgz, "--foo" }, "package"},
	}
	for _, tt := range tests {
		a := ok
		tt.mod(&a)
		err := a.Validate()
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}
