package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const playwrightServerJSON = `{"server":{"name":"io.github.microsoft/playwright-mcp","version":"0.0.82",
	"packages":[{"registryType":"npm","identifier":"@playwright/mcp","version":"0.0.82","transport":{"type":"stdio"}}]}}`

func TestMCPRegistryImport(t *testing.T) {
	var paths []string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		if r.Method != http.MethodGet {
			t.Errorf("method %s: the import is read-only", r.Method)
		}
		_, _ = w.Write([]byte(playwrightServerJSON))
	}))
	defer hs.Close()
	f := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(f, []byte(playwrightServerJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"mcp", "registry", "import", f},
		{"mcp", "registry", "import", "--registry", hs.URL, "io.github.microsoft/playwright-mcp"},
	} {
		code, out, errOut := halo(t, args...)
		if code != 0 || !strings.Contains(out, "- id: playwright-mcp") || !strings.Contains(out, "version: 0.0.82") ||
			!strings.Contains(out, "type: npm") || !strings.Contains(errOut, "set rings") {
			t.Fatalf("%v: %d\n%s\n%s", args, code, out, errOut)
		}
	}
	if len(paths) != 1 || paths[0] != "/v0/servers/io.github.microsoft%2Fplaywright-mcp/versions/latest" {
		t.Fatalf("registry paths %v", paths)
	}
	if code, _, errOut := halo(t, "mcp", "registry", "import", "http://registry.example/server.json"); code == 0 || !strings.Contains(errOut, "https") {
		t.Fatalf("plain http accepted: %d %s", code, errOut)
	}
}

func TestMCPToken(t *testing.T) {
	var form map[string][]string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.URL.Path != "/api/v1/token/exchange" {
			t.Errorf("request %s: %v", r.URL.Path, err)
		}
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "mcp.tok", "token_type": "Bearer", "expires_in": 300})
	}))
	defer hs.Close()
	t.Setenv("HALO_SERVER", hs.URL)
	t.Setenv("HALO_GATEWAY_TOKEN", "")
	t.Setenv("HALO_SESSION", "sess")
	code, out, errOut := halo(t, "mcp", "token", "--resource", "https://wiki.acme.example/mcp")
	if code != 0 || strings.TrimSpace(out) != `{"Authorization":"Bearer mcp.tok"}` {
		t.Fatalf("%d %q %s", code, out, errOut)
	}
	if form["resource"][0] != "https://wiki.acme.example/mcp" || form["subject_token"][0] != "sess" || form["subject_token_type"][0] != tokenTypeSessionURN {
		t.Fatalf("form %v", form)
	}
	t.Setenv("HALO_SESSION", "")
	t.Setenv("HALO_GATEWAY_TOKEN", "wl.jwt")
	if code, out, _ := halo(t, "mcp", "token", "--resource", "https://wiki.acme.example/mcp", "--format", "token"); code != 0 || out != "mcp.tok\n" ||
		form["subject_token"][0] != "wl.jwt" || form["subject_token_type"][0] != ciTokenTypeJWT {
		t.Fatalf("workload: %d %q %v", code, out, form)
	}
	for _, args := range [][]string{
		{"mcp", "token", "--resource", "http://wiki.acme.example/mcp"},
		{"mcp", "token", "--resource", "https://wiki.acme.example/mcp", "--format", "yaml"},
	} {
		if code, _, _ := halo(t, args...); code == 0 {
			t.Errorf("%v: want failure", args)
		}
	}
	t.Setenv("HALO_GATEWAY_TOKEN", "")
	if code, _, errOut := halo(t, "mcp", "token", "--resource", "https://wiki.acme.example/mcp"); code == 0 || !strings.Contains(errOut, "no Halos credential") {
		t.Fatalf("no credential: %d %s", code, errOut)
	}
}
