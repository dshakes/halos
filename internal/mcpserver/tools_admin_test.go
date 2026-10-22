package mcpserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// admin_plan is registered read-only and no apply tool exists, even with
// --allow-writes; it diffs with the credential from the environment only.
func TestAdminPlanReadOnly(t *testing.T) {
	dir := copyExample(t)
	f, err := os.OpenFile(filepath.Join(dir, "halos.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\nvendorAdmin:\n  claude: {}\n  copilot:\n    org: acme\n")
	_ = f.Close()

	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.Method != http.MethodGet {
			t.Errorf("admin_plan sent %s %s", r.Method, r.URL.Path)
		}
		switch r.URL.Path {
		case "/orgs/acme/copilot/billing":
			_, _ = io.WriteString(w, `{"cli":"disabled"}`)
		case "/orgs/acme/copilot/content_exclusion":
			_, _ = io.WriteString(w, `{"*":["/.env"]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	names := toolNames(t, connect(t, Options{PolicyDir: dir, AllowWrites: true}))
	if !names["admin_plan"] {
		t.Fatal("admin_plan missing")
	}
	for n := range names {
		if strings.HasPrefix(n, "admin_") && n != "admin_plan" {
			t.Errorf("admin write tool %s registered", n)
		}
	}

	// M3: without --admin-read, no console is contacted even with tokens set.
	t.Setenv("HALO_ADMIN_COPILOT_TOKEN", "ghp_cli_shell")
	t.Setenv("HALO_MCP_ADMIN_COPILOT_TOKEN", "ghp_mcp")
	off := connect(t, Options{PolicyDir: dir, AdminBaseURLs: map[string]string{"copilot": srv.URL}})
	out, err := call(t, off, "admin_plan", nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" || out["checked"] != false || out["drift"] != false ||
		!strings.Contains(strings.Join(anyStrings(out["next_steps"]), "\n"), "--admin-read") {
		t.Fatalf("offline by default: auth %q out %v", auth, out)
	}

	// M3: with --admin-read, the CLI's HALO_ADMIN_* token is never used.
	cs := connect(t, Options{PolicyDir: dir, AdminRead: true, AdminBaseURLs: map[string]string{"copilot": srv.URL}})
	t.Setenv("HALO_MCP_ADMIN_COPILOT_TOKEN", "")
	out, err = call(t, cs, "admin_plan", nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" || !strings.Contains(strings.Join(anyStrings(out["next_steps"]), "\n"), "HALO_MCP_ADMIN_COPILOT_TOKEN is not set") {
		t.Fatalf("shell token used or missing credential not surfaced: auth %q %v", auth, out["next_steps"])
	}

	t.Setenv("HALO_MCP_ADMIN_COPILOT_TOKEN", "ghp_mcp")
	out, err = call(t, cs, "admin_plan", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["checked"] != true || out["drift"] != true || auth != "Bearer ghp_mcp" {
		t.Fatalf("checked %v drift %v auth %q", out["checked"], out["drift"], auth)
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
