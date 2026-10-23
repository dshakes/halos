package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const vendorAdminYAML = `
vendorAdmin:
  claude: {}
  codex: {}
  cursor: {}
  copilot:
    org: acme
`

func adminPolicy(t *testing.T) string {
	t.Helper()
	dir := copyDir(t, example)
	f, err := os.OpenFile(filepath.Join(dir, "halos.yaml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(vendorAdminYAML); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeGitHub serves the two Copilot endpoints; cli is the billing summary's
// Copilot CLI policy and excl the org content exclusion "*" list.
func fakeGitHub(t *testing.T, cli, excl string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /orgs/acme/copilot/billing":
			_, _ = io.WriteString(w, `{"cli":"`+cli+`"}`)
		case "GET /orgs/acme/copilot/content_exclusion":
			_, _ = io.WriteString(w, `{"*":`+excl+`}`)
		case "PUT /orgs/acme/copilot/content_exclusion":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			puts = append(puts, string(b))
			mu.Unlock()
			_, _ = io.WriteString(w, `{"message":"ok"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &puts
}

const inSync = `["/.env","/.env.*","/secrets/**"]`

func TestAdminPlanExitCodes(t *testing.T) {
	dir := adminPolicy(t)
	tok := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tok, []byte("ghp_cli_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sync, _ := fakeGitHub(t, "disabled", inSync)
	code, out, errb := halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-token-file", tok, "--copilot-base-url", sync.URL, "--output", "json")
	if code != 0 {
		t.Fatalf("in sync: exit %d\n%s\n%s", code, out, errb)
	}
	var rep struct {
		Ring    string
		Vendors []struct {
			Vendor  string
			Read    bool
			Changes []any
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Ring != "ring3-ga" || len(rep.Vendors) != 4 {
		t.Fatalf("report %+v", rep)
	}

	drift, _ := fakeGitHub(t, "enabled", `["/.env"]`)
	code, out, _ = halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-token-file", tok, "--copilot-base-url", drift.URL)
	if code != exitValidation || !strings.Contains(out, "2 drifted") {
		t.Fatalf("drift: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "ghp_cli_secret") {
		t.Fatal("token printed")
	}

	t.Setenv("HALO_ADMIN_COPILOT_TOKEN", "")
	code, _, errb = halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-base-url", drift.URL)
	if code != exitError || !strings.Contains(errb, "no credential") {
		t.Fatalf("no credential: exit %d %s", code, errb)
	}
	// L6: offline compares nothing, so it is neither in sync nor drift
	code, out, errb = halo(t, "admin", "plan", "--policy-dir", dir, "--offline")
	if code != exitUnchecked || !strings.Contains(out, "not checked (offline)") {
		t.Fatalf("offline: exit %d %s\n%s", code, errb, out)
	}

	// L6: manual vendors are never reported as in sync
	code, out, _ = halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-token-file", tok, "--copilot-base-url", sync.URL)
	if code != 0 || strings.Count(out, "not checked (manual)") != 3 || strings.Count(out, "in sync") != 1 {
		t.Fatalf("manual vendors: exit %d\n%s", code, out)
	}

	// L3: a credential never goes to a plain-http, non-loopback API
	code, _, errb = halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-token-file", tok, "--copilot-base-url", "http://api.github.example")
	if code != exitError || !strings.Contains(errb, "must be https") {
		t.Fatalf("http base URL: exit %d %s", code, errb)
	}
}

// L4: the apply record is truthful when the write fails.
func TestAdminApplyRecordOnFailure(t *testing.T) {
	dir := adminPolicy(t)
	t.Setenv("HALO_ADMIN_COPILOT_TOKEN", "t")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /orgs/acme/copilot/billing":
			_, _ = io.WriteString(w, `{"cli":"disabled"}`)
		case "GET /orgs/acme/copilot/content_exclusion":
			_, _ = io.WriteString(w, `{"*":["/.env"]}`)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	code, out, errb := halo(t, "admin", "apply", "--policy-dir", dir, "--copilot-base-url", srv.URL, "--yes", "--output", "json")
	var rec adminRecord
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, errb)
	}
	if code != exitError || len(rec.Applied) != 1 || rec.Applied[0].OK || !strings.Contains(rec.Applied[0].Error, "HTTP 500") {
		t.Fatalf("exit %d record %+v", code, rec)
	}
}

// L1/L2: identifiers are validated, and console values cannot inject
// terminal escapes or Markdown into plan output and STEPS.md.
func TestAdminOutputSanitized(t *testing.T) {
	dir := adminPolicy(t)
	tok := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tok, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	evil, _ := fakeGitHub(t, "disabled", `["/.env","/.env.*","/secrets/**","/x\u001b[2J|`+"`"+`\u202e"]`)
	code, out, _ := halo(t, "admin", "plan", "--policy-dir", dir, "--copilot-token-file", tok, "--copilot-base-url", evil.URL)
	if code != exitValidation || strings.ContainsAny(out, "\x1b\u202e") {
		t.Fatalf("exit %d, escape reached the terminal: %q", code, out)
	}
	if got := md("a|b`c\x1b[0m\u202ed"); got != `a\|b'c[0md` {
		t.Fatalf("md = %q", got)
	}

	bad := copyDir(t, dir)
	hp := filepath.Join(bad, "halos.yaml")
	b, err := os.ReadFile(hp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hp, []byte(strings.Replace(string(b), "  claude: {}\n", "  claude:\n    org: \"../x\"\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errb := halo(t, "admin", "export", "--policy-dir", bad, "--out", t.TempDir()); code != exitValidation {
		t.Fatalf("org ../x accepted: exit %d %s", code, errb)
	}
}

func TestAdminApply(t *testing.T) {
	dir := adminPolicy(t)
	t.Setenv("HALO_ADMIN_COPILOT_TOKEN", "ghp_env_secret")
	srv, puts := fakeGitHub(t, "disabled", `["/.env"]`)

	code, _, errb := halo(t, "admin", "apply", "--policy-dir", dir, "--copilot-base-url", srv.URL)
	if code != exitError || !strings.Contains(errb, "not confirmed") || len(*puts) != 0 {
		t.Fatalf("unconfirmed apply: exit %d puts %v\n%s", code, *puts, errb)
	}
	code, out, errb := halo(t, "admin", "apply", "--policy-dir", dir, "--copilot-base-url", srv.URL, "--yes", "--output", "json")
	if code != 0 || len(*puts) != 1 || (*puts)[0] != `{"*":["/.env","/.env.*","/secrets/**"]}` {
		t.Fatalf("apply: exit %d puts %v\n%s\n%s", code, *puts, out, errb)
	}
	var rec adminRecord
	if err := json.Unmarshal([]byte(out), &rec); err != nil || len(rec.Applied) != 1 || !rec.Applied[0].OK || rec.Actor == "" {
		t.Fatalf("apply record %+v %v", rec, err)
	}

	loose, puts2 := fakeGitHub(t, "disabled", `["/.env","/.env.*","/secrets/**","/extra"]`)
	code, _, errb = halo(t, "admin", "apply", "--policy-dir", dir, "--copilot-base-url", loose.URL, "--yes")
	if code != exitError || !strings.Contains(errb, "loosen") || len(*puts2) != 0 {
		t.Fatalf("loosening apply: exit %d puts %v\n%s", code, *puts2, errb)
	}
}

func TestAdminExport(t *testing.T) {
	dir := adminPolicy(t)
	out := filepath.Join(t.TempDir(), "va")
	if code, o, e := halo(t, "admin", "export", "--policy-dir", dir, "--out", out); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o, e)
	}
	for _, f := range []string{"claude/claude-managed-settings.json", "claude/STEPS.md", "codex/codex-requirements.toml", "codex/codex-config.toml", "cursor/cursor-models.md", "copilot/STEPS.md"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil || len(b) == 0 {
			t.Errorf("%s: %v", f, err)
		}
		if strings.Contains(string(b), "bypassPermissions") || strings.Contains(string(b), "danger-full-access") {
			t.Errorf("%s emits a permission bypass", f)
		}
	}
}
