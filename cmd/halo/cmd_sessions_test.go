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
	"time"

	"github.com/dshakes/halos/internal/ledger"
	"github.com/dshakes/halos/internal/server"
)

// fakeLedgerServer stands in for halo-server's ledger API: it stores what it
// is posted (resolving dev@acme.example) and lists it back.
func fakeLedgerServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var (
		mu     sync.Mutex
		bodies []string
		stored []ledger.Stored
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("halo_session"); err != nil || c.Value != "sess" {
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/sessions":
			b, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(b))
			var in server.SessionsIngest
			if err := json.Unmarshal(b, &in); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ledger.Join(in.Records, func(v string) (string, bool) { return v, v == "dev@acme.example" })
			for i, rec := range in.Records {
				stored = append(stored, ledger.Stored{Record: rec, AuditSeq: uint64(len(stored) + i + 1), AuditHash: "h"})
			}
			_ = json.NewEncoder(w).Encode(in)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/sessions":
			if r.URL.Query().Get("limit") == "" {
				http.Error(w, "no limit", http.StatusBadRequest)
			}
			_ = json.NewEncoder(w).Encode(server.SessionsResponse{Sessions: stored, Total: len(stored), Verified: r.URL.Query().Get("user") != "tampered", VerifyError: "seq 2: entry was modified"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func TestSessionsImportListExport(t *testing.T) {
	srv, bodies := fakeLedgerServer(t)
	t.Setenv("HALO_SESSION", "sess")
	dir := t.TempDir()
	file := filepath.Join(dir, "s.jsonl")
	line := `{"sessionId":"cur-1","harness":"cursor","who":{"vendorUser":"dev@acme.example"},"tools":["edit_file"],"files":["/home/dev/secret-roadmap.md"],"start":"` +
		time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) + `","outcome":"completed"}`
	if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// dry run: normalized and redacted, nothing sent
	code, out, errs := halo(t, "sessions", "import", "--source", "jsonl", "--file", file, "--dry-run")
	if code != 0 || !strings.Contains(out, "cursor") || strings.Contains(out, "secret-roadmap") || !strings.Contains(out, "dry run") || len(*bodies) != 0 {
		t.Fatalf("dry run: %d %q %q", code, out, errs)
	}
	// store: the path never leaves the machine
	code, out, errs = halo(t, "sessions", "import", "--source", "jsonl", "--file", file, "--server", srv.URL)
	if code != 0 || !strings.Contains(out, "stored") || len(*bodies) != 1 || strings.Contains((*bodies)[0], "secret-roadmap") ||
		!strings.Contains((*bodies)[0], `"filesTouched":1`) {
		t.Fatalf("import: %d %q %q %v", code, out, errs, *bodies)
	}
	// a prompt field in the file fails the import before anything is sent
	bad := filepath.Join(dir, "bad.jsonl")
	if err := os.WriteFile(bad, []byte(`{"sessionId":"x","harness":"cursor","start":"2026-10-26T12:00:00Z","prompt":"draft the memo"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := halo(t, "sessions", "import", "--source", "jsonl", "--file", bad, "--server", srv.URL, "--since", "30d"); code != 1 || !strings.Contains(errs, "prompt") || len(*bodies) != 1 {
		t.Fatalf("prompt field: %d %q", code, errs)
	}

	code, out, _ = halo(t, "sessions", "list", "--server", srv.URL, "--since", "7d")
	if code != 0 || !strings.Contains(out, "dev@acme.example") || !strings.Contains(out, "1 of 1 sessions") {
		t.Fatalf("list: %d %q", code, out)
	}
	code, out, _ = halo(t, "--output", "json", "sessions", "list", "--server", srv.URL)
	var lr server.SessionsResponse
	if code != 0 || json.Unmarshal([]byte(out), &lr) != nil || len(lr.Sessions) != 1 || lr.Sessions[0].Who.User != "dev@acme.example" {
		t.Fatalf("list json: %d %q", code, out)
	}
	exp := filepath.Join(dir, "out.jsonl")
	if code, _, errs := halo(t, "sessions", "export", "--server", srv.URL, "--out", exp); code != 0 {
		t.Fatalf("export: %d %q", code, errs)
	}
	b, err := os.ReadFile(exp)
	if err != nil {
		t.Fatal(err)
	}
	var st ledger.Stored
	if lines := strings.Split(strings.TrimSpace(string(b)), "\n"); len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &st) != nil || st.AuditSeq != 1 || st.SessionID != "cur-1" {
		t.Fatalf("export file: %q", b)
	}
	// an unverified chain is loud and fails export
	if code, _, errs := halo(t, "sessions", "export", "--server", srv.URL, "--user", "tampered"); code != 1 || !strings.Contains(errs, "does not verify") {
		t.Fatalf("export of an unverified chain: %d %q", code, errs)
	}
}

func TestSessionsImportErrors(t *testing.T) {
	t.Setenv("HALO_SESSION", "")
	t.Setenv("HALO_SERVER", "")
	t.Setenv("HALO_SESSIONS_ANTHROPIC_TOKEN", "")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no server":            {[]string{"--source", "jsonl", "--file", "x"}, "HALO_SESSION"},
		"no source":            {[]string{"--dry-run"}, "--source"},
		"unknown source":       {[]string{"--dry-run", "--source", "rumour"}, "unknown --source"},
		"gateway without CH":   {[]string{"--dry-run", "--source", "gateway"}, "--clickhouse"},
		"anthropic, no key":    {[]string{"--dry-run", "--source", "anthropic"}, "HALO_SESSIONS_ANTHROPIC_TOKEN"},
		"github, no slug":      {[]string{"--dry-run", "--source", "github"}, "--github-enterprise"},
		"hash without salt":    {[]string{"--dry-run", "--source", "jsonl", "--file", os.DevNull, "--paths", "hash"}, "salt"},
		"bad window":           {[]string{"--dry-run", "--source", "jsonl", "--since", "tomorrow"}, "--since"},
		"plain http to remote": {[]string{"--source", "anthropic", "--anthropic-base-url", "http://api.example", "--dry-run"}, "HALO_SESSIONS_ANTHROPIC_TOKEN"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, errs := halo(t, append([]string{"sessions", "import"}, tc.args...)...)
			if code != 1 || !strings.Contains(errs, tc.want) {
				t.Fatalf("%d %q, want %q", code, errs, tc.want)
			}
		})
	}
}

func TestSessionsVendorKeyNeverPrinted(t *testing.T) {
	const key = "fake-ledger-key-9f8e7d6c5b4a" // allowlist secret: test placeholder
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad key "+key, http.StatusUnauthorized)
	}))
	defer vendor.Close()
	kf := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(kf, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errs := halo(t, "sessions", "import", "--dry-run", "--source", "anthropic", "--anthropic-token-file", kf, "--anthropic-base-url", vendor.URL)
	if code != 1 || strings.Contains(out+errs, key) || !strings.Contains(errs, "401") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	code, _, errs = halo(t, "sessions", "import", "--dry-run", "--source", "anthropic", "--anthropic-token-file", kf, "--anthropic-base-url", "http://api.example")
	if code != 1 || !strings.Contains(errs, "https") {
		t.Fatalf("plain-http base URL: %d %q", code, errs)
	}
}
