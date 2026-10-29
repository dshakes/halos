package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestROIIngestFileAndReport(t *testing.T) {
	dir := t.TempDir()
	var roster, prs strings.Builder
	roster.WriteString("login,subject\n")
	prs.WriteString("repo,number,author,opened_at,merged_at,review_rounds,additions,deletions\n")
	for i := range 200 {
		fmt.Fprintf(&roster, "gh%d,dev%d@acme.com\n", i, i)
		for j := range 2 {
			fmt.Fprintf(&prs, "acme/api,%d,gh%d,2026-09-%02dT10:00:00Z,2026-09-%02dT18:00:00Z,1,10,2\n", 2*i+j+1, i, 1+j*10, 1+j*10)
		}
	}
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rosterPath, csvPath, store := write("roster.csv", roster.String()), write("prs.csv", prs.String()), filepath.Join(dir, "store.jsonl")

	code, out, errOut := halo(t, "roi", "ingest", "file", csvPath, "--store", store)
	if code != 0 || !strings.Contains(out, "imported 400 records") {
		t.Fatalf("ingest exit %d: %s %s", code, out, errOut)
	}
	code, out, errOut = halo(t, "roi", "report", "--policy-dir", example, "--experiment", "claude-cli-2.1.3xx-ab",
		"--identities", rosterPath, "--store", store, "--since", "2026-09-01", "--until", "2026-10-01")
	if code != 0 || !strings.Contains(out, "randomized") || !strings.Contains(out, "pr_cycle_time_hours") || !strings.Contains(out, "SRM:") {
		t.Fatalf("report exit %d:\n%s\n%s", code, out, errOut)
	}
	code, out, _ = halo(t, "--output", "json", "roi", "report", "--policy-dir", example, "--rings", "ring3-ga,ring1-canary",
		"--identities", rosterPath, "--store", store, "--since", "2026-09-01", "--until", "2026-10-01")
	var rep struct {
		Design  string `json:"design"`
		Effects []struct {
			Kind string `json:"kind"`
		} `json:"effects"`
	}
	if err := json.Unmarshal([]byte(out), &rep); code != 0 || err != nil || rep.Design != "observational" || len(rep.Effects) == 0 || rep.Effects[0].Kind != "association" {
		t.Fatalf("json exit %d err %v: %s", code, err, out)
	}
	for name, args := range map[string][]string{
		"no store":           {"roi", "report", "--policy-dir", example, "--experiment", "claude-cli-2.1.3xx-ab", "--identities", rosterPath, "--since", "2026-09-01"},
		"no since":           {"roi", "report", "--policy-dir", example, "--experiment", "claude-cli-2.1.3xx-ab", "--identities", rosterPath, "--store", store},
		"unknown experiment": {"roi", "report", "--policy-dir", example, "--experiment", "nope", "--identities", rosterPath, "--store", store, "--since", "2026-09-01"},
		"bad file":           {"roi", "ingest", "file", rosterPath, "--store", store},
		"github no token":    {"roi", "ingest", "github", "--repo", "a/b", "--since", "2026-09-01", "--store", store, "--token-env", "HALO_TEST_UNSET_TOKEN"},
	} {
		if code, _, _ := halo(t, args...); code == 0 {
			t.Errorf("%s: want failure", name)
		}
	}
}

func TestROIIngestGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_cli_test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"repository":{"pullRequests":{"pageInfo":{"hasNextPage":false},"nodes":[` +
			`{"number":1,"title":"t","body":"","createdAt":"2026-09-02T00:00:00Z","mergedAt":"2026-09-02T05:00:00Z","additions":1,"deletions":1,` +
			`"author":{"__typename":"User","login":"Alice"},"labels":{"nodes":[]},"changesRequested":{"totalCount":0},"approved":{"totalCount":1}}]}}}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HALO_GITHUB_TOKEN", "ghp_cli_test")
	store := filepath.Join(t.TempDir(), "s.jsonl")
	code, out, errOut := halo(t, "roi", "ingest", "github", "--repo", "acme/api", "--since", "2026-09-01", "--graphql-url", srv.URL, "--store", store)
	if code != 0 || !strings.Contains(out, "imported 1 pull requests") {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	b, err := os.ReadFile(store)
	if err != nil || !strings.Contains(string(b), `"author":"alice"`) || strings.Contains(string(b), "ghp_cli_test") {
		t.Fatalf("store %s %v", b, err)
	}
}
