package promote

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const testToken = "s3cr3t-token-value"

// recorded is one request the fake forge saw.
type recorded struct {
	Method, URI, Body, Auth string
}

// fakeForge is an httptest server that records every request and answers via h.
type fakeForge struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []recorded
}

func newFakeForge(t *testing.T, h http.HandlerFunc) *fakeForge {
	t.Helper()
	f := &fakeForge{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("PRIVATE-TOKEN")
		if auth == "" {
			auth = r.Header.Get("Authorization")
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, recorded{r.Method, r.RequestURI, string(b), auth})
		f.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		h(w, r)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeForge) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.reqs...)
}

// assertNeverMerges fails if any recorded request could merge, enable
// auto-merge, or approve: invariant 5, a human merges.
func (f *fakeForge) assertNeverMerges(t *testing.T) {
	t.Helper()
	for _, r := range f.requests() {
		path := r.URI
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		if r.Method == "PUT" || r.Method == "DELETE" || r.Method == "PATCH" {
			t.Errorf("mutating call %s %s", r.Method, r.URI)
		}
		for _, seg := range strings.Split(path, "/") {
			if seg == "merge" || seg == "approve" || seg == "approval" || seg == "graphql" || seg == "auto_merge" {
				t.Errorf("merge-like endpoint called: %s %s", r.Method, r.URI)
			}
		}
		for _, bad := range []string{"merge_when_pipeline_succeeds", "auto_merge", "automerge", "enable_auto_merge", "merge_commit", "squash", "should_remove_source_branch", "skip_ci"} {
			if strings.Contains(strings.ToLower(r.Body), bad) {
				t.Errorf("request body carries %q: %s %s %s", bad, r.Method, r.URI, r.Body)
			}
		}
	}
}

// forgeExec answers `git remote get-url origin` with remote and runs every
// other command for real (push goes to the repo's real bare origin).
func forgeExec(remote string, gh *[]string) RunFunc {
	return func(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
		if name == "git" && len(args) >= 3 && args[0] == "remote" && args[1] == "get-url" {
			if remote == "" {
				return nil, fmt.Errorf("no such remote")
			}
			return []byte(remote + "\n"), nil
		}
		if name == "gh" {
			*gh = append(*gh, strings.Join(args, " "))
			return []byte("https://github.com/o/r/pull/9\n"), nil
		}
		return Run(ctx, dir, name, args...)
	}
}

func tokenEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func testReq(dir string) PRRequest {
	return PRRequest{RepoDir: dir, Base: "main", Branch: "halos/promote-x", Title: "Promote x", Body: "body <!-- halos:k=1 -->",
		Files: map[string][]byte{"ring.yaml": []byte(strings.Replace(ringYAML, "sha256:old", "sha256:new", 1))}}
}

func TestParseRemote(t *testing.T) {
	for _, tc := range []struct {
		in           string
		host, path   string
		scheme, name string
		err          bool
	}{
		{"https://github.com/o/r.git", "github.com", "o/r", "https", "github.com", false},
		{"https://user:tok@gitlab.example.com:8443/group/sub/repo\n", "gitlab.example.com:8443", "group/sub/repo", "https", "gitlab.example.com", false},
		{"git@gitlab.com:group/sub/repo.git", "gitlab.com", "group/sub/repo", "ssh", "gitlab.com", false},
		{"ssh://git@gitlab.corp:2222/a/b.git", "gitlab.corp", "a/b", "ssh", "gitlab.corp", false},
		{"http://GitLab.Local/a/b/", "gitlab.local", "a/b", "http", "gitlab.local", false},
		{"/tmp/some/local/repo", "", "", "", "", true},
		{"https://gitlab.com/", "", "", "", "", true},
		{"", "", "", "", "", true},
	} {
		r, err := ParseRemote(tc.in)
		if (err != nil) != tc.err {
			t.Errorf("%q: err=%v", tc.in, err)
			continue
		}
		if err == nil && (r.Host != tc.host || r.Path != tc.path || r.Scheme != tc.scheme || r.Hostname != tc.name) {
			t.Errorf("%q: got %+v", tc.in, r)
		}
		if err != nil && strings.Contains(err.Error(), "tok@") {
			t.Errorf("error leaks userinfo: %v", err)
		}
	}
}

func TestDetectAndResolve(t *testing.T) {
	for _, tc := range []struct {
		name, kind, remote, want string
	}{
		{"github.com stays gh", "", "https://github.com/o/r.git", ForgeGH},
		{"ghes stays gh", "", "git@ghe.corp.example:o/r.git", ForgeGH},
		{"unknown host stays gh", "", "https://git.example.com/o/r", ForgeGH},
		{"gitlab.com", "", "git@gitlab.com:g/r.git", ForgeGitLab},
		{"self-managed gitlab host", "", "https://gitlab.corp.example/g/s/r", ForgeGitLab},
		{"auto spelled out", "auto", "https://gitlab.corp.example/g/r", ForgeGitLab},
		{"explicit github beats host", ForgeGitHub, "https://gitlab.com/g/r", ForgeGitHub},
		{"explicit gitlab beats host", ForgeGitLab, "https://github.com/o/r", ForgeGitLab},
		{"explicit gh skips remote", ForgeGH, "https://gitlab.com/g/r", ForgeGH},
		{"auto with unreadable remote falls back to gh", "", "", ForgeGH},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ParseForgeKind(tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			var gh []string
			f := &ForgeOpener{Kind: k, Exec: forgeExec(tc.remote, &gh)}
			got, _, err := f.resolve(context.Background(), t.TempDir())
			if err != nil || got != tc.want {
				t.Fatalf("resolve = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	// An explicit REST forge with no readable remote is an error, not a guess.
	f := &ForgeOpener{Kind: ForgeGitLab, Exec: forgeExec("", new([]string))}
	if _, _, err := f.resolve(context.Background(), t.TempDir()); err == nil {
		t.Fatal("want error for gitlab without a remote")
	}
}

func TestNewForgeValidation(t *testing.T) {
	for _, tc := range []struct {
		cfg ForgeConfig
		err string
	}{
		{ForgeConfig{}, ""},
		{ForgeConfig{Kind: "gitlab", BaseURL: "https://gitlab.corp/api/v4"}, ""},
		{ForgeConfig{Kind: "github", BaseURL: "http://127.0.0.1:1/api/v3"}, ""},
		{ForgeConfig{Kind: "bitbucket"}, "unknown forge"},
		{ForgeConfig{Kind: "gitlab", BaseURL: "http://gitlab.corp/api/v4"}, "loopback"},
		{ForgeConfig{Kind: "gitlab", BaseURL: "https://u:p@gitlab.corp/api/v4"}, "credentials"},
		{ForgeConfig{Kind: "gitlab", BaseURL: "ftp://x"}, "https"},
		{ForgeConfig{Kind: "gh", BaseURL: "https://x"}, "gh CLI"},
	} {
		_, err := NewForge(tc.cfg)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%+v: err=%v want %q", tc.cfg, err, tc.err)
		}
	}
}

func TestForgeDerivedBaseURL(t *testing.T) {
	for _, tc := range []struct {
		kind, remote, want string
	}{
		{ForgeGitLab, "git@gitlab.com:g/r.git", "https://gitlab.com/api/v4"},
		{ForgeGitLab, "https://gitlab.corp.example:8443/g/s/r", "https://gitlab.corp.example:8443/api/v4"},
		{ForgeGitLab, "ssh://git@gitlab.corp.example:2222/g/r", "https://gitlab.corp.example/api/v4"},
		{ForgeGitHub, "https://github.com/o/r", "https://api.github.com"},
		{ForgeGitHub, "git@ghe.corp.example:o/r.git", "https://ghe.corp.example/api/v3"},
	} {
		rem, err := ParseRemote(tc.remote)
		if err != nil {
			t.Fatal(err)
		}
		a, err := (&ForgeOpener{Getenv: tokenEnv(map[string]string{"GITLAB_TOKEN": "x", "GITHUB_TOKEN": "x"})}).api(tc.kind, rem)
		if err != nil {
			t.Fatal(err)
		}
		var got string
		switch v := a.(type) {
		case *gitlabAPI:
			got = v.c.base
		case *githubAPI:
			got = v.c.base
		}
		if got != tc.want {
			t.Errorf("%s %s: base %q want %q", tc.kind, tc.remote, got, tc.want)
		}
	}
	rem, _ := ParseRemote("https://github.com/o/r/extra")
	if _, err := (&ForgeOpener{Getenv: tokenEnv(map[string]string{"GITHUB_TOKEN": "x"})}).api(ForgeGitHub, rem); err == nil {
		t.Error("github path with 3 segments must be rejected")
	}
}

// gitlabHandler is a fake GitLab v4 project API for project path
// group/sub/repo. listPages are returned for the merge request list, one per
// page, with X-Next-Page.
func gitlabHandler(t *testing.T, created *map[string]any, listPages [][]gitlabMR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const proj = "/api/v4/projects/group%2Fsub%2Frepo"
		path := strings.SplitN(r.RequestURI, "?", 2)[0]
		switch {
		case r.Method == "GET" && path == proj:
			jsonOut(w, 200, map[string]string{"default_branch": "trunk"})
		case r.Method == "GET" && path == "/api/v4/users":
			if r.URL.Query().Get("username") == "ghost" {
				jsonOut(w, 200, []any{})
				return
			}
			jsonOut(w, 200, []map[string]int{{"id": 77}})
		case r.Method == "POST" && path == proj+"/merge_requests":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			if created != nil {
				*created = m
			}
			jsonOut(w, 201, map[string]any{"web_url": "https://gitlab.example.com/group/sub/repo/-/merge_requests/5", "iid": 5})
		case r.Method == "GET" && path == proj+"/merge_requests":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 || page > len(listPages) {
				jsonOut(w, 200, []any{})
				return
			}
			if page < len(listPages) {
				w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
			}
			jsonOut(w, 200, listPages[page-1])
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.RequestURI)
			http.NotFound(w, r)
		}
	}
}

func gitlabForge(srv *fakeForge, gh *[]string, env map[string]string) *ForgeOpener {
	return &ForgeOpener{Kind: ForgeGitLab, BaseURL: srv.URL + "/api/v4",
		Exec:   forgeExec("git@gitlab.example.com:group/sub/repo.git", gh),
		Getenv: tokenEnv(env)}
}

func TestGitLabOpenPR(t *testing.T) {
	var created map[string]any
	srv := newFakeForge(t, gitlabHandler(t, &created, nil))
	dir := gitRepo(t)
	var gh []string
	f := gitlabForge(srv, &gh, map[string]string{"GITLAB_TOKEN": testToken})
	req := testReq(dir)
	req.Labels = []string{"halos", "promotion"}
	req.Reviewers = []string{"alice"}
	url, err := f.OpenPR(context.Background(), req)
	if err != nil || url != "https://gitlab.example.com/group/sub/repo/-/merge_requests/5" {
		t.Fatalf("OpenPR = %q, %v", url, err)
	}
	if len(gh) != 0 {
		t.Fatalf("gh must not be called: %v", gh)
	}
	if created["target_branch"] != "main" || created["title"] != "Promote x" || created["description"] != req.Body ||
		!strings.HasPrefix(created["source_branch"].(string), "halos/promote-x") ||
		created["labels"] != "halos,promotion" || fmt.Sprint(created["reviewer_ids"]) != "[77]" {
		t.Fatalf("create body: %v", created)
	}
	// The nested group path stays one %2F-encoded segment.
	var posted bool
	for _, r := range srv.requests() {
		if r.Method == "POST" {
			posted = true
			if r.URI != "/api/v4/projects/group%2Fsub%2Frepo/merge_requests" {
				t.Errorf("project path encoding: %s", r.URI)
			}
		}
		if r.Auth != testToken {
			t.Errorf("PRIVATE-TOKEN header: %q", r.Auth)
		}
	}
	if !posted {
		t.Fatal("no create call")
	}
	srv.assertNeverMerges(t)
	// The branch was really pushed by git, not the API.
	if remote, _ := Run(context.Background(), dir, "git", "ls-remote", "--heads", "origin"); !strings.Contains(string(remote), "halos/promote-x-") {
		t.Fatalf("branch not pushed: %s", remote)
	}
}

func TestGitLabDefaultBranchAndMissingReviewer(t *testing.T) {
	var created map[string]any
	srv := newFakeForge(t, gitlabHandler(t, &created, nil))
	var gh []string
	f := gitlabForge(srv, &gh, map[string]string{"GITLAB_TOKEN": testToken})
	req := testReq(gitRepo(t))
	req.Base = ""
	if _, err := f.OpenPR(context.Background(), req); err != nil || created["target_branch"] != "trunk" {
		t.Fatalf("default branch: %v %v", err, created)
	}
	req.Reviewers = []string{"ghost"}
	if _, err := f.OpenPR(context.Background(), req); err == nil || !strings.Contains(err.Error(), `reviewer "ghost"`) {
		t.Fatalf("unknown reviewer: %v", err)
	}
	srv.assertNeverMerges(t)
}

func TestGitLabFindPagination(t *testing.T) {
	const marker = "<!-- halos:intent=abc -->"
	mr := func(n int, desc string) gitlabMR {
		return gitlabMR{WebURL: fmt.Sprintf("https://gl/mr/%d", n), Description: desc}
	}
	pages := [][]gitlabMR{
		{mr(1, "other"), mr(2, "halos:intent=abc but not the marker")},
		{mr(3, "x"), mr(4, "Body\n"+marker)},
		{mr(5, marker)},
	}
	srv := newFakeForge(t, gitlabHandler(t, nil, pages))
	f := gitlabForge(srv, new([]string), map[string]string{"GITLAB_TOKEN": testToken})
	url, found, err := f.FindPR(context.Background(), t.TempDir(), marker)
	if err != nil || !found || url != "https://gl/mr/4" {
		t.Fatalf("FindPR = %q %v %v", url, found, err)
	}
	var lists int
	for _, r := range srv.requests() {
		if r.Method == "GET" {
			lists++
			if !strings.Contains(r.URI, "search=halos%3Aintent%3Dabc") || !strings.Contains(r.URI, "state=all") {
				t.Errorf("list query: %s", r.URI)
			}
		}
	}
	if lists != 2 {
		t.Errorf("want 2 list pages, got %d", lists)
	}
	// Absent everywhere: scans all pages, reports not found, no error.
	if url, found, err := f.FindPR(context.Background(), t.TempDir(), "<!-- halos:intent=zzz -->"); err != nil || found || url != "" {
		t.Fatalf("absent: %q %v %v", url, found, err)
	}
	srv.assertNeverMerges(t)
}

func TestGitLabFindStopsAtPageCap(t *testing.T) {
	pages := make([][]gitlabMR, forgeMaxPages+5)
	srv := newFakeForge(t, gitlabHandler(t, nil, pages))
	f := gitlabForge(srv, new([]string), map[string]string{"GITLAB_TOKEN": testToken})
	if _, found, err := f.FindPR(context.Background(), t.TempDir(), "<!-- m -->"); err != nil || found {
		t.Fatalf("%v %v", found, err)
	}
	if n := len(srv.requests()); n != forgeMaxPages {
		t.Fatalf("requests = %d, want cap %d", n, forgeMaxPages)
	}
}

func githubHandler(t *testing.T, created *map[string]any, listPages [][]githubPR) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const repo = "/api/v3/repos/acme/policy"
		path := strings.SplitN(r.RequestURI, "?", 2)[0]
		switch {
		case r.Method == "GET" && path == repo:
			jsonOut(w, 200, map[string]string{"default_branch": "trunk"})
		case r.Method == "POST" && path == repo+"/pulls":
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			if created != nil {
				*created = m
			}
			jsonOut(w, 201, map[string]any{"html_url": "https://ghe.example.com/acme/policy/pull/12", "number": 12})
		case r.Method == "POST" && path == repo+"/issues/12/labels":
			jsonOut(w, 200, []any{})
		case r.Method == "POST" && path == repo+"/pulls/12/requested_reviewers":
			jsonOut(w, 201, map[string]any{})
		case r.Method == "GET" && path == repo+"/pulls":
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 || page > len(listPages) {
				jsonOut(w, 200, []any{})
				return
			}
			if page < len(listPages) {
				w.Header().Add("Link", fmt.Sprintf(`<%s%s?state=all&page=%d>; rel="next", <%s%s?page=9>; rel="last"`, "http://x", repo+"/pulls", page+1, "http://x", repo+"/pulls"))
			}
			jsonOut(w, 200, listPages[page-1])
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.RequestURI)
			http.NotFound(w, r)
		}
	}
}

func githubForge(srv *fakeForge, gh *[]string, env map[string]string) *ForgeOpener {
	return &ForgeOpener{Kind: ForgeGitHub, BaseURL: srv.URL + "/api/v3",
		Exec:   forgeExec("git@ghe.example.com:acme/policy.git", gh),
		Getenv: tokenEnv(env)}
}

func TestGitHubOpenAndFind(t *testing.T) {
	const marker = "<!-- halos:intent=abc -->"
	var created map[string]any
	pages := [][]githubPR{{{HTMLURL: "https://ghe/pull/1", Body: "no"}}, {{HTMLURL: "https://ghe/pull/2", Body: "yes " + marker}}}
	srv := newFakeForge(t, githubHandler(t, &created, pages))
	var gh []string
	// GH_TOKEN is accepted when GITHUB_TOKEN is unset.
	f := githubForge(srv, &gh, map[string]string{"GH_TOKEN": testToken})
	req := testReq(gitRepo(t))
	req.Base = ""
	req.Labels = []string{"halos"}
	req.Reviewers = []string{"alice", "bob"}
	url, err := f.OpenPR(context.Background(), req)
	if err != nil || url != "https://ghe.example.com/acme/policy/pull/12" {
		t.Fatalf("OpenPR = %q %v", url, err)
	}
	if created["base"] != "trunk" || created["title"] != "Promote x" || created["body"] != req.Body ||
		!strings.HasPrefix(created["head"].(string), "halos/promote-x") {
		t.Fatalf("create body: %v", created)
	}
	if len(gh) != 0 {
		t.Fatalf("gh must not be called: %v", gh)
	}
	url, found, err := f.FindPR(context.Background(), t.TempDir(), marker)
	if err != nil || !found || url != "https://ghe/pull/2" {
		t.Fatalf("FindPR = %q %v %v", url, found, err)
	}
	for _, r := range srv.requests() {
		if r.Auth != "Bearer "+testToken {
			t.Errorf("auth header %q on %s", r.Auth, r.URI)
		}
	}
	srv.assertNeverMerges(t)
}

func TestForgeStatusErrors(t *testing.T) {
	for _, kind := range []string{ForgeGitLab, ForgeGitHub} {
		for _, tc := range []struct {
			status int
			body   string
			want   []string
		}{
			{401, `{"message":"401 Unauthorized"}`, []string{"HTTP 401", "rejected"}},
			{403, `{"message":"403 Forbidden"}`, []string{"HTTP 403", map[string]string{ForgeGitLab: "api scope", ForgeGitHub: "repo scope"}[kind]}},
			{404, `{"message":"404 Project Not Found"}`, []string{"HTTP 404", "not found"}},
			{409, `{"message":"Another open merge request already exists"}`, []string{"HTTP 409", "Another open merge request already exists"}},
			{422, `{"message":"Validation Failed","errors":[{"message":"A pull request already exists"}]}`, []string{"HTTP 422", "Validation Failed"}},
			{429, `{"message":"slow down"}`, []string{"HTTP 429", "rate limited"}},
			{500, `<html>boom</html>`, []string{"HTTP 500", "boom"}},
		} {
			t.Run(fmt.Sprintf("%s/%d", kind, tc.status), func(t *testing.T) {
				srv := newFakeForge(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "POST" {
						w.WriteHeader(tc.status)
						_, _ = io.WriteString(w, tc.body)
						return
					}
					jsonOut(w, 200, []any{})
				})
				var gh []string
				env := map[string]string{"GITLAB_TOKEN": testToken, "GITHUB_TOKEN": testToken}
				f := &ForgeOpener{Kind: kind, BaseURL: srv.URL, Getenv: tokenEnv(env),
					Exec: forgeExec("git@host.example:acme/policy.git", &gh)}
				_, err := f.OpenPR(context.Background(), testReq(gitRepo(t)))
				if err == nil {
					t.Fatal("want error")
				}
				for _, w := range tc.want {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error %q lacks %q", err, w)
					}
				}
				if strings.Contains(err.Error(), testToken) {
					t.Errorf("error leaks the token: %v", err)
				}
			})
		}
	}
}

func TestForgeListErrors(t *testing.T) {
	srv := newFakeForge(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `{"message":"insufficient_scope"}`)
	})
	f := gitlabForge(srv, new([]string), map[string]string{"GITLAB_TOKEN": testToken})
	_, _, err := f.FindPR(context.Background(), t.TempDir(), "<!-- m -->")
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "insufficient_scope") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestForgeMissingTokenNamesVariable(t *testing.T) {
	for _, tc := range []struct {
		kind string
		want []string
	}{
		{ForgeGitLab, []string{"GITLAB_TOKEN"}},
		{ForgeGitHub, []string{"GITHUB_TOKEN", "GH_TOKEN"}},
	} {
		srv := newFakeForge(t, func(w http.ResponseWriter, r *http.Request) { t.Error("no request may be sent without a token") })
		f := &ForgeOpener{Kind: tc.kind, BaseURL: srv.URL, Getenv: tokenEnv(nil), Exec: forgeExec("git@h.example:a/b.git", new([]string))}
		_, err := f.OpenPR(context.Background(), testReq(gitRepo(t)))
		if err == nil {
			t.Fatalf("%s: want error", tc.kind)
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: %q lacks %s", tc.kind, err, w)
			}
		}
		if _, _, err := f.FindPR(context.Background(), t.TempDir(), "m"); err == nil || !strings.Contains(err.Error(), tc.want[0]) {
			t.Errorf("%s FindPR: %v", tc.kind, err)
		}
	}
}

func TestForgeContextCanceled(t *testing.T) {
	srv := newFakeForge(t, gitlabHandler(t, nil, nil))
	f := gitlabForge(srv, new([]string), map[string]string{"GITLAB_TOKEN": testToken})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := f.FindPR(ctx, t.TempDir(), "m"); err == nil {
		t.Fatal("canceled context must fail")
	}
}

// Default behaviour for GitHub users is unchanged: gh pr create, no HTTP.
func TestForgeAutoUsesGHForGitHubRemote(t *testing.T) {
	srv := newFakeForge(t, func(w http.ResponseWriter, r *http.Request) { t.Errorf("no API call expected: %s", r.RequestURI) })
	_ = srv
	var gh []string
	f := &ForgeOpener{Exec: forgeExec("https://github.com/o/r.git", &gh)}
	req := testReq(gitRepo(t))
	req.Labels, req.Reviewers = []string{"halos"}, []string{"alice"}
	url, err := f.OpenPR(context.Background(), req)
	if err != nil || url != "https://github.com/o/r/pull/9" {
		t.Fatalf("%q %v", url, err)
	}
	if len(gh) != 1 || !strings.HasPrefix(gh[0], "pr create --title Promote x --body ") ||
		!strings.Contains(gh[0], "--base main") || !strings.Contains(gh[0], "--label halos") || !strings.Contains(gh[0], "--reviewer alice") {
		t.Fatalf("gh args: %q", gh)
	}
}
