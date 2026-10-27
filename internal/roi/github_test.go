package roi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const ghToken = "ghp_roi_secret_token"

func node(num int, created, merged, login, typ, body string, labels []string, changes, approved int) map[string]any {
	ls := []map[string]any{}
	for _, l := range labels {
		ls = append(ls, map[string]any{"name": l})
	}
	n := map[string]any{
		"number": num, "title": "change " + body, "body": body, "createdAt": created, "additions": 10 * num, "deletions": num,
		"author": map[string]any{"__typename": typ, "login": login}, "labels": map[string]any{"nodes": ls},
		"changesRequested": map[string]any{"totalCount": changes}, "approved": map[string]any{"totalCount": approved},
	}
	if merged != "" {
		n["mergedAt"] = merged
	}
	if login == "" {
		n["author"] = nil
	}
	return n
}

// fakeGraphQL serves two pages of acme/api pull requests, newest first.
func fakeGraphQL(t *testing.T) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var seen []map[string]any
	pages := [][]map[string]any{
		{
			node(6, "2026-09-20T10:00:00Z", "2026-09-20T12:00:00Z", "Alice", "User", "Reverts acme/api#2", nil, 0, 1),
			node(5, "2026-09-15T10:00:00Z", "2026-09-15T11:00:00Z", "bob", "User", "fix crash from #3", []string{"HotFix"}, 0, 1),
			node(4, "2026-09-10T10:00:00Z", "", "dependabot", "Bot", "bump", nil, 0, 0),
		},
		{
			node(3, "2026-09-05T10:00:00Z", "2026-09-06T10:00:00Z", "bob", "User", "feature", nil, 2, 1),
			node(2, "2026-09-02T10:00:00Z", "2026-09-03T10:00:00Z", "alice", "User", "feature", nil, 0, 1),
			node(1, "2026-08-20T10:00:00Z", "2026-08-21T10:00:00Z", "", "", "before the window", nil, 0, 0),
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer "+ghToken {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if strings.Contains(req.Query, "mutation") {
			t.Error("ingest must only query")
		}
		mu.Lock()
		seen = append(seen, req.Variables)
		mu.Unlock()
		page := 0
		if req.Variables["cursor"] == "c1" {
			page = 1
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": map[string]any{"pullRequests": map[string]any{
			"pageInfo": map[string]any{"hasNextPage": page == 0, "endCursor": "c1"},
			"nodes":    pages[page],
		}}}})
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

func TestGitHubFetch(t *testing.T) {
	srv, seen := fakeGraphQL(t)
	g := &GitHub{URL: srv.URL + "/graphql", Token: ghToken}
	prs, err := g.Fetch(context.Background(), "acme/API", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 2 || (*seen)[0]["owner"] != "acme" || (*seen)[0]["name"] != "API" || (*seen)[0]["cursor"] != nil {
		t.Fatalf("requests %v", *seen)
	}
	got := map[int64]PR{}
	for _, p := range prs {
		got[p.Number] = p
		if err := p.Check(); err != nil {
			t.Error(err)
		}
	}
	if len(prs) != 5 || got[1].Number != 0 {
		t.Fatalf("want PRs 2..6 (1 is before --since), got %d: %+v", len(prs), prs)
	}
	tests := []struct {
		num     int64
		author  string
		bot     bool
		failure bool
		rounds  int
		merged  bool
	}{
		{6, "alice", false, false, 1, true},
		{5, "bob", false, false, 1, true},
		{4, "dependabot", true, false, 0, false},
		{3, "bob", false, true, 3, true},   // hotfix #5 references it
		{2, "alice", false, true, 1, true}, // reverted by #6
	}
	for _, tc := range tests {
		p := got[tc.num]
		if p.Author != tc.author || p.Bot != tc.bot || p.ChangeFailure != tc.failure || p.ReviewRounds != tc.rounds || (p.MergedAt != nil) != tc.merged {
			t.Errorf("#%d = %+v, want author %s bot %v failure %v rounds %d merged %v", tc.num, p, tc.author, tc.bot, tc.failure, tc.rounds, tc.merged)
		}
		if p.Repo != "acme/api" || p.Source != "github" || p.Additions != 10*int(tc.num) {
			t.Errorf("#%d: %+v", tc.num, p)
		}
	}
}

func TestGitHubErrors(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/errors":
			_, _ = io.WriteString(w, `{"errors":[{"message":"bad credentials `+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+`"}]}`)
		case "/missing":
			_, _ = io.WriteString(w, `{"data":{"repository":null}}`)
		case "/redirect":
			http.Redirect(w, r, "http://evil.example/graphql", http.StatusFound)
		default:
			http.Error(w, "token "+r.Header.Get("Authorization"), http.StatusForbidden)
		}
	}))
	t.Cleanup(echo.Close)
	since := time.Now()
	tests := []struct {
		name, url, repo, token, want string
	}{
		{"graphql error redacted", echo.URL + "/errors", "a/b", ghToken, "[REDACTED]"},
		{"http status redacted", echo.URL + "/x", "a/b", ghToken, "HTTP 403"},
		{"repo not visible", echo.URL + "/missing", "a/b", ghToken, "not found"},
		{"redirect not followed", echo.URL + "/redirect", "a/b", ghToken, "not followed"},
		{"plain http off loopback", "http://api.github.example/graphql", "a/b", ghToken, "https"},
		{"bad repo", echo.URL, "a/b/c", ghToken, "owner/name"},
		{"no token", echo.URL, "a/b", "", "no token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (&GitHub{URL: tc.url, Token: tc.token}).Fetch(context.Background(), tc.repo, since)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), ghToken) {
				t.Fatalf("token leaked: %v", err)
			}
		})
	}
}

func TestParseIdentities(t *testing.T) {
	ids, err := ParseIdentities(strings.NewReader("Login, Subject, Groups, Kind\nAlice-GH, Alice@Corp.com, eng;ai-platform,\nalice-work,alice@corp.com,eng;ai-platform,\nci,ci@corp.com,,workload\n,nologin@corp.com,,\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := ids.Resolve(PR{Author: "ALICE-gh"})
	if !ok || s.ID != "alice@corp.com" || len(s.Groups) != 2 || s.Groups[1] != "ai-platform" {
		t.Fatalf("resolve by login: %+v %v", s, ok)
	}
	if s2, ok := ids.Resolve(PR{Author: "alice-work"}); !ok || s2.ID != s.ID {
		t.Fatalf("second login: %+v", s2)
	}
	if s, ok := ids.Resolve(PR{Author: "whoever", Subject: " NoLogin@corp.com"}); !ok || s.ID != "nologin@corp.com" {
		t.Fatalf("resolve by subject: %+v %v", s, ok)
	}
	if _, ok := ids.Resolve(PR{Author: "stranger"}); ok {
		t.Fatal("stranger mapped")
	}
	if s, _ := ids.Resolve(PR{Author: "ci"}); s.Kind != "workload" {
		t.Fatalf("kind %q", s.Kind)
	}
	if n := len(ids.Subjects()); n != 3 {
		t.Fatalf("roster %d, want 3 unique subjects", n)
	}
	for name, in := range map[string]string{
		"no subject column":  "login\nx\n",
		"unknown column":     "login,subject,team\nx,y,z\n",
		"empty subject":      "login,subject\nx,\n",
		"bad kind":           "login,subject,kind\nx,y,robot\n",
		"login two subjects": "login,subject\nx,a@c\nX,b@c\n",
		"subject regrouped":  "login,subject,groups\nx,a@c,g1\ny,a@c,g2\n",
	} {
		if _, err := ParseIdentities(strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := dir + "/" + name
		if err := writeFile(p, s); err != nil {
			t.Fatal(err)
		}
		return p
	}
	csvPath := write("prs.csv", "repo,number,author,opened_at,merged_at,review_rounds,additions,deletions,change_failure\n"+
		"jira/PROJ,1,Alice,2026-09-01,2026-09-02T10:00:00Z,2,10,5,true\n"+
		"jira/PROJ,2,bob,2026-09-03T00:00:00Z,,0,0,0,\n")
	prs, err := ReadFile(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].Source != "file" || prs[0].Author != "alice" || !prs[0].ChangeFailure || prs[0].ReviewRounds != 2 || prs[1].MergedAt != nil {
		t.Fatalf("csv: %+v", prs)
	}
	jsonl := write("prs.jsonl", `{"source":"gitlab","repo":"g/r","number":7,"subject":"a@c","opened_at":"2026-09-01T00:00:00Z","review_rounds":1,"additions":1,"deletions":1}`+"\n\n")
	if prs, err = ReadFile(jsonl); err != nil || len(prs) != 1 || prs[0].Source != "gitlab" || prs[0].Subject != "a@c" {
		t.Fatalf("jsonl: %+v %v", prs, err)
	}
	for name, body := range map[string]string{
		"bad.csv":       "repo,number,author,opened_at,team\n",
		"merged.csv":    "repo,number,author,opened_at,merged_at\nr,1,a,2026-09-02,2026-09-01\n",
		"number.csv":    "repo,number,author,opened_at\nr,x,a,2026-09-02\n",
		"time.csv":      "repo,number,author,opened_at\nr,1,a,yesterday\n",
		"noauthor.csv":  "repo,number,opened_at\nr,1,2026-09-02\n",
		"unknown.jsonl": `{"repo":"r","number":1,"author":"a","opened_at":"2026-09-01T00:00:00Z","title":"leak"}`,
		"prs.txt":       "",
	} {
		if _, err := ReadFile(write(name, body)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestFileStoreReplaces(t *testing.T) {
	st := FileStore{Path: t.TempDir() + "/s.jsonl"}
	ctx := context.Background()
	a := PR{Source: "github", Repo: "a/b", Number: 1, Author: "x", OpenedAt: t0}
	b := PR{Source: "github", Repo: "a/b", Number: 2, Author: "x", OpenedAt: t1}
	if err := st.Put(ctx, []PR{a, b}); err != nil {
		t.Fatal(err)
	}
	a.ChangeFailure = true // a later ingest found the revert
	if err := st.Put(ctx, []PR{a}); err != nil {
		t.Fatal(err)
	}
	got, err := st.PRs(ctx, t0, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].ChangeFailure {
		t.Fatalf("got %+v: want only #1 (window is [from, to)) with the update", got)
	}
	if none, err := (FileStore{Path: t.TempDir() + "/missing.jsonl"}).PRs(ctx, t0, t1); err != nil || len(none) != 0 {
		t.Fatalf("missing store: %v %v", none, err)
	}
}
