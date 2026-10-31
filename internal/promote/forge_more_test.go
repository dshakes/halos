package promote

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The PR exists but adding labels fails: the error carries the PR URL, and a
// retry finds the PR by its marker instead of opening a second one.
func TestGitHubLabelFailureAfterCreateThenRetryFinds(t *testing.T) {
	const marker = "<!-- halos:intent=lbl -->"
	const prURL = "https://ghe.example.com/acme/policy/pull/12"
	var createdBody string
	var creates int
	srv := newFakeForge(t, func(w http.ResponseWriter, r *http.Request) {
		path := strings.SplitN(r.RequestURI, "?", 2)[0]
		switch {
		case r.Method == "POST" && path == "/api/v3/repos/acme/policy/pulls":
			creates++
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			createdBody, _ = m["body"].(string)
			jsonOut(w, 201, map[string]any{"html_url": prURL, "number": 12})
		case r.Method == "POST" && strings.HasSuffix(path, "/issues/12/labels"):
			jsonOut(w, 403, map[string]string{"message": "Resource not accessible by personal access token"})
		case r.Method == "GET" && path == "/api/v3/repos/acme/policy/pulls":
			jsonOut(w, 200, []githubPR{{HTMLURL: prURL, Body: createdBody}})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.RequestURI)
		}
	})
	f := githubForge(srv, new([]string), map[string]string{"GITHUB_TOKEN": testToken})
	req := testReq(gitRepo(t))
	req.Body += "\n" + marker
	req.Labels = []string{"halos"}
	_, err := f.OpenPR(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), prURL) || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("want an error naming the opened PR and the 403, got %v", err)
	}
	// What a retrying caller does first: find by marker.
	url, found, err := f.FindPR(context.Background(), t.TempDir(), marker)
	if err != nil || !found || url != prURL {
		t.Fatalf("FindPR = %q %v %v", url, found, err)
	}
	if creates != 1 {
		t.Fatalf("pull requests created = %d, want 1", creates)
	}
	srv.assertNeverMerges(t)
}

// With --forge-base-url under a URL prefix, the prefix is not part of the
// project path.
func TestForgeSubPathProject(t *testing.T) {
	for _, tc := range []struct {
		name, kind, base, remote, want string
	}{
		{"https remote, prefix, .git", ForgeGitLab, "https://host.example/gitlab/api/v4", "https://host.example/gitlab/group/sub/repo.git", "group/sub/repo"},
		{"https remote, prefix, no .git", ForgeGitLab, "https://host.example/gitlab/api/v4", "https://host.example/gitlab/group/sub/repo", "group/sub/repo"},
		{"scp ssh remote", ForgeGitLab, "https://host.example/gitlab/api/v4", "git@host.example:gitlab/group/repo.git", "group/repo"},
		{"ssh:// remote with port", ForgeGitLab, "https://host.example/gitlab/api/v4/", "ssh://git@host.example:2222/gitlab/group/repo.git", "group/repo"},
		{"remote without the prefix is unchanged", ForgeGitLab, "https://host.example/gitlab/api/v4", "git@host.example:group/repo.git", "group/repo"},
		{"no prefix in base: a group named gitlab is kept", ForgeGitLab, "https://host.example/api/v4", "https://host.example/gitlab/repo", "gitlab/repo"},
		{"nested prefix", ForgeGitLab, "https://host.example/a/b/api/v4", "https://host.example/a/b/g/r", "g/r"},
		{"prefix only is not stripped to nothing", ForgeGitLab, "https://host.example/gitlab/api/v4", "https://host.example/gitlab/repo", "repo"},
		{"github enterprise under a prefix", ForgeGitHub, "https://host.example/ghe/api/v3", "https://host.example/ghe/acme/policy.git", "acme/policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rem, err := ParseRemote(tc.remote)
			if err != nil {
				t.Fatal(err)
			}
			f := &ForgeOpener{BaseURL: tc.base, Getenv: tokenEnv(map[string]string{"GITLAB_TOKEN": "x", "GITHUB_TOKEN": "x"})}
			a, err := f.api(tc.kind, rem)
			if err != nil {
				t.Fatal(err)
			}
			var got string
			switch v := a.(type) {
			case *gitlabAPI:
				got = v.project
			case *githubAPI:
				got = v.owner + "/" + v.repo
			}
			if got != tc.want {
				t.Fatalf("project = %q, want %q", got, tc.want)
			}
		})
	}
}
