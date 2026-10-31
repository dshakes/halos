package promote

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// githubAPI opens and finds pull requests with the GitHub REST API (github.com
// or GitHub Enterprise Server). It never calls a merge endpoint or enables
// auto-merge: a human merges.
type githubAPI struct {
	c           *httpAPI
	owner, repo string
}

func githubHints(status int) string {
	switch status {
	case 401:
		return "GITHUB_TOKEN/GH_TOKEN was rejected: it is invalid, expired or revoked"
	case 403:
		return "the token needs repo scope (classic) or Pull requests: write and Contents: write (fine-grained), and SSO authorisation if the org enforces it; this can also be a rate limit"
	case 404:
		return "repository not found, or the token cannot see it; check the origin remote and the token's repository access"
	case 409:
		return "conflict; the branch may have changed"
	case 422:
		return "GitHub rejected the pull request; a PR for this branch may already exist, or the base branch is missing"
	case 429:
		return "rate limited; retry later"
	}
	return ""
}

func (g *githubAPI) repoPath(suffix string) string {
	return "/repos/" + url.PathEscape(g.owner) + "/" + url.PathEscape(g.repo) + suffix
}

type githubPR struct {
	HTMLURL string `json:"html_url"`
	Body    string `json:"body"`
	Number  int    `json:"number"`
}

func (g *githubAPI) open(ctx context.Context, branch string, r PRRequest) (string, error) {
	base := r.Base
	if base == "" {
		var rp struct {
			DefaultBranch string `json:"default_branch"`
		}
		if _, err := g.c.do(ctx, "github get repository", "GET", g.repoPath(""), nil, &rp); err != nil {
			return "", err
		}
		if rp.DefaultBranch == "" {
			return "", fmt.Errorf("promote: github: %s/%s has no default branch; pass a base branch", g.owner, g.repo)
		}
		base = rp.DefaultBranch
	}
	var pr githubPR
	body := map[string]any{"title": r.Title, "head": branch, "base": base, "body": r.Body}
	if _, err := g.c.do(ctx, "github create pull request", "POST", g.repoPath("/pulls"), body, &pr); err != nil {
		return "", err
	}
	if pr.HTMLURL == "" || pr.Number == 0 {
		return "", fmt.Errorf("promote: github create pull request: response has no html_url")
	}
	n := strconv.Itoa(pr.Number)
	// The PR exists now; failing here must say so, or a retry would look like
	// nothing was opened.
	if len(r.Labels) > 0 {
		if _, err := g.c.do(ctx, "github add labels", "POST", g.repoPath("/issues/"+n+"/labels"), map[string]any{"labels": r.Labels}, nil); err != nil {
			return "", fmt.Errorf("pull request %s was opened but: %w", pr.HTMLURL, err)
		}
	}
	if len(r.Reviewers) > 0 {
		if _, err := g.c.do(ctx, "github request reviewers", "POST", g.repoPath("/pulls/"+n+"/requested_reviewers"), map[string]any{"reviewers": r.Reviewers}, nil); err != nil {
			return "", fmt.Errorf("pull request %s was opened but: %w", pr.HTMLURL, err)
		}
	}
	return pr.HTMLURL, nil
}

var linkNext = regexp.MustCompile(`<[^>]*[?&]page=(\d+)[^>]*>\s*;\s*rel="next"`)

// find scans pull requests of any state, newest first, for the exact marker.
// The pulls endpoint cannot search bodies, so it pages (Link rel=next) up to
// forgeMaxPages x 100.
func (g *githubAPI) find(ctx context.Context, marker string, openOnly bool) (string, bool, error) {
	page := "1"
	state := "all"
	if openOnly {
		state = "open"
	}
	for i := 0; i < forgeMaxPages && page != ""; i++ {
		q := url.Values{"state": {state}, "sort": {"created"}, "direction": {"desc"},
			"per_page": {strconv.Itoa(forgePerPage)}, "page": {page}}
		var prs []githubPR
		h, err := g.c.do(ctx, "github list pull requests", "GET", g.repoPath("/pulls?"+q.Encode()), nil, &prs)
		if err != nil {
			return "", false, err
		}
		for _, p := range prs {
			if strings.Contains(p.Body, marker) {
				return p.HTMLURL, true, nil
			}
		}
		page = ""
		for _, l := range h.Values("Link") {
			if m := linkNext.FindStringSubmatch(l); m != nil {
				page = m[1]
				break
			}
		}
	}
	return "", false, nil
}
