package promote

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// gitlabAPI opens and finds merge requests with the GitLab REST API v4. The
// create body carries only source/target branch, title, description, labels
// and reviewer ids: never merge_when_pipeline_succeeds, auto-merge or a call to
// the merge endpoint. A human merges.
type gitlabAPI struct {
	c       *httpAPI
	project string // group/sub/repo
}

func gitlabHints(status int) string {
	switch status {
	case 401:
		return "GITLAB_TOKEN was rejected: it is invalid, expired or revoked"
	case 403:
		return "GITLAB_TOKEN needs the api scope and at least the Developer role on the project; check branch protection allows Halos to push halos/* branches"
	case 404:
		return "project not found, or GITLAB_TOKEN cannot see it; check the origin remote path and the token's access"
	case 409:
		return "a merge request for this branch may already exist"
	case 422:
		return "GitLab rejected the merge request; check the target branch exists and the title and description are valid"
	case 429:
		return "rate limited; retry later"
	}
	return ""
}

func (g *gitlabAPI) projectPath(suffix string) string {
	// PathEscape turns the slashes of group/sub/repo into %2F, which GitLab
	// requires for a path in place of a numeric id.
	return "/projects/" + url.PathEscape(g.project) + suffix
}

type gitlabMR struct {
	WebURL      string `json:"web_url"`
	Description string `json:"description"`
	IID         int    `json:"iid"`
}

func (g *gitlabAPI) open(ctx context.Context, branch string, r PRRequest) (string, error) {
	base := r.Base
	if base == "" {
		var p struct {
			DefaultBranch string `json:"default_branch"`
		}
		if _, err := g.c.do(ctx, "gitlab get project", "GET", g.projectPath(""), nil, &p); err != nil {
			return "", err
		}
		if p.DefaultBranch == "" {
			return "", fmt.Errorf("promote: gitlab: project %s has no default branch; pass a base branch", g.project)
		}
		base = p.DefaultBranch
	}
	body := map[string]any{
		"source_branch": branch,
		"target_branch": base,
		"title":         r.Title,
		"description":   r.Body,
	}
	if len(r.Labels) > 0 {
		body["labels"] = strings.Join(r.Labels, ",")
	}
	if len(r.Reviewers) > 0 {
		ids := make([]int, 0, len(r.Reviewers))
		for _, name := range r.Reviewers {
			var us []struct {
				ID int `json:"id"`
			}
			if _, err := g.c.do(ctx, "gitlab find reviewer", "GET", "/users?username="+url.QueryEscape(name), nil, &us); err != nil {
				return "", err
			}
			if len(us) == 0 {
				return "", fmt.Errorf("promote: gitlab: reviewer %q is not a GitLab user", name)
			}
			ids = append(ids, us[0].ID)
		}
		body["reviewer_ids"] = ids
	}
	var mr gitlabMR
	if _, err := g.c.do(ctx, "gitlab create merge request", "POST", g.projectPath("/merge_requests"), body, &mr); err != nil {
		return "", err
	}
	if mr.WebURL == "" {
		return "", fmt.Errorf("promote: gitlab create merge request: response has no web_url")
	}
	return mr.WebURL, nil
}

func (g *gitlabAPI) find(ctx context.Context, marker string) (string, bool, error) {
	term := markerTerm(marker)
	page := "1"
	for i := 0; i < forgeMaxPages && page != ""; i++ {
		q := url.Values{"state": {"all"}, "scope": {"all"}, "search": {term}, "in": {"description"},
			"order_by": {"created_at"}, "sort": {"desc"}, "per_page": {strconv.Itoa(forgePerPage)}, "page": {page}}
		var mrs []gitlabMR
		h, err := g.c.do(ctx, "gitlab list merge requests", "GET", g.projectPath("/merge_requests?"+q.Encode()), nil, &mrs)
		if err != nil {
			return "", false, err
		}
		for _, m := range mrs {
			if strings.Contains(m.Description, marker) {
				return m.WebURL, true, nil
			}
		}
		page = strings.TrimSpace(h.Get("X-Next-Page"))
	}
	return "", false, nil
}

// markerTerm strips the HTML-comment wrapper so the server-side search narrows
// on the text; the exact marker check on the returned body decides.
func markerTerm(marker string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(marker), "<!--"), "-->"))
}
