package roi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/vendoradmin"
)

// GitHubGraphQL is the public GraphQL endpoint. GitHub Enterprise Server
// serves it at https://<host>/api/graphql.
const GitHubGraphQL = "https://api.github.com/graphql"

// maxPRPages bounds pagination (100 PRs a page) for one repository.
const maxPRPages = 500

var repoRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)

// GitHub reads pull requests through the GraphQL API with a read-only query.
// The token is sent only in the Authorization header and scrubbed from every
// error; redirects are never followed.
type GitHub struct {
	URL   string // GraphQL endpoint; default GitHubGraphQL
	Token string
	// HotfixLabel marks a hotfix PR; a merged one marks every PR it
	// references (#N) as a change failure. Default "hotfix".
	HotfixLabel string
	Client      *http.Client // default: 60s timeout, no redirects
}

const prQuery = `query($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(first: 100, after: $cursor, orderBy: {field: CREATED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number title body createdAt mergedAt additions deletions
        author { __typename login }
        labels(first: 20) { nodes { name } }
        changesRequested: reviews(states: [CHANGES_REQUESTED]) { totalCount }
        approved: reviews(states: [APPROVED]) { totalCount }
      }
    }
  }
}`

type ghPR struct {
	Number    int64      `json:"number"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	CreatedAt time.Time  `json:"createdAt"`
	MergedAt  *time.Time `json:"mergedAt"`
	Additions int        `json:"additions"`
	Deletions int        `json:"deletions"`
	Author    *struct {
		Type  string `json:"__typename"`
		Login string `json:"login"`
	} `json:"author"`
	Labels struct {
		Nodes []struct {
			Name string `json:"name"`
		} `json:"nodes"`
	} `json:"labels"`
	ChangesRequested struct{ TotalCount int } `json:"changesRequested"`
	Approved         struct{ TotalCount int } `json:"approved"`
}

type ghResp struct {
	Data *struct {
		Repository *struct {
			PullRequests struct {
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
				Nodes []ghPR `json:"nodes"`
			} `json:"pullRequests"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (g *GitHub) redact(s string) string {
	if g.Token == "" {
		return s
	}
	return strings.ReplaceAll(s, g.Token, "[REDACTED]")
}

// Fetch returns the PRs of repo ("owner/name") created at or after since,
// with change failures marked: a merged PR whose body carries GitHub's
// revert line "Reverts owner/name#N", or a merged hotfix-labelled PR that
// references #N, marks PR N. Only PRs fetched in the same call are marked, so
// fetch a window that also covers the follow-ups.
func (g *GitHub) Fetch(ctx context.Context, repo string, since time.Time) ([]PR, error) {
	if !repoRE.MatchString(repo) {
		return nil, fmt.Errorf("github: repo %q: want owner/name", repo)
	}
	if g.Token == "" {
		return nil, errors.New("github: no token (set the variable named by --token-env)")
	}
	endpoint := g.URL
	if endpoint == "" {
		endpoint = GitHubGraphQL
	}
	if err := vendoradmin.CheckBaseURL(endpoint); err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	hc := g.Client
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	owner, name, _ := strings.Cut(repo, "/")
	var nodes []ghPR
	cursor := ""
	for page := 0; ; page++ {
		if page == maxPRPages {
			return nil, fmt.Errorf("github: %s has more than %d pages since %s; narrow --since", repo, maxPRPages, since.Format(time.DateOnly))
		}
		vars := map[string]any{"owner": owner, "name": name, "cursor": nil}
		if cursor != "" {
			vars["cursor"] = cursor
		}
		r, err := g.post(ctx, hc, endpoint, vars)
		if err != nil {
			return nil, fmt.Errorf("github %s: %w", repo, err)
		}
		prs := r.Data.Repository.PullRequests
		done := false
		for _, n := range prs.Nodes {
			if n.CreatedAt.Before(since) {
				done = true // ordered newest first
				break
			}
			nodes = append(nodes, n)
		}
		if done || !prs.PageInfo.HasNextPage {
			break
		}
		cursor = prs.PageInfo.EndCursor
	}
	return g.toPRs(repo, nodes), nil
}

func (g *GitHub) post(ctx context.Context, hc *http.Client, endpoint string, vars map[string]any) (*ghResp, error) {
	body, err := json.Marshal(map[string]any{"query": prQuery, "variables": vars})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New(g.redact(err.Error()))
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, errors.New(g.redact(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, errors.New(g.redact(err.Error()))
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(raw[:min(len(raw), 512)]))
		if loc := resp.Header.Get("Location"); loc != "" {
			msg = "redirect to " + loc + " not followed"
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, g.redact(msg))
	}
	var r ghResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(r.Errors) > 0 {
		msgs := make([]string, len(r.Errors))
		for i, e := range r.Errors {
			msgs[i] = e.Message
		}
		return nil, errors.New(g.redact(strings.Join(msgs, "; ")))
	}
	if r.Data == nil || r.Data.Repository == nil {
		return nil, errors.New("repository not found or not visible to the token")
	}
	return &r, nil
}

var (
	refRE    = regexp.MustCompile(`#(\d+)\b`)
	revertRE = regexp.MustCompile(`(?mi)^\s*Reverts\s+([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)#(\d+)`)
)

func (g *GitHub) toPRs(repo string, nodes []ghPR) []PR {
	label := g.HotfixLabel
	if label == "" {
		label = "hotfix"
	}
	failed := map[int64]bool{}
	for _, n := range nodes {
		if n.MergedAt == nil {
			continue
		}
		for _, m := range revertRE.FindAllStringSubmatch(n.Body, -1) {
			if strings.EqualFold(m[1], repo) {
				if num, err := strconv.ParseInt(m[2], 10, 64); err == nil {
					failed[num] = true
				}
			}
		}
		hotfix := false
		for _, l := range n.Labels.Nodes {
			hotfix = hotfix || strings.EqualFold(l.Name, label)
		}
		if hotfix {
			for _, m := range refRE.FindAllStringSubmatch(n.Title+"\n"+n.Body, -1) {
				if num, err := strconv.ParseInt(m[1], 10, 64); err == nil && num != n.Number {
					failed[num] = true
				}
			}
		}
	}
	out := make([]PR, 0, len(nodes))
	for _, n := range nodes {
		p := PR{
			Source: "github", Repo: strings.ToLower(repo), Number: n.Number,
			OpenedAt: n.CreatedAt.UTC(), Additions: n.Additions, Deletions: n.Deletions,
			ChangeFailure: n.MergedAt != nil && failed[n.Number],
		}
		if n.MergedAt != nil {
			m := n.MergedAt.UTC()
			p.MergedAt = &m
		}
		if n.Author == nil {
			p.Author, p.Bot = "ghost", true // deleted account: not attributable
		} else {
			p.Author, p.Bot = strings.ToLower(n.Author.Login), n.Author.Type == "Bot"
		}
		// A round is one review pass: every change request starts another,
		// the approval closes the last one.
		if rounds := n.ChangesRequested.TotalCount; rounds+n.Approved.TotalCount > 0 {
			p.ReviewRounds = rounds + 1
		}
		out = append(out, p)
	}
	return out
}
