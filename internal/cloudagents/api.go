package cloudagents

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/vendoradmin"
)

// API base URLs.
const (
	GitHubBaseURL = vendoradmin.GitHubBaseURL
	CursorBaseURL = "https://api.cursor.com"
)

// Bounds on what one fetch reads.
const (
	runsPerRepo  = 100 // first page of runs per repository
	cursorPages  = 10  // Cursor list pages of 100
	cursorDetail = 100 // agents whose detail and usage are read
)

// NewClient returns a vendor API client ("github" or "cursor") with the
// credential rules of vendoradmin.Client, or an error for a base URL that is
// not https (or loopback http). base "" uses the vendor's.
func NewClient(vendor, base, token string) (*vendoradmin.Client, error) {
	def := map[string]string{"github": GitHubBaseURL, "cursor": CursorBaseURL}[vendor]
	if def == "" {
		return nil, fmt.Errorf("cloudagents: no API for %q", vendor)
	}
	if base == "" {
		base = def
	}
	if err := vendoradmin.CheckBaseURL(base); err != nil {
		return nil, fmt.Errorf("%s: %w", vendor, err)
	}
	return &vendoradmin.Client{Vendor: vendor, BaseURL: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// Clients are the vendor APIs a caller was given; a nil client is not read
// and its actions are not attempted.
type Clients struct {
	GitHub *vendoradmin.Client
	Cursor *vendoradmin.Client
	// CursorUser is the Halos user the Cursor key belongs to: Cursor lists
	// only the key's own agents and names no user.
	CursorUser string
}

func repoPath(repo string) (string, error) {
	owner, name, ok := strings.Cut(repo, "/")
	if !ok || !repoRe.MatchString(repo) {
		return "", fmt.Errorf("malformed repository %q", trunc(repo))
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

// githubRepos are the explicit repositories of the enabled GitHub-hosted
// vendors, plus a warning per owner/* pattern (not enumerable here: webhooks
// cover those).
func githubRepos(c *policy.CloudAgents) (repos, warns []string) {
	for _, v := range []string{policy.CloudClaude, policy.CloudGemini, policy.CloudCopilot} {
		a := c.Vendor(v)
		if a == nil {
			continue
		}
		for _, r := range a.Repos {
			if strings.HasSuffix(r, "/*") {
				warns = append(warns, fmt.Sprintf("github: %s (%s) is not listed by API; its runs arrive by webhook", r, v))
				continue
			}
			if !slices.Contains(repos, r) {
				repos = append(repos, r)
			}
		}
	}
	slices.Sort(repos)
	return repos, warns
}

// Fetch reads the cloud agent tasks created since `since` from every client
// it has, attributed to Halos users. Each vendor that fails is reported in
// errs (credential-free) and the others are still read.
func (c Clients) Fetch(ctx context.Context, org *policy.Org, since time.Time) (tasks []Task, warns, errs []string) {
	ca := org.CloudAgents
	if ca == nil {
		return nil, nil, nil
	}
	if c.GitHub != nil {
		repos, w := githubRepos(ca)
		warns = append(warns, w...)
		for _, r := range repos {
			got, err := c.githubRuns(ctx, r, since)
			if err != nil {
				errs = append(errs, "github: "+err.Error())
				continue
			}
			tasks = append(tasks, got...)
		}
	}
	if c.Cursor != nil && ca.Cursor != nil {
		got, err := c.cursorAgents(ctx, since, len(ca.Cursor.Budgets) > 0)
		if err != nil {
			errs = append(errs, "cursor: "+err.Error())
		}
		tasks = append(tasks, got...)
	}
	for i := range tasks {
		tasks[i].Attribute(ca)
	}
	return tasks, warns, errs
}

func (c Clients) githubRuns(ctx context.Context, repo string, since time.Time) ([]Task, error) {
	p, err := repoPath(repo)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Runs []workflowRun `json:"workflow_runs"`
	}
	q := url.Values{"per_page": {fmt.Sprint(runsPerRepo)}, "created": {">=" + since.UTC().Format("2006-01-02")}}
	if _, err := c.GitHub.Get(ctx, p+"/actions/runs?"+q.Encode(), &resp); err != nil {
		return nil, err
	}
	var out []Task
	for _, r := range resp.Runs {
		if r.Repository.FullName == "" {
			r.Repository.FullName = repo
		}
		t, ok, err := taskFromRun(r, SourceGitHubAPI)
		if err != nil {
			return out, err
		}
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

func (c Clients) cursorAgents(ctx context.Context, since time.Time, usage bool) ([]Task, error) {
	var out []Task
	cursor := ""
	for page := 0; page < cursorPages; page++ {
		q := url.Values{"limit": {"100"}, "includeArchived": {"false"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp struct {
			Items      []cursorAgent `json:"items"`
			NextCursor string        `json:"nextCursor"`
		}
		if _, err := c.Cursor.Get(ctx, "/v1/agents?"+q.Encode(), &resp); err != nil {
			return out, err
		}
		old := false
		for _, a := range resp.Items {
			if a.Status != "ACTIVE" && a.UpdatedAt.Before(since) {
				old = true // newest first: the rest are older still
				continue
			}
			if len(out) < cursorDetail && safeID(a.ID) {
				_, _ = c.Cursor.Get(ctx, "/v1/agents/"+url.PathEscape(a.ID), &a) // repos; the list item is enough without it
			}
			t, err := taskFromCursor(a, c.CursorUser)
			if err != nil {
				return out, err
			}
			if usage && len(out) < cursorDetail {
				var u struct {
					Total struct {
						Tokens int64 `json:"totalTokens"`
					} `json:"totalUsage"`
				}
				if _, err := c.Cursor.Get(ctx, "/v1/agents/"+url.PathEscape(a.ID)+"/usage", &u); err == nil && u.Total.Tokens > 0 {
					t.Tokens = u.Total.Tokens
				}
			}
			out = append(out, t)
		}
		if old || resp.NextCursor == "" {
			return out, nil
		}
		cursor = resp.NextCursor
	}
	return out, nil
}

// Operations on a task.
const (
	OpCancel = "cancel" // stop the running task (terminal)
	OpPause  = "pause"  // stop new tasks, reversibly (a human resumes)
)

// Results of an Action.
const (
	ResultDryRun   = "dry-run"
	ResultDone     = "done"
	ResultFailed   = "failed"
	ResultManual   = "manual"    // no API: Manual says what a human does
	ResultNoClient = "no-client" // the vendor API was not configured
)

// Action is one operation on one task, planned and then (unless a dry run)
// executed.
type Action struct {
	Task Task   `json:"task"`
	Op   string `json:"op"`
	// Call is the vendor API request, or "" when there is none.
	Call   string `json:"call,omitempty"`
	Manual string `json:"manual,omitempty"`
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// Plan maps tasks to op's vendor calls. Every action starts as a dry run (or
// manual, where the vendor has no API).
func Plan(tasks []Task, op string) []Action {
	out := make([]Action, 0, len(tasks))
	for _, t := range tasks {
		a := Action{Task: t, Op: op, Result: ResultDryRun}
		rp, _ := repoPath(t.Repo)
		switch {
		case t.Vendor == policy.CloudCursor && op == OpCancel && t.RunRef != "":
			a.Call = "POST /v1/agents/" + url.PathEscape(t.Ref) + "/runs/" + url.PathEscape(t.RunRef) + "/cancel"
		case t.Vendor == policy.CloudCursor && op == OpPause:
			a.Call = "POST /v1/agents/" + url.PathEscape(t.Ref) + "/archive" // unarchive resumes
		case t.Vendor == policy.CloudCursor:
			a.Manual = "the agent has no run to cancel"
		case rp == "":
			a.Manual = "the task names no repository"
		case op == OpCancel:
			a.Call = "POST " + rp + "/actions/runs/" + url.PathEscape(t.Ref) + "/cancel"
			if t.Vendor == policy.CloudCopilot {
				a.Manual = "UNVERIFIED that the Copilot cloud agent stops on an Actions cancel: also stop the session from the pull request"
			}
		case op == OpPause && t.Vendor != policy.CloudCopilot && strings.HasPrefix(t.Workflow, ".github/workflows/"):
			// enable (PUT .../enable) resumes; a human does that
			a.Call = "PUT " + rp + "/actions/workflows/" + url.PathEscape(path.Base(t.Workflow)) + "/disable"
		default:
			a.Manual = "no pause API: set Copilot cloud agent repository access in the organization's Copilot settings"
		}
		if a.Call == "" {
			a.Result = ResultManual
		}
		out = append(out, a)
	}
	return out
}

// Execute sends every planned call. It never resumes or enables anything.
func (c Clients) Execute(ctx context.Context, actions []Action) []Action {
	out := slices.Clone(actions)
	for i := range out {
		a := &out[i]
		if a.Call == "" {
			continue
		}
		cl := c.GitHub
		if a.Task.Vendor == policy.CloudCursor {
			cl = c.Cursor
		}
		if cl == nil {
			a.Result = ResultNoClient
			continue
		}
		method, p, _ := strings.Cut(a.Call, " ")
		_, err := cl.Send(ctx, method, p, nil, nil)
		switch {
		case err == nil:
			a.Result = ResultDone
		case a.Op == OpCancel && vendoradmin.StatusCode(err) == http.StatusConflict:
			a.Result, a.Error = ResultDone, "already finished" // GitHub and Cursor answer 409 for a run that is not cancellable
		default:
			a.Result, a.Error = ResultFailed, err.Error()
		}
	}
	return out
}
