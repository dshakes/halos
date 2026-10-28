// Package cloudagents governs background coding agents that run on vendor or
// CI infrastructure rather than a developer machine (ADR-0034): it normalizes
// tasks from vendor APIs and GitHub webhooks into one inventory mapped to
// Halos identities, plans and executes kill fan-out (cancel) and over-limit
// pauses, and turns finished tasks into session ledger records. Rendering is
// in the workflow subpackage.
//
// Vendor calls go through vendoradmin.Client, so they share its credential
// rules: token only in the Authorization header and scrubbed from errors, no
// redirects, https (or loopback http) only. Tests run against httptest fakes.
package cloudagents

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/cloudagents/workflow"
	"github.com/dshakes/halos/internal/policy"
)

// Task statuses, normalized across vendors.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
	StatusUnknown   = "unknown"
)

// Task sources.
const (
	SourceGitHubWebhook = "github-webhook"
	SourceGitHubAPI     = "github-api"
	SourceCursorAPI     = "cursor-api"
)

// Task is one cloud agent task, normalized. Every string in it came from a
// vendor and passed safeID or a fixed vocabulary, so it is safe to print and
// to use as an API path segment.
type Task struct {
	// ID is "<vendor>:<repo or agent>:<run>", stable across sources.
	ID     string `json:"id"`
	Vendor string `json:"vendor"`
	Source string `json:"source"`
	Repo   string `json:"repo,omitempty"` // owner/repo
	// Ref is the vendor object a cancel targets: the Actions run id, or the
	// Cursor agent id. RunRef is Cursor's run id.
	Ref    string `json:"ref"`
	RunRef string `json:"runRef,omitempty"`
	// Workflow is the Actions workflow file (GitHub-hosted vendors).
	Workflow string `json:"workflow,omitempty"`
	// Managed is false for a run of a workflow Halos did not render (a copy
	// of the vendor's quick-setup file): it is a violation, not governed.
	Managed    bool   `json:"managed"`
	VendorUser string `json:"vendorUser,omitempty"`
	// User is the Halos identity (cloudAgents.identities); "" = unattributed.
	User    string    `json:"user,omitempty"`
	Model   string    `json:"model,omitempty"`
	Status  string    `json:"status"`
	Tokens  int64     `json:"tokens,omitempty"`
	URL     string    `json:"url,omitempty"`
	Start   time.Time `json:"start"`
	Updated time.Time `json:"updated"`
	End     time.Time `json:"end,omitzero"`
}

// Active reports whether the task may still be running (and so counts toward
// concurrency and can be cancelled).
func (t Task) Active() bool { return t.Status == StatusQueued || t.Status == StatusRunning }

var (
	safeIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
	wfPathRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
)

func safeID(s string) bool { return safeIDRe.MatchString(s) }

// Attribute sets t.User from the policy's identity map.
// A Cursor task keeps the API key owner it was fetched with.
func (t *Task) Attribute(c *policy.CloudAgents) {
	if t.Vendor == policy.CloudCursor {
		return
	}
	t.User, _ = c.UserForGitHub(t.VendorUser)
}

// ---- GitHub Actions runs (Claude and Gemini actions, Copilot cloud agent) ----

// workflowRun is the subset of a GitHub workflow run object (webhook payload
// and REST API) Halos reads.
type workflowRun struct {
	ID              int64     `json:"id"`
	Path            string    `json:"path"`
	Event           string    `json:"event"`
	Status          string    `json:"status"`
	Conclusion      string    `json:"conclusion"`
	HTMLURL         string    `json:"html_url"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	RunStartedAt    time.Time `json:"run_started_at"`
	Actor           ghUser    `json:"actor"`
	TriggeringActor ghUser    `json:"triggering_actor"`
	Repository      struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

type ghUser struct {
	Login string `json:"login"`
}

// copilotPathPrefix is the workflow path of Copilot cloud agent runs.
// UNVERIFIED: observed on github.com runs, not in GitHub's documentation.
const copilotPathPrefix = "dynamic/copilot-swe-agent/"

// classifyRun maps a workflow path to the vendor and whether Halos rendered
// it; ok is false for every other workflow (not a cloud agent).
func classifyRun(path string) (vendor string, managed, ok bool) {
	switch {
	case path == workflow.ClaudeWorkflow:
		return policy.CloudClaude, true, true
	case path == workflow.GeminiWorkflow:
		return policy.CloudGemini, true, true
	case strings.HasPrefix(path, copilotPathPrefix):
		return policy.CloudCopilot, true, true
	// The vendors' quick-setup file names: a run of one is an ungoverned agent.
	case path == ".github/workflows/claude.yml" || path == ".github/workflows/claude-code-review.yml":
		return policy.CloudClaude, false, true
	case path == ".github/workflows/gemini-cli.yml" || path == ".github/workflows/gemini-dispatch.yml":
		return policy.CloudGemini, false, true
	}
	return "", false, false
}

// githubStatus normalizes a run's status and conclusion.
func githubStatus(status, conclusion string) string {
	switch status {
	case "queued", "requested", "waiting", "pending":
		return StatusQueued
	case "in_progress":
		return StatusRunning
	case "completed":
		switch conclusion {
		case "success", "neutral", "skipped":
			return StatusCompleted
		case "cancelled":
			return StatusCancelled
		case "failure", "timed_out", "startup_failure", "action_required", "stale":
			return StatusFailed
		}
	}
	return StatusUnknown
}

// taskFromRun normalizes a workflow run; ok is false when it is not a cloud
// agent run. Every vendor string is checked before it is kept.
func taskFromRun(r workflowRun, source string) (Task, bool, error) {
	vendor, managed, ok := classifyRun(r.Path)
	if !ok {
		return Task{}, false, nil
	}
	repo := r.Repository.FullName
	if !repoRe.MatchString(repo) || r.ID <= 0 || !wfPathRe.MatchString(r.Path) {
		return Task{}, false, fmt.Errorf("workflow run: malformed repository %q, id %d or path", trunc(repo), r.ID)
	}
	who := r.TriggeringActor.Login
	if who == "" {
		who = r.Actor.Login
	}
	if who != "" && !safeID(strings.TrimSuffix(who, "[bot]")) {
		return Task{}, false, fmt.Errorf("workflow run %d: malformed actor login", r.ID)
	}
	t := Task{
		ID: fmt.Sprintf("%s:%s:%d", vendor, repo, r.ID), Vendor: vendor, Source: source, Repo: repo,
		Ref: strconv.FormatInt(r.ID, 10), Workflow: r.Path, Managed: managed, VendorUser: who,
		Status: githubStatus(r.Status, r.Conclusion), Start: r.RunStartedAt, Updated: r.UpdatedAt,
	}
	if t.Start.IsZero() {
		t.Start = r.CreatedAt
	}
	if strings.HasPrefix(r.HTMLURL, "https://") && len(r.HTMLURL) < 300 {
		t.URL = r.HTMLURL
	}
	if !t.Active() && t.Status != StatusUnknown {
		t.End = r.UpdatedAt
	}
	return t, true, nil
}

// ---- GitHub webhooks ----

// MaxWebhookBody bounds a webhook delivery GitHub sends (GitHub caps payloads at 25 MB;
// a workflow_run delivery is a few KiB).
const MaxWebhookBody = 1 << 20

// ErrBadSignature means a delivery's X-Hub-Signature-256 is missing or does
// not match any configured secret.
var ErrBadSignature = errors.New("webhook signature missing or invalid")

// VerifySignature checks GitHub's X-Hub-Signature-256 header ("sha256=" +
// hex HMAC-SHA256 of the raw body) against each secret (two while rotating),
// in constant time. Per https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries.
func VerifySignature(secrets []string, body []byte, header string) error {
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	got, err := hex.DecodeString(hexSig)
	if !ok || err != nil || len(got) != sha256.Size {
		return ErrBadSignature
	}
	match := false
	for _, s := range secrets {
		if s == "" {
			continue
		}
		m := hmac.New(sha256.New, []byte(s))
		m.Write(body)
		if hmac.Equal(m.Sum(nil), got) {
			match = true // keep going: the time taken does not say which secret matched
		}
	}
	if !match {
		return ErrBadSignature
	}
	return nil
}

// ParseGitHubEvent normalizes a verified delivery. ok is false for events
// that are not cloud agent runs (ping, other workflows, other event types);
// they are acknowledged and dropped. Call VerifySignature first.
func ParseGitHubEvent(event string, body []byte) (Task, bool, error) {
	if event != "workflow_run" {
		return Task{}, false, nil
	}
	var p struct {
		WorkflowRun *workflowRun `json:"workflow_run"`
		Repository  struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return Task{}, false, fmt.Errorf("workflow_run payload: %w", err)
	}
	if p.WorkflowRun == nil {
		return Task{}, false, errors.New("workflow_run payload: no workflow_run object")
	}
	if p.WorkflowRun.Repository.FullName == "" {
		p.WorkflowRun.Repository.FullName = p.Repository.FullName
	}
	return taskFromRun(*p.WorkflowRun, SourceGitHubWebhook)
}

// ---- Cursor cloud agents ----

type cursorAgent struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	LatestRun string    `json:"latestRunId"`
	Repos     []struct {
		URL string `json:"url"`
	} `json:"repos"`
}

// cursorStatus normalizes an agent's lifecycle status (ACTIVE: a run is
// going; IDLE: the last run ended; ARCHIVED: terminal).
func cursorStatus(s string) string {
	switch s {
	case "ACTIVE":
		return StatusRunning
	case "IDLE":
		return StatusCompleted
	case "ARCHIVED":
		return StatusCancelled
	}
	return StatusUnknown
}

// taskFromCursor normalizes a Cursor agent. owner is the Halos user the API
// key belongs to: Cursor lists only the key's own agents and names no user.
func taskFromCursor(a cursorAgent, owner string) (Task, error) {
	if !safeID(a.ID) || (a.LatestRun != "" && !safeID(a.LatestRun)) {
		return Task{}, errors.New("cursor agent: malformed agent or run id")
	}
	t := Task{
		ID: "cursor:" + a.ID, Vendor: policy.CloudCursor, Source: SourceCursorAPI, Ref: a.ID, RunRef: a.LatestRun,
		Managed: true, User: owner, Status: cursorStatus(a.Status), Start: a.CreatedAt, Updated: a.UpdatedAt,
	}
	if len(a.Repos) > 0 {
		r := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(a.Repos[0].URL, "https://"), "github.com/"), ".git")
		if repoRe.MatchString(r) {
			t.Repo = r
		}
	}
	if strings.HasPrefix(a.URL, "https://") && len(a.URL) < 300 {
		t.URL = a.URL
	}
	if !t.Active() {
		t.End = a.UpdatedAt
	}
	return t, nil
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
