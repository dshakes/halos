package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/yamledit"
)

// Every tool here edits policy YAML only, on a local branch or in a PR. None
// publishes a release, retags a registry ring, merges, or pushes to a default
// branch: a human does that at the irreversible step.

type writeIn struct {
	Name   string `json:"name" jsonschema:"experiment name"`
	Reason string `json:"reason" jsonschema:"why; recorded in the commit message"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the diff and change nothing"`
}

type promoteIn struct {
	Experiment string `json:"experiment"`
	Ring       string `json:"ring" jsonschema:"ring to re-point"`
	Release    string `json:"release" jsonschema:"release digest (sha256:...) to pin"`
	Reason     string `json:"reason" jsonschema:"why; recorded in the commit message and PR body"`
	Base       string `json:"base,omitempty" jsonschema:"PR base branch (default: repo default)"`
	DryRun     *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the diff and verdict, open nothing"`
}

type rollbackIn struct {
	Experiment string `json:"experiment"`
	Ring       string `json:"ring,omitempty" jsonschema:"ring to re-point (required with release)"`
	Release    string `json:"release,omitempty" jsonschema:"last known-good release digest; empty only pauses the experiment"`
	Reason     string `json:"reason" jsonschema:"why; recorded in the commit message"`
	DryRun     *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the patch and change nothing"`
}

type writeOut struct {
	DryRun  bool   `json:"dry_run"`
	Applied bool   `json:"applied"`
	Patch   string `json:"patch"`
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit,omitempty"`
	PR      string `json:"pr,omitempty"`
	Verdict string `json:"verdict,omitempty"`
	Note    string `json:"note,omitempty"`
	// NextSteps names the next tool call, or the exact human command at a gate.
	NextSteps []string `json:"next_steps"`
}

func isDry(p *bool) bool { return p == nil || *p }

func (s *srv) addWriteTools(m *mcp.Server) {
	ann := &mcp.ToolAnnotations{DestructiveHint: boolp(false)}
	for _, verb := range []string{"start", "pause", "conclude"} {
		mcp.AddTool(m, &mcp.Tool{Name: verb + "_experiment", Annotations: ann,
			Description: fmt.Sprintf("Set an experiment's status to %q. dry_run (default true) returns the diff; otherwise commits it to a new local branch. Never pushes or merges.", promote.StatusTransitions[verb].To)},
			func(ctx context.Context, _ *mcp.CallToolRequest, in writeIn) (*mcp.CallToolResult, writeOut, error) {
				out, err := s.setStatus(ctx, verb, in)
				return nil, out, err
			})
	}
	mcp.AddTool(m, &mcp.Tool{Name: "propose_promotion", Annotations: ann,
		Description: "Open a PR pointing a ring at a release and concluding the experiment. Requires a promote verdict. dry_run (default true) returns the diff. Never merges."}, s.proposePromotion)
	mcp.AddTool(m, &mcp.Tool{Name: "propose_rollback", Annotations: ann,
		Description: "Pause an experiment and optionally re-point a ring at a known-good release in policy YAML. dry_run (default true) returns the patch; otherwise commits it to a new local branch. Does not retag the registry."}, s.proposeRollback)
	s.addToggleWriteTools(m)
	s.addRolloutWriteTools(m)
}

func boolp(b bool) *bool { return &b }

func need(reason string) (string, error) {
	if r := strings.TrimSpace(reason); r != "" {
		return r, nil
	}
	return "", errors.New("reason is required for write tools")
}

func (s *srv) setStatus(ctx context.Context, verb string, in writeIn) (writeOut, error) {
	reason, err := need(in.Reason)
	if err != nil {
		return writeOut{}, err
	}
	if _, err := s.loadValid(); err != nil {
		return writeOut{}, err
	}
	ref, err := yamledit.Find(s.dir, policy.KindExperiment, in.Name)
	if err != nil {
		return writeOut{}, err
	}
	_, _, data, err := promote.TransitionStatus(ref, verb)
	if err != nil {
		return writeOut{}, err
	}
	// The preview (data) comes from the working tree; the commit re-applies only
	// the status edit to HEAD's version so uncommitted edits are never committed.
	edit := func(read promote.ReadFunc) (map[string][]byte, error) {
		b, err := read(ref.Rel)
		if err != nil {
			return nil, err
		}
		m, err := yamledit.Parse(b, policy.KindExperiment, in.Name)
		if err != nil {
			return nil, fmt.Errorf("parse committed %s: %w", ref.Rel, err)
		}
		if m == nil {
			return nil, fmt.Errorf("experiment %q not found in committed %s", in.Name, ref.Rel)
		}
		_, _, nd, err := promote.TransitionStatus(&yamledit.Doc{Path: ref.Rel, Rel: ref.Rel, Data: b, Mapping: m}, verb)
		if err != nil {
			return nil, err
		}
		return map[string][]byte{ref.Rel: nd}, nil
	}
	return s.finish(ctx, isDry(in.DryRun), map[string][]byte{ref.Rel: data}, edit, "halos/"+verb+"-"+in.Name,
		fmt.Sprintf("halo: %s experiment %s", verb, in.Name), reason)
}

// finish returns the diff of files (the working-tree preview), and when not
// dry-running commits edit's result, applied to HEAD, to a new branch.
func (s *srv) finish(ctx context.Context, dry bool, files map[string][]byte, edit func(promote.ReadFunc) (map[string][]byte, error), branch, subject, reason string) (writeOut, error) {
	patch, err := diffFiles(s.dir, files)
	if err != nil {
		return writeOut{}, err
	}
	out := writeOut{DryRun: dry, Patch: patch}
	if dry {
		out.Note = "dry run: nothing written; pass dry_run=false to commit this to a local branch"
		out.NextSteps = []string{gateApprove}
		if patch == "" {
			out.Note = "dry run: nothing would change (already in that state)"
			out.NextSteps = []string{"nothing to apply; continue with the next step"}
		}
		return out, nil
	}
	branch, c, err := promote.CommitOnBranch(ctx, nil, s.dir, promote.BranchCommit{
		Branch: branch, Subject: subject, Body: "Reason: " + reason, Edit: edit,
	})
	if err != nil {
		return writeOut{}, err
	}
	out.Applied, out.Branch, out.Commit = true, branch, c
	out.Note = "committed locally; push and merge are human steps"
	out.NextSteps = []string{fmt.Sprintf("human gate: git -C %s push -u origin %s && gh pr create --head %s --fill; then review and merge", s.dir, branch, branch)}
	return out, nil
}

// openPR pushes ch as a review branch and opens the PR, the same way
// `halo rollout advance|rollback` does; a human merges it.
func (s *srv) openPR(ctx context.Context, branch, title, body, reason, base string, files map[string][]byte, edit func(promote.ReadFunc) (map[string][]byte, error)) (writeOut, error) {
	patch, err := diffFiles(s.dir, files)
	if err != nil {
		return writeOut{}, err
	}
	url, err := s.prOpener().OpenPR(ctx, promote.PRRequest{RepoDir: s.dir, Base: base, Branch: branch, Title: title,
		Body: "**Reason:** " + reason + "\n\n" + body, CommitBody: "Reason: " + reason, Files: files, Edit: edit})
	if err != nil {
		return writeOut{}, err
	}
	return writeOut{Patch: patch, Applied: true, Branch: branch, PR: url, Note: "PR opened; a human reviews and merges", NextSteps: []string{gateMerge + ": " + url}}, nil
}

func (s *srv) target(org *policy.Org, exp, ring string, needRing bool) (*policy.Experiment, promote.Target, error) {
	t := promote.Target{RepoDir: s.dir}
	e, err := findExp(org, exp)
	if err != nil {
		return nil, t, err
	}
	ee, err := yamledit.Find(s.dir, policy.KindExperiment, e.Name)
	if err != nil {
		return nil, t, err
	}
	t.ExperimentFile = ee.Rel
	if needRing {
		if _, err := findRing(org, ring); err != nil {
			return nil, t, err
		}
		rr, err := yamledit.Find(s.dir, policy.KindRing, ring)
		if err != nil {
			return nil, t, err
		}
		t.RingFile = rr.Rel
	}
	return e, t, nil
}

func (s *srv) proposePromotion(ctx context.Context, _ *mcp.CallToolRequest, in promoteIn) (*mcp.CallToolResult, writeOut, error) {
	reason, err := need(in.Reason)
	if err != nil {
		return nil, writeOut{}, err
	}
	org, err := s.loadValid()
	if err != nil {
		return nil, writeOut{}, err
	}
	e, t, err := s.target(org, in.Experiment, in.Ring, true)
	if err != nil {
		return nil, writeOut{}, err
	}
	ch, err := promote.PlanPromote(t, e, in.Ring, in.Release)
	if err != nil {
		return nil, writeOut{}, err
	}
	out := writeOut{DryRun: isDry(in.DryRun), Patch: ch.Patch, Verdict: "unknown (no ClickHouse configured)"}
	var rep promote.Report
	if s.ClickHouse != nil {
		if rep, err = promote.Evaluate(ctx, e, s.ClickHouse); err != nil {
			return nil, writeOut{}, fmt.Errorf("analyze %s: %w", e.Name, err)
		}
		out.Verdict = string(rep.Verdict)
	}
	if out.DryRun {
		out.Note = "dry run: no PR opened"
		switch {
		case s.ClickHouse == nil:
			out.NextSteps = []string{"a real PR needs a promote verdict: " + gateEvidence}
		case rep.Verdict != promote.Promote:
			out.NextSteps = []string{"verdict is " + out.Verdict + ", not promote: wait_for kind=experiment name=" + e.Name + " before proposing"}
		default:
			out.NextSteps = []string{gateApprove, "the release digest must already be published (halo release publish is the human's step)"}
		}
		return nil, out, nil
	}
	if s.ClickHouse == nil {
		return nil, writeOut{}, errors.New("opening a promotion PR needs evidence: " + gateEvidence)
	}
	o := reasonOpener{reason: reason, gh: s.prOpener()}
	if out.PR, err = promote.OpenPR(ctx, o, t, ch, e, rep, in.Base); err != nil {
		return nil, writeOut{}, err
	}
	out.Applied, out.Note = true, "PR opened; a human reviews and merges"
	out.NextSteps = []string{gateMerge + ": " + out.PR, "after the merge: wait_for kind=rollout (if one backs this experiment) or status to confirm the ring points at the release"}
	return nil, out, nil
}

// reasonOpener adds the reason to the PR body and the commit message.
type reasonOpener struct {
	reason string
	gh     promote.PROpener
}

func (r reasonOpener) OpenPR(ctx context.Context, req promote.PRRequest) (string, error) {
	req.Body = "**Reason:** " + r.reason + "\n\n" + req.Body
	req.CommitBody = "Reason: " + r.reason
	return r.gh.OpenPR(ctx, req)
}

func (s *srv) proposeRollback(ctx context.Context, _ *mcp.CallToolRequest, in rollbackIn) (*mcp.CallToolResult, writeOut, error) {
	reason, err := need(in.Reason)
	if err != nil {
		return nil, writeOut{}, err
	}
	if in.Release != "" && in.Ring == "" {
		return nil, writeOut{}, errors.New("ring is required when release is set")
	}
	org, err := s.loadValid()
	if err != nil {
		return nil, writeOut{}, err
	}
	e, t, err := s.target(org, in.Experiment, in.Ring, in.Release != "")
	if err != nil {
		return nil, writeOut{}, err
	}
	ch, err := promote.PlanRollback(t, e, in.Ring, in.Release)
	if err != nil {
		return nil, writeOut{}, err
	}
	out, err := s.finish(ctx, isDry(in.DryRun), ch.Files, ch.Edit, "halos/rollback-"+e.Name,
		"halo: roll back "+e.Name, reason)
	return nil, out, err
}
