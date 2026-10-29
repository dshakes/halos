package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

type rolloutIn struct {
	Name string `json:"name" jsonschema:"rollout name"`
}

type rolloutWriteIn struct {
	Name   string `json:"name" jsonschema:"rollout name"`
	Reason string `json:"reason" jsonschema:"why; recorded in the commit message"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the diff and change nothing"`
	OpenPR bool   `json:"open_pr,omitempty" jsonschema:"with dry_run false: push a review branch and open the PR (like halo rollout advance) instead of committing locally"`
	Base   string `json:"base,omitempty" jsonschema:"PR base branch (default: repo default)"`
}

func findRollout(org *policy.Org, name string) (*policy.Rollout, error) {
	for _, r := range org.Rollouts {
		if r.Name == name {
			return r, nil
		}
	}
	return nil, fmt.Errorf("unknown rollout %q", name)
}

func (s *srv) addRolloutReadTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "list_rollouts", Description: "List phased rollouts with their status, live step and step timeline.", Annotations: readOnly}, s.listRollouts)
	mcp.AddTool(m, &mcp.Tool{Name: "rollout_status", Description: "Evaluate a rollout's live step: gate values vs thresholds and the next action (advance|hold|rollback|pause|complete). Metric gates need --clickhouse; bake time is unknown without the controller's state.", Annotations: readOnly}, s.rolloutStatus)
}

func (s *srv) addRolloutWriteTools(m *mcp.Server) {
	ann := &mcp.ToolAnnotations{DestructiveHint: boolp(false)}
	mcp.AddTool(m, &mcp.Tool{Name: "propose_rollout_advance", Annotations: ann,
		Description: "Move a rollout to its next step (or complete it) in policy YAML. Refused when a gate failed. dry_run (default true) returns the diff; otherwise commits it to a new local branch. Never pushes or merges."}, s.proposeRolloutAdvance)
	mcp.AddTool(m, &mcp.Tool{Name: "propose_rollout_rollback", Annotations: ann,
		Description: "Abort a rollout in policy YAML: experiment paused, rings re-pointed at baseline.release. dry_run (default true) returns the patch; otherwise commits it to a new local branch. Does not trip the kill switch or retag the registry."}, s.proposeRolloutRollback)
}

func (s *srv) listRollouts(context.Context, *mcp.CallToolRequest, empty) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	rs := make([]map[string]any, 0, len(org.Rollouts))
	for _, r := range org.Rollouts {
		m, err := toMap(rollout.BuildTimeline(org, r))
		if err != nil {
			return nil, nil, err
		}
		m["step"] = r.Step
		rs = append(rs, m)
	}
	return nil, map[string]any{"rollouts": rs}, nil
}

// evaluate is the rollout's live decision on the policy alone plus ClickHouse
// when configured (MCP has no controller state: bake time is unknown).
func (s *srv) evaluate(ctx context.Context, org *policy.Org, r *policy.Rollout) (rollout.Evidence, rollout.Decision, error) {
	var ms promote.MetricSource
	if s.ClickHouse != nil {
		ms = s.ClickHouse
	}
	now := time.Now()
	st := rollout.PolicyState(r)
	ev, err := rollout.Gather(ctx, s.dir, org, r, st, ms, now)
	if err != nil {
		return ev, rollout.Decision{}, err
	}
	g, _, err := s.governance(ctx, r)
	if err != nil {
		return ev, rollout.Decision{}, err
	}
	g.Apply(org, r, st, &ev, now)
	return ev, rollout.Evaluate(rollout.Effective(org, r), st, ev, now), nil
}

// governance reads halo-server's incident freeze and, for r (nil = none),
// the live step's approvals and the session's user (ADR-0030). ok is false
// without --server and HALO_SESSION: policy freeze windows only, no approvals.
func (s *srv) governance(ctx context.Context, r *policy.Rollout) (g rollout.Governance, ok bool, err error) {
	if s.serverURL() == "" || s.session() == "" {
		return g, false, nil
	}
	var fz struct {
		Incident *policy.ActiveFreeze `json:"incident"`
	}
	if err := s.serverInto(ctx, "/api/v1/freeze", &fz); err != nil {
		return g, false, fmt.Errorf("read the incident freeze: %w", err)
	}
	g.Incident = fz.Incident
	if r == nil {
		return g, true, nil
	}
	var ap struct {
		Approvals []policy.Approval `json:"approvals"`
	}
	var me struct {
		ID string `json:"id"`
	}
	if err := s.serverInto(ctx, "/api/v1/rollouts/"+url.PathEscape(r.Name)+"/approvals", &ap); err != nil {
		return g, false, fmt.Errorf("read rollout approvals: %w", err)
	}
	if err := s.serverInto(ctx, "/api/v1/me", &me); err != nil {
		return g, false, err
	}
	g.Approvals, g.Requester = ap.Approvals, me.ID
	return g, true, nil
}

// noIncidentFreeze is the warning on a forward change proposed without
// halo-server: the policy's freeze windows were checked, the incident freeze
// was not (the controller and halo freeze check --server still hold it).
const noIncidentFreeze = "incident freeze not checked: no halo-server configured, only the policy's freeze windows were (start the MCP server with --server and HALO_SESSION)"

// warnNoIncidentFreeze adds noIncidentFreeze to out's note and next steps.
func warnNoIncidentFreeze(out *writeOut) {
	out.Note += "; warning: " + noIncidentFreeze
	out.NextSteps = append(out.NextSteps, "before the merge, check the incident freeze: halo freeze status --server URL")
}

// serverInto GETs path from halo-server into out.
func (s *srv) serverInto(ctx context.Context, path string, out any) error {
	m, err := s.serverJSON(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// governanceBlock is why a forward change may not be proposed: a freeze, or
// a short approval quorum ("" when neither).
func governanceBlock(d rollout.Decision, governed bool) string {
	if d.Frozen != "" {
		return d.Frozen
	}
	if q := d.Quorum; q != nil && !q.Met {
		msg := "approvals needed: " + q.String() + " (an approver runs halo rollout approve)"
		if !governed {
			msg += "; approvals are recorded on halo-server: start the MCP server with --server and HALO_SESSION"
		}
		return msg
	}
	return ""
}

func (s *srv) rolloutStatus(ctx context.Context, _ *mcp.CallToolRequest, in rolloutIn) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	r, err := findRollout(org, in.Name)
	if err != nil {
		return nil, nil, err
	}
	ev, d, err := s.evaluate(ctx, org, r)
	if err != nil {
		return nil, nil, err
	}
	m, err := toMap(map[string]any{"rollout": r.Name, "status": r.EffectiveStatus(), "step": r.Step,
		"timeline": rollout.BuildTimeline(org, r), "evidence": ev, "decision": d})
	return nil, m, err
}

func (s *srv) proposeRolloutAdvance(ctx context.Context, _ *mcp.CallToolRequest, in rolloutWriteIn) (*mcp.CallToolResult, writeOut, error) {
	return s.proposeRollout(ctx, in, true)
}

func (s *srv) proposeRolloutRollback(ctx context.Context, _ *mcp.CallToolRequest, in rolloutWriteIn) (*mcp.CallToolResult, writeOut, error) {
	return s.proposeRollout(ctx, in, false)
}

func (s *srv) proposeRollout(ctx context.Context, in rolloutWriteIn, advance bool) (*mcp.CallToolResult, writeOut, error) {
	reason, err := need(in.Reason)
	if err != nil {
		return nil, writeOut{}, err
	}
	org, err := s.loadValid()
	if err != nil {
		return nil, writeOut{}, err
	}
	r, err := findRollout(org, in.Name)
	if err != nil {
		return nil, writeOut{}, err
	}
	act, next, verdict, block := rollout.Rollback, -1, "", ""
	var d rollout.Decision
	governed := s.serverURL() != "" && s.session() != "" // evaluate read it (or failed)
	if advance {
		if st := r.EffectiveStatus(); st == policy.RolloutAborted || st == policy.RolloutCompleted {
			return nil, writeOut{}, fmt.Errorf("rollout %s is %s", r.Name, st)
		}
		if _, d, err = s.evaluate(ctx, org, r); err != nil {
			return nil, writeOut{}, err
		}
		if d.Action == rollout.Rollback || d.Action == rollout.Pause {
			return nil, writeOut{}, fmt.Errorf("rollout %s: a gate failed (%s); not proposing an advance", r.Name, strings.Join(d.Reasons, "; "))
		}
		if block = governanceBlock(d, governed); block != "" && !isDry(in.DryRun) {
			return nil, writeOut{}, fmt.Errorf("rollout %s: %s; not proposing an advance (rollbacks are always allowed: propose_rollout_rollback)", r.Name, block)
		}
		act, next = rollout.NextAction(r)
		verdict = string(d.Action)
	}
	ch, err := rollout.Plan(s.dir, org, r, act, next)
	if err != nil {
		return nil, writeOut{}, err
	}
	manual := rollout.ManualSteps(org, r, act)
	var out writeOut
	if in.OpenPR && !isDry(in.DryRun) {
		intro := fmt.Sprintf("Proposed %s of rollout `%s` (step `%s`), opened through the Halos MCP server.", act, r.Name, r.Step)
		out, err = s.openPR(ctx, rollout.Branch(r, act, next), rollout.Title(r, act, next), rollout.Body(intro, d, manual, ch.Patch), reason, in.Base, ch.Files, ch.Edit)
	} else {
		out, err = s.finish(ctx, isDry(in.DryRun), ch.Files, ch.Edit, rollout.Branch(r, act, next), "halo: "+strings.ToLower(rollout.Title(r, act, next)), reason)
	}
	if err != nil {
		return nil, writeOut{}, err
	}
	out.Verdict = verdict
	if block != "" { // dry run only: a real proposal was refused above
		out.Note += "; refused if applied now: " + block
		out.NextSteps = []string{"wait: " + block, "rollbacks are never blocked: propose_rollout_rollback"}
	}
	if len(manual) > 0 {
		out.Note += "; manual: " + strings.Join(manual, "; ")
		out.NextSteps = append(out.NextSteps, "human steps after the merge: "+strings.Join(manual, "; "))
	}
	if advance && !governed {
		warnNoIncidentFreeze(&out)
	}
	if !advance && r.Experiment != "" {
		out.NextSteps = append(out.NextSteps, "for an immediate stop before this merges: kill_switch name="+r.Name+" (dry_run first)")
	}
	return nil, out, nil
}
