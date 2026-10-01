package mcpserver

import (
	"context"
	"fmt"
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
	return ev, rollout.Evaluate(r, st, ev, now), nil
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
	act, next, verdict := rollout.Rollback, -1, ""
	if advance {
		if st := r.EffectiveStatus(); st == policy.RolloutAborted || st == policy.RolloutCompleted {
			return nil, writeOut{}, fmt.Errorf("rollout %s is %s", r.Name, st)
		}
		_, d, err := s.evaluate(ctx, org, r)
		if err != nil {
			return nil, writeOut{}, err
		}
		if d.Action == rollout.Rollback || d.Action == rollout.Pause {
			return nil, writeOut{}, fmt.Errorf("rollout %s: a gate failed (%s); not proposing an advance", r.Name, strings.Join(d.Reasons, "; "))
		}
		act, next = rollout.NextAction(r)
		verdict = string(d.Action)
	}
	ch, err := rollout.Plan(s.dir, org, r, act, next)
	if err != nil {
		return nil, writeOut{}, err
	}
	out, err := s.finish(ctx, isDry(in.DryRun), ch.Files, ch.Edit, rollout.Branch(r, act, next), "halo: "+strings.ToLower(rollout.Title(r, act, next)), reason)
	if err != nil {
		return nil, writeOut{}, err
	}
	out.Verdict = verdict
	if m := rollout.ManualSteps(org, r, act); len(m) > 0 {
		out.Note += "; manual: " + strings.Join(m, "; ")
	}
	return nil, out, nil
}
