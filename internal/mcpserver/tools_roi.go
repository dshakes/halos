package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/roi"
)

type roiIn struct {
	Experiment string   `json:"experiment,omitempty" jsonschema:"experiment whose variants are the arms (randomized: causal effects)"`
	Rings      []string `json:"rings,omitempty" jsonschema:"compare these rings instead, the first as baseline (observational: associations, never effects)"`
	Since      string   `json:"since,omitempty" jsonschema:"window start, YYYY-MM-DD or RFC 3339; default: the experiment's first telemetry (needs --clickhouse)"`
	Until      string   `json:"until,omitempty" jsonschema:"window end; default now"`
}

const gateROI = "delivery ROI is off: a human restarts with `halo mcp serve --roi-identities <roster.csv>` and either --clickhouse <url> or --roi-store <prs.jsonl>, after importing outcomes with `halo roi ingest github|file`"

// roiConfigured reports whether roi_report and the PR section have sources.
func (s *srv) roiConfigured() bool {
	return s.ROIIdentities != "" && (s.ClickHouse != nil || s.ROIStore != "")
}

// roiReport is `halo roi report` over MCP. Read-only: it reads the
// server-configured roster and stores; paths are never tool arguments.
func (s *srv) roiReport(ctx context.Context, _ *mcp.CallToolRequest, in roiIn) (*mcp.CallToolResult, map[string]any, error) {
	if !s.roiConfigured() {
		return nil, map[string]any{"configured": false, "next_steps": []string{gateROI}}, nil
	}
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	var e *policy.Experiment
	if in.Experiment != "" {
		if e, err = findExp(org, in.Experiment); err != nil {
			return nil, nil, err
		}
	}
	rep, err := s.roiAnalyze(ctx, roi.Options{Org: org, Experiment: e, Rings: in.Rings}, in.Since, in.Until)
	if err != nil {
		return nil, nil, err
	}
	m, err := toMap(rep)
	if err != nil {
		return nil, nil, err
	}
	return nil, map[string]any{"configured": true, "report": m, "next_steps": roiNextSteps(rep)}, nil
}

func (s *srv) roiAnalyze(ctx context.Context, o roi.Options, since, until string) (*roi.Report, error) {
	ids, err := roi.LoadIdentities(s.ROIIdentities)
	if err != nil {
		return nil, err
	}
	st, cost, err := roi.Open(s.ClickHouse, s.ROIStore)
	if err != nil {
		return nil, err
	}
	if o.From, o.To, err = roi.Window(ctx, s.ClickHouse, o.Experiment, since, until, time.Now()); err != nil {
		return nil, fmt.Errorf("roi_report: %w", err)
	}
	return roi.Analyze(ctx, st, cost, ids, o)
}

func roiNextSteps(rep *roi.Report) []string {
	var next []string
	switch rep.Status {
	case roi.StatusSRM:
		next = append(next, "sample ratio mismatch: do not report these effects; find why developers are missing from one arm (roster groups, ingest gaps, attrition) before using them")
	case roi.StatusInsufficientData:
		next = append(next, "not enough developers with PRs per arm yet: re-run after more PRs land (a human re-runs `halo roi ingest` over the window)")
	}
	if len(rep.UnmappedLogins) > 0 {
		next = append(next, "authors missing from the roster ("+strings.Join(rep.UnmappedLogins, ", ")+"): a human adds them to the identity roster CSV")
	}
	if rep.Design == roi.DesignObservational {
		next = append(next, "observational: present differences as associations only; for a causal estimate start an experiment over these rings (start_experiment, human gate)")
	} else if rep.Status == roi.StatusOK {
		next = append(next, "informational: quote the effects with their CIs and states in the promotion review; propose_promotion adds this section to the PR body; it is never a promotion gate")
	}
	return next
}

// roiSection is the PR-body section for propose_promotion over [the
// experiment's first telemetry, now): "" when ROI is not configured, there is
// no ClickHouse to date the window (a promotion PR needs it anyway) or no
// data. The caller turns an error into a note; it never blocks.
func (s *srv) roiSection(ctx context.Context, org *policy.Org, e *policy.Experiment) (string, error) {
	if !s.roiConfigured() || s.ClickHouse == nil {
		return "", nil
	}
	ids, err := roi.LoadIdentities(s.ROIIdentities)
	if err != nil {
		return "", err
	}
	st, cost, err := roi.Open(s.ClickHouse, s.ROIStore)
	if err != nil {
		return "", err
	}
	from, to, err := roi.Window(ctx, s.ClickHouse, e, "", "", time.Now())
	if err != nil {
		return "", err
	}
	return roi.PromotionSection(ctx, st, cost, ids, org, e, from, to)
}

func (s *srv) addROITools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "roi_report", Annotations: readOnly,
		Description: "Delivery ROI (ADR-0027): PR cycle time, merged PRs per developer-week, review rounds, change-failure rate and lines changed per experiment arm, with developer-clustered bootstrap CIs, an SRM check, novelty time slices and cost per merged PR. Only an experiment's arms are randomized (causal); rings are observational (associations). Read-only and informational: it never promotes."}, s.roiReport)
}
