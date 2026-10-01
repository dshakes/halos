package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
)

type empty struct{}

type issue struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

type validateOut struct {
	OK       bool    `json:"ok"`
	Errors   int     `json:"errors"`
	Warnings int     `json:"warnings"`
	Issues   []issue `json:"issues"`
}

type planIn struct {
	Ring           string `json:"ring" jsonschema:"ring to plan"`
	Against        string `json:"against" jsonschema:"path to a baseline release.tar (registry refs are not supported over MCP)"`
	ReleaseVersion string `json:"release_version,omitempty" jsonschema:"release version label (default 0.0.0-dev)"`
}

type planOut struct {
	Changed  bool     `json:"changed"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Versions []string `json:"versions"`
	Diff     string   `json:"diff"`
}

type renderIn struct {
	Ring    string `json:"ring"`
	OS      string `json:"os" jsonschema:"darwin, linux or windows"`
	Harness string `json:"harness,omitempty" jsonschema:"limit to one harness (default all)"`
}

type renderedFile struct {
	Harness string `json:"harness"`
	Path    string `json:"path"`
	Mode    uint32 `json:"mode"`
	Content string `json:"content"`
}

type renderOut struct {
	Files    []renderedFile `json:"files"`
	Warnings []string       `json:"warnings"`
}

type whoamiIn struct {
	User   string   `json:"user"`
	Groups []string `json:"groups,omitempty"`
}

type assignment struct {
	Experiment string `json:"experiment"`
	Variant    string `json:"variant"`
}

type whoamiOut struct {
	User        string       `json:"user"`
	Groups      []string     `json:"groups"`
	Ring        string       `json:"ring"`
	Profile     string       `json:"profile"`
	Experiments []assignment `json:"experiments"`
}

type nameIn struct {
	Name string `json:"name" jsonschema:"experiment name"`
}

type diffIn struct {
	From string `json:"from" jsonschema:"path to the older release.tar"`
	To   string `json:"to" jsonschema:"path to the newer release.tar"`
}

type scorecardIn struct {
	Path string `json:"path" jsonschema:"scorecard .json file under the policy dir or the working directory"`
}

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true}

func (s *srv) addReadTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "validate", Description: "Load and validate the policy repo.", Annotations: readOnly}, s.validate)
	mcp.AddTool(m, &mcp.Tool{Name: "plan", Description: "Diff the release a ring would get against a baseline release.tar.", Annotations: readOnly}, s.plan)
	mcp.AddTool(m, &mcp.Tool{Name: "render_preview", Description: "Render a ring's harness config files for an OS and return their contents. Writes nothing.", Annotations: readOnly}, s.renderPreview)
	mcp.AddTool(m, &mcp.Tool{Name: "whoami", Description: "Show the ring and experiment variants a user would be assigned.", Annotations: readOnly}, s.whoami)
	mcp.AddTool(m, &mcp.Tool{Name: "list_rings", Description: "List rollout rings in order.", Annotations: readOnly}, s.listRings)
	mcp.AddTool(m, &mcp.Tool{Name: "list_experiments", Description: "List experiments.", Annotations: readOnly}, s.listExperiments)
	mcp.AddTool(m, &mcp.Tool{Name: "show_experiment", Description: "Show one experiment definition.", Annotations: readOnly}, s.showExperiment)
	mcp.AddTool(m, &mcp.Tool{Name: "harness_matrix", Description: "Capability matrix of registered harness adapters.", Annotations: readOnly}, s.harnessMatrix)
	mcp.AddTool(m, &mcp.Tool{Name: "explain_release_diff", Description: "Diff two release.tar files and summarise per-harness version changes.", Annotations: readOnly}, s.explainDiff)
	mcp.AddTool(m, &mcp.Tool{Name: "eval_scorecard", Description: "Read an eval scorecard JSON file produced by `halo eval run --output json`.", Annotations: readOnly}, s.evalScorecard)
	s.addEvalTools(m)
	s.addToggleReadTools(m)
	s.addRolloutReadTools(m)
	if s.ClickHouse != nil {
		mcp.AddTool(m, &mcp.Tool{Name: "analyze_experiment", Description: "Evaluate experiment evidence from ClickHouse: verdict promote|rollback|continue|expired.", Annotations: readOnly}, s.analyze)
	}
}

func (s *srv) validate(_ context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, validateOut, error) {
	org, err := s.load()
	if err != nil {
		return nil, validateOut{}, err
	}
	out := validateOut{Issues: []issue{}}
	for _, i := range org.Validate() {
		out.Issues = append(out.Issues, issue{string(i.Severity), i.Path, i.Message})
		if i.Severity == policy.SeverityError {
			out.Errors++
		} else {
			out.Warnings++
		}
	}
	out.OK = out.Errors == 0
	return nil, out, nil
}

func (s *srv) buildRelease(ring, ver string, oses ...harness.OS) (*release.Release, error) {
	org, err := s.loadValid()
	if err != nil {
		return nil, err
	}
	r, err := findRing(org, ring)
	if err != nil {
		return nil, err
	}
	if ver == "" {
		ver = "0.0.0-dev"
	}
	rel, err := release.Build(org, r.Profile, ring, release.Options{Version: ver, OSes: oses})
	if err != nil {
		return nil, fmt.Errorf("build release for ring %s: %w", ring, err)
	}
	return rel, nil
}

func openRelease(p string) (*release.Release, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read release %s: %w", p, err)
	}
	rel, err := release.Open(b)
	if err != nil {
		return nil, fmt.Errorf("open release %s: %w", p, err)
	}
	return rel, nil
}

func (s *srv) plan(_ context.Context, _ *mcp.CallToolRequest, in planIn) (*mcp.CallToolResult, planOut, error) {
	cur, err := s.buildRelease(in.Ring, in.ReleaseVersion)
	if err != nil {
		return nil, planOut{}, err
	}
	prev, err := openRelease(in.Against)
	if err != nil {
		return nil, planOut{}, err
	}
	return nil, diffOut(prev, cur), nil
}

func diffOut(prev, cur *release.Release) planOut {
	d := release.Diff(prev, cur)
	return planOut{Changed: d != "", From: prev.Digest, To: cur.Digest, Versions: versionBumps(prev, cur), Diff: d}
}

func versionBumps(prev, cur *release.Release) []string {
	seen := map[string]bool{}
	var names []string
	for _, hs := range []map[string]release.HarnessEntry{prev.Manifest.Harnesses, cur.Manifest.Harnesses} {
		for n := range hs {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	out := []string{}
	for _, n := range names {
		p, hadP := prev.Manifest.Harnesses[n]
		c, hadC := cur.Manifest.Harnesses[n]
		switch {
		case !hadP:
			out = append(out, fmt.Sprintf("%s: added at %s", n, c.Version))
		case !hadC:
			out = append(out, fmt.Sprintf("%s: removed (was %s)", n, p.Version))
		case p.Version != c.Version:
			out = append(out, fmt.Sprintf("%s: %s -> %s", n, p.Version, c.Version))
		default:
			out = append(out, fmt.Sprintf("%s: %s (unchanged)", n, c.Version))
		}
	}
	return out
}

func (s *srv) explainDiff(_ context.Context, _ *mcp.CallToolRequest, in diffIn) (*mcp.CallToolResult, planOut, error) {
	a, err := openRelease(in.From)
	if err != nil {
		return nil, planOut{}, err
	}
	b, err := openRelease(in.To)
	if err != nil {
		return nil, planOut{}, err
	}
	return nil, diffOut(a, b), nil
}

func (s *srv) renderPreview(_ context.Context, _ *mcp.CallToolRequest, in renderIn) (*mcp.CallToolResult, renderOut, error) {
	switch in.OS {
	case "darwin", "linux", "windows":
	default:
		return nil, renderOut{}, fmt.Errorf("os must be darwin, linux or windows, got %q", in.OS)
	}
	rel, err := s.buildRelease(in.Ring, "", harness.OS(in.OS))
	if err != nil {
		return nil, renderOut{}, err
	}
	out := renderOut{Files: []renderedFile{}, Warnings: rel.Manifest.Warnings}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	hs := make([]string, 0, len(rel.Manifest.Harnesses))
	for h := range rel.Manifest.Harnesses {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	found := in.Harness == ""
	for _, h := range hs {
		if in.Harness != "" && h != in.Harness {
			continue
		}
		found = true
		for _, f := range rel.Manifest.Harnesses[h].Files[in.OS] {
			data, ok := rel.Content(f)
			if !ok {
				return nil, renderOut{}, fmt.Errorf("release is missing blob for %s", f.Path)
			}
			out.Files = append(out.Files, renderedFile{h, f.Path, f.Mode, string(data)})
		}
	}
	if !found {
		return nil, renderOut{}, fmt.Errorf("harness %q not enabled for ring %s (have: %s)", in.Harness, in.Ring, strings.Join(hs, ", "))
	}
	return nil, out, nil
}

func (s *srv) whoami(_ context.Context, _ *mcp.CallToolRequest, in whoamiIn) (*mcp.CallToolResult, whoamiOut, error) {
	if in.User == "" {
		return nil, whoamiOut{}, errors.New("user is required")
	}
	org, err := s.load()
	if err != nil {
		return nil, whoamiOut{}, err
	}
	sub := policy.Subject{ID: in.User, Groups: in.Groups}
	out := whoamiOut{User: in.User, Groups: in.Groups, Experiments: []assignment{}}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	if ring := org.ResolveRing(sub); ring != nil {
		out.Ring, out.Profile = ring.Name, ring.Profile
		for _, e := range org.Experiments {
			if e.Status != "running" {
				continue
			}
			if v := e.ResolveVariant(sub, ring.Name); v != nil {
				out.Experiments = append(out.Experiments, assignment{e.Name, v.Name})
			}
		}
	}
	return nil, out, nil
}

func (s *srv) listRings(context.Context, *mcp.CallToolRequest, empty) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	rs := make([]map[string]any, 0, len(org.Rings))
	for _, r := range org.Rings {
		m, err := toMap(r)
		if err != nil {
			return nil, nil, err
		}
		rs = append(rs, m)
	}
	return nil, map[string]any{"rings": rs}, nil
}

func (s *srv) listExperiments(context.Context, *mcp.CallToolRequest, empty) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	es := make([]map[string]any, 0, len(org.Experiments))
	for _, e := range org.Experiments {
		m, err := toMap(e)
		if err != nil {
			return nil, nil, err
		}
		es = append(es, m)
	}
	return nil, map[string]any{"experiments": es}, nil
}

func (s *srv) showExperiment(_ context.Context, _ *mcp.CallToolRequest, in nameIn) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	e, err := findExp(org, in.Name)
	if err != nil {
		return nil, nil, err
	}
	m, err := toMap(e)
	return nil, m, err
}

func (s *srv) harnessMatrix(context.Context, *mcp.CallToolRequest, empty) (*mcp.CallToolResult, map[string]any, error) {
	return nil, map[string]any{"harnesses": harness.Matrix()}, nil
}

func (s *srv) evalScorecard(_ context.Context, _ *mcp.CallToolRequest, in scorecardIn) (*mcp.CallToolResult, map[string]any, error) {
	p, err := filepath.Abs(in.Path)
	if err != nil {
		return nil, nil, err
	}
	cwd, _ := os.Getwd()
	if !strings.HasSuffix(p, ".json") || (!within(s.dir, p) && !within(cwd, p)) {
		return nil, nil, fmt.Errorf("scorecard must be a .json file under the policy dir or working directory, got %q", in.Path)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, fmt.Errorf("read scorecard: %w", err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, nil, fmt.Errorf("parse scorecard %s: %w", in.Path, err)
	}
	return nil, map[string]any{"scorecard": v}, nil
}

func (s *srv) analyze(ctx context.Context, _ *mcp.CallToolRequest, in nameIn) (*mcp.CallToolResult, map[string]any, error) {
	org, err := s.load()
	if err != nil {
		return nil, nil, err
	}
	e, err := findExp(org, in.Name)
	if err != nil {
		return nil, nil, err
	}
	rep, err := promote.Evaluate(ctx, e, s.ClickHouse)
	if err != nil {
		return nil, nil, fmt.Errorf("analyze %s: %w", in.Name, err)
	}
	m, err := toMap(rep)
	return nil, m, err
}
