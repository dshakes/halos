package mcpserver

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/rollout"
)

// The autopilot tools let an agent drive the whole lifecycle hands-off and
// stop at the human gates: one-call status, a release build preview, bounded
// waits on evidence, the fleet plane (kill switch, audit, devices) and an eval
// run. Every output carries next_steps naming the next tool call or the exact
// human command. None of them publishes, retags, merges or pushes.

//go:embed autopilot.md
var autopilotGuide string

const (
	guideURI    = "halos://guide/autopilot"
	waitMax     = 600 * time.Second
	evalRunMax  = 2 * time.Hour
	serverLimit = 1 << 20 // bytes of a halo-server reply we read
)

// gate names the human steps as the tools print them.
const (
	gateApprove  = "human gate: show the patch and wait for a yes; then call again with dry_run false"
	gateMerge    = "human gate: review and merge the PR; nothing merges itself"
	gatePublish  = "human gate (publishes to the registry): halo release publish <policy-dir> --ring %s --release-version %s --key <release.key> --registry <registry>"
	gateAllowW   = "write tools are off: ask the human to restart with `halo mcp serve --allow-writes` (dry runs still work)"
	gateEvidence = "no evidence source: ask the human to restart with `halo mcp serve --clickhouse <url>`; without it analyze_experiment and wait_for cannot decide"
	gateServer   = "halo-server is not configured: start the MCP server with --server <url> (or HALO_SERVER) and export HALO_SESSION (an admin halo_session cookie value)"
)

type statusOut struct {
	Org    string `json:"org"`
	Policy struct {
		OK       bool `json:"ok"`
		Errors   int  `json:"errors"`
		Warnings int  `json:"warnings"`
	} `json:"policy"`
	Server struct {
		Version      string `json:"version"`
		PolicyDir    string `json:"policy_dir"`
		AllowWrites  bool   `json:"allow_writes"`
		ClickHouse   bool   `json:"clickhouse"`
		HaloServer   string `json:"halo_server,omitempty"`
		AdminSession bool   `json:"admin_session"`
	} `json:"server"`
	Rings       []ringRow      `json:"rings"`
	Experiments []expRow       `json:"experiments"`
	Rollouts    []rolloutRow   `json:"rollouts"`
	Toggles     int            `json:"toggles"`
	KillSwitch  *killListOut   `json:"kill_switch,omitempty"`
	Fleet       map[string]any `json:"fleet,omitempty"`
	FleetError  string         `json:"fleet_error,omitempty"`
	NextSteps   []string       `json:"next_steps"`
}

type ringRow struct {
	Name    string `json:"name"`
	Order   int    `json:"order"`
	Profile string `json:"profile"`
	Release string `json:"release,omitempty"`
}

type expRow struct {
	Name   string   `json:"name"`
	Status string   `json:"status"`
	Type   string   `json:"type"`
	Axis   string   `json:"axis"`
	Rings  []string `json:"rings"`
	Killed bool     `json:"killed,omitempty"`
}

type rolloutRow struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	Step       string `json:"step,omitempty"`
	Experiment string `json:"experiment,omitempty"`
}

type killListOut struct {
	Configured bool             `json:"configured"`
	Version    uint64           `json:"version,omitempty"`
	Killed     []map[string]any `json:"killed"`
	Reason     string           `json:"reason,omitempty"`
	NextSteps  []string         `json:"next_steps,omitempty"`
}

type releaseBuildIn struct {
	Ring           string `json:"ring" jsonschema:"ring to build for"`
	ReleaseVersion string `json:"release_version,omitempty" jsonschema:"version label (default 0.0.0-dev)"`
}

type releaseBuildOut struct {
	Ring      string            `json:"ring"`
	Profile   string            `json:"profile"`
	Version   string            `json:"version"`
	Digest    string            `json:"digest"`
	Harnesses map[string]string `json:"harnesses"`
	Files     []string          `json:"files"`
	Warnings  []string          `json:"warnings"`
	NextSteps []string          `json:"next_steps"`
}

type waitIn struct {
	Kind            string `json:"kind" jsonschema:"experiment or rollout"`
	Name            string `json:"name"`
	TimeoutSeconds  int    `json:"timeout_seconds,omitempty" jsonschema:"stop polling after this long (default 60, max 600); call again to keep waiting"`
	IntervalSeconds int    `json:"interval_seconds,omitempty" jsonschema:"seconds between polls (default 10)"`
}

type waitOut struct {
	Kind           string         `json:"kind"`
	Name           string         `json:"name"`
	Satisfied      bool           `json:"satisfied"`
	Outcome        string         `json:"outcome,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	Polls          int            `json:"polls"`
	ElapsedSeconds float64        `json:"elapsed_seconds"`
	Last           map[string]any `json:"last,omitempty"`
	NextSteps      []string       `json:"next_steps"`
}

type auditIn struct {
	Limit int    `json:"limit,omitempty" jsonschema:"entries to return, newest last (default server default)"`
	Since string `json:"since,omitempty" jsonschema:"sequence number or RFC3339 time to start from"`
}

type killIn struct {
	Name   string `json:"name" jsonschema:"experiment, toggle or rollout name"`
	Kind   string `json:"kind,omitempty" jsonschema:"experiment | toggle | rollout, when the name is ambiguous"`
	Reason string `json:"reason" jsonschema:"why; recorded in halo-server's audit log"`
	Unkill bool   `json:"unkill,omitempty" jsonschema:"clear the kill instead"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the request and the halo command, send nothing"`
}

type killOut struct {
	DryRun    bool           `json:"dry_run"`
	Applied   bool           `json:"applied"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	Request   string         `json:"request"`
	Command   string         `json:"command"`
	Result    map[string]any `json:"result,omitempty"`
	Note      string         `json:"note,omitempty"`
	NextSteps []string       `json:"next_steps"`
}

type evalRunIn struct {
	Suite          string `json:"suite" jsonschema:"eval suite YAML under the policy dir"`
	Matrix         bool   `json:"matrix,omitempty" jsonschema:"run the suite's harness x model x provider matrix"`
	Local          bool   `json:"local,omitempty" jsonschema:"run on the host instead of Docker (no isolation; testing only)"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"kill the run after this long (default 1800, max 7200)"`
	DryRun         *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the command and what it would run; false runs it (spends credentials; needs --allow-writes)"`
}

type evalRunOut struct {
	DryRun    bool           `json:"dry_run"`
	Ran       bool           `json:"ran"`
	Command   string         `json:"command"`
	Scorecard map[string]any `json:"scorecard,omitempty"`
	Path      string         `json:"scorecard_path,omitempty"`
	ExitCode  int            `json:"exit_code,omitempty"`
	Stderr    string         `json:"stderr,omitempty"`
	NextSteps []string       `json:"next_steps"`
}

func (s *srv) addAutopilotTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "status", Annotations: readOnly,
		Description: "One call: policy health, rings with their pinned release, experiments, rollouts, toggles, what this server can do (writes, ClickHouse, halo-server) and the kill switch when halo-server is configured. Ends with next_steps."}, s.status)
	mcp.AddTool(m, &mcp.Tool{Name: "release_build", Annotations: readOnly,
		Description: "Build a ring's release in memory (the `halo release build` dry run): digest, per-harness versions, file list and adapter warnings. Publishing it to the registry is the human's `halo release publish`, printed in next_steps."}, s.releaseBuild)
	mcp.AddTool(m, &mcp.Tool{Name: "wait_for", Annotations: readOnly,
		Description: "Poll an experiment (until analyze_experiment's verdict leaves `continue`; needs --clickhouse) or a rollout (until its decision leaves `hold`) with a bounded timeout. Returns the latest evidence either way; call again to keep waiting."}, s.waitFor)
	mcp.AddTool(m, &mcp.Tool{Name: "kill_switch_status", Annotations: readOnly,
		Description: "The kill list halo-server is serving (experiments and toggles killed fleet-wide). Needs --server/HALO_SERVER and HALO_SESSION; otherwise says so with the fix."}, s.killSwitchStatus)
	mcp.AddTool(m, &mcp.Tool{Name: "fleet_status", Annotations: readOnly,
		Description: "Devices halo-server knows: hosts per ring, drift count, last report, releases applied. Needs --server/HALO_SERVER and HALO_SESSION."}, s.fleetStatus)
	mcp.AddTool(m, &mcp.Tool{Name: "audit_tail", Annotations: readOnly,
		Description: "Tail halo-server's audit log (kills, status changes, enrollments, approvals). Needs --server/HALO_SERVER and HALO_SESSION."}, s.auditTail)
	mcp.AddTool(m, &mcp.Tool{Name: "kill_switch", Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(false), IdempotentHint: true, OpenWorldHint: boolp(true)},
		Description: "Kill (or unkill) an experiment, toggle or rollout fleet-wide through halo-server's signed kill list: the fast rollback, effective at the next poll and reversible. dry_run (default true) returns the request and the `halo kill` command; false sends it and, like every write, needs --allow-writes plus a reason. Never edits policy: pair it with propose_rollback or propose_rollout_rollback."}, s.killSwitch)
	mcp.AddTool(m, &mcp.Tool{Name: "eval_run", Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(false), OpenWorldHint: boolp(true)},
		Description: "Run an eval suite (`halo eval run --output json`) and return the scorecard. dry_run (default true) returns the command and the matrix cells; false runs it with a bounded timeout and, since it spends credentials and compute, needs --allow-writes. Writes the scorecard under <policy>/.halos/scorecards."}, s.evalRun)
	m.AddResource(&mcp.Resource{URI: guideURI, Name: "autopilot guide", MIMEType: "text/markdown",
		Description: "What Halos is, the invariants an agent must respect, the full lifecycle and where the human gates are"},
		func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: req.Params.URI, MIMEType: "text/markdown", Text: autopilotGuide}}}, nil
		})
}

// ---- status ----

func (s *srv) status(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, statusOut, error) {
	var out statusOut
	out.Rings, out.Experiments, out.Rollouts, out.NextSteps = []ringRow{}, []expRow{}, []rolloutRow{}, []string{}
	out.Server.Version, out.Server.PolicyDir, out.Server.AllowWrites, out.Server.ClickHouse = s.Version, s.dir, s.AllowWrites, s.ClickHouse != nil
	out.Server.HaloServer, out.Server.AdminSession = s.serverURL(), s.session() != ""
	org, err := s.load()
	if err != nil {
		out.NextSteps = append(out.NextSteps, "policy does not load: "+err.Error())
		return nil, out, nil
	}
	out.Org = org.Name
	for _, i := range org.Validate() {
		if i.Severity == policy.SeverityError {
			out.Policy.Errors++
		} else {
			out.Policy.Warnings++
		}
	}
	out.Policy.OK = out.Policy.Errors == 0
	for _, r := range org.Rings {
		out.Rings = append(out.Rings, ringRow{r.Name, r.Order, r.Profile, r.Release})
	}
	killed := map[string]bool{}
	if out.Server.HaloServer != "" && out.Server.AdminSession {
		kl := s.killList(ctx)
		out.KillSwitch = &kl
		for _, k := range kl.Killed {
			if n, _ := k["experiment"].(string); n != "" {
				killed[n] = true
			}
		}
		if f, err := s.serverJSON(ctx, "GET", "/api/v1/fleet", nil); err != nil {
			out.FleetError = err.Error()
		} else {
			out.Fleet = map[string]any{"total": f["total"], "drift": f["drift"], "rings": f["rings"]}
		}
	}
	for _, e := range org.Experiments {
		out.Experiments = append(out.Experiments, expRow{e.Name, e.Status, string(e.Type), string(e.Axis), e.Rings, killed[e.Name]})
	}
	for _, r := range org.Rollouts {
		out.Rollouts = append(out.Rollouts, rolloutRow{r.Name, r.EffectiveStatus(), r.Step, r.Experiment})
	}
	out.Toggles = len(org.Toggles)
	out.NextSteps = s.statusNext(out)
	return nil, out, nil
}

func (s *srv) statusNext(o statusOut) []string {
	var n []string
	if !o.Policy.OK {
		n = append(n, "policy has errors: call validate and fix them before anything else")
	}
	if !o.Server.AllowWrites {
		n = append(n, gateAllowW)
	}
	if !o.Server.ClickHouse {
		n = append(n, gateEvidence)
	}
	if o.Server.HaloServer == "" || !o.Server.AdminSession {
		n = append(n, "fleet plane off: "+gateServer)
	}
	for _, e := range o.Experiments {
		switch e.Status {
		case "running":
			n = append(n, fmt.Sprintf("experiment %s is running: wait_for kind=experiment name=%s, then propose_promotion or propose_rollback on the verdict", e.Name, e.Name))
		case "draft", "":
			n = append(n, fmt.Sprintf("experiment %s is a draft: validate, plan, eval_run, then start_experiment after a human yes", e.Name))
		}
	}
	for _, r := range o.Rollouts {
		if r.Status == policy.RolloutActive {
			n = append(n, fmt.Sprintf("rollout %s is active: rollout_status name=%s; propose_rollout_advance when its decision is advance", r.Name, r.Name))
		}
	}
	if len(n) == 0 {
		n = append(n, "nothing in flight: read "+guideURI+" or the autopilot prompt to start a rollout")
	}
	return n
}

// ---- release build ----

func (s *srv) releaseBuild(_ context.Context, _ *mcp.CallToolRequest, in releaseBuildIn) (*mcp.CallToolResult, releaseBuildOut, error) {
	rel, err := s.buildRelease(in.Ring, in.ReleaseVersion)
	if err != nil {
		return nil, releaseBuildOut{}, err
	}
	m := rel.Manifest
	out := releaseBuildOut{Ring: m.Ring, Profile: m.Profile, Version: m.Version, Digest: rel.Digest,
		Harnesses: map[string]string{}, Files: []string{}, Warnings: m.Warnings}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	for h, e := range m.Harnesses {
		out.Harnesses[h] = e.Version
		for osName, fs := range e.Files {
			for _, f := range fs {
				out.Files = append(out.Files, h+"/"+osName+"/"+f.Path)
			}
		}
	}
	sort.Strings(out.Files)
	out.NextSteps = []string{
		"the digest above is this local build's; the published digest is what `halo release publish` prints, and rings pin that one",
		fmt.Sprintf(gatePublish, m.Ring, m.Version),
		"after publishing: `plan` against the published release.tar before the next change, and `render_preview` to review what lands",
	}
	if len(out.Warnings) > 0 {
		out.NextSteps = append([]string{"adapter warnings above name settings a harness cannot honour; decide with the human whether that is acceptable"}, out.NextSteps...)
	}
	return nil, out, nil
}

// ---- wait_for ----

func (s *srv) waitFor(ctx context.Context, _ *mcp.CallToolRequest, in waitIn) (*mcp.CallToolResult, waitOut, error) {
	out := waitOut{Kind: in.Kind, Name: in.Name, NextSteps: []string{}}
	if in.Kind != "experiment" && in.Kind != "rollout" {
		return nil, out, fmt.Errorf("kind must be experiment or rollout, got %q", in.Kind)
	}
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if timeout > waitMax {
		timeout = waitMax
	}
	interval := time.Duration(in.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 10 * time.Second
	}
	org, err := s.load()
	if err != nil {
		return nil, out, err
	}
	var poll func(context.Context) (map[string]any, string, bool, error)
	switch in.Kind {
	case "experiment":
		e, err := findExp(org, in.Name)
		if err != nil {
			return nil, out, err
		}
		if e.Status != "running" {
			out.Satisfied, out.Outcome, out.Reason = true, e.Status, "experiment is not running; nothing to wait for"
			out.NextSteps = append(out.NextSteps, "show_experiment "+e.Name+"; start_experiment to run it (human yes first)")
			return nil, out, nil
		}
		if s.ClickHouse == nil {
			out.Reason = "no evidence source"
			out.NextSteps = append(out.NextSteps, gateEvidence)
			return nil, out, nil
		}
		poll = func(ctx context.Context) (map[string]any, string, bool, error) {
			rep, err := promote.Evaluate(ctx, e, s.ClickHouse)
			if err != nil {
				return nil, "", false, err
			}
			m, _ := toMap(rep)
			return m, string(rep.Verdict), rep.Verdict != promote.Continue, nil
		}
	case "rollout":
		r, err := findRollout(org, in.Name)
		if err != nil {
			return nil, out, err
		}
		if st := r.EffectiveStatus(); st == policy.RolloutAborted || st == policy.RolloutCompleted {
			out.Satisfied, out.Outcome, out.Reason = true, st, "rollout is "+st+"; nothing to wait for"
			return nil, out, nil
		}
		poll = func(ctx context.Context) (map[string]any, string, bool, error) {
			_, d, err := s.evaluate(ctx, org, r)
			if err != nil {
				return nil, "", false, err
			}
			m, _ := toMap(d)
			return m, string(d.Action), d.Action != rollout.Hold, nil
		}
	}
	start := time.Now()
	deadline := start.Add(timeout)
	for {
		last, outcome, done, err := poll(ctx)
		out.Polls++
		out.Last, out.Outcome, out.ElapsedSeconds = last, outcome, time.Since(start).Seconds()
		if err != nil {
			return nil, out, fmt.Errorf("poll %s %s: %w", in.Kind, in.Name, err)
		}
		if done {
			out.Satisfied = true
			break
		}
		if time.Now().Add(interval).After(deadline) {
			out.Reason = "timeout: still " + outcome
			break
		}
		select {
		case <-ctx.Done():
			out.Reason = "cancelled"
			return nil, out, nil
		case <-time.After(interval):
		}
	}
	out.NextSteps = waitNext(in, out)
	return nil, out, nil
}

func waitNext(in waitIn, o waitOut) []string {
	if !o.Satisfied {
		return []string{fmt.Sprintf("call wait_for again (kind=%s name=%s); nothing to decide yet", in.Kind, in.Name)}
	}
	if in.Kind == "experiment" {
		switch promote.Verdict(o.Outcome) {
		case promote.Promote:
			return []string{"verdict promote: propose_promotion (dry_run first) for the ring and the published release digest; " + gateMerge}
		case promote.Rollback:
			return []string{"verdict rollback: kill_switch " + in.Name + " for the immediate stop (dry_run first), then propose_rollback to record it in policy; " + gateApprove}
		default:
			return []string{"verdict " + o.Outcome + ": pause_experiment or conclude_experiment after a human decision"}
		}
	}
	switch rollout.Action(o.Outcome) {
	case rollout.Advance, rollout.Complete:
		return []string{"decision " + o.Outcome + ": propose_rollout_advance " + in.Name + " (dry_run first); " + gateApprove}
	case rollout.Rollback, rollout.Pause:
		return []string{"decision " + o.Outcome + ": kill_switch " + in.Name + " for the immediate stop, then propose_rollout_rollback " + in.Name + "; " + gateApprove}
	}
	return []string{"decision " + o.Outcome + ": rollout_status " + in.Name + " for the gate detail"}
}

// ---- halo-server client ----

func (s *srv) serverURL() string {
	if s.Server != "" {
		return s.Server
	}
	return os.Getenv("HALO_SERVER")
}

// session is the admin cookie value, read from the environment at call time
// and never from a tool argument.
func (s *srv) session() string { return strings.TrimSpace(os.Getenv("HALO_SESSION")) }

func (s *srv) serverJSON(ctx context.Context, method, path string, body any) (map[string]any, error) {
	raw := s.serverURL()
	if raw == "" || s.session() == "" {
		return nil, errors.New(gateServer)
	}
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("invalid halo-server URL %q", raw)
	}
	if host := base.Hostname(); base.Scheme != "https" && host != "localhost" && !isLoopback(host) {
		return nil, errors.New("halo-server URL must be https (or http on loopback): the session cookie would travel in clear")
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(raw, "/")+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "halo_session", Value: s.session()})
	cl := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("halo-server %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, serverLimit))
	if err != nil {
		return nil, fmt.Errorf("halo-server %s %s: read: %w", method, path, err)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("halo-server %s %s: %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	// Objects come back as-is; a bare array (e.g. /api/v1/devices) is wrapped as {"items": [...]}.
	var v any
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("halo-server %s %s: decode: %w", method, path, err)
	}
	switch m := v.(type) {
	case map[string]any:
		return m, nil
	case []any:
		return map[string]any{"items": m}, nil
	}
	return nil, fmt.Errorf("halo-server %s %s: unexpected reply %.100s", method, path, b)
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *srv) killList(ctx context.Context) killListOut {
	out := killListOut{Killed: []map[string]any{}}
	m, err := s.serverJSON(ctx, "GET", "/api/v1/killswitch", nil)
	if err != nil {
		out.Reason = err.Error()
		out.NextSteps = []string{gateServer}
		if s.serverURL() != "" && s.session() != "" {
			out.NextSteps = []string{"halo-server answered an error; if it is 501 the kill switch is not configured there (--killswitch-key-file)"}
		}
		return out
	}
	out.Configured = true
	if v, ok := m["version"].(float64); ok {
		out.Version = uint64(v)
	}
	if ks, ok := m["killed"].([]any); ok {
		for _, k := range ks {
			if km, ok := k.(map[string]any); ok {
				out.Killed = append(out.Killed, km)
			}
		}
	}
	if len(out.Killed) == 0 {
		out.NextSteps = []string{"nothing is killed"}
	} else {
		out.NextSteps = []string{"every kill needs its policy counterpart: propose_rollback (experiment) or propose_rollout_rollback (rollout), then a human merges; kill_switch unkill=true clears one"}
	}
	return out
}

func (s *srv) killSwitchStatus(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, killListOut, error) {
	return nil, s.killList(ctx), nil
}

func (s *srv) fleetStatus(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, map[string]any, error) {
	f, err := s.serverJSON(ctx, "GET", "/api/v1/fleet", nil)
	if err != nil {
		return nil, nil, err
	}
	d, err := s.serverJSON(ctx, "GET", "/api/v1/devices", nil)
	if err != nil {
		return nil, nil, err
	}
	f["devices"] = d["items"]
	if f["devices"] == nil {
		f["devices"] = d["devices"]
	}
	f["next_steps"] = []string{"drift > 0 means a device's managed config differs from its ring's release: fleet_status lists which; a device off its release fails posture on enforce rings"}
	return nil, f, nil
}

func (s *srv) auditTail(ctx context.Context, _ *mcp.CallToolRequest, in auditIn) (*mcp.CallToolResult, map[string]any, error) {
	q := url.Values{}
	if in.Limit > 0 {
		q.Set("limit", strconv.Itoa(in.Limit))
	}
	if in.Since != "" {
		q.Set("since", in.Since)
	}
	path := "/api/v1/audit"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	m, err := s.serverJSON(ctx, "GET", path, nil)
	if err != nil {
		return nil, nil, err
	}
	m["next_steps"] = []string{"pass the last entry's seq as `since` to tail from there"}
	return nil, m, nil
}

// ---- kill switch (write) ----

func (s *srv) killSwitch(ctx context.Context, _ *mcp.CallToolRequest, in killIn) (*mcp.CallToolResult, killOut, error) {
	out := killOut{DryRun: isDry(in.DryRun), NextSteps: []string{}}
	reason, err := need(in.Reason)
	if err != nil {
		return nil, out, err
	}
	org, err := s.load()
	if err != nil {
		return nil, out, err
	}
	kind, target, hint, err := resolveKill(org, in.Name, in.Kind)
	if err != nil {
		return nil, out, err
	}
	verb := "kill"
	if in.Unkill {
		verb = "unkill"
	}
	out.Kind, out.Name = kind, target
	out.Request = fmt.Sprintf("POST %s/api/v1/%ss/%s/%s", s.serverURL(), kind, target, verb)
	out.Command = fmt.Sprintf("halo kill %s --kind %s --reason %q", in.Name, kind, reason)
	if in.Unkill {
		out.Command += " --unkill"
	}
	run, err := s.mayWrite(in.DryRun, out.Command)
	if err != nil {
		return nil, out, err
	}
	if hint != "" {
		out.NextSteps = append(out.NextSteps, hint)
	}
	if !run {
		out.Note = "dry run: nothing sent; pass dry_run=false to " + verb + " through halo-server"
		out.NextSteps = append(out.NextSteps, gateApprove)
		return nil, out, nil
	}
	res, err := s.serverJSON(ctx, "POST", fmt.Sprintf("/api/v1/%ss/%s/%s", kind, url.PathEscape(target), verb), map[string]string{"reason": reason})
	if err != nil {
		return nil, out, err
	}
	out.Applied, out.Result = true, res
	if ch, _ := res["changed"].(bool); !ch {
		out.Note = "already in that state (idempotent)"
	} else {
		out.Note = verb + " recorded; devices and gateways pick it up at their next poll"
	}
	if !in.Unkill {
		out.NextSteps = append(out.NextSteps, "record it in policy: propose_rollback (experiment) or propose_rollout_rollback (rollout) with the same reason; "+gateApprove)
	}
	return nil, out, nil
}

// resolveKill mirrors `halo kill`: a rollout kills its backing experiment.
func resolveKill(org *policy.Org, name, kind string) (string, string, string, error) {
	var kinds []string
	for _, e := range org.Experiments {
		if e.Name == name {
			kinds = append(kinds, "experiment")
		}
	}
	for _, t := range org.Toggles {
		if t.Name == name {
			kinds = append(kinds, "toggle")
		}
	}
	for _, r := range org.Rollouts {
		if r.Name == name {
			kinds = append(kinds, "rollout")
		}
	}
	if kind != "" {
		found := false
		for _, k := range kinds {
			found = found || k == kind
		}
		if !found {
			return "", "", "", fmt.Errorf("no %s named %q", kind, name)
		}
		kinds = []string{kind}
	}
	switch len(kinds) {
	case 0:
		return "", "", "", fmt.Errorf("no experiment, toggle or rollout named %q", name)
	case 1:
	default:
		return "", "", "", fmt.Errorf("%q names a %s; pick one with kind", name, strings.Join(kinds, " and a "))
	}
	if kinds[0] != "rollout" {
		return kinds[0], name, "", nil
	}
	r, _ := findRollout(org, name)
	if r.Experiment == "" {
		return "", "", "", fmt.Errorf("rollout %s has no backing experiment to kill; abort it with propose_rollout_rollback", name)
	}
	return "experiment", r.Experiment, "then propose_rollout_rollback " + name + " (dry_run first) so policy records the abort", nil
}

// ---- eval run ----

func (s *srv) evalRun(ctx context.Context, _ *mcp.CallToolRequest, in evalRunIn) (*mcp.CallToolResult, evalRunOut, error) {
	out := evalRunOut{DryRun: isDry(in.DryRun), NextSteps: []string{}}
	p, err := s.policyFile(in.Suite, "")
	if err != nil {
		return nil, out, err
	}
	if in.Suite == "" {
		return nil, out, errors.New("suite is required")
	}
	su, err := eval.LoadSuite(p)
	if err != nil {
		return nil, out, err
	}
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	if timeout > evalRunMax {
		timeout = evalRunMax
	}
	scDir := filepath.Join(s.dir, ".halos", "scorecards")
	out.Path = filepath.Join(scDir, fmt.Sprintf("%s-%s.json", su.Name, time.Now().UTC().Format("20060102T150405Z")))
	args := []string{"eval", "run", p, "--output", "json", "--scorecard", out.Path}
	if in.Matrix {
		args = append(args, "--matrix")
	}
	if in.Local {
		args = append(args, "--local")
	}
	out.Command = "halo " + strings.Join(args, " ")
	run, err := s.mayWrite(in.DryRun, out.Command)
	if err != nil {
		return nil, out, err
	}
	if !run {
		out.NextSteps = []string{"this spends the human's model credentials and Docker time: " + gateApprove, "after the run: eval_scorecard on scorecard_path, and compare pass rate with the baseline before start_experiment"}
		return nil, out, nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil, out, err
	}
	if err := os.MkdirAll(scDir, 0o755); err != nil {
		return nil, out, err
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, self, args...)
	cmd.Dir = s.dir
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	err = cmd.Run()
	out.Ran = true
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		out.ExitCode = ee.ExitCode()
	case err != nil:
		return nil, out, fmt.Errorf("run %s: %w", out.Command, err)
	}
	if tail := se.String(); len(tail) > 4000 {
		tail = tail[len(tail)-4000:]
		out.Stderr = tail
	} else {
		out.Stderr = tail
	}
	if cctx.Err() != nil {
		out.NextSteps = []string{"timed out after " + timeout.String() + ": run the command in a terminal or raise timeout_seconds"}
		return nil, out, nil
	}
	var sc map[string]any
	if err := json.Unmarshal(so.Bytes(), &sc); err == nil {
		out.Scorecard = sc
	}
	out.NextSteps = []string{"eval_scorecard path=" + out.Path + " for the full card; the gate verdict decides whether to start_experiment (hold or block: stop and tell the human)"}
	return nil, out, nil
}
