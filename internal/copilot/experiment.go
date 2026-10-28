package copilot

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/stats"
)

// Design is an experiment's shape: what the model (or the offline flags)
// proposes. It carries no numbers that need statistics; Sizing does.
type Design struct {
	Name       string              `json:"name"`
	Axis       policy.Axis         `json:"axis"`
	Rings      []string            `json:"rings"`
	Variants   []policy.Variant    `json:"variants"`
	Primary    policy.MetricGoal   `json:"primary"`
	Guardrails []policy.MetricGoal `json:"guardrails"`
	Rationale  string              `json:"rationale"`
}

const designSchema = `{"type":"object","additionalProperties":false,"required":["name","axis","rings","variants","primary","guardrails","rationale"],
 "properties":{
  "name":{"type":"string","pattern":"^[a-z0-9][a-z0-9.-]{0,62}$"},
  "axis":{"enum":["client","traffic"],"description":"client: arms are profiles; traffic: arms are gateway model routes"},
  "rings":{"type":"array","minItems":1,"items":{"type":"string","description":"existing ring names"}},
  "variants":{"type":"array","minItems":2,"items":{"type":"object","additionalProperties":false,"required":["name","weight"],
   "properties":{"name":{"type":"string"},"weight":{"type":"number","exclusiveMinimum":0},"profile":{"type":"string"},
                 "control":{"type":"boolean","description":"exactly one variant is the control"},
                 "routes":{"type":"object","description":"traffic axis: model alias -> route, as in the policy's gateway routes"}}}},
  "primary":{"type":"object","additionalProperties":false,"required":["metric","direction"],
   "properties":{"metric":{"type":"string","pattern":"^halo\\."},"direction":{"enum":["increase","decrease"]}}},
  "guardrails":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["metric","direction","maxRegression"],
   "properties":{"metric":{"type":"string","pattern":"^halo\\."},"direction":{"enum":["increase","decrease"]},"maxRegression":{"type":"number","exclusiveMinimum":0,"maximum":1}}}},
  "rationale":{"type":"string","minLength":1}}}`

var expName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

func (d *Design) check() error {
	switch {
	case !expName.MatchString(d.Name):
		return fmt.Errorf("name %q must match %s", d.Name, expName)
	case d.Axis != policy.AxisClient && d.Axis != policy.AxisTraffic:
		return fmt.Errorf("axis %q: want client or traffic", d.Axis)
	case len(d.Rings) == 0:
		return errors.New("rings: at least one")
	case len(d.Variants) < 2:
		return errors.New("variants: at least two (one control)")
	case strings.TrimSpace(d.Rationale) == "":
		return errors.New("rationale is required")
	}
	controls := 0
	for _, v := range d.Variants {
		if v.Name == "" || !(v.Weight > 0) {
			return fmt.Errorf("variant %q needs a name and a weight > 0", v.Name)
		}
		if v.Control {
			controls++
		}
	}
	if controls != 1 {
		return fmt.Errorf("want exactly one control variant, got %d", controls)
	}
	for _, g := range append([]policy.MetricGoal{d.Primary}, d.Guardrails...) {
		if !strings.HasPrefix(g.Metric, "halo.") || (g.Direction != "increase" && g.Direction != "decrease") {
			return fmt.Errorf("metric %q direction %q: want a halo.* metric and increase|decrease", g.Metric, g.Direction)
		}
	}
	for _, g := range d.Guardrails {
		if !(g.MaxRegression > 0 && g.MaxRegression <= 1) {
			return fmt.Errorf("guardrail %s: maxRegression must be in (0,1]", g.Metric)
		}
	}
	if d.Primary.MaxRegression != 0 {
		return errors.New("primary: maxRegression is for guardrails only")
	}
	return nil
}

// Sizing is the human's input to the statistics: never the model's.
type Sizing struct {
	Baseline   float64 `json:"baseline"`             // primary metric's current mean
	SD         float64 `json:"sd,omitempty"`         // per-unit sd; 0 = sqrt(p(1-p)) for a rate in (0,1)
	MDE        float64 `json:"mde"`                  // relative minimum detectable effect, e.g. 0.05
	Alpha      float64 `json:"alpha"`                // default 0.05
	Power      float64 `json:"power"`                // default 0.8
	DailyUnits float64 `json:"dailyUnits,omitempty"` // users entering the experiment per day; 0 = no duration
}

// Stats is what internal/stats computed.
type Stats struct {
	SD          float64 `json:"sd"`
	SDDerived   bool    `json:"sdDerived,omitempty"` // sqrt(p(1-p)) from the baseline
	AbsoluteMDE float64 `json:"absoluteMDE"`
	PerArm      int     `json:"perArm"` // min units in the smallest arm
	Total       int     `json:"total"`  // all arms at their weights
	Days        int     `json:"days,omitempty"`
	MaxDays     int     `json:"maxDays"`
	Formula     string  `json:"formula"`
}

// ExperimentResult is the outcome of `halo copilot experiment`.
type ExperimentResult struct {
	Hypothesis string   `json:"hypothesis"`
	OK         bool     `json:"ok"`
	Offline    bool     `json:"offline"`
	Design     *Design  `json:"design,omitempty"`
	Sizing     Sizing   `json:"sizing"`
	Stats      *Stats   `json:"stats,omitempty"`
	File       *File    `json:"file,omitempty"`
	Check      *Check   `json:"check,omitempty"`
	Notes      []string `json:"notes"`
	Stopped    string   `json:"stopped,omitempty"`
	Spend      Spend    `json:"spend"`
}

// isRate reports whether a metric is a proportion, so its sd follows from
// the baseline.
func isRate(metric string) bool {
	return strings.Contains(metric, "rate") || strings.HasSuffix(metric, ".success")
}

// Size computes the sample size and duration for d with internal/stats. It
// is deterministic: the model never does arithmetic.
func Size(d *Design, s Sizing) (*Stats, error) {
	if s.Alpha == 0 {
		s.Alpha = 0.05
	}
	if s.Power == 0 {
		s.Power = 0.8
	}
	if s.Baseline == 0 || math.IsNaN(s.Baseline) {
		return nil, errors.New("copilot: --baseline (the primary metric's current mean) is required and non-zero")
	}
	if !(s.MDE > 0) {
		return nil, errors.New("copilot: --mde (relative minimum detectable effect, e.g. 0.05) must be > 0")
	}
	st := &Stats{SD: s.SD, Formula: "n per arm = 2 (z(1-alpha/2) + z(power))^2 sd^2 / mde^2 (stats.SampleSize)"}
	if st.SD == 0 {
		if !isRate(d.Primary.Metric) || s.Baseline <= 0 || s.Baseline >= 1 {
			return nil, fmt.Errorf("copilot: --sd is required for %s (sd is derived only for a rate metric with a baseline in (0,1))", d.Primary.Metric)
		}
		st.SD, st.SDDerived = math.Sqrt(s.Baseline*(1-s.Baseline)), true
	}
	st.AbsoluteMDE = s.MDE * math.Abs(s.Baseline)
	n, err := stats.SampleSize(st.SD, st.AbsoluteMDE, s.Alpha, s.Power)
	if err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	st.PerArm = n
	var sum, minW float64
	for i, v := range d.Variants {
		sum += v.Weight
		if i == 0 || v.Weight < minW {
			minW = v.Weight
		}
	}
	share := minW / sum
	st.Total = int(math.Ceil(float64(n) / share))
	st.MaxDays = 21
	if s.DailyUnits > 0 {
		st.Days = int(math.Ceil(float64(n) / (s.DailyUnits * share)))
		st.MaxDays = max(2*st.Days, 7)
	}
	return st, nil
}

// experimentYAML renders the experiment document Halos writes: status draft,
// minSamples from stats, mSPRT stopping at alpha.
func experimentYAML(hypothesis string, d *Design, s Sizing, st *Stats) (string, error) {
	alpha := s.Alpha
	if alpha == 0 {
		alpha = 0.05
	}
	e := policy.Experiment{
		Meta:     policy.Meta{APIVersion: "halos.dev/v1", Kind: policy.KindExperiment, Name: d.Name},
		Type:     policy.ExperimentAB,
		Axis:     d.Axis,
		Status:   "draft",
		Rings:    d.Rings,
		Variants: d.Variants,
		Metrics:  policy.Metrics{Primary: d.Primary, Guardrails: d.Guardrails},
		Stopping: policy.Stopping{Method: "msprt", Alpha: alpha, MinSamples: st.PerArm, MaxDays: st.MaxDays},
	}
	b, err := yaml.Marshal(&e)
	if err != nil {
		return "", fmt.Errorf("copilot: render experiment: %w", err)
	}
	head := fmt.Sprintf("# Drafted by halo copilot experiment (ADR-0035). Hypothesis: %s\n"+
		"# minSamples per arm by internal/stats: baseline %g, sd %.4g, relative MDE %g (absolute %.4g), alpha %g, power %g.\n"+
		"# mSPRT stops early when evidence allows; minSamples is the fixed-horizon size. Start with `halo exp start %s` (a human step).\n",
		oneLine(hypothesis), s.Baseline, st.SD, s.MDE, st.AbsoluteMDE, alpha, orDefault(s.Power, 0.8), d.Name)
	return head + string(b), nil
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func orDefault(v, d float64) float64 {
	if v == 0 {
		return d
	}
	return v
}

const experimentSystem = `You are Halos Copilot. Design an A/B experiment in a Halos policy repository to test the operator's hypothesis.
Use only rings and profiles that exist in the policy. Pick one primary metric (halo.*) and guardrails for errors, latency or cost with a maxRegression.
Do not compute sample sizes or durations: Halos computes them.
Reply with ONLY one JSON object matching this JSON Schema (no prose, no code fences):
`

// Experiment designs an experiment for hypothesis: the model (or, offline,
// the given design) proposes the shape, Size computes the numbers, Halos
// renders the YAML and Verify checks it. A design that fails is fed back to
// the model within the run's ceilings. It never writes to dir.
func (c *Client) Experiment(ctx context.Context, dir, hypothesis string, offline *Design, s Sizing) (*ExperimentResult, error) {
	hypothesis = strings.TrimSpace(hypothesis)
	if hypothesis == "" {
		return nil, errors.New("copilot: hypothesis is required")
	}
	res := &ExperimentResult{Hypothesis: hypothesis, Offline: c.Offline(), Sizing: s, Notes: []string{}}
	if c.Offline() {
		if offline == nil {
			return nil, errors.New("copilot: offline experiment design needs the design flags")
		}
		if err := offline.check(); err != nil {
			return nil, fmt.Errorf("copilot: design: %w", err)
		}
		if err := res.build(dir, offline); err != nil {
			return nil, err
		}
		return res, nil
	}
	policyText, err := policyFiles(dir)
	if err != nil {
		return nil, err
	}
	var feedback string
	for i := 1; i <= c.Budget.withDefaults().MaxIterations; i++ {
		parts := []eval.Part{{Title: "Hypothesis (from the operator)", Body: hypothesis}, {Title: "Current policy files", Body: policyText, Untrusted: true}}
		if feedback != "" {
			parts = append(parts, eval.Part{Title: "Halos rejected your previous design; fix these", Body: feedback, Untrusted: true})
		}
		prompt, notice, err := fence(parts...)
		if err != nil {
			return nil, err
		}
		var d Design
		err = c.ask(ctx, experimentSystem+designSchema+"\n\n"+notice, prompt, &d, d.check)
		res.Spend = c.Spend()
		switch {
		case errors.Is(err, ErrBudget):
			res.Stopped = err.Error()
			return res, nil
		case errors.Is(err, ErrSchema):
			feedback, res.Stopped = err.Error(), "the last reply failed schema validation: "+err.Error()
			continue
		case err != nil:
			return nil, err
		}
		if err := res.build(dir, &d); err != nil {
			return nil, err
		}
		if res.OK {
			res.Stopped = ""
			return res, nil
		}
		feedback = "Errors:\n- " + strings.Join(res.Check.Errors, "\n- ")
		res.Stopped = fmt.Sprintf("the design still fails %d checks", len(res.Check.Errors))
	}
	return res, nil
}

func (res *ExperimentResult) build(dir string, d *Design) error {
	st, err := Size(d, res.Sizing)
	if err != nil {
		return err
	}
	y, err := experimentYAML(res.Hypothesis, d, res.Sizing, st)
	if err != nil {
		return err
	}
	f := File{Path: "experiments/" + d.Name + ".yaml", Content: y}
	chk, err := Verify(dir, []File{f})
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f.Path))); err == nil {
		chk.Errors = append(chk.Errors, f.Path+" already exists: choose a new experiment name")
		chk.OK = false
	}
	res.Design, res.Stats, res.File, res.Check, res.OK = d, st, &f, chk, chk.OK
	res.Notes = []string{
		"sample size assumes independent users and a normal approximation; mSPRT may need more units than the fixed-horizon size to reach the same power",
		"the experiment is written with status: draft; starting it is a human step (halo exp start " + d.Name + ")",
	}
	if st.Days == 0 {
		res.Notes = append(res.Notes, "no --daily-units: duration not computed; maxDays defaults to 21")
	}
	if st.SDDerived {
		res.Notes = append(res.Notes, "sd derived as sqrt(p(1-p)) from the baseline rate; pass --sd if the unit is not one Bernoulli trial per user")
	}
	return nil
}
