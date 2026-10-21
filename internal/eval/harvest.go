package eval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/shadow"
)

// Harvest turns shadow steps into step-level regression cases (ADR-0020):
// the real (redacted) prefix, the offered tools and the action production
// took, graded later by a deterministic action matcher.

// Selection reasons: why a step became a case.
const (
	SelectDiverged      = "diverged"       // candidate's tools differ from the control replay or from production
	SelectInvalidCall   = "invalid-call"   // candidate called a tool not offered, or missed a required argument
	SelectPrematureStop = "premature-stop" // production kept working; the candidate ended its turn
	SelectJudgeLoss     = "judge-loss"     // judge scored the candidate below the control by more than JudgeLoss
	SelectSample        = "sample"         // stratified random sample by depth
)

// DefaultSelect is the selection when none is given: the step-level failures.
var DefaultSelect = []string{SelectDiverged, SelectInvalidCall, SelectPrematureStop}

var knownSelect = []string{SelectDiverged, SelectInvalidCall, SelectPrematureStop, SelectJudgeLoss, SelectSample}

// Matcher modes for StepCase.Match.
const (
	MatchTools = "tools" // same multiset of tool names (or both stopped)
	MatchCalls = "calls" // same tools with identical canonical arguments
)

// Expected-action sources.
const (
	FromProduction = "production" // recovered from the session's next mirrored request
	FromControl    = "control"    // the control replay, when production's action was not recovered
)

// StepCase is one harvested step: the request the coding agent really sent,
// the tools it offered and the action to reproduce. Graded by GradeStep.
type StepCase struct {
	ID       string          `json:"id"`
	Protocol string          `json:"protocol"`
	Request  json.RawMessage `json:"request"` // redacted
	// Tools are the offered tools: name -> required argument keys (null for
	// freeform and server tools).
	Tools        map[string][]string `json:"tools"`
	Expected     Action              `json:"expected"`
	ExpectedFrom string              `json:"expectedFrom"`
	// Alternatives are also accepted: the control replay, when it differed
	// from production's action but was valid (the incumbent's own choice).
	Alternatives []Action   `json:"alternatives,omitempty"`
	Match        string     `json:"match"`
	Reasons      []string   `json:"reasons"`
	Provenance   Provenance `json:"provenance"`
}

// Provenance says where a case came from. Session is hashed (SessionUnit):
// a raw session id is never written.
type Provenance struct {
	PairID         string    `json:"pairId"`
	Experiment     string    `json:"experiment"`
	Session        string    `json:"session"`
	Depth          int       `json:"depth"`
	HarvestedAt    time.Time `json:"harvestedAt"`
	RedactionRules string    `json:"redactionRules"`
}

// HarvestOptions selects and redacts steps.
type HarvestOptions struct {
	// Experiment limits the harvest to one experiment ("" = all).
	Experiment string
	// Select lists the reasons that make a step a case (default DefaultSelect).
	Select []string
	// Scores are judge scores per pair id (HistoryScores); needed by judge-loss.
	Scores map[string]PairScore
	// JudgeLoss: control minus candidate judge score above which a step is
	// selected (default 0.2).
	JudgeLoss float64
	// PerDepth caps the stratified sample per depth bucket (default 5).
	PerDepth int
	Seed     uint64
	// Redactor is required: nothing is harvested unredacted.
	Redactor *Redactor
	Now      func() time.Time
}

// HarvestResult is the harvested cases plus what was looked at.
type HarvestResult struct {
	Steps int `json:"steps"` // parsed steps considered
	// Skipped: selected steps whose expected action was itself invalid
	// (a tool not offered, a missing argument), so not a usable test.
	Skipped  int            `json:"skipped"`
	ByReason map[string]int `json:"byReason"`
	Cases    []StepCase     `json:"-"`
}

// CaseSummary is a case without its content (safe to print or return over MCP).
type CaseSummary struct {
	ID           string     `json:"id"`
	Reasons      []string   `json:"reasons"`
	ExpectedFrom string     `json:"expectedFrom"`
	Expected     []string   `json:"expectedTools"`
	Provenance   Provenance `json:"provenance"`
}

// Summary lists the cases by provenance and expected tool names only.
func (h *HarvestResult) Summary() []CaseSummary {
	out := []CaseSummary{}
	for _, c := range h.Cases {
		out = append(out, CaseSummary{ID: c.ID, Reasons: c.Reasons, ExpectedFrom: c.ExpectedFrom, Expected: c.Expected.names(), Provenance: c.Provenance})
	}
	return out
}

func (o *HarvestOptions) defaults() error {
	if o.Redactor == nil {
		return errors.New("harvest: a redactor is required (redaction is mandatory)")
	}
	if len(o.Select) == 0 {
		o.Select = DefaultSelect
	}
	for _, s := range o.Select {
		if !slices.Contains(knownSelect, s) {
			return fmt.Errorf("harvest: unknown selection %q (want %v)", s, knownSelect)
		}
	}
	if slices.Contains(o.Select, SelectJudgeLoss) && o.Scores == nil {
		return errors.New("harvest: judge-loss needs judge scores (the `halo eval online` history)")
	}
	if o.JudgeLoss == 0 {
		o.JudgeLoss = 0.2
	}
	if o.JudgeLoss < 0 || o.JudgeLoss > 1 {
		return fmt.Errorf("harvest: judge loss must be in (0,1], got %v", o.JudgeLoss)
	}
	if o.PerDepth == 0 {
		o.PerDepth = 5
	}
	if o.PerDepth < 0 {
		return fmt.Errorf("harvest: per-depth sample must be >= 1, got %d", o.PerDepth)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return nil
}

// sampled picks up to per steps per depth bucket with a seeded shuffle.
func sampled(steps []agentStep, per int, seed uint64) map[int]bool {
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)) //nolint:gosec // reproducible sampling, not security
	out := map[int]bool{}
	for _, bk := range depthBuckets {
		var idx []int
		for i, s := range steps {
			if d := s.conv.steps(); d >= bk.lo && d <= bk.hi {
				idx = append(idx, i)
			}
		}
		rng.Shuffle(len(idx), func(i, j int) { idx[i], idx[j] = idx[j], idx[i] })
		for _, i := range idx[:min(per, len(idx))] {
			out[i] = true
		}
	}
	return out
}

// Harvest reads the pair store, selects steps and returns them as redacted
// cases. Any redaction failure fails the whole harvest: nothing partial.
func Harvest(ctx context.Context, src PairSource, o HarvestOptions) (*HarvestResult, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	pairs, err := src.Pairs(ctx)
	if err != nil {
		return nil, fmt.Errorf("harvest: %w", err)
	}
	if o.Experiment != "" {
		pairs = slices.DeleteFunc(pairs, func(p shadow.Pair) bool { return p.Experiment != o.Experiment })
	}
	// Auxiliary requests, retries and truncated steps are not steps.
	steps := agentSteps(pairs).steps
	on := map[string]bool{}
	for _, s := range o.Select {
		on[s] = true
	}
	var sample map[int]bool
	if on[SelectSample] {
		sample = sampled(steps, o.PerDepth, o.Seed)
	}
	res := &HarvestResult{Steps: len(steps), ByReason: map[string]int{}}
	at := o.Now().UTC()
	for i, s := range steps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var why []string
		inv, sch := s.conv.tools.validity(s.cand)
		ps, scored := o.Scores[s.pair.ID]
		for _, r := range []struct {
			name string
			hit  bool
		}{
			{SelectDiverged, !SameTools(s.cand, s.ctl) || (s.ref != nil && !SameTools(s.cand, *s.ref))},
			{SelectInvalidCall, inv || sch},
			{SelectPrematureStop, s.ref != nil && !s.ref.Stopped() && s.cand.Stopped()},
			{SelectJudgeLoss, scored && ps.Control-ps.Candidate > o.JudgeLoss},
			{SelectSample, sample[i]},
		} {
			if on[r.name] && r.hit {
				why = append(why, r.name)
			}
		}
		if len(why) == 0 {
			continue
		}
		c, ok, err := buildCase(s, why, o.Redactor, at)
		if err != nil {
			return nil, fmt.Errorf("harvest: pair %s: %w", s.pair.ID, err)
		}
		if !ok {
			res.Skipped++
			continue
		}
		for _, w := range why {
			res.ByReason[w]++
		}
		res.Cases = append(res.Cases, c)
	}
	return res, nil
}

// buildCase redacts one step into a case; ok is false when the expected
// action is not a valid call for the offered tools.
func buildCase(s agentStep, why []string, r *Redactor, at time.Time) (StepCase, bool, error) {
	exp, from := s.ctl, FromControl
	if s.ref != nil {
		exp, from = *s.ref, FromProduction
	}
	if inv, sch := s.conv.tools.validity(exp); inv || sch {
		return StepCase{}, false, nil
	}
	alts := []Action{}
	if from == FromProduction && !SameCalls(s.ctl, exp) {
		if inv, sch := s.conv.tools.validity(s.ctl); !inv && !sch {
			alts = append(alts, s.ctl)
		}
	}
	body, err := r.Request(s.pair.Request)
	if err != nil {
		return StepCase{}, false, err
	}
	// The redacted request must still be the same step of the same
	// conversation, or the case would test something else.
	cv, ok := parseRequest(s.pair.Protocol, body)
	if !ok || cv.steps() != s.conv.steps() {
		return StepCase{}, false, errors.New("redacted request no longer parses as the same step")
	}
	c := StepCase{Protocol: s.pair.Protocol, Request: body, Tools: cv.tools, ExpectedFrom: from, Match: MatchTools, Reasons: why,
		Provenance: Provenance{PairID: s.pair.ID, Experiment: s.pair.Experiment, Session: SessionUnit(cluster(s.pair)), Depth: s.conv.steps(),
			HarvestedAt: at, RedactionRules: r.Version()}}
	if c.Expected, err = r.Action(exp); err != nil {
		return StepCase{}, false, err
	}
	for _, a := range alts {
		ra, err := r.Action(a)
		if err != nil {
			return StepCase{}, false, err
		}
		c.Alternatives = append(c.Alternatives, ra)
	}
	h := sha256.Sum256([]byte(s.pair.ID))
	c.ID = "step-" + hex.EncodeToString(h[:6])
	return c, true, nil
}

func (c StepCase) validate() error {
	switch {
	case c.ID == "" || filepath.Base(c.ID) != c.ID:
		return fmt.Errorf("case %q: id must be a plain name", c.ID)
	case !slices.Contains([]string{gateway.ProtoAnthropic, gateway.ProtoBedrock, gateway.ProtoResponses, gateway.ProtoGemini}, c.Protocol):
		return fmt.Errorf("case %s: unknown protocol %q", c.ID, c.Protocol)
	case c.Match != MatchTools && c.Match != MatchCalls:
		return fmt.Errorf("case %s: match must be %s or %s, got %q", c.ID, MatchTools, MatchCalls, c.Match)
	case c.Provenance.Session == "":
		return fmt.Errorf("case %s: provenance.session is required (steps are clustered by session)", c.ID)
	}
	if _, ok := parseRequest(c.Protocol, c.Request); !ok {
		return fmt.Errorf("case %s: request does not parse as a %s model call", c.ID, c.Protocol)
	}
	return nil
}

// WriteStepCases writes one <id>.json per case into dir (created 0700), each
// 0600. Every file is encoded and re-checked for surviving credentials before
// the first one is written, so a failure leaves no partial suite.
func WriteStepCases(dir string, cases []StepCase) error {
	bufs := make([][]byte, len(cases))
	for i, c := range cases {
		if err := c.validate(); err != nil {
			return fmt.Errorf("write cases: %w", err)
		}
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("write cases: encode %s: %w", c.ID, err)
		}
		if err := checkRedacted(b); err != nil {
			return fmt.Errorf("write cases: %s: %w", c.ID, err)
		}
		bufs[i] = append(b, '\n')
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("write cases: %w", err)
	}
	for i, c := range cases {
		if err := writePrivate(filepath.Join(dir, c.ID+".json"), bufs[i]); err != nil {
			return fmt.Errorf("write cases: %w", err)
		}
	}
	return nil
}

// writePrivate writes b to path atomically with mode 0600 (CreateTemp's
// mode), whatever mode an existing file had.
func writePrivate(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".case-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }() // no-op after the rename
	if _, err := f.Write(b); err != nil {
		_ = f.Close() // already failing
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if err := os.Chmod(f.Name(), 0o600); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return os.Rename(f.Name(), path)
}

// LoadStepCases reads every *.json case in dir, sorted by file name.
func LoadStepCases(dir string) ([]StepCase, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("load cases: %w", err)
	}
	sort.Strings(files)
	var out []StepCase
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // operator-chosen suite dir
		if err != nil {
			return nil, fmt.Errorf("load cases: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var c StepCase
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("load cases: %s: %w", f, err)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("load cases: %s: %w", f, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("load cases: no *.json cases in %s", dir)
	}
	return out, nil
}
