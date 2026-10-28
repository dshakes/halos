package copilot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/roi"
)

// Suggestion is one next step, with the evidence it rests on and the exact
// command. HumanGate marks a command that changes state: a human runs it.
type Suggestion struct {
	Title     string   `json:"title"`
	Evidence  []string `json:"evidence"`
	Command   string   `json:"command"`
	HumanGate bool     `json:"humanGate"`
}

// Verdict is one row of the verdicts file (`halo exp analyze --verdicts-file`).
type Verdict struct {
	Experiment string `json:"experiment"`
	promote.Report
	EvaluatedAt time.Time `json:"evaluatedAt"`
}

// ReadVerdicts reads a verdicts file (a JSON array).
func ReadVerdicts(path string) ([]Verdict, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-named file
	if err != nil {
		return nil, fmt.Errorf("copilot: read verdicts: %w", err)
	}
	var v []Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("copilot: parse verdicts %s (want a JSON array): %w", path, err)
	}
	return v, nil
}

// ReadJSON decodes a JSON file (a scorecard, an ROI report) into v.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path) //nolint:gosec // operator-named file
	if err != nil {
		return fmt.Errorf("copilot: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("copilot: parse %s: %w", path, err)
	}
	return nil
}

// BudgetState is one budget counter (halo-server `GET /api/v1/budgets`).
type BudgetState struct {
	Budget      string  `json:"budget"`
	Key         string  `json:"key"`
	Utilization float64 `json:"utilization"`
	Exceeded    bool    `json:"exceeded"`
	Alert       bool    `json:"alert"`
}

// NextInput is the data `halo copilot next` reads. Only Org is required.
type NextInput struct {
	Org        *policy.Org
	PolicyDir  string // added to commands as --policy-dir when not "."
	Verdicts   []Verdict
	Scorecards map[string]*eval.Scorecard // by file path
	ROI        *roi.Report
	Budgets    []BudgetState
}

var safeWord = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

func sh(argv ...string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = a
		if a == "" || !safeWord.MatchString(a) {
			q[i] = hutil.ShQuote(a)
		}
	}
	return strings.Join(q, " ")
}

// Next derives suggestions from existing data by fixed rules: no model.
func Next(in NextInput) ([]Suggestion, error) {
	if in.Org == nil {
		return nil, errors.New("copilot: next needs the policy")
	}
	halo := func(args ...string) string {
		if in.PolicyDir != "" && in.PolicyDir != "." {
			args = append(args, "--policy-dir", in.PolicyDir)
		}
		return sh(append([]string{"halo"}, args...)...)
	}
	verdicts := map[string]Verdict{}
	for _, v := range in.Verdicts {
		verdicts[v.Experiment] = v
	}
	out := []Suggestion{}
	exps := append([]*policy.Experiment(nil), in.Org.Experiments...)
	sort.Slice(exps, func(i, j int) bool { return exps[i].Name < exps[j].Name })
	for _, e := range exps {
		status := e.Status
		if status == "" {
			status = "draft"
		}
		ev := []string{fmt.Sprintf("experiment %s: status %s, rings %s, primary %s (%s)", e.Name, status, strings.Join(e.Rings, ","), e.Metrics.Primary.Metric, e.Metrics.Primary.Direction)}
		v, hasV := verdicts[e.Name]
		if hasV {
			ev = append(ev, fmt.Sprintf("verdict %s at %s: %s (n=%d/%d, effect %+.4g, p=%.4g)", v.Verdict, v.EvaluatedAt.UTC().Format(time.RFC3339), v.Reason, v.NControl, v.NTreatment, v.Effect, v.PValue))
		}
		switch {
		case status == "draft":
			out = append(out, Suggestion{Title: "start draft experiment " + e.Name + " after review", Evidence: ev, Command: halo("exp", "start", e.Name), HumanGate: true})
		case status == "running" && !hasV:
			out = append(out, Suggestion{Title: "analyze running experiment " + e.Name + " (no verdict on record)", Evidence: ev,
				Command: halo("exp", "analyze", e.Name, "--clickhouse", "<clickhouse-url>")})
		case status == "running" && v.Verdict == promote.Promote:
			ring := ""
			if len(e.Rings) > 0 {
				ring = e.Rings[0]
			}
			out = append(out, Suggestion{Title: "promote " + e.Name + ": the verdict is promote (opens a PR; a human merges)", Evidence: append(ev, "the release digest comes from `halo release build --ring "+ring+"` of the treatment"),
				Command: halo("exp", "promote", e.Name, "--ring", ring, "--release", "<sha256:treatment-release>", "--dry-run"), HumanGate: true})
		case status == "running" && v.Verdict == promote.Rollback:
			out = append(out, Suggestion{Title: "pause " + e.Name + ": the verdict is rollback", Evidence: ev, Command: halo("exp", "pause", e.Name), HumanGate: true})
		case status == "running" && v.Verdict == promote.Expired:
			out = append(out, Suggestion{Title: "conclude " + e.Name + ": its day or spend budget ran out without a decision", Evidence: ev, Command: halo("exp", "conclude", e.Name), HumanGate: true})
		case status == "paused":
			out = append(out, Suggestion{Title: "decide on paused experiment " + e.Name + ": conclude it, or restart it after a fix", Evidence: ev, Command: halo("exp", "conclude", e.Name), HumanGate: true})
		}
	}
	paths := make([]string, 0, len(in.Scorecards))
	for p := range in.Scorecards {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		sc := in.Scorecards[p]
		if sc == nil || sc.Gate == nil {
			continue
		}
		ev := []string{fmt.Sprintf("scorecard %s (suite %s): gate %s", p, sc.Suite, sc.Gate.Verdict)}
		for _, r := range sc.Gate.Reasons {
			ev = append(ev, "gate reason: "+r)
		}
		for _, c := range sc.Comparisons {
			ev = append(ev, fmt.Sprintf("%s vs %s: pass delta %+.3f [%.3f, %.3f] over %d tasks (%s)", c.Variant, c.Control, c.Delta, c.CILo, c.CIHi, c.Tasks, c.Verdict))
		}
		cand := sc.Control
		if len(sc.Comparisons) > 0 {
			cand = sc.Comparisons[0].Variant
		}
		switch sc.Gate.Verdict {
		case "ship":
			out = append(out, Suggestion{Title: "eval suite " + sc.Suite + " ships " + cand + ": design an online experiment for it", Evidence: ev,
				Command: halo("copilot", "experiment", cand+" improves on "+sc.Control+" in production (eval suite "+sc.Suite+" ships)")})
		case "hold", "block":
			s := Suggestion{Title: "eval suite " + sc.Suite + " says " + sc.Gate.Verdict + " for " + cand + ": do not widen its rollout", Evidence: ev, Command: halo("exp", "list")}
			if e := runningWith(exps, cand); e != nil {
				s.Title = "pause " + e.Name + ": its arm " + cand + " fails eval suite " + sc.Suite + " (" + sc.Gate.Verdict + ")"
				s.Command, s.HumanGate = halo("exp", "pause", e.Name), true
			}
			out = append(out, s)
		}
	}
	if r := in.ROI; r != nil {
		ev := []string{fmt.Sprintf("ROI report (%s, %s): status %s", r.Design, r.Experiment, r.Status)}
		ev = append(ev, r.Warnings...)
		switch r.Status {
		case roi.StatusSRM:
			out = append(out, Suggestion{Title: "ROI sample ratio mismatch: do not quote its effects", Evidence: ev, Command: halo("roi", "report", "--experiment", r.Experiment)})
		case roi.StatusInsufficientData:
			out = append(out, Suggestion{Title: "ROI has too few developers per arm: re-run after more PRs land", Evidence: ev, Command: halo("roi", "report", "--experiment", r.Experiment)})
		}
	}
	for _, b := range in.Budgets {
		ev := []string{fmt.Sprintf("budget %s key %s at %.0f%%", b.Budget, b.Key, 100*b.Utilization)}
		switch {
		case b.Exceeded:
			out = append(out, Suggestion{Title: "budget " + b.Budget + " is exceeded for " + b.Key, Evidence: ev, Command: sh("halo", "budget", "status", "--budget", b.Budget, "--key", b.Key)})
		case b.Alert:
			out = append(out, Suggestion{Title: "budget " + b.Budget + " passed an alert threshold for " + b.Key, Evidence: ev, Command: sh("halo", "budget", "status", "--budget", b.Budget, "--key", b.Key)})
		}
	}
	return out, nil
}

// runningWith is the first running experiment with a treatment arm named,
// or using the profile, cand.
func runningWith(exps []*policy.Experiment, cand string) *policy.Experiment {
	for _, e := range exps {
		if e.Status != "running" {
			continue
		}
		for _, v := range e.Variants {
			if !v.Control && (v.Name == cand || v.Profile == cand) {
				return e
			}
		}
	}
	return nil
}
